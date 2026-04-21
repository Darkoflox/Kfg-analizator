import requests
import base64
import json
import re
import time
import hashlib
import socket
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Импорты для надежных запросов ---
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Основные настройки ---
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

# --- Названия файлов ---
MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
STATS = OUTPUT_DIR / "stats.json"

# --- Настройки производительности и таймаутов ---
FETCH_TIMEOUT = 10
CHECK_TIMEOUT = 5
FETCH_WORKERS = 30
CHECK_WORKERS = 150
MAX_CONFIGS_PER_SOURCE = 2000

# --- Поддерживаемые протоколы ---
SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# --- URL для получения источников с GitHub ---
GITHUB_SOURCES_API_URL = "https://api.github.com/repos/Darkoflox/Kfg-analizator/contents/sources"


def fetch_sources_from_github():
    """
    Динамически загружает все источники из указанной папки на GitHub.
    """
    print("📥 Загрузка списка источников из GitHub...")
    all_sources = []
    session = create_requests_session()
    
    try:
        # 1. Получаем список файлов в директории
        response = session.get(GITHUB_SOURCES_API_URL, timeout=15)
        response.raise_for_status()
        files = response.json()

        # 2. Итерируемся по файлам и загружаем их содержимое
        for file_info in files:
            if file_info['type'] == 'file' and file_info['name'].endswith('.txt'):
                download_url = file_info['download_url']
                print(f"   - Чтение файла: {file_info['name']}")
                try:
                    # 3. Скачиваем содержимое файла со списком источников
                    source_file_content = session.get(download_url, timeout=10).text
                    urls = [line.strip() for line in source_file_content.splitlines() if line.strip() and not line.startswith('#')]

                    # 4. Преобразуем URL в структурированный формат
                    for url in urls:
                        source_type = "telegram" if "t.me" in url else "base64"
                        all_sources.append({"url": url, "type": source_type, "enabled": True})
                except Exception as e:
                    print(f"     ⚠️ Не удалось прочитать файл {file_info['name']}: {e}")

        print(f"✅ Успешно загружено {len(all_sources)} источников из {len(files)} файлов.")
        return all_sources
    except Exception as e:
        print(f"❌ Критическая ошибка при загрузке источников с GitHub: {e}")
        return []

def load_whitelist():
    """Загружает белые списки доменов и IP-адресов."""
    try:
        r_domain = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/main/domain.txt", timeout=10)
        domain_list = {line.strip().lower() for line in r_domain.text.splitlines() if line.strip()}
        
        r_ip = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/main/iP.txt", timeout=10)
        ip_list = {line.strip() for line in r_ip.text.splitlines() if line.strip() and not line.startswith('#')}
        
        print(f"✅ Загружено: {len(domain_list)} доменов + {len(ip_list)} IP из белых списков")
        return domain_list, ip_list
    except Exception as e:
        print(f"⚠️ Не удалось загрузить белые списки: {e}")
        return set(), set()

DOMAIN_WHITELIST, IP_WHITELIST = load_whitelist()

def create_requests_session():
    """Создает сессию requests с настроенными повторными попытками."""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
    return session

def fetch(url, session):
    """Скачивает содержимое по URL с использованием сессии."""
    try:
        response = session.get(url, timeout=FETCH_TIMEOUT)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        # Уменьшаем "шум" в логах, делая сообщение короче
        # print(f"   ⚠️ Не удалось скачать {url[-50:]}: {e}")
        return None

def tcp_check(link):
    """Быстрая проверка доступности хоста и порта."""
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        with socket.create_connection((host, port), timeout=CHECK_TIMEOUT):
            return True
    except (socket.timeout, socket.error, TypeError, AttributeError, OSError):
        return False

def full_check(link):
    if not tcp_check(link):
        return False
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        r = requests.get("https://www.gstatic.com/generate_204", proxies=proxies, timeout=CHECK_TIMEOUT, allow_redirects=False, verify=False)
        return r.status_code in (204, 200)
    except:
        return False

def config_hash(link):
    try:
        p = urlparse(link)
        return hashlib.md5(p._replace(fragment="").geturl().encode()).hexdigest()
    except:
        return None

def rename_config(link):
    protocol = link.split("://")[0].upper()
    transport = ""
    if "reality" in link.lower(): transport = "Reality"
    elif "ws" in link.lower(): transport = "WS"
    elif "grpc" in link.lower(): transport = "gRPC"
    elif "hysteria2" in link.lower(): transport = "Hysteria2"
    
    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    except:
        sni = ""

    name = f"Niyakwi-{protocol}-{transport}-{sni}" if transport else f"Niyakwi-{protocol}"
    name = re.sub(r'-+', '-', name).strip('-')

    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(link[8:] + "===").decode(errors='ignore'))
            data["ps"] = name
            return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
        except:
            pass
    else:
        try:
            parsed = urlparse(link)
            return urlunparse(parsed._replace(fragment=name))
        except:
            pass
    return link

def priority_key(link):
    lower = link.lower()
    if 'reality' in lower: return 100
    if 'vless' in lower: return 80
    if 'hysteria2' in lower: return 60
    if 'trojan' in lower: return 40
    return 20

def main():
    print(f"🚀 Niyakwi-Parser v10 (Динамические источники с GitHub, {CHECK_WORKERS} потоков) запущен")
    
    requests.packages.urllib3.disable_warnings() # Отключаем предупреждения о небезопасных SSL
    
    sources = fetch_sources_from_github()
    if not sources:
        print("❌ Не удалось загрузить источники. Завершение работы.")
        return

    all_configs = []
    session = create_requests_session()
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        future_to_src = {executor.submit(fetch, src['url'], session): src for src in sources}
        
        for i, future in enumerate(as_completed(future_to_src), 1):
            src = future_to_src[future]
            content = future.result()
            print(f"\r   Скачивание: {i}/{len(sources)}", end="")
            if content:
                text = content.decode('utf-8', errors='ignore')
                found_configs = []
                
                if src.get("type") == "telegram":
                    pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\\s<>"\'`]+'
                    found_configs = re.findall(pat, text)
                else:
                    found_configs = [l.strip() for l in text.splitlines() if any(l.startswith(p + "://") for p in SUPPORTED)]

                all_configs.extend(found_configs[:MAX_CONFIGS_PER_SOURCE])

    unique_raw = {config_hash(link): link for link in all_configs if link}
    print(f"\n📦 Собрано уникальных конфигов: {len(unique_raw)}")

    print("\n🔍 Этап 1: Быстрая TCP-проверка...")
    candidates = []
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
        future_to_link = {executor.submit(tcp_check, link): link for link in unique_raw.values()}
        for i, future in enumerate(as_completed(future_to_link), 1):
            if future.result():
                candidates.append(future_to_link[future])
            print(f"\r   Проверено: {i}/{len(unique_raw)} | Прошло: {len(candidates)}", end="")
    print(f"\n   TCP-проверку прошло: {len(candidates)}")

    print("\n🔍 Этап 2: Полная проверка...")
    working = []
    candidates.sort(key=priority_key, reverse=True)
    check_pool = candidates[:4000] # Увеличим пул для более тщательной проверки

    if not check_pool:
         print("   Не найдено кандидатов для полной проверки.")
    else:
        with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
            future_to_link = {executor.submit(full_check, link): link for link in check_pool}
            for i, future in enumerate(as_completed(future_to_link), 1):
                if future.result():
                    working.append(future_to_link[future])
                print(f"\r   Проверено: {i}/{len(check_pool)} | Работает: {len(working)}", end="")
    print(f"\n✅ Прошло полную проверку: {len(working)}")

    valid = [rename_config(link) for link in working]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid
    if len(android_configs) < 500: # Порог для добавления из fallback
        print(f"⚠️ Мало рабочих конфигов. Добавляем из TCP-кандидатов.")
        fallback_candidates = [c for c in candidates if c not in working]
        fallback = [rename_config(link) for link in fallback_candidates]
        android_configs.extend(fallback)
        android_configs = android_configs[:2500] 

    ios_configs = android_configs[:100] # iOS можно дать побольше

    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode(), encoding='utf-8')
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode(), encoding='utf-8')

    stats = {
        "total_android": len(android_configs),
        "total_ios": len(ios_configs),
        "last_update": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    }
    with open(STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    print(f"\n✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}")

if __name__ == "__main__":
    main()
