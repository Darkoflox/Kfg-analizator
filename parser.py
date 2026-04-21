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

# --- Новые импорты для надежных запросов ---
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Основные настройки ---
OUTPUT_DIR = Path("public")
SOURCES_DIR = Path("sources")
OUTPUT_DIR.mkdir(exist_ok=True)
SOURCES_DIR.mkdir(exist_ok=True)

# --- Названия файлов ---
MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"
SOURCES_FILE = SOURCES_DIR / "sources.json" # <--- ИЗМЕНЕНО

# --- Настройки производительности и таймаутов ---
REQUEST_DELAY = 0.5
FETCH_TIMEOUT = 10
CHECK_TIMEOUT = 5
FETCH_WORKERS = 20
CHECK_WORKERS = 100 # <--- УВЕЛИЧЕНО
MAX_CONFIGS_PER_SOURCE = 2000

# --- Поддерживаемые протоколы ---
SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

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
    retry = Retry(
        total=3,          # 3 повторные попытки
        backoff_factor=1, # Пауза между попытками (1с, 2с, 4с)
        status_forcelist=[500, 502, 503, 504] # Коды, при которых повторять
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch(url, session):
    """Скачивает содержимое по URL с использованием сессии."""
    try:
        response = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT)
        response.raise_for_status() # Вызовет ошибку для плохих статусов (4xx, 5xx)
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"   ⚠️ Не удалось скачать {url[-50:]}: {e}")
        return None

def tcp_check(link):
    """Быстрая проверка доступности хоста и порта."""
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        with socket.create_connection((host, port), timeout=CHECK_TIMEOUT):
            return True
    except (socket.timeout, socket.error, TypeError, AttributeError):
        return False

# ... (остальные функции-помощники остаются без изменений) ...
def full_check(link):
    if not tcp_check(link):
        return False
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        r = requests.get("https://www.gstatic.com/generate_204", proxies=proxies, timeout=CHECK_TIMEOUT, allow_redirects=False)
        return r.status_code in (204, 200)
    except:
        return False

def is_in_whitelist(link):
    if not DOMAIN_WHITELIST and not IP_WHITELIST:
        return True
    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        target = sni if sni else p.hostname
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return target in IP_WHITELIST
        return target.lower() in DOMAIN_WHITELIST
    except:
        return True

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
    print(f"🚀 Kfg-analyzer Parser v8.0 (JSON-источники, ретраи, {CHECK_WORKERS} потоков) запущен")

    # --- Загрузка источников из JSON ---
    if not SOURCES_FILE.exists():
        print(f"❌ Файл источников {SOURCES_FILE} не найден. Создайте его.")
        return
        
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        all_sources = json.load(f)
    
    sources = [s for s in all_sources if s.get("enabled", True)]
    print(f"📋 Всего источников: {len(sources)} (включено)")

    # --- Параллельное скачивание источников ---
    all_configs = []
    session = create_requests_session()
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        future_to_src = {executor.submit(fetch, src['url'], session): src for src in sources}
        
        for future in as_completed(future_to_src):
            src = future_to_src[future]
            content = future.result()
            if content:
                text = content.decode('utf-8', errors='ignore')
                found_configs = []
                
                # Логика парсинга в зависимости от типа источника
                if src.get("type") == "telegram":
                    pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\\s<>"\'`]+'
                    found_configs = re.findall(pat, text)
                else: # По умолчанию считаем, что это base64 или просто список
                    found_configs = [l.strip() for l in text.splitlines() if any(l.startswith(p + "://") for p in SUPPORTED)]

                limited_configs = found_configs[:MAX_CONFIGS_PER_SOURCE]
                all_configs.extend(limited_configs)
                print(f"   ↳ {src['type']} {src['url'][-40:]}: {len(limited_configs)}")

    unique_raw = {config_hash(link): link for link in all_configs if link and any(link.startswith(p + "://") for p in SUPPORTED)}
    print(f"\n📦 Собрано уникальных конфигов: {len(unique_raw)}")

    # --- Этап 1: Быстрая TCP-проверка ---
    print("🔍 Этап 1: Быстрая TCP-проверка...")
    candidates = []
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
        future_to_link = {executor.submit(tcp_check, link): link for link in unique_raw.values()}
        for i, future in enumerate(as_completed(future_to_link)):
            if future.result():
                candidates.append(future_to_link[future])
            print(f"\r   Проверено: {i+1}/{len(unique_raw)}", end="")
    print(f"\n   TCP-проверку прошло: {len(candidates)}")

    # --- Этап 2: Полная проверка (ограничим до 3000 лучших) ---
    print("\n🔍 Этап 2: Полная проверка...")
    working = []
    # Сортируем кандидатов, чтобы сначала проверять самые "перспективные"
    candidates.sort(key=priority_key, reverse=True)
    check_pool = candidates[:3000] # Проверяем не больше 3000

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
        future_to_link = {executor.submit(full_check, link): link for link in check_pool}
        for i, future in enumerate(as_completed(future_to_link)):
            if future.result():
                working.append(future_to_link[future])
            print(f"\r   Проверено: {i+1}/{len(check_pool)}", end="")
    print(f"\n✅ Прошло полную проверку: {len(working)}")

    valid = [rename_config(link) for link in working]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid
    ios_configs = valid[:50]

    # Если рабочих конфигов мало, берем из TCP-кандидатов
    if len(android_configs) < 400:
        print(f"⚠️ Мало рабочих конфигов ({len(android_configs)}). Добавляем из TCP-кандидатов.")
        fallback = [rename_config(link) for link in candidates if link not in working][:2000]
        android_configs.extend(fallback)
        android_configs = android_configs[:2000] # Ограничим итоговое кол-во
        ios_configs = android_configs[:50]

    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode(), encoding='utf-8')
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode(), encoding='utf-8')

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        singbox_json = {
            "version": 1,
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["auto", "direct"]},
                {"type": "urltest", "tag": "auto", "outbounds": [urlparse(c).fragment for c in android_configs]},
            ]
        }
        # Добавляем сами конфиги
        for config_url in android_configs:
            # Тут нужна будет более сложная логика для преобразования URL в формат Sing-box
            # Для примера пока оставим заглушку
            pass
        # json.dump(singbox_json, f, indent=2) # Пока не реализуем парсинг в sing-box формат

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
