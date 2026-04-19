import requests
import base64
import json
import re
import time
import hashlib
import socket
import ipaddress
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# ---------- НАСТРОЙКИ ----------
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"

SOURCES_DIR = Path("sources")
SOURCES_DIR.mkdir(exist_ok=True)
SOURCES_FILE = SOURCES_DIR / "sources.txt"

# Параметры работы (оптимизированы для GitHub Actions)
REQUEST_DELAY = 1.0          # пауза между запросами к источникам
FETCH_TIMEOUT = 10           # таймаут на загрузку источника
TCP_TIMEOUT = 4              # таймаут проверки TCP-порта
MAX_WORKERS = 20             # потоков для проверки (меньше 30 — бережём ресурсы раннера)
MIN_WORKING_FOR_FALLBACK = 100  # если прошло проверку меньше, включаем "мягкий" режим (берём все уникальные)

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ---------- ЗАГРУЗКА БЕЛЫХ СПИСКОВ RKP ----------
def load_whitelist():
    """Загружает списки доменов и IP от RKP с поддержкой wildcard-доменов."""
    domain_list = set()
    ip_list = set()
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt",
            timeout=10
        )
        for line in r.text.splitlines():
            line = line.strip().lower()
            if line and not line.startswith('#'):
                # Если строка начинается с точки — wildcard, иначе точное совпадение
                domain_list.add(line)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки domain.txt: {e}", flush=True)

    try:
        r = requests.get(
            "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/iP.txt",
            timeout=10
        )
        for line in r.text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                ip_list.add(line)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки iP.txt: {e}", flush=True)

    print(f"✅ Белые списки: {len(domain_list)} доменов, {len(ip_list)} IP", flush=True)
    return domain_list, ip_list

DOMAIN_WHITELIST, IP_WHITELIST = load_whitelist()

def is_ip_address(value: str) -> bool:
    """Проверяет, является ли строка IP-адресом (IPv4 или IPv6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def matches_domain_whitelist(target: str) -> bool:
    """
    Проверяет, входит ли target в белый список доменов.
    Поддерживает wildcard: если запись начинается с точки (например, .example.com),
    то разрешает все поддомены, оканчивающиеся на этот суффикс.
    """
    target = target.lower()
    for entry in DOMAIN_WHITELIST:
        if entry.startswith('.'):
            # wildcard: .example.com соответствует example.com и *.example.com
            if target == entry[1:] or target.endswith(entry):
                return True
        else:
            if target == entry:
                return True
    return False

def is_in_whitelist(link: str) -> bool:
    """Проверяет SNI или хост ссылки на присутствие в белых списках."""
    if not DOMAIN_WHITELIST and not IP_WHITELIST:
        return True   # если списки не загружены, пропускаем всё

    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        target = sni if sni else p.hostname
        if not target:
            return True
    except Exception:
        return True  # если не можем разобрать — считаем допустимым

    # Проверка IP (включая IPv6)
    if is_ip_address(target):
        return target in IP_WHITELIST

    # Проверка домена
    return matches_domain_whitelist(target)

# ---------- КЭШ ПРОВЕРОК ----------
check_cache = {}

def get_cache_key(link: str):
    """Формирует ключ кэша: (host, port, sni)."""
    try:
        p = urlparse(link)
        host = p.hostname
        if not host:
            return None
        port = p.port or 443
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        return (host, port, sni)
    except Exception:
        return None

def check_server(link: str) -> bool:
    """
    Двойная проверка:
      1) TCP-доступность (connect)
      2) Наличие в белых списках RKP (если списки загружены)
    Результат кэшируется по ключу (host, port, sni).
    """
    key = get_cache_key(link)
    if key is None:
        return False
    if key in check_cache:
        return check_cache[key]

    # 1) TCP-проверка
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        # Обработка IPv6: socket.create_connection поддерживает IPv6
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        if result != 0:
            check_cache[key] = False
            return False
    except Exception:
        check_cache[key] = False
        return False

    # 2) Проверка белого списка
    if not is_in_whitelist(link):
        check_cache[key] = False
        return False

    check_cache[key] = True
    return True

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
def config_hash(link: str) -> str | None:
    """MD5-хеш конфига (без фрагмента) для дедупликации."""
    try:
        p = urlparse(link)
        clean = p._replace(fragment="").geturl()
        return hashlib.md5(clean.encode()).hexdigest()
    except Exception:
        return None

def rename_config(link: str) -> str:
    """Переименовывает конфиг в читаемый формат."""
    protocol = link.split("://")[0].upper()
    transport = ""
    sni = ""
    lower = link.lower()
    if "reality" in lower:
        transport = "Reality"
    elif "ws" in lower:
        transport = "WS"
    elif "grpc" in lower:
        transport = "gRPC"
    elif "hysteria2" in lower:
        transport = "Hysteria2"

    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
    except Exception:
        sni = ""

    name = f"{protocol}-{transport}-{sni}-#Kfg-analyzer" if transport else f"{protocol}-#Kfg-analyzer"
    name = re.sub(r'-+', '-', name).strip('-')

    # Обработка vmess
    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(link[8:] + "===").decode(errors='ignore'))
            data["ps"] = name
            return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
        except Exception:
            pass
    else:
        try:
            parsed = urlparse(link)
            return urlunparse(parsed._replace(fragment=name))
        except Exception:
            pass
    return link

def priority_key(link: str) -> int:
    """Определяет приоритет протокола (чем выше, тем лучше)."""
    lower = link.lower()
    if 'reality' in lower:
        return 100
    if 'vless' in lower:
        return 80
    if 'hysteria2' in lower:
        return 60
    if 'trojan' in lower:
        return 40
    return 20

def fetch(url: str) -> bytes | None:
    """Загружает содержимое источника с таймаутом и User-Agent."""
    try:
        resp = requests.get(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
            timeout=FETCH_TIMEOUT
        )
        resp.raise_for_status()
        return resp.content
    except Exception:
        return None

# ---------- ОСНОВНАЯ ЛОГИКА ----------
def main():
    print("🚀 Kfg-analyzer Parser v7.0 (улучшенный) запущен", flush=True)
    sys.stdout.reconfigure(line_buffering=True)

    if not SOURCES_FILE.exists():
        print(f"❌ {SOURCES_FILE} не найден!", flush=True)
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # ----- 1. Загрузка всех ссылок из источников -----
    all_configs = []
    for src in sources:
        content = fetch(src)
        if not content:
            continue
        text = content.decode('utf-8', errors='ignore')
        if 't.me' in src:
            pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
            found = re.findall(pat, text)
            all_configs.extend(found)
            print(f"📥 {src} → {len(found)} ссылок", flush=True)
        else:
            lines = text.splitlines()
            from_file = [line.strip() for line in lines if any(line.startswith(p + "://") for p in SUPPORTED)]
            all_configs.extend(from_file)
            print(f"📥 {src} → {len(from_file)} ссылок", flush=True)
        time.sleep(REQUEST_DELAY)  # защита от бана

    print(f"📦 Всего ссылок (до дедупликации): {len(all_configs)}", flush=True)

    # ----- 2. Группировка по серверам (host:port:sni) с выбором лучшего по приоритету -----
    server_best = {}
    for link in all_configs:
        if not any(link.startswith(p + "://") for p in SUPPORTED):
            continue
        try:
            p = urlparse(link)
            host = p.hostname
            if not host:
                continue
            port = p.port or 443
            sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
            key = (host, port, sni)
            prio = priority_key(link)
            if key not in server_best or prio > server_best[key][1]:
                server_best[key] = (link, prio)
        except Exception:
            continue

    print(f"📦 Уникальных серверов (до проверки): {len(server_best)}", flush=True)

    # ----- 3. Многопоточная проверка (TCP + белый список) -----
    unique_working = {}

    def check_one(item):
        link, _ = item
        if check_server(link):
            return link
        return None

    print("🔍 Запуск многопоточной проверки...", flush=True)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_one, item): item for item in server_best.values()}
        for i, future in enumerate(as_completed(futures), 1):
            link = future.result()
            if link:
                h = config_hash(link)
                if h:
                    unique_working[h] = link
            if i % 100 == 0:
                print(f"   Проверено {i}/{len(server_best)} серверов, отобрано {len(unique_working)}", flush=True)

    print(f"✅ Прошло проверку (TCP + белые списки): {len(unique_working)}", flush=True)

    # ----- 4. Формирование финальных списков -----
    # Если прошло проверку слишком мало, включаем «мягкий» режим — берём все уникальные конфиги
    if len(unique_working) < MIN_WORKING_FOR_FALLBACK:
        print(f"⚠️ Мало рабочих конфигов ({len(unique_working)}). Включаю мягкий режим (все уникальные без проверок).", flush=True)
        # Собираем все уникальные конфиги из загруженных ссылок
        all_unique = {}
        for link in all_configs:
            h = config_hash(link)
            if h:
                all_unique[h] = link
        final_links = list(all_unique.values())
    else:
        final_links = list(unique_working.values())

    # Переименовываем и сортируем по приоритету
    renamed = [rename_config(link) for link in final_links]
    renamed.sort(key=priority_key, reverse=True)

    # Android — максимум (без жёсткого лимита), iOS — топ-50
    android_configs = renamed
    ios_configs = renamed[:50]

    # ----- 5. Сохранение результатов -----
    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode())
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode())

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({
            "outbounds": [{
                "type": "urltest",
                "tag": "Kfg-analyzer",
                "outbounds": android_configs
            }]
        }, f, indent=2, ensure_ascii=False)

    stats = {
        "total_android": len(android_configs),
        "ios_top50": len(ios_configs),
        "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    }
    with open(STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}", flush=True)

if __name__ == "__main__":
    main()
