import requests
import base64
import json
import re
import time
import hashlib
import socket
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"

SOURCES_DIR = Path("sources")
SOURCES_DIR.mkdir(exist_ok=True)
SOURCES_FILE = SOURCES_DIR / "sources.txt"

REQUEST_DELAY = 1.0          # уменьшил для скорости
FETCH_TIMEOUT = 10
TCP_TIMEOUT = 4              # 4 сек достаточно
MAX_WORKERS = 30             # потоков для проверки

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ==================== БЕЛЫЕ СПИСКИ RKP ====================
def load_whitelist():
    domain_list = set()
    ip_list = set()
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/iP.txt", timeout=10)
        ip_list = {line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')}
        print(f"✅ Загружено: {len(domain_list)} доменов + {len(ip_list)} IP", flush=True)
    except Exception as e:
        print(f"⚠️ Не удалось загрузить белые списки: {e}", flush=True)
    return domain_list, ip_list

DOMAIN_WHITELIST, IP_WHITELIST = load_whitelist()

# ==================== КЭШ ПРОВЕРОК ====================
check_cache = {}

def get_cache_key(link):
    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        port = p.port or 443
        return (p.hostname, port, sni)
    except:
        return None

def check_server(link):
    """Проверяет TCP + белый список, с кэшем"""
    key = get_cache_key(link)
    if key is None:
        return False
    if key in check_cache:
        return check_cache[key]

    # TCP-проверка
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        if result != 0:
            check_cache[key] = False
            return False
    except:
        check_cache[key] = False
        return False

    # Проверка белого списка
    if not is_in_whitelist(link):
        check_cache[key] = False
        return False

    check_cache[key] = True
    return True

def is_in_whitelist(link):
    if not DOMAIN_WHITELIST and not IP_WHITELIST:
        return True
    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        target = sni if sni else p.hostname
        if not target:
            return True

        # Проверка IP
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return target in IP_WHITELIST
        # Проверка домена
        if DOMAIN_WHITELIST:
            return target.lower() in DOMAIN_WHITELIST
        return True
    except:
        return True

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def config_hash(link):
    try:
        p = urlparse(link)
        return hashlib.md5(p._replace(fragment="").geturl().encode()).hexdigest()
    except:
        return None

def rename_config(link):
    protocol = link.split("://")[0].upper()
    transport = ""
    sni = ""
    if "reality" in link.lower(): transport = "Reality"
    elif "ws" in link.lower(): transport = "WS"
    elif "grpc" in link.lower(): transport = "gRPC"
    elif "hysteria2" in link.lower(): transport = "Hysteria2"

    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    except:
        sni = ""

    name = f"{protocol}-{transport}-{sni}-#Kfg-analyzer" if transport else f"{protocol}-#Kfg-analyzer"
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

def fetch(url):
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT).content
    except:
        return None

# ==================== ОСНОВНАЯ ФУНКЦИЯ ====================
def main():
    print("🚀 Kfg-analyzer Parser v6.2 (многопоточный, быстрый) запущен", flush=True)
    sys.stdout.reconfigure(line_buffering=True)

    if not SOURCES_FILE.exists():
        print(f"❌ {SOURCES_FILE} не найден!", flush=True)
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # 1. Загрузка всех ссылок (последовательная, но с задержкой)
    all_configs = []
    for src in sources:
        content = fetch(src)
        if content:
            text = content.decode('utf-8', errors='ignore')
            if 't.me' in src:
                pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                found = re.findall(pat, text)
                all_configs.extend(found)
                print(f"📥 {src} → {len(found)} ссылок", flush=True)
            else:
                lines = text.splitlines()
                from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
                all_configs.extend(from_file)
                print(f"📥 {src} → {len(from_file)} ссылок", flush=True)
        time.sleep(REQUEST_DELAY)

    print(f"📦 Всего ссылок (до дедупликации): {len(all_configs)}", flush=True)

    # 2. Группировка по серверам (хост:порт:сни) с выбором лучшего приоритета
    server_best = {}
    for link in all_configs:
        if not any(link.startswith(p + "://") for p in SUPPORTED):
            continue
        try:
            p = urlparse(link)
            host = p.hostname
            port = p.port or 443
            sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
            key = (host, port, sni)
            prio = priority_key(link)
            if key not in server_best or prio > server_best[key][1]:
                server_best[key] = (link, prio)
        except:
            continue

    print(f"📦 Уникальных серверов (до проверки): {len(server_best)}", flush=True)

    # 3. Многопоточная проверка уникальных серверов
    unique = {}
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
                    unique[h] = link
            if i % 100 == 0:
                print(f"   Проверено {i}/{len(server_best)} серверов, отобрано {len(unique)}", flush=True)

    print(f"✅ Прошло проверку (TCP + белые списки): {len(unique)}", flush=True)

    # 4. Переименование и сортировка
    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid               # без лимита
    ios_configs = valid[:50]

    # Если после фильтрации очень мало – берём fallback (первые 1200 уникальных конфигов)
    if len(android_configs) < 300:
        print(f"⚠️ После фильтрации осталось мало ({len(android_configs)}). Включаю мягкий режим (без проверок).", flush=True)
        fallback = list({config_hash(l): l for l in all_configs if config_hash(l)}.values())[:1200]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

    # 5. Сохранение файлов
    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode())
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode())

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({"outbounds": [{"type": "urltest", "tag": "Kfg-analyzer", "outbounds": android_configs}]}, f, indent=2)

    stats = {
        "total_android": len(android_configs),
        "ios_top50": len(ios_configs),
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }
    json.dump(stats, open(STATS, 'w'), indent=2)

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}", flush=True)

if __name__ == "__main__":
    main()
