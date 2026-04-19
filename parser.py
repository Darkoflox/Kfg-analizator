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

OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"

SOURCES_DIR = Path("sources")
SOURCES_DIR.mkdir(exist_ok=True)
SOURCES_FILE = SOURCES_DIR / "sources.txt"

REQUEST_DELAY = 3.0
FETCH_TIMEOUT = 15
CHECK_TIMEOUT = 8

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ==================== БЕЛЫЙ СПИСОК ====================
def load_whitelist():
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        return {line.strip().lower() for line in r.text.splitlines() if line.strip()}
    except:
        print("⚠️ Не удалось загрузить domain.txt")
        return set()

DOMAIN_WHITELIST = load_whitelist()

# ==================== КЭШ ПРОВЕРОК ====================
check_cache = {}

def get_cache_key(link):
    p = urlparse(link)
    sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
    return (p.hostname, p.port or 443, sni)

# ==================== ПРОВЕРКА ====================
def check_server(link):
    key = get_cache_key(link)
    if key in check_cache:
        return check_cache[key]

    # 1. Быстрый TCP + SNI
    if not is_in_whitelist(link):
        check_cache[key] = False
        return False

    # 2. Простая HTTP-проверка (самый эффективный способ)
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443

        proxies = {"http": None, "https": f"http://{host}:{port}" if "socks" not in link.lower() else None}

        r = requests.get("https://www.gstatic.com/generate_204", 
                        proxies=proxies, 
                        timeout=CHECK_TIMEOUT,
                        allow_redirects=False)
        success = r.status_code in (204, 200)
        check_cache[key] = success
        return success
    except:
        check_cache[key] = False
        return False

def is_in_whitelist(link):
    if not DOMAIN_WHITELIST:
        return True
    p = urlparse(link)
    sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
    return bool(sni and sni.lower() in DOMAIN_WHITELIST)

# ==================== ОСТАЛЬНЫЕ ФУНКЦИИ ====================
def config_hash(link):
    return hashlib.md5(urlparse(link)._replace(fragment="").geturl().encode()).hexdigest()

def rename_config(link):
    protocol = link.split("://")[0].upper()
    transport = ""
    sni = ""
    if "reality" in link.lower(): transport = "Reality"
    elif "ws" in link.lower(): transport = "WS"
    elif "grpc" in link.lower(): transport = "gRPC"
    elif "hysteria2" in link.lower(): transport = "Hysteria2"

    if "sni=" in link or "host=" in link:
        sni = parse_qs(urlparse(link).query).get('sni', [''])[0] or parse_qs(urlparse(link).query).get('host', [''])[0]

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
        parsed = urlparse(link)
        return urlunparse(parsed._replace(fragment=name))
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

def main():
    print("🚀 Kfg-analyzer Parser v5.1 (улучшенная проверка) запущен")

    if not SOURCES_FILE.exists():
        print(f"❌ {SOURCES_FILE} не найден!")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []
    for src in sources:
        content = fetch(src)
        if content:
            text = content.decode('utf-8', errors='ignore')
            if 't.me' in src:
                pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                all_configs.extend(re.findall(pat, text))
            else:
                lines = text.splitlines()
                all_configs.extend([l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)])
        time.sleep(REQUEST_DELAY)

    # Дедупликация
    unique_raw = {config_hash(link): link for link in all_configs if any(link.startswith(p + "://") for p in SUPPORTED)}

    print(f"📦 Уникальных конфигов: {len(unique_raw)}")

    # Проверка
    unique = {}
    for link in unique_raw.values():
        if check_server(link):
            unique[config_hash(link)] = link

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    if len(android_configs) == 0:
        print("⚠️ Ничего не прошло. Беру первые 200.")
        fallback = list(unique_raw.values())[:200]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

    # Сохранение
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

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}")

if __name__ == "__main__":
    main()
