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

# ==================== БЕЛЫЕ СПИСКИ (RKP) ====================
def load_whitelist():
    domain_list = set()
    ip_list = set()
    try:
        # Домены
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}

        # IP
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/iP.txt", timeout=10)
        r.raise_for_status()
        ip_list = {line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')}
        
        print(f"✅ Загружено: {len(domain_list)} доменов + {len(ip_list)} IP")
    except Exception as e:
        print(f"⚠️ Не удалось загрузить белые списки: {e}")
    return domain_list, ip_list

DOMAIN_WHITELIST, IP_WHITELIST = load_whitelist()

# ==================== БЕЗОПАСНЫЕ ФУНКЦИИ ====================
def safe_port(parsed):
    """Защита от IPv6 ошибок"""
    netloc = parsed.netloc
    if not netloc:
        return 443
    if ']:' in netloc:
        parts = netloc.rsplit(']:', 1)
    else:
        parts = netloc.rsplit(':', 1)
    if len(parts) == 2:
        try:
            return int(parts[1])
        except ValueError:
            return 443
    return 443

def is_valid_config_url(link):
    if not any(link.startswith(p + "://") for p in SUPPORTED):
        return False
    try:
        p = urlparse(link)
        if not p.scheme or not p.hostname:
            return False
        return True
    except:
        return False

# ==================== ПРОВЕРКА ====================
check_cache = {}

def get_cache_key(link):
    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        port = safe_port(p)
        return (p.hostname, port, sni)
    except:
        return None

def check_server(link):
    key = get_cache_key(link)
    if key is None or key in check_cache:
        return check_cache.get(key, False)

    # 1. Белый список (домен или IP)
    if not is_in_whitelist(link):
        check_cache[key] = False
        return False

    # 2. Быстрая HTTP-проверка (самый надёжный способ)
    try:
        p = urlparse(link)
        host = p.hostname
        port = safe_port(p)

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
    if not DOMAIN_WHITELIST and not IP_WHITELIST:
        return True
    try:
        p = urlparse(link)
        sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
        target = sni if sni else p.hostname

        # Если это IP — проверяем по IP_WHITELIST
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return target in IP_WHITELIST
        # Иначе — по доменам
        return target.lower() in DOMAIN_WHITELIST
    except:
        return False

# ==================== ОСТАЛЬНЫЕ ФУНКЦИИ ====================
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

def main():
    print("🚀 Kfg-analyzer Parser v5.2 (стабильная + быстрый check) запущен")

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

    unique_raw = {}
    for link in all_configs:
        if any(link.startswith(p + "://") for p in SUPPORTED):
            h = config_hash(link)
            if h:
                unique_raw[h] = link

    print(f"📦 Уникальных конфигов: {len(unique_raw)}")

    unique = {}
    for link in unique_raw.values():
        if check_server(link):
            unique[config_hash(link)] = link

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    if len(android_configs) == 0:
        print("⚠️ Ничего не прошло фильтрацию. Беру первые 200.")
        fallback = list(unique_raw.values())[:200]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

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
