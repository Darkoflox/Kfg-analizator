import requests
import base64
import json
import re
import time
import hashlib
import socket
from urllib.parse import urlparse, unquote, parse_qs, urlunparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"          # Android — до 4000
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"       # iOS — топ-50
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"
SOURCES_FILE = Path("sources.txt")
README = Path("README.md")

REQUEST_DELAY = 4.0
TCP_TIMEOUT = 3                           # уменьшено с 6 до 3 секунд

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# Загрузка белых списков RKP
def load_whitelist():
    domain_list = set()
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
    except:
        pass
    return domain_list

DOMAIN_WHITELIST = load_whitelist()

def fetch(url):
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15).content
    except:
        return None

def tcp_check(link):
    """Быстрая TCP‑проверка с connect_ex"""
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def is_in_whitelist(link):
    parsed = urlparse(link)
    sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    if sni and sni.lower() in DOMAIN_WHITELIST:
        return True
    return False

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
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
            return "vmess://" + new_b64
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

def main():
    print("🚀 Kfg-analyzer Parser v3.2 (4000 для Android) запущен")

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []
    for src in sources:
        if 't.me' in src:
            content = fetch(src)
            if content:
                html = content.decode('utf-8', errors='ignore')
                pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                all_configs.extend(re.findall(pat, html))
        else:
            content = fetch(src)
            if content:
                lines = content.decode('utf-8', errors='ignore').splitlines()
                all_configs.extend([l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)])
        time.sleep(REQUEST_DELAY)

    print(f"📦 Всего найдено ссылок: {len(all_configs)}")
    print("🔍 Начинаю TCP‑проверку и фильтрацию по белому списку...")

    unique = {}
    for i, link in enumerate(all_configs, 1):
        if i % 100 == 0:
            print(f"   Прогресс: {i}/{len(all_configs)}")
        if tcp_check(link) and is_in_whitelist(link):
            unique[config_hash(link)] = link

    valid = [rename_config(link) for link in unique.values()]

    # Сортировка по качеству
    valid.sort(key=priority_key, reverse=True)

    # Android — максимум 4000
    android_configs = valid[:4000]
    # iOS — топ-50
    ios_configs = valid[:50]

    # Сохранение
    b64 = base64.b64encode('\n'.join(android_configs).encode()).decode()
    MAIN_SUB.write_text(b64)

    b64_ios = base64.b64encode('\n'.join(ios_configs).encode()).decode()
    IOS_SUB.write_text(b64_ios)

    # Sing-Box
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
