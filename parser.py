import requests
import base64
import json
import re
import time
import hashlib
import socket
import sys
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

REQUEST_DELAY = 4.0
TCP_TIMEOUT = 5.0
FETCH_TIMEOUT = 20

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

def load_whitelist():
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
        print(f"✅ Загружено {len(domain_list)} доменов из белого списка RKP")
        return domain_list
    except Exception as e:
        print(f"❌ Критическая ошибка загрузки белого списка: {e}")
        sys.exit(1)   # ← Останавливаемся сразу

DOMAIN_WHITELIST = load_whitelist()

def fetch(url):
    print(f"📥 Запрос: {url}")
    try:
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"❌ Ошибка при скачивании {url}: {e}")
        sys.exit(1)   # ← Останавливаемся при любой ошибке скачивания

def tcp_check(link):
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"❌ TCP-check ошибка: {e}")
        return False

def is_in_whitelist(link):
    if not DOMAIN_WHITELIST:
        return True
    parsed = urlparse(link)
    sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    return bool(sni and sni.lower() in DOMAIN_WHITELIST)

def config_hash(link):
    return hashlib.md5(urlparse(link)._replace(fragment="").geturl().encode()).hexdigest()

def rename_config(link):
    # ... (твой текущий rename_config без изменений)
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
    print("🚀 Kfg-analyzer Parser v3.9 (строгий режим) запущен")

    if not SOURCES_FILE.exists():
        print(f"❌ Файл {SOURCES_FILE} не найден!")
        sys.exit(1)

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []
    for src in sources:
        content = fetch(src)          # ← любая ошибка здесь остановит парсер
        if content:
            text = content.decode('utf-8', errors='ignore')
            if 't.me' in src:
                pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                found = re.findall(pat, text)
                all_configs.extend(found)
                print(f"   ↳ TG: найдено {len(found)}")
            else:
                lines = text.splitlines()
                from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
                all_configs.extend(from_file)
                print(f"   ↳ Загружено: {len(from_file)}")
        time.sleep(REQUEST_DELAY)

    # Дальше всё как раньше...
    unique_raw = {config_hash(link): link for link in all_configs if any(link.startswith(p + "://") for p in SUPPORTED)}

    print(f"📦 Уникальных конфигов: {len(unique_raw)}")

    unique = {}
    for link in unique_raw.values():
        if tcp_check(link) and is_in_whitelist(link):
            unique[config_hash(link)] = link

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    if len(android_configs) == 0:
        print("⚠️ После фильтрации 0 конфигов!")
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
