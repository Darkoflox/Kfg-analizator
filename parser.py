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

REQUEST_DELAY = 2.5
TCP_TIMEOUT = 5.0
FETCH_TIMEOUT = 15

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

def load_whitelist():
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        return {line.strip().lower() for line in r.text.splitlines() if line.strip()}
    except:
        print("⚠️ Не удалось загрузить domain.txt")
        return set()

DOMAIN_WHITELIST = load_whitelist()

def fetch(url):
    print(f"📥 {url}")
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT).content
    except Exception as e:
        print(f"❌ Ошибка {url}: {e}")
        return None

def tcp_check(link):
    try:
        p = urlparse(link)
        if not p.hostname or not p.port:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((p.hostname, p.port))
        sock.close()
        return result == 0
    except (ValueError, socket.error):
        return False

def is_in_whitelist(link):
    if not DOMAIN_WHITELIST:
        return True
    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
        return bool(sni and sni.lower() in DOMAIN_WHITELIST)
    except ValueError:
        return False

def config_hash(link):
    return hashlib.md5(urlparse(link)._replace(fragment="").geturl().encode()).hexdigest()

def rename_config(link):
    protocol = link.split("://")[0].upper()
    transport = ""
    sni = ""

    if "reality" in link.lower():
        transport = "Reality"
    elif "ws" in link.lower():
        transport = "WS"
    elif "grpc" in link.lower():
        transport = "gRPC"
    elif "hysteria2" in link.lower():
        transport = "Hysteria2"

    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    except ValueError:
        sni = ""

    name = f"{protocol}-{transport}-{sni}-#Kfg-analyzer" if transport else f"{protocol}-#Kfg-analyzer"
    name = re.sub(r'-+', '-', name).strip('-')

    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(link[8:] + "===").decode(errors='ignore'))
            data["ps"] = name
            return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
        except:
            return link
    else:
        try:
            return urlunparse(parsed._replace(fragment=name))
        except:
            return link

def priority_key(link):
    lower = link.lower()
    if 'reality' in lower: return 100
    if 'vless' in lower: return 80
    if 'hysteria2' in lower: return 60
    if 'trojan' in lower: return 40
    return 20

def main():
    print("🚀 Kfg-analyzer Parser v3.9 (быстрая версия) запущен")

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
                found = re.findall(pat, text)
                all_configs.extend(found)
                print(f"   ↳ TG: {len(found)}")
            else:
                lines = text.splitlines()
                from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
                all_configs.extend(from_file)
                print(f"   ↳ Загружено: {len(from_file)}")
        time.sleep(REQUEST_DELAY)

    unique_raw = {}
    for link in all_configs:
        if not any(link.startswith(p + "://") for p in SUPPORTED):
            continue
        try:
            h = config_hash(link)
            unique_raw[h] = link
        except ValueError:
            print(f"⚠️ Пропущена некорректная ссылка (IPv6): {link[:80]}...")
            continue

    print(f"📦 Уникальных: {len(unique_raw)}")

    unique = {}
    for link in unique_raw.values():
        try:
            if tcp_check(link) and is_in_whitelist(link):
                unique[config_hash(link)] = link
        except Exception as e:
            print(f"⚠️ Ошибка при проверке ссылки: {e}\n   {link[:100]}")
            continue

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
