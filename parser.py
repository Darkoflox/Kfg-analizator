#!/usr/bin/env python3
# Kfg-analyzer Parser v4.6 – фикс whitelist (пропуск ссылок без sni/host)

import requests
import base64
import json
import re
import time
import hashlib
import socket
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os

# ==================== НАСТРОЙКИ ====================
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = Path("stats.json")
README = Path("README.md")

SOURCES_DIR = Path("sources")
SOURCES_DIR.mkdir(exist_ok=True)
SOURCES_FILE = SOURCES_DIR / "sources.txt"

REQUEST_DELAY = 0.5
TCP_TIMEOUT = 4.0
FETCH_TIMEOUT = 10
MAX_WORKERS_FETCH = 10
MAX_WORKERS_CHECK = 30
SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

MOSCOW_TZ = timezone(timedelta(hours=3))

def moscow_now():
    return datetime.now(MOSCOW_TZ)

# ==================== БЕЛЫЙ СПИСОК ====================
def load_whitelist():
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        whitelist = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
        print(f"✅ Загружен whitelist: {len(whitelist)} доменов", flush=True)
        return whitelist
    except Exception as e:
        print(f"⚠️ Не удалось загрузить domain.txt: {e}", flush=True)
        return set()

DOMAIN_WHITELIST = load_whitelist()

# ==================== TCP КЭШ ====================
_tcp_cache = {}

def tcp_check_cached(link):
    try:
        p = urlparse(link)
        if not p.hostname or not p.port:
            return False
        key = (p.hostname, p.port)
        if key not in _tcp_cache:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_TIMEOUT)
            _tcp_cache[key] = (sock.connect_ex((p.hostname, p.port)) == 0)
            sock.close()
        return _tcp_cache[key]
    except (ValueError, socket.error):
        return False

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def get_server_key(link, include_sni=True):
    try:
        p = urlparse(link)
        if not p.hostname or not p.port:
            return None
        if include_sni:
            sni = parse_qs(p.query).get('sni', [''])[0] or parse_qs(p.query).get('host', [''])[0]
            return (p.hostname, p.port, sni)
        else:
            return (p.hostname, p.port)
    except:
        return None

def priority_key(link):
    lower = link.lower()
    if 'reality' in lower: return 100
    if 'vless' in lower: return 80
    if 'hysteria2' in lower: return 60
    if 'trojan' in lower: return 40
    return 20

def is_in_whitelist(link):
    """Проверяет sni/host по белому списку. Если sni/host отсутствует – пропускаем (True)."""
    if not DOMAIN_WHITELIST:
        return True
    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
        if not sni:
            # Нет sni/host – нечего проверять, считаем что прошло
            return True
        return sni.lower() in DOMAIN_WHITELIST
    except ValueError:
        return True   # при ошибке парсинга тоже не блокируем

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

def fetch(url):
    print(f"📥 {url}", flush=True)
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT).content
    except Exception as e:
        print(f"❌ Ошибка {url}: {e}", flush=True)
        return None

def process_source(src):
    content = fetch(src)
    if not content:
        return []
    text = content.decode('utf-8', errors='ignore')
    if 't.me' in src:
        pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
        found = re.findall(pat, text)
        print(f"   ↳ TG: {len(found)}", flush=True)
        return found
    else:
        lines = text.splitlines()
        from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
        print(f"   ↳ Загружено: {len(from_file)}", flush=True)
        return from_file

def update_readme(total_count, update_time_str, raw_url):
    stats_block = f"""<!-- STATS_START -->
**Всего конфигов:** {total_count}  
**Обновлено (МСК):** {update_time_str}

**Ссылка для импорта в VPN (нажмите для копирования):**  
`{raw_url}`
<!-- STATS_END -->"""

    if README.exists():
        with open(README, 'r', encoding='utf-8') as f:
            content = f.read()
        pattern = r'(<!-- STATS_START -->).*?(<!-- STATS_END -->)'
        new_content = re.sub(pattern, rf'\1\n{stats_block}\n\2', content, flags=re.DOTALL)
        with open(README, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("✅ README.md обновлён (МСК)", flush=True)
    else:
        readme_content = f"""# Kfg-analyzer

**Автоматический парсер конфигов**

{stats_block}

### Подписки
- [Полная](public/sub.txt)
- [iOS топ-50](public/sub_ios.txt)
- [Sing-Box](public/sub_singbox.json)

ТГК: https://t.me/Niyakwi_news

Обновление каждые 2 часа.
"""
        with open(README, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print("✅ README.md создан", flush=True)

# ==================== ОСНОВНАЯ ФУНКЦИЯ ====================
def main():
    print("🚀 Kfg-analyzer Parser v4.6 (фикс whitelist) запущен", flush=True)
    sys.stdout.reconfigure(line_buffering=True)

    if not SOURCES_FILE.exists():
        print(f"❌ {SOURCES_FILE} не найден!", flush=True)
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = [executor.submit(process_source, src) for src in sources]
        for future in as_completed(futures):
            all_configs.extend(future.result())
            time.sleep(REQUEST_DELAY)

    print(f"📦 Всего ссылок (до дедупликации): {len(all_configs)}", flush=True)

    # Группировка по серверам
    server_best = {}
    for link in all_configs:
        if not any(link.startswith(p + "://") for p in SUPPORTED):
            continue
        key = get_server_key(link, include_sni=True)
        if not key:
            continue
        prio = priority_key(link)
        if key not in server_best or prio > server_best[key][1]:
            server_best[key] = (link, prio)

    print(f"📦 Уникальных серверов (до проверки): {len(server_best)}", flush=True)

    # Отладка первых 5 (чтобы видеть, что whitelist теперь не блокирует)
    debug_links = list(server_best.values())[:5]
    print("\n🔍 Отладка первых 5 серверов:", flush=True)
    for i, (link, prio) in enumerate(debug_links, 1):
        wl = is_in_whitelist(link)
        tcp = tcp_check_cached(link)
        print(f"  {i}. whitelist={wl}, TCP={tcp}, prio={prio}", flush=True)
    print("", flush=True)

    # Фильтрация
    unique = {}
    stats_whitelist_fail = 0
    stats_tcp_fail = 0
    for key, (link, _) in server_best.items():
        if not is_in_whitelist(link):
            stats_whitelist_fail += 1
            continue
        if not tcp_check_cached(link):
            stats_tcp_fail += 1
            continue
        unique[config_hash(link)] = link

    print(f"📊 Статистика фильтрации:", flush=True)
    print(f"   Отсеяно по whitelist: {stats_whitelist_fail}", flush=True)
    print(f"   Отсеяно по TCP: {stats_tcp_fail}", flush=True)
    print(f"✅ Отобрано серверов после проверки: {len(unique)}", flush=True)

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    # Если всё же ничего не прошло (например, все TCP упали) – берём первые 200
    if len(android_configs) == 0:
        print("⚠️ Ничего не прошло фильтрацию. Использую первые 200 уникальных серверов (без TCP-проверки).", flush=True)
        fallback = [link for (link, _) in list(server_best.values())[:200]]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

    # Заголовки подписки
    sub_header = (
        "#profile-title: Kfg-analyzer\n"
        "#profile-update-interval: 2\n"
        "#support-url: https://t.me/Niyakwi_news\n"
        "#announce: Свобода заключается в смелости! Использовать ТОЛЬКО при белом списке.\n"
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0\n"
        "\n"
    )
    full_sub_content = sub_header + "\n".join(android_configs)
    MAIN_SUB.write_text(base64.b64encode(full_sub_content.encode()).decode())

    ios_full = sub_header + "\n".join(ios_configs)
    IOS_SUB.write_text(base64.b64encode(ios_full.encode()).decode())

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({"outbounds": [{"type": "urltest", "tag": "Kfg-analyzer", "outbounds": android_configs}]}, f, indent=2)

    # Время и статистика
    now_moscow = moscow_now()
    now_str = now_moscow.strftime("%Y-%m-%d %H:%M:%S MSK")
    now_json = now_moscow.strftime("%Y-%m-%d %H:%M UTC+3")

    stats = {
        "total_android": len(android_configs),
        "ios_top50": len(ios_configs),
        "last_update": now_json,
        "whitelist_fail": stats_whitelist_fail,
        "tcp_fail": stats_tcp_fail,
        "unique_servers_before_filter": len(server_best)
    }
    with open(STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    # Генерация raw-ссылки для README
    raw_url = "https://raw.githubusercontent.com/REPO_OWNER/REPO_NAME/main/public/sub.txt"
    if os.getenv("GITHUB_REPOSITORY"):
        repo = os.getenv("GITHUB_REPOSITORY")
        raw_url = f"https://raw.githubusercontent.com/{repo}/main/public/sub.txt"
    else:
        # Попробуем определить из git remote (локально)
        try:
            import subprocess
            remote = subprocess.check_output(["git", "config", "--get", "remote.origin.url"], text=True).strip()
            # Извлекаем owner/repo из URL
            match = re.search(r"github\.com[:/](.+?)(\.git)?$", remote)
            if match:
                repo = match.group(1)
                raw_url = f"https://raw.githubusercontent.com/{repo}/main/public/sub.txt"
        except:
            pass

    update_readme(len(android_configs), now_str, raw_url)

    # Проверка файлов
    for f in [MAIN_SUB, IOS_SUB, SINGBOX_SUB, STATS]:
        if f.exists():
            print(f"✅ Создан {f}", flush=True)
        else:
            print(f"⚠️ Файл {f} не создан!", flush=True)

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)} (МСК {now_str})", flush=True)
    print(f"📋 Raw-ссылка для импорта: {raw_url}", flush=True)

if __name__ == "__main__":
    main()
