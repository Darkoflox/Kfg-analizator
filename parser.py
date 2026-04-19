#!/usr/bin/env python3
# Kfg-analyzer Parser v4.1 – дедупликация по серверам, многопоточность, кэш TCP

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

# ==================== НАСТРОЙКИ ====================
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"

SOURCES_DIR = Path("sources")
SOURCES_DIR.mkdir(exist_ok=True)
SOURCES_FILE = SOURCES_DIR / "sources.txt"

REQUEST_DELAY = 0.5          # задержка между источниками (сек)
TCP_TIMEOUT = 2.0            # таймаут TCP-проверки
FETCH_TIMEOUT = 10           # таймаут загрузки источника
MAX_WORKERS_FETCH = 10       # потоков для загрузки источников
MAX_WORKERS_CHECK = 30       # потоков для TCP-проверки
SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def load_whitelist():
    """Загружает белый список доменов (sni/host)"""
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        r.raise_for_status()
        return {line.strip().lower() for line in r.text.splitlines() if line.strip()}
    except:
        print("⚠️ Не удалось загрузить domain.txt", flush=True)
        return set()

DOMAIN_WHITELIST = load_whitelist()

# ---------- КЭШ TCP ----------
_tcp_cache = {}

def tcp_check_cached(link):
    """Проверяет доступность порта (хост+порт), кэширует результат"""
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

# ---------- Обработка ссылок ----------
def get_server_key(link, include_sni=True):
    """
    Возвращает уникальный ключ сервера:
    - если include_sni=True: (host, port, sni) – разделяет виртуальные хосты
    - иначе: (host, port)
    """
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
    """Приоритет для выбора лучшего конфига на сервере (выше = лучше)"""
    lower = link.lower()
    if 'reality' in lower: return 100
    if 'vless' in lower: return 80
    if 'hysteria2' in lower: return 60
    if 'trojan' in lower: return 40
    return 20

def is_in_whitelist(link):
    """Проверяет sni/host по белому списку"""
    if not DOMAIN_WHITELIST:
        return True
    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
        return bool(sni and sni.lower() in DOMAIN_WHITELIST)
    except ValueError:
        return False

def config_hash(link):
    """MD5 хеш ссылки (без фрагмента) для уникальности"""
    return hashlib.md5(urlparse(link)._replace(fragment="").geturl().encode()).hexdigest()

def rename_config(link):
    """Переименовывает конфиг: добавляет теги (протокол, транспорт, sni)"""
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

# ---------- Загрузка источников ----------
def fetch(url):
    """Загружает содержимое источника"""
    print(f"📥 {url}", flush=True)
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT).content
    except Exception as e:
        print(f"❌ Ошибка {url}: {e}", flush=True)
        return None

def process_source(src):
    """Загружает один источник и извлекает ссылки"""
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

# ==================== ОСНОВНАЯ ФУНКЦИЯ ====================
def main():
    print("🚀 Kfg-analyzer Parser v4.1 (дедупликация по серверам) запущен", flush=True)
    sys.stdout.reconfigure(line_buffering=True)

    if not SOURCES_FILE.exists():
        print(f"❌ {SOURCES_FILE} не найден!", flush=True)
        return

    # 1. Чтение источников
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # 2. Параллельная загрузка всех источников
    all_configs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = [executor.submit(process_source, src) for src in sources]
        for future in as_completed(futures):
            all_configs.extend(future.result())
            time.sleep(REQUEST_DELAY)   # небольшая пауза после каждого источника

    print(f"📦 Всего ссылок (до дедупликации): {len(all_configs)}", flush=True)

    # 3. Группировка по серверам (с учётом SNI) и выбор лучшей ссылки для каждого сервера
    server_best = {}   # key -> (link, priority)
    for link in all_configs:
        if not any(link.startswith(p + "://") for p in SUPPORTED):
            continue
        key = get_server_key(link, include_sni=True)
        if not key:
            continue   # ссылки без хоста/порта пропускаем
        prio = priority_key(link)
        if key not in server_best or prio > server_best[key][1]:
            server_best[key] = (link, prio)

    print(f"📦 Уникальных серверов (до проверки): {len(server_best)}", flush=True)

    # 4. Фильтрация: whitelist + TCP-проверка (с кэшем)
    unique = {}
    for key, (link, _) in server_best.items():
        try:
            if is_in_whitelist(link) and tcp_check_cached(link):
                unique[config_hash(link)] = link
        except Exception as e:
            print(f"⚠️ Ошибка при проверке {key}: {e}", flush=True)
            continue

    print(f"✅ Отобрано серверов после проверки: {len(unique)}", flush=True)

    # 5. Переименование и сортировка
    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    # 6. Формирование выходных файлов
    android_configs = valid[:4000]
    ios_configs = valid[:50]

    if len(android_configs) == 0:
        print("⚠️ Ничего не прошло фильтрацию. Беру первые 200 уникальных серверов.", flush=True)
        fallback = [link for (link, _) in list(server_best.values())[:200]]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

    # Запись sub.txt (base64)
    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode())
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode())

    # Запись sub_singbox.json
    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({"outbounds": [{"type": "urltest", "tag": "Kfg-analyzer", "outbounds": android_configs}]}, f, indent=2)

    # Статистика
    stats = {
        "total_android": len(android_configs),
        "ios_top50": len(ios_configs),
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }
    json.dump(stats, open(STATS, 'w'), indent=2)

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}", flush=True)

if __name__ == "__main__":
    main()
