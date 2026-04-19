import sys
sys.stdout.reconfigure(line_buffering=True)

import requests
import base64
import json
import re
import time
import hashlib
import socket
import os
from urllib.parse import urlparse, parse_qs, urlunparse
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Попытка импорта telethon
try:
    from telethon import TelegramClient
    from telethon.tl.types import MessageEntityTextUrl
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Telethon не установлен, Telegram-каналы пропущены", flush=True)

# ---------- НАСТРОЙКИ ----------
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"
SOURCES_FILE = Path("sources.txt")
LAST_IDS_FILE = Path("last_ids.json")

REQUEST_DELAY = 4.0
TCP_TIMEOUT = 4.0                # увеличен для надёжности
FRESH_HOURS_LIMIT = 2
MAX_WORKERS = 30

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ---------- БЕЛЫЙ СПИСОК ----------
def load_whitelist():
    domain_list = set()
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
        print(f"✅ Белый список загружен: {len(domain_list)} доменов", flush=True)
    except Exception as e:
        print(f"⚠️ Белый список не загружен: {e}", flush=True)
    return domain_list

DOMAIN_WHITELIST = load_whitelist()

# ---------- УТИЛИТЫ ----------
def fetch(url):
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15).content
    except:
        return None

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

# ---------- TELEGRAM ----------
def load_last_ids():
    if LAST_IDS_FILE.exists():
        with open(LAST_IDS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_last_ids(ids_dict):
    with open(LAST_IDS_FILE, 'w') as f:
        json.dump(ids_dict, f, indent=2)

def extract_configs_from_text(text):
    pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
    return re.findall(pat, text)

async def fetch_new_telegram_configs(client, channel_username):
    new_configs = []
    last_ids = load_last_ids()
    last_id = last_ids.get(channel_username, 0)

    try:
        messages = await client.get_messages(channel_username, limit=20)

        for message in messages:
            if message.id <= last_id:
                break
            time_diff = datetime.now(message.date.tzinfo) - message.date
            if time_diff > timedelta(hours=FRESH_HOURS_LIMIT):
                continue
            if message.text:
                new_configs.extend(extract_configs_from_text(message.text))
            if message.entities:
                for entity in message.entities:
                    if isinstance(entity, MessageEntityTextUrl):
                        url = entity.url
                        if any(url.startswith(p + "://") for p in SUPPORTED):
                            new_configs.append(url)

        if messages:
            last_ids[channel_username] = max(last_id, messages[0].id)
            save_last_ids(last_ids)

    except Exception as e:
        print(f"❌ Ошибка в канале {channel_username}: {e}", flush=True)

    return new_configs

# ---------- MAIN ----------
def main():
    print("🚀 Kfg-analyzer Parser v3.6 (с резервным режимом) запущен", flush=True)

    if not SOURCES_FILE.exists():
        print(f"❌ Файл {SOURCES_FILE} не найден! Создаю пустые файлы и выхожу.", flush=True)
        create_empty_outputs()
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []
    telegram_sources = [s for s in sources if 't.me' in s]
    other_sources = [s for s in sources if 't.me' not in s]

    # --- Telegram ---
    if telegram_sources and TELETHON_AVAILABLE:
        api_id = os.environ.get('TG_API_ID')
        api_hash = os.environ.get('TG_API_HASH')
        if not api_id or not api_hash:
            print("⚠️ Нет TG_API_ID / TG_API_HASH, Telegram пропущен.", flush=True)
        else:
            try:
                api_id = int(api_id)
            except ValueError:
                print("❌ TG_API_ID должен быть числом!", flush=True)
            else:
                client = TelegramClient('tg_session', api_id, api_hash)
                with client:
                    for channel_url in telegram_sources:
                        username = '@' + channel_url.split('/')[-1]
                        print(f"📡 Проверяю канал {username}...", flush=True)
                        try:
                            new = client.loop.run_until_complete(
                                fetch_new_telegram_configs(client, username)
                            )
                            print(f"   ➕ Новых конфигов: {len(new)}", flush=True)
                            all_configs.extend(new)
                        except Exception as e:
                            print(f"❌ Ошибка {username}: {e}", flush=True)
                        time.sleep(2)

    # --- Обычные URL ---
    for src in other_sources:
        print(f"📥 Скачиваю {src}", flush=True)
        content = fetch(src)
        if content:
            lines = content.decode('utf-8', errors='ignore').splitlines()
            configs_from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
            all_configs.extend(configs_from_file)
        time.sleep(REQUEST_DELAY)

    # Удаление дубликатов
    all_configs = list(set(all_configs))
    total = len(all_configs)
    print(f"📦 Всего уникальных ссылок: {total}", flush=True)

    if total == 0:
        print("⚠️ Нет ссылок для проверки. Создаю пустые файлы.", flush=True)
        create_empty_outputs()
        return

    print("🔍 Многопоточная TCP-проверка и белый список...", flush=True)

    tcp_passed = 0
    whitelist_passed = 0

    def check_config(link):
        nonlocal tcp_passed, whitelist_passed
        tcp_ok = tcp_check(link)
        if tcp_ok:
            tcp_passed += 1
            wl_ok = is_in_whitelist(link)
            if wl_ok:
                whitelist_passed += 1
                return config_hash(link), link
        return None, None

    unique = {}
    progress_lock = Lock()
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_config, link): link for link in all_configs}
        for future in as_completed(futures):
            h, link = future.result()
            if h:
                unique[h] = link
            with progress_lock:
                completed += 1
                if completed % 100 == 0 or completed == total:
                    print(f"   Прогресс: {completed}/{total} (TCP: {tcp_passed}, WL: {whitelist_passed})", flush=True)

    print(f"📊 Итог фильтрации: TCP прошло {tcp_passed}, белый список прошло {whitelist_passed}", flush=True)

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    # --- Резервный режим: если после фильтрации ноль, берём первые 200 уникальных ссылок ---
    if len(android_configs) == 0:
        print("⚠️ После фильтрации 0 конфигов! Включаю резервный режим (без проверок).", flush=True)
        fallback = all_configs[:200]
        android_configs = [rename_config(link) for link in fallback]
        ios_configs = android_configs[:50]

    # --- Сохранение ---
    create_output_files(android_configs, ios_configs)

    print(f"✅ Готово! Android: {len(android_configs)} | iOS: {len(ios_configs)}", flush=True)

def create_empty_outputs():
    """Создаёт пустые файлы и статистику с нулями."""
    create_output_files([], [])

def create_output_files(android_list, ios_list):
    """Записывает подписки и статистику."""
    b64 = base64.b64encode('\n'.join(android_list).encode()).decode()
    MAIN_SUB.write_text(b64)

    b64_ios = base64.b64encode('\n'.join(ios_list).encode()).decode()
    IOS_SUB.write_text(b64_ios)

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({"outbounds": [{"type": "urltest", "tag": "Kfg-analyzer", "outbounds": android_list}]}, f, indent=2)

    stats = {
        "total_android": len(android_list),
        "ios_top50": len(ios_list),
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }
    json.dump(stats, open(STATS, 'w'), indent=2)

if __name__ == "__main__":
    main()
