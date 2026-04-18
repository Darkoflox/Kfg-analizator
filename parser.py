import requests
import base64
import json
import re
import time
import hashlib
import socket
import os
from urllib.parse import urlparse, unquote, parse_qs, urlunparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# --- Telethon для Telegram ---
from telethon import TelegramClient
from telethon.tl.types import MessageEntityTextUrl

# ========== НАСТРОЙКИ ==========
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"
SOURCES_FILE = Path("sources.txt")
README = Path("README.md")
LAST_IDS_FILE = Path("last_ids.json")          # хранение ID обработанных постов ТГ

REQUEST_DELAY = 4.0
TCP_TIMEOUT = 3                                 # секунд на TCP‑проверку
FRESH_HOURS_LIMIT = 2                           # брать посты не старше N часов

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# ========== ЗАГРУЗКА БЕЛОГО СПИСКА ==========
def load_whitelist():
    domain_list = set()
    try:
        r = requests.get("https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/domain.txt", timeout=10)
        domain_list = {line.strip().lower() for line in r.text.splitlines() if line.strip()}
    except:
        pass
    return domain_list

DOMAIN_WHITELIST = load_whitelist()

# ========== УТИЛИТЫ ==========
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

# ========== ОБРАБОТКА TELEGRAM (НОВОЕ) ==========
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
    """Асинхронно получает новые конфиги из Telegram-канала."""
    new_configs = []
    last_ids = load_last_ids()
    last_id = last_ids.get(channel_username, 0)

    try:
        messages = await client.get_messages(channel_username, limit=20)

        for message in messages:
            if message.id <= last_id:
                break

            # Фильтр по времени
            time_diff = datetime.now(message.date.tzinfo) - message.date
            if time_diff > timedelta(hours=FRESH_HOURS_LIMIT):
                continue

            # Текст сообщения
            if message.text:
                new_configs.extend(extract_configs_from_text(message.text))

            # Ссылки в entities
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
        print(f"❌ Ошибка в канале {channel_username}: {e}")

    return new_configs

# ========== ГЛАВНАЯ ЛОГИКА ==========
def main():
    print("🚀 Kfg-analyzer Parser v3.3 (Telegram только свежее)")

    # Читаем источники
    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_configs = []

    # Разделяем источники: Telegram и остальные
    telegram_sources = [s for s in sources if 't.me' in s]
    other_sources = [s for s in sources if 't.me' not in s]

    # --- Обработка Telegram через Telethon ---
    if telegram_sources:
        api_id = int(os.environ.get('TG_API_ID', 0))
        api_hash = os.environ.get('TG_API_HASH', '')
        if api_id == 0 or not api_hash:
            print("⚠️ Не заданы TG_API_ID / TG_API_HASH в секретах. Пропускаю Telegram.")
        else:
            client = TelegramClient('tg_session', api_id, api_hash)
            with client:
                for channel_url in telegram_sources:
                    username = '@' + channel_url.split('/')[-1]
                    print(f"📡 Проверяю канал {username}...")
                    try:
                        new = client.loop.run_until_complete(
                            fetch_new_telegram_configs(client, username)
                        )
                        print(f"   ➕ Найдено новых конфигов: {len(new)}")
                        all_configs.extend(new)
                    except Exception as e:
                        print(f"❌ Ошибка при обработке {username}: {e}")
                    time.sleep(2)

    # --- Обработка обычных URL (подписки, файлы) ---
    for src in other_sources:
        print(f"📥 Скачиваю {src}")
        content = fetch(src)
        if content:
            lines = content.decode('utf-8', errors='ignore').splitlines()
            configs_from_file = [l.strip() for l in lines if any(l.startswith(p + "://") for p in SUPPORTED)]
            all_configs.extend(configs_from_file)
        time.sleep(REQUEST_DELAY)

    # --- Удаление дубликатов ---
    print(f"📦 Всего найдено ссылок: {len(all_configs)}")
    print("🔍 Начинаю TCP‑проверку и фильтрацию по белому списку...")

    unique = {}
    for i, link in enumerate(all_configs, 1):
        if i % 100 == 0:
            print(f"   Прогресс: {i}/{len(all_configs)}")
        if tcp_check(link) and is_in_whitelist(link):
            unique[config_hash(link)] = link

    valid = [rename_config(link) for link in unique.values()]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid[:4000]
    ios_configs = valid[:50]

    # --- Сохранение результатов ---
    b64 = base64.b64encode('\n'.join(android_configs).encode()).decode()
    MAIN_SUB.write_text(b64)

    b64_ios = base64.b64encode('\n'.join(ios_configs).encode()).decode()
    IOS_SUB.write_text(b64_ios)

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
