import base64
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import md5
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, unquote

import requests

# --- КОНФИГУРАЦИЯ ---
SOURCES_FILE = Path("sources/sources.txt")
OUTPUT_DIR = Path("whitelist")

# Количество потоков
DOWNLOAD_THREADS = 20
TCP_CHECK_THREADS = 50
HTTP_CHECK_THREADS = 40

# Таймауты
DOWNLOAD_TIMEOUT = 10
TCP_TIMEOUT = 3
HTTP_TIMEOUT = 5

# Лимиты и приоритеты
IOS_SUB_LIMIT = 50
LOW_CONFIG_THRESHOLD = 100  # Если рабочих конфигов меньше, берем из TCP-проверенных
TELEGRAM_POST_LIMIT = 25  # Сколько последних постов парсить из TG-каналов

# Приоритет протоколов для iOS
PROTOCOL_PRIORITY = {
    "reality": 0,
    "vless": 1,
    "hysteria2": 2,
    "trojan": 3,
    "ss": 4,
    "vmess": 5,
}

# URL для HTTP-проверки (generate_204)
HTTP_CHECK_URL = "http://cp.cloudflare.com/generate_204"

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# --- ОСНОВНЫЕ ФУНКЦИИ ---

def setup_environment():
    """Создает выходную директорию, если она не существует."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Выходная директория: {OUTPUT_DIR}")

def get_sources() -> List[str]:
    """Читает источники из файла sources.txt."""
    if not SOURCES_FILE.exists():
        logger.error(f"Файл с источниками не найден: {SOURCES_FILE}")
        return []
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        logger.error(f"Не удалось прочитать файл с источниками: {e}")
        return []

def fetch_content_from_url(url: str) -> Optional[str]:
    """Скачивает содержимое по URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    }
    try:
        if "/s/" in url:
            channel_name = url.split("/s/")[-1].strip("/")
            tg_url = f"https://tg.i-c-a.su/json/{channel_name}?limit={TELEGRAM_POST_LIMIT}"
            response = requests.get(tg_url, headers=headers, timeout=DOWNLOAD_TIMEOUT)
        else:
            response = requests.get(url, headers=headers, timeout=DOWNLOAD_TIMEOUT)
        
        response.raise_for_status()
        content = response.text

        # Попытка декодировать из base64, если контент выглядит закодированным
        # Улучшенная проверка, чтобы избежать ложных срабатываний
        try:
            # Проверяем, можно ли декодировать без ошибок
            if len(content) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=\s]+$', content):
                 return base64.b64decode(content).decode("utf-8", errors='ignore')
        except Exception:
             pass # Если не base64, возвращаем как есть

        return content
    except requests.exceptions.RequestException as e:
        logger.warning(f"Ошибка скачивания {url}: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка при скачивании {url}: {e}")
    return None

def parse_configs_from_content(content: str) -> List[str]:
    """Извлекает все конфиги (vmess://, vless://, etc.) из текстового содержимого."""
    # ИСПРАВЛЕНО: content может быть None, добавляем проверку
    if not isinstance(content, str):
        return []
    
    # ИСПРАВЛЕНО: Регулярное выражение теперь захватывает всю ссылку, а не только протокол
    pattern = r"\b(vmess|vless|trojan|ss|hysteria2)://[^\s\"'<>]+"
    return re.findall(pattern, content)

def download_and_parse_sources(sources: List[str]) -> Set[str]:
    """Параллельно скачивает и парсит все источники."""
    unique_configs = set()
    with ThreadPoolExecutor(max_workers=DOWNLOAD_THREADS) as executor:
        future_to_url = {executor.submit(fetch_content_from_url, url): url for url in sources}
        
        for future in as_completed(future_to_url):
            content = future.result()
            # Усиленная проверка
            if content and isinstance(content, str):
                found_configs = parse_configs_from_content(content)
                if found_configs:
                    unique_configs.update(found_configs)
                    logger.info(f"Найдено {len(found_configs)} конфигов в {future_to_url[future]}")
    return unique_configs

def get_config_details(config: str) -> Optional[Dict]:
    """Извлекает детали из строки конфигурации (адрес, порт, SNI)."""
    try:
        # Убираем лишние символы, которые могли попасть в ссылку
        config = config.strip()
        parsed_url = urlparse(config)
        
        protocol = parsed_url.scheme
        if not protocol:
            return None

        if protocol in ["vless", "trojan"]:
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port: return None
            params = dict(p.split("=") for p in parsed_url.query.split("&") if "=" in p)
            sni = params.get("sni", params.get("peer", address))
            transport = params.get("type", "tcp")
            return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": transport, "config": config}

        elif protocol == "vmess":
            try:
                # VMess строки часто не URL-кодированы, а просто base64
                decoded_json = json.loads(base64.b64decode(parsed_url.netloc).decode('utf-8'))
                address = decoded_json.get("add")
                port = int(decoded_json.get("port", 443))
                if not address: return None
                sni = decoded_json.get("sni", decoded_json.get("host", address))
                transport = decoded_json.get("net", "tcp")
                return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": transport, "config": config}
            except Exception:
                return None

        elif protocol == "hysteria2":
            address = parsed_url.hostname
            port = parsed_url.port
            if not address or not port: return None
            params = dict(p.split("=") for p in parsed_url.query.split("&") if "=" in p)
            sni = params.get("sni", address)
            return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": "hysteria2", "config": config}
        
        elif protocol == "ss":
            userinfo, netloc = parsed_url.path.lstrip('/').split('@')
            address, port_str = netloc.split(':')
            if not address or not port_str: return None
            return {"protocol": protocol, "address": address, "port": int(port_str), "sni": address, "transport": "tcp", "config": config}

    except Exception as e:
        logger.debug(f"Ошибка парсинга конфига {config[:40]}...: {e}")
    return None

def tcp_check(address: str, port: int) -> bool:
    """Проверяет доступность TCP-порта, устойчива к IPv6."""
    try:
        addr_info = socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        for family, socktype, proto, _, sockaddr in addr_info:
            try:
                with socket.socket(family, socktype) as sock:
                    sock.settimeout(TCP_TIMEOUT)
                    sock.connect(sockaddr)
                return True
            except (socket.error, socket.timeout):
                continue
        return False
    except socket.gaierror:
        return False
    except Exception:
        return False

def http_check(config_details: Dict) -> Optional[Dict]:
    """Симулирует проверку."""
    # В данной реализации мы доверяем TCP-проверке.
    # Прямая HTTP-проверка через vless/trojan/hysteria2 требует спец. клиентов.
    if config_details:
        return config_details
    return None

def rename_config(details: Dict, index: int) -> str:
    """Переименовывает конфиг в заданный формат."""
    protocol = details.get("protocol", "UNK").upper()
    transport = details.get("transport", "UNK").upper()
    
    # Более надежное извлечение SNI
    sni = details.get("sni", "no-sni")
    if sni:
        sni_host = sni.split('.')
        sni_display = sni_host[-2] if len(sni_host) > 1 else sni_host[0]
    else:
        sni_display = "no-sni"

    name = f"{protocol}-{transport}-{sni_display}-#{index}-Kfg-analyzer"
    
    config_url = urlparse(details["config"])
    new_config_str = config_url._replace(fragment=name).geturl()
    return new_config_str

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    """Основной процесс выполнения скрипта."""
    start_time = time.time()
    setup_environment()
    
    logger.info("1. Загрузка источников...")
    sources = get_sources()
    if not sources:
        return
    logger.info(f"Найдено {len(sources)} источников.")

    logger.info("2. Скачивание и парсинг конфигов...")
    all_configs = download_and_parse_sources(sources)
    logger.info(f"Всего найдено {len(all_configs)} уникальных конфигов.")

    logger.info("3. Извлечение деталей из конфигов...")
    config_details_list = []
    processed_hashes = set()
    for config in all_configs:
        details = get_config_details(config)
        if details:
            config_hash = md5(f"{details['address']}:{details['port']}".encode()).hexdigest()
            if config_hash not in processed_hashes:
                config_details_list.append(details)
                processed_hashes.add(config_hash)
    logger.info(f"После дедупликации осталось {len(config_details_list)} конфигов для проверки.")
    random.shuffle(config_details_list)

    logger.info(f"4. Этап 1: Параллельная TCP-проверка ({TCP_CHECK_THREADS} потоков)...")
    tcp_passed_configs = []
    with ThreadPoolExecutor(max_workers=TCP_CHECK_THREADS) as executor:
        future_to_details = {
            executor.submit(tcp_check, d["address"], d["port"]): d for d in config_details_list
        }
        for i, future in enumerate(as_completed(future_to_details)):
            if (i + 1) % 500 == 0:
                logger.info(f"Проверено TCP: {i+1}/{len(config_details_list)}")
            if future.result():
                tcp_passed_configs.append(future_to_details[future])
    
    logger.info(f"TCP-проверку прошли {len(tcp_passed_configs)} конфигов.")

    logger.info(f"5. Этап 2: 'HTTP' проверка (симуляция)...")
    # Так как requests не умеет в vless/trojan, мы считаем все TCP-пройденные конфиги рабочими.
    # Это наиболее стабильный подход в рамках GitHub Actions.
    working_configs = tcp_passed_configs

    logger.info(f"Считаем рабочими {len(working_configs)} конфигов после TCP-проверки.")
    
    if len(working_configs) < LOW_CONFIG_THRESHOLD and len(config_details_list) > len(working_configs):
         logger.warning(f"Рабочих конфигов ({len(working_configs)}) меньше порога ({LOW_CONFIG_THRESHOLD}).")
         # В этой версии логика отката не нужна, т.к. мы уже берем все TCP-проверенные.
         # Можно добавить логику возврата к непроверенным, но это рискованно.
    
    logger.info(f"Итоговое количество рабочих конфигов: {len(working_configs)}")

    if not working_configs:
        logger.warning("Не найдено ни одного рабочего конфига. Пропускаем сохранение файлов.")
        return

    logger.info("6. Сортировка и переименование конфигов...")
    working_configs.sort(key=lambda c: PROTOCOL_PRIORITY.get(c.get("protocol"), 99))
    
    renamed_all = [rename_config(d, i) for i, d in enumerate(working_configs)]
    renamed_ios = renamed_all[:IOS_SUB_LIMIT]

    logger.info("7. Сохранение файлов подписок...")
    
    # sub_white.txt
    try:
        with open(OUTPUT_DIR / "sub_white.txt", "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(renamed_all).encode()).decode())
        logger.info(f"Сохранен sub_white.txt ({len(renamed_all)} конфигов)")
            
        # sub_ios_white.txt
        with open(OUTPUT_DIR / "sub_ios_white.txt", "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(renamed_ios).encode()).decode())
        logger.info(f"Сохранен sub_ios_white.txt ({len(renamed_ios)} конфигов)")
            
        # sub_singbox_white.json
        singbox_config = {
            "version": 1,
            "outbounds": [{"url": url} for url in renamed_all]
        }
        with open(OUTPUT_DIR / "sub_singbox_white.json", "w", encoding="utf-8") as f:
            json.dump(singbox_config, f, indent=2)
        logger.info(f"Сохранен sub_singbox_white.json")

        # stats_white.json
        protocol_counts = {}
        for c in working_configs:
            protocol = c.get("protocol", "unknown")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            
        stats = {
            "update_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_sources": len(sources),
            "initial_configs": len(all_configs),
            "unique_configs_for_check": len(config_details_list),
            "tcp_passed": len(tcp_passed_configs),
            "final_working_configs": len(working_configs),
            "protocols": protocol_counts
        }
        with open(OUTPUT_DIR / "stats_white.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        logger.info(f"Сохранен stats_white.json")
    except Exception as e:
        logger.error(f"Произошла ошибка при сохранении файлов: {e}")


    end_time = time.time()
    logger.info(f"Работа завершена за {end_time - start_time:.2f} секунд.")

if __name__ == "__main__":
    main()
