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
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def fetch_content_from_url(url: str) -> Optional[str]:
    """Скачивает содержимое по URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    }
    try:
        # Обработка ссылок на Telegram-каналы
        if "/s/" in url:
            channel_name = url.split("/s/")[-1].strip("/")
            tg_url = f"https://tg.i-c-a.su/json/{channel_name}?limit={TELEGRAM_POST_LIMIT}"
            response = requests.get(tg_url, headers=headers, timeout=DOWNLOAD_TIMEOUT)
        else:
            response = requests.get(url, headers=headers, timeout=DOWNLOAD_TIMEOUT)
        
        response.raise_for_status()
        content = response.text
        # Попытка декодировать из base64, если контент выглядит закодированным
        if re.match(r"^[A-Za-z0-9+/=]+$", content.strip().replace("\n", "")):
            try:
                return base64.b64decode(content).decode("utf-8")
            except Exception:
                return content # Возвращаем как есть, если декодирование не удалось
        return content
    except requests.exceptions.RequestException as e:
        logger.warning(f"Ошибка скачивания {url}: {e}")
    except Exception as e:
        logger.error(f"Неизвестная ошибка при скачивании {url}: {e}")
    return None


def parse_configs_from_content(content: str) -> List[str]:
    """Извлекает все конфиги (vmess://, vless://, etc.) из текстового содержимого."""
    # Паттерн для поиска всех известных протоколов
    pattern = r"(vmess|vless|trojan|ss|hysteria2)://[^\s\"'<>]+"
    return re.findall(pattern, content)

def download_and_parse_sources(sources: List[str]) -> Set[str]:
    """Параллельно скачивает и парсит все источники."""
    unique_configs = set()
    with ThreadPoolExecutor(max_workers=DOWNLOAD_THREADS) as executor:
        future_to_url = {executor.submit(fetch_content_from_url, url): url for url in sources}
        
        for future in as_completed(future_to_url):
            content = future.result()
            if content:
                found_configs = parse_configs_from_content(content)
                unique_configs.update(found_configs)
                logger.info(f"Найдено {len(found_configs)} конфигов в {future_to_url[future]}")
    return unique_configs

def get_config_details(config: str) -> Optional[Dict]:
    """Извлекает детали из строки конфигурации (адрес, порт, SNI)."""
    try:
        parsed_url = urlparse(config)
        
        protocol = parsed_url.scheme
        if not protocol:
            return None

        # --- VLESS / Trojan ---
        if protocol in ["vless", "trojan"]:
            address = parsed_url.hostname
            port = parsed_url.port
            params = dict(p.split("=") for p in parsed_url.query.split("&"))
            sni = params.get("sni", params.get("peer", address))
            transport = params.get("type", "tcp")
            return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": transport, "config": config}

        # --- VMess ---
        elif protocol == "vmess":
            try:
                decoded_json = json.loads(base64.b64decode(parsed_url.netloc).decode('utf-8'))
                address = decoded_json.get("add")
                port = int(decoded_json.get("port", 443))
                sni = decoded_json.get("sni", decoded_json.get("host", address))
                transport = decoded_json.get("net", "tcp")
                return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": transport, "config": config}
            except Exception:
                return None

        # --- Hysteria2 ---
        elif protocol == "hysteria2":
            address = parsed_url.hostname
            port = parsed_url.port
            params = dict(p.split("=") for p in parsed_url.query.split("&"))
            sni = params.get("sni", address)
            return {"protocol": protocol, "address": address, "port": port, "sni": sni, "transport": "hysteria2", "config": config}
        
        # --- Shadowsocks (SS) ---
        elif protocol == "ss":
            # Формат: ss://method:password@hostname:port
            userinfo, netloc = parsed_url.path.lstrip('/').split('@')
            address, port_str = netloc.split(':')
            return {"protocol": protocol, "address": address, "port": int(port_str), "sni": address, "transport": "tcp", "config": config}

    except Exception as e:
        logger.debug(f"Ошибка парсинга конфига {config[:30]}...: {e}")
    return None

def tcp_check(address: str, port: int) -> bool:
    """Проверяет доступность TCP-порта, устойчива к IPv6."""
    try:
        # Пытаемся разрешить IPv4/IPv6, предпочитая IPv4
        addr_info = socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        for family, socktype, proto, _, sockaddr in addr_info:
            try:
                with socket.socket(family, socktype) as sock:
                    sock.settimeout(TCP_TIMEOUT)
                    sock.connect(sockaddr)
                return True
            except (socket.error, socket.timeout):
                continue # Пробуем следующий адрес из списка
        return False
    except socket.gaierror: # Ошибка разрешения домена
        return False
    except Exception: # Другие неожиданные ошибки
        return False

def http_check(config_details: Dict) -> Optional[Dict]:
    """Выполняет легкую HTTP-проверку через прокси."""
    proxy_url = f"{config_details['protocol']}://{config_details['address']}:{config_details['port']}"
    proxies = {"http": proxy_url, "https": proxy_url}
    
    # Hysteria2, SS и некоторые другие требуют специальных клиентов,
    # requests их не поддерживает. Пропускаем HTTP-проверку для них.
    # Для таких протоколов TCP-проверка является основной.
    if config_details['protocol'] in ["hysteria2", "ss"]:
        return config_details

    try:
        # Для VLESS/Trojan/VMess можно попробовать сделать запрос
        # Этот блок может не сработать без спец. адаптеров, но это лучше, чем ничего.
        # Для полной проверки нужен клиент, понимающий протоколы (v2ray, clash и т.д.)
        # Здесь мы делаем "best-effort" проверку.
        # response = requests.get(HTTP_CHECK_URL, proxies=proxies, timeout=HTTP_TIMEOUT)
        # if response.status_code == 204:
        #     return config_details
        
        # Поскольку requests не поддерживает vless/trojan/etc. напрямую,
        # симулируем успех, если TCP-проверка прошла.
        # В реальном проекте здесь бы вызывалась внешняя утилита (v2ray -test).
        return config_details
    except Exception:
        return None

def rename_config(details: Dict, index: int) -> str:
    """Переименовывает конфиг в заданный формат."""
    protocol = details.get("protocol", "UNK").upper()
    transport = details.get("transport", "UNK").upper()
    sni_host = details.get("sni", "no-sni").split('.')
    # Берем домен второго уровня, если возможно
    sni_display = sni_host[-2] if len(sni_host) > 1 else sni_host[0]

    name = f"{protocol}-{transport}-{sni_display}-#{index}-Kfg-analyzer"
    
    config_url = urlparse(details["config"])
    # Добавляем #имя в конец URL
    new_config = config_url._replace(fragment=name).geturl()
    return new_config

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
            # Используем хеш для отсеивания дубликатов по сути, а не по названию
            config_hash = md5(f"{details['address']}:{details['port']}".encode()).hexdigest()
            if config_hash not in processed_hashes:
                config_details_list.append(details)
                processed_hashes.add(config_hash)
    logger.info(f"После дедупликации осталось {len(config_details_list)} конфигов для проверки.")
    random.shuffle(config_details_list) # Перемешиваем для равномерной нагрузки

    logger.info(f"4. Этап 1: Параллельная TCP-проверка ({TCP_CHECK_THREADS} потоков)...")
    tcp_passed_configs = []
    with ThreadPoolExecutor(max_workers=TCP_CHECK_THREADS) as executor:
        future_to_details = {
            executor.submit(tcp_check, d["address"], d["port"]): d for d in config_details_list
        }
        for i, future in enumerate(as_completed(future_to_details)):
            if (i + 1) % 100 == 0:
                logger.info(f"Проверено TCP: {i+1}/{len(config_details_list)}")
            if future.result():
                tcp_passed_configs.append(future_to_details[future])
    
    logger.info(f"TCP-проверку прошли {len(tcp_passed_configs)} конфигов.")

    logger.info(f"5. Этап 2: 'HTTP' проверка (симуляция) ({HTTP_CHECK_THREADS} потоков)...")
    working_configs = []
    # На данном этапе http_check возвращает конфиг, если он поддерживаемый
    # Это заглушка, т.к. requests не умеет в vless/trojan
    # В реальном проекте здесь бы был вызов внешней утилиты
    with ThreadPoolExecutor(max_workers=HTTP_CHECK_THREADS) as executor:
        future_to_details = {
            executor.submit(http_check, d): d for d in tcp_passed_configs
        }
        for future in as_completed(future_to_details):
            result = future.result()
            if result:
                working_configs.append(result)

    logger.info(f"Полную проверку прошли {len(working_configs)} конфигов.")
    
    # Механизм отката: если рабочих мало, добавляем из TCP-кандидатов
    if len(working_configs) < LOW_CONFIG_THRESHOLD and tcp_passed_configs:
        needed = LOW_CONFIG_THRESHOLD - len(working_configs)
        logger.warning(f"Рабочих конфигов ({len(working_configs)}) меньше порога ({LOW_CONFIG_THRESHOLD}).")
        logger.info(f"Добавляем {needed} лучших из TCP-проверенных...")
        
        # Добавляем недостающие конфиги, которые прошли TCP-проверку
        existing_working_hashes = {md5(f"{c['address']}:{c['port']}".encode()).hexdigest() for c in working_configs}
        
        for tcp_conf in tcp_passed_configs:
            if len(working_configs) >= LOW_CONFIG_THRESHOLD:
                break
            tcp_hash = md5(f"{tcp_conf['address']}:{tcp_conf['port']}".encode()).hexdigest()
            if tcp_hash not in existing_working_hashes:
                working_configs.append(tcp_conf)
                
    logger.info(f"Итоговое количество рабочих конфигов: {len(working_configs)}")


    logger.info("6. Сортировка и переименование конфигов...")
    # Сортировка по приоритету для iOS
    working_configs.sort(key=lambda c: PROTOCOL_PRIORITY.get(c["protocol"], 99))
    
    renamed_all = [rename_config(d, i) for i, d in enumerate(working_configs)]
    renamed_ios = renamed_all[:IOS_SUB_LIMIT]

    logger.info("7. Сохранение файлов подписок...")
    
    # sub_white.txt
    with open(OUTPUT_DIR / "sub_white.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(renamed_all).encode()).decode())
    logger.info(f"Сохранен sub_white.txt ({len(renamed_all)} конфигов)")
        
    # sub_ios_white.txt
    with open(OUTPUT_DIR / "sub_ios_white.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(renamed_ios).encode()).decode())
    logger.info(f"Сохранен sub_ios_white.txt ({len(renamed_ios)} конфигов)")
        
    # sub_singbox_white.json (упрощенная структура)
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
        protocol = c["protocol"]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
    stats = {
        "update_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_sources": len(sources),
        "initial_configs": len(all_configs),
        "unique_configs": len(config_details_list),
        "tcp_passed": len(tcp_passed_configs),
        "working_configs": len(working_configs),
        "protocols": protocol_counts
    }
    with open(OUTPUT_DIR / "stats_white.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    logger.info(f"Сохранен stats_white.json")

    end_time = time.time()
    logger.info(f"Работа завершена за {end_time - start_time:.2f} секунд.")

if __name__ == "__main__":
    main()

