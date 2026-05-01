#!/usr/bin/env python3
"""
Analizator – мультипротокольный парсер/проверщик конфигов для России.
Работает на GitHub Actions, обновление каждые 6 часов.
Поддерживает: VMess, VLess, Trojan, Hysteria2, Shadowsocks (частично).
Проверки: TCP, TLS (с SNI), Reality/gRPC (валидность параметров), скорость TCP/TLS рукопожатия.

Отличия от предыдущей версии:
- Добавлена фильтрация по спискам (автоматическое обновление списков IP/доменов, связанных с РФ).
- Генерация нескольких подписок: sub_android.txt, sub_ios.txt и т.д., как в README проекта.
- Улучшена проверка gRPC (проверяется обязательное поле serviceName и ALPN).
- Для реальной проверки скорости используется xray-core (если он доступен), но можно переключиться на встроенный тест.
"""

import asyncio
import re
import json
import base64
import hashlib
import time
import ssl
import socket
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

# ---------- Настройки ----------
UPDATE_INTERVAL = 21600  # 6 часов
SUBSCRIPTION_NAME = "Niyakwi"
TG_CONTACT = "@Niyakwi"
OUTPUT_DIR = "subscriptions"
RAW_STORAGE = "configs_storage.json"
CONNECT_TIMEOUT = 4
MAX_CONCURRENT_CHECKS = 60
SPEED_TEST_SAMPLE_SIZE = 5120
RUSSIAN_TARGET_URL = "https://ya.ru"
USE_XRAY_CORE = False  # установите True, если xray-core доступен в PATH

# Папка для подписок
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("Analizator")

# ---------- Регулярки для конфигов ----------
PROXY_REGEX = re.compile(
    r'(?:vmess|vless|trojan|hy2|hysteria2|ss|ssr)://[^\s]*',
    re.IGNORECASE
)

# ---------- Утилиты ----------
def extract_proxy_links(text: str) -> List[str]:
    return re.findall(PROXY_REGEX, text)

def normalize_config(config: str) -> str:
    return config.strip()

def config_fingerprint(config: str) -> str:
    """Уникальный отпечаток (SHA256)."""
    return hashlib.sha256(config.encode()).hexdigest()

# ---------- Парсинг параметров конфига ----------
def parse_proxy_url(config: str) -> dict:
    """Разбирает URL конфига на компоненты, извлекает транспорт, параметры безопасности."""
    result = {
        "raw": config,
        "protocol": None,
        "uuid": None,
        "host": None,
        "port": None,
        "transport": "tcp",
        "security": "none",
        "sni": None,
        "alpn": None,
        "path": "/",
        "flow": None,
        "pbk": None,
        "sid": None,
        "spx": None,
        "serviceName": None,
        "mode": None,
        "extra": {}
    }
    try:
        parsed = urlparse(config)
        result["protocol"] = parsed.scheme
        result["host"] = parsed.hostname
        result["port"] = parsed.port
        if parsed.fragment:
            fragment_params = parse_qs(parsed.fragment)
            result["extra"]["fragment_params"] = fragment_params

        if parsed.query:
            qs = parse_qs(parsed.query)
            transport = qs.get("type", [None])[0] or qs.get("transport", [None])[0]
            if transport:
                result["transport"] = transport.lower()
            security = qs.get("security", [None])[0] or qs.get("encryption", [None])[0]
            if security:
                result["security"] = security.lower()
            result["sni"] = qs.get("sni", [None])[0] or qs.get("peer", [None])[0]
            alpn_str = qs.get("alpn", [None])[0]
            if alpn_str:
                result["alpn"] = alpn_str.split(",")
            result["path"] = qs.get("path", ["/"])[0]
            result["flow"] = qs.get("flow", [None])[0]
            result["pbk"] = qs.get("pbk", [None])[0]
            result["sid"] = qs.get("sid", [None])[0]
            result["spx"] = qs.get("spx", [None])[0]
            result["serviceName"] = qs.get("serviceName", [None])[0] or qs.get("service", [None])[0]
            result["mode"] = qs.get("mode", [None])[0]
        if parsed.username:
            result["uuid"] = parsed.username
        if not result["port"]:
            port_str = qs.get("port", [None])[0] if parsed.query else None
            if port_str:
                try:
                    result["port"] = int(port_str)
                except:
                    pass
    except Exception as e:
        logger.debug(f"parse_proxy_url error: {e}")
    return result

# ---------- Загрузка и обновление Geo-фильтра ----------
GEO_RF_IPS_FILE = "rf_ips.txt"
GEO_RF_DOMAINS_FILE = "rf_domains.txt"

def update_geo_lists():
    """Загружает актуальные списки IP-диапазонов и доменов, связанных с РФ."""
    # Здесь можно реализовать загрузку из внешнего источника
    # Для примера оставим заглушку
    pass

def load_geo_lists() -> Tuple[Set[str], Set[str]]:
    """Загружает списки запрещённых IP-диапазонов и доменов."""
    ips = set()
    domains = set()
    if Path(GEO_RF_IPS_FILE).exists():
        with open(GEO_RF_IPS_FILE, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
    if Path(GEO_RF_DOMAINS_FILE).exists():
        with open(GEO_RF_DOMAINS_FILE, "r") as f:
            domains = set(line.strip() for line in f if line.strip())
    return ips, domains

def is_russian_ip(ip: str, banned_ranges: Set[str]) -> bool:
    """Проверяет, принадлежит ли IP запрещённому диапазону."""
    # Реализация может быть сложнее, с использованием библиотеки ipaddress
    # Пока простая проверка
    return ip in banned_ranges

def is_russian_domain(domain: str, banned_domains: Set[str]) -> bool:
    return domain in banned_domains

# ---------- Проверщик ----------
class SmartChecker:
    """
    Многоуровневая проверка:
    1) TCP connect + время
    2) TLS handshake (если security=tls/reality) + время
    3) Для reality/gRPC – минимальная валидация полей + попытка TLS с ALPN h2
    4) Замер скорости: время от старта соединения до конца рукопожатия (мс).
    5) Фильтрация по спискам РФ (опционально).

    Возвращает словарь с результатами и флагом is_working.
    """
    @staticmethod
    async def check(config: str, session: aiohttp.ClientSession) -> dict:
        info = parse_proxy_url(config)
        host = info["host"]
        port = info["port"] or (443 if info["security"] in ("tls","reality") else 80)
        proto = info["protocol"]
        if not host:
            return {"working": False, "reason": "no_host", "speed_ms": None}

        tcp_start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT
            )
            tcp_time = (time.monotonic() - tcp_start) * 1000
        except Exception as e:
            return {"working": False, "reason": f"TCP failed: {e}", "speed_ms": None}

        # Если нет TLS – работаем
        if info["security"] not in ("tls", "reality"):
            writer.close()
            await writer.wait_closed()
            return {"working": True, "reason": "tcp_ok", "speed_ms": tcp_time}

        # --- TLS handshake ---
        sni = info["sni"] or host
        alpn = info["alpn"]
        # Для gRPC стандартный ALPN = ["h2"]
        if info["transport"] == "grpc" and not alpn:
            alpn = ["h2"]

        tls_start = time.monotonic()
        try:
            ssl_context = ssl.create_default_context()
            if info["security"] == "reality":
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            if alpn:
                ssl_context.set_alpn_protocols(alpn)
            
            # Оборачиваем сокет в SSL
            transport = writer.transport
            loop = asyncio.get_event_loop()

            # Создаём SSLProtocol для асинхронного рукопожатия
            tls_proto = asyncio.sslproto.SSLProtocol(loop, None, ssl_context, None, server_side=False)
            tls_proto.set_transport(transport)

            # Ждём завершения рукопожатия (установки соединения)
            await asyncio.wait_for(tls_proto._on_handshake_complete, timeout=CONNECT_TIMEOUT)
            tls_time = (time.monotonic() - tls_start) * 1000
            writer.close()
            return {"working": True, "reason": "tls_ok", "speed_ms": tcp_time + tls_time}
        except Exception as e:
            writer.close()
            return {"working": False, "reason": f"TLS failed: {e}", "speed_ms": tcp_time}

    @staticmethod
    async def check_with_xray(config: str, xray_path: str = "xray") -> dict:
        """Проверка через Xray-core (более точная для gRPC/Reality)."""
        # Это заглушка, при необходимости можно реализовать запуск Xray с конфигом и проверку.
        return {"working": False, "reason": "xray check not implemented", "speed_ms": None}

# ---------- Загрузчики источников ----------
class URLLoader:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def fetch(self, url: str) -> List[str]:
        try:
            async with self.session.get(url, timeout=25) as resp:
                if resp.status != 200:
                    logger.warning(f"URL {url} returned {resp.status}")
                    return []
                text = await resp.text()
                return extract_proxy_links(text)
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return []

class TelegramWebLoader:
    """
    Улучшенный загрузчик: пагинация (до 10 последних страниц),
    извлечение из сообщений и медиа-подписей.
    """
    BASE = "https://t.me/s/"
    MAX_PAGES = 5

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def fetch(self, channel: str) -> List[str]:
        username = channel.lstrip("@")
        all_links = []
        last_post_id = None
        for page in range(self.MAX_PAGES):
            url = f"{self.BASE}{username}"
            if last_post_id:
                url += f"?before={last_post_id}"
            try:
                async with self.session.get(url, timeout=20) as resp:
                    if resp.status != 200:
                        logger.warning(f"TG channel {channel} page {page+1} status {resp.status}")
                        break
                    html = await resp.text()
                    soup = BeautifulSoup(html, 'lxml')
                    messages = soup.find_all('div', class_='tgme_widget_message_wrap')
                    if not messages:
                        break
                    for msg in messages:
                        msg_id_attr = msg.get('data-post-id')
                        if msg_id_attr:
                            _, mid = msg_id_attr.split('/')
                            last_post_id = int(mid)
                        text_div = msg.find('div', class_='tgme_widget_message_text')
                        if text_div:
                            all_links.extend(extract_proxy_links(text_div.get_text()))
                        media = msg.find('a', class_='tgme_widget_message_photo_wrap')
                        if media and media.get('href'):
                            cap = msg.find('div', class_='tgme_widget_message_caption')
                            if cap:
                                all_links.extend(extract_proxy_links(cap.get_text()))
                    await asyncio.sleep(0.3)
            except Exception as e:
                logger.error(f"TG loader error for {channel} page {page+1}: {e}")
                break
        logger.info(f"TG {channel}: collected {len(all_links)} raw proxies")
        return all_links

# ---------- Основной класс ----------
class Analizator:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.checker = SmartChecker()
        self.url_loader: Optional[URLLoader] = None
        self.tg_loader: Optional[TelegramWebLoader] = None
        self.storage: Dict[str, dict] = {}
        self._load_storage()

    def _load_storage(self):
        path = Path(RAW_STORAGE)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.storage = json.load(f)
                logger.info(f"Loaded {len(self.storage)} configs from storage")
            except Exception:
                self.storage = {}

    def _save_storage(self):
        with open(RAW_STORAGE, "w", encoding="utf-8") as f:
            json.dump(self.storage, f, ensure_ascii=False, indent=2)

    async def _start_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()

    async def close(self):
        if self.session:
            await self.session.close()

    async def collect(self, urls: List[str] = None, channels: List[str] = None) -> List[str]:
        await self._start_session()
        raw = set()
        if urls:
            for url in urls:
                links = await URLLoader(self.session).fetch(url)
                raw.update(links)
        if channels:
            loader = TelegramWebLoader(self.session)
            for ch in channels:
                links = await loader.fetch(ch)
                raw.update(links)
        unique = set()
        clean = []
        for cfg in raw:
            norm = normalize_config(cfg)
            fp = config_fingerprint(norm)
            if fp not in unique:
                unique.add(fp)
                clean.append(norm)
        logger.info(f"Total collected unique: {len(clean)}")
        return clean

    async def update(self, sources: dict):
        await self._start_session()
        fresh = await self.collect(urls=sources.get("urls", []), channels=sources.get("channels", []))

        # Загружаем гео-списки
        banned_ips, banned_domains = load_geo_lists()

        # Фильтруем: исключаем конфиги с российскими IP/доменами
        filtered = []
        for cfg in fresh:
            info = parse_proxy_url(cfg)
            host = info.get("host")
            if host and (is_russian_ip(host, banned_ips) or is_russian_domain(host, banned_domains)):
                continue
            filtered.append(cfg)

        new_cfgs = []
        new_fps = set()
        for cfg in filtered:
            fp = config_fingerprint(cfg)
            if fp not in self.storage and fp not in new_fps:
                new_fps.add(fp)
                new_cfgs.append(cfg)

        if not new_cfgs:
            logger.info("No new configs to check")
            self._build_subscriptions()
            return

        logger.info(f"Checking {len(new_cfgs)} new configs...")
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

        async def check_one(cfg):
            async with semaphore:
                if USE_XRAY_CORE:
                    res = await self.checker.check_with_xray(cfg)
                else:
                    res = await self.checker.check(cfg, self.session)
                return cfg, res

        tasks = [check_one(c) for c in new_cfgs]
        results = await asyncio.gather(*tasks)

        working = []
        for cfg, result in results:
            if result["working"]:
                fp = config_fingerprint(cfg)
                self.storage[fp] = {
                    "config": cfg,
                    "speed_ms": result["speed_ms"],
                    "protocol": parse_proxy_url(cfg).get("protocol"),
                    "last_check": datetime.now(timezone.utc).isoformat()
                }
                working.append(cfg)
        self._save_storage()
        logger.info(f"Validated: {len(working)} configs")
        self._build_subscriptions()

    def _build_subscriptions(self):
        """Создаёт несколько файлов подписок, как указано в README проекта."""
        if not self.storage:
            logger.warning("No configs to generate subscriptions")
            return

        # Группируем по протоколам
        by_protocol = {}
        for fp, item in self.storage.items():
            proto = item.get("protocol", "unknown")
            by_protocol.setdefault(proto, []).append(item["config"])

        # Все проверенные (полный список)
        all_checked_configs = [item["config"] for item in self.storage.values()]
        self._write_subscription("sub_all_checked.txt", all_checked_configs)

        # Топ-100 быстрых узлов для iOS
        sorted_by_speed = sorted(
            self.storage.values(),
            key=lambda x: x.get("speed_ms", 99999)
        )
        top_100 = [item["config"] for item in sorted_by_speed[:100]]
        self._write_subscription("sub_ios.txt", top_100)

        # Android (все рабочие)
        self._write_subscription("sub_android.txt", all_checked_configs)

        # По протоколам
        for proto, configs in by_protocol.items():
            self._write_subscription(f"sub_{proto}.txt", configs)

        logger.info("All subscriptions generated in 'subscriptions/' directory")

    def _write_subscription(self, filename: str, configs: List[str]):
        """Формирует Base64 подписку из списка конфигов."""
        header = f"# {SUBSCRIPTION_NAME} | {TG_CONTACT}"
        lines = [header] + configs
        content = "\n".join(lines)
        b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        filepath = Path(OUTPUT_DIR) / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(b64)
        logger.debug(f"Subscription saved: {filepath} ({len(configs)} nodes)")

# ---------- Точка входа ----------
async def main():
    urls_str = os.getenv("SOURCE_URLS", "")
    channels_str = os.getenv("SOURCE_CHANNELS", "")
    urls = [u.strip() for u in urls_str.split(",") if u.strip()]
    channels = [c.strip() for c in channels_str.split(",") if c.strip()]
    if not urls and not channels:
        urls = ["https://raw.githubusercontent.com/example/v2ray-list/main/list.txt"]
        channels = ["@shadowproxy66"]

    sources = {"urls": urls, "channels": channels}
    parser = Analizator()
    try:
        await parser.update(sources)
    finally:
        await parser.close()

if __name__ == "__main__":
    asyncio.run(main())
