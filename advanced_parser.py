#!/usr/bin/env python3
"""
Универсальный асинхронный парсер подписок с проверкой через Xray-core,
фильтрацией по IP/доменам РФ и генерацией подписок для Android и iOS.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import aiohttp
import yaml

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Поддерживаемые протоколы
SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(
    r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s]+',
    re.IGNORECASE
)

# URL для загрузки Xray-core
XRAY_DOWNLOAD_URLS = {
    'linux': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip',
    'darwin': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-64.zip',
    'windows': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip',
}

# Сопоставление TLD с флагами
TLD_FLAGS = {
    'ru': '🇷🇺', 'us': '🇺🇸', 'de': '🇩🇪', 'nl': '🇳🇱', 'fr': '🇫🇷', 'gb': '🇬🇧', 'uk': '🇬🇧',
    'ca': '🇨🇦', 'jp': '🇯🇵', 'kr': '🇰🇷', 'sg': '🇸🇬', 'hk': '🇭🇰', 'tw': '🇹🇼',
    'au': '🇦🇺', 'br': '🇧🇷', 'in': '🇮🇳', 'tr': '🇹🇷', 'ua': '🇺🇦', 'pl': '🇵🇱',
    'se': '🇸🇪', 'no': '🇳🇴', 'fi': '🇫🇮', 'dk': '🇩🇰', 'ch': '🇨🇭', 'at': '🇦🇹',
    'it': '🇮🇹', 'es': '🇪🇸', 'pt': '🇵🇹', 'gr': '🇬🇷', 'cz': '🇨🇿', 'ro': '🇷🇴',
    'hu': '🇭🇺', 'bg': '🇧🇬', 'hr': '🇭🇷', 'rs': '🇷🇸', 'ae': '🇦🇪', 'il': '🇮🇱',
    'kz': '🇰🇿', 'uz': '🇺🇿', 'ge': '🇬🇪', 'am': '🇦🇲', 'az': '🇦🇿', 'md': '🇲🇩',
    'by': '🇧🇾', 'lt': '🇱🇹', 'lv': '🇱🇻', 'ee': '🇪🇪', 'sk': '🇸🇰', 'si': '🇸🇮',
    'lu': '🇱🇺', 'mt': '🇲🇹', 'cy': '🇨🇾', 'is': '🇮🇸', 'ie': '🇮🇪', 'be': '🇧🇪',
}

# Источники по умолчанию
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_links.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/yebekhe/TVIP/main/all",
    "https://raw.githubusercontent.com/LalatinaHub/Mineralhe/main/all.txt",
    "https://raw.githubusercontent.com/alien-v2ray/alien-v2ray.github.io/main/all.txt",
    "https://raw.githubusercontent.com/Lonelystar/v2ray-configs/main/all.txt",
    "https://raw.githubusercontent.com/SamanGoli66/v2ray-configs/main/v2ray-clients",
    "https://raw.githubusercontent.com/Pawel-S-K/free-v2ray-config/main/sub",
    "https://raw.githubusercontent.com/Emsis/v2ray-configs/main/configs.txt",
    "https://raw.githubusercontent.com/Bypass-LAN/V2ray/main/Sub.txt",
]


# ---------- Вспомогательные функции ----------
def load_sources(filename: str = "sources.txt") -> List[str]:
    """Загружает список источников из файла, при необходимости создаёт файл."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            sources = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith('#')
            ]
        if sources:
            logger.info(f"✅ Загружено {len(sources)} источников из {filename}")
            return sources
        logger.warning(f"⚠️ Файл {filename} пуст, использую список по умолчанию")
        return DEFAULT_SOURCES
    except FileNotFoundError:
        logger.warning(f"⚠️ Файл {filename} не найден, создаю пример и использую список по умолчанию")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("# Список источников подписок (по одному URL на строку)\n")
            for url in DEFAULT_SOURCES:
                f.write(f"{url}\n")
        return DEFAULT_SOURCES


def get_flag_from_host(host: str) -> str:
    """Возвращает эмодзи флага по TLD домена."""
    if not host:
        return '🏳️'
    parts = host.split('.')
    if len(parts) >= 2:
        tld = parts[-1].lower()
        return TLD_FLAGS.get(tld, '🌐')
    return '🌐'


class RussianFilter:
    """Фильтр по российским IP и доменам."""

    def __init__(self, ip_file: str = "russia_ip.txt", domain_file: str = "russia_domains.txt"):
        self.ip_networks = []
        self.domains = set()
        self._load_lists(ip_file, domain_file)

    def _ensure_file(self, path: str, example_content: str = ""):
        """Создаёт файл, если его нет."""
        if not Path(path).exists():
            Path(path).write_text(example_content, encoding='utf-8')
            logger.info(f"📄 Создан файл {path}")

    def _load_lists(self, ip_file: str, domain_file: str):
        # Примеры содержимого
        ip_example = "# IP-адреса и CIDR диапазоны РФ (по одному на строку)\n# Например:\n# 195.208.1.1\n# 92.63.96.0/20\n"
        domain_example = "# Домены РФ (по одному на строку)\n# Например:\n# mail.ru\n# yandex.ru\n"

        self._ensure_file(ip_file, ip_example)
        self._ensure_file(domain_file, domain_example)

        # Загружаем IP
        with open(ip_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    self.ip_networks.append(network)
                except ValueError as e:
                    logger.warning(f"⚠️ Некорректная запись в {ip_file}: {line} ({e})")

        # Загружаем домены
        with open(domain_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue
                self.domains.add(line)

        logger.info(f"🛡️ Загружено IP-сетей РФ: {len(self.ip_networks)}, доменов РФ: {len(self.domains)}")

    def is_russian(self, host: str) -> bool:
        """
        Проверяет, принадлежит ли хост (домен или IP) российскому сегменту.
        Возвращает True, если нужно отфильтровать.
        """
        if not host:
            return False

        # 1. Проверка домена
        host_lower = host.lower()
        for domain in self.domains:
            if host_lower == domain or host_lower.endswith('.' + domain):
                return True

        # 2. Проверка IP
        try:
            ip_addr = ipaddress.ip_address(host)
            for network in self.ip_networks:
                if ip_addr in network:
                    return True
        except ValueError:
            # host не является IP-адресом – возможно, домен, но мы уже проверили
            pass

        return False


# ---------- Модель конфигурации ----------
from dataclasses import dataclass, field


@dataclass
class ProxyConfig:
    raw: str
    protocol: str
    host: str
    port: int
    uuid: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None
    transport: str = "tcp"
    tls: str = "none"
    sni: Optional[str] = None
    path: Optional[str] = None
    latency: Optional[float] = None
    working: bool = False
    remarks: Optional[str] = None
    id: str = field(default_factory=lambda: hashlib.md5(str(random.random()).encode()).hexdigest()[:8])

    def __post_init__(self):
        if not self.remarks:
            self.remarks = f"{self.protocol.upper()}-{self.host}"

    def to_uri(self) -> str:
        return self.raw

    def format_name(self, include_latency: bool = True) -> str:
        flag = get_flag_from_host(self.host)
        proto_icon = {
            'vmess': '📦', 'vless': '🔒', 'trojan': '🐴', 'ss': '🕶️', 'hysteria2': '⚡'
        }.get(self.protocol, '🔗')
        base = f"{flag} {self.host} | {proto_icon} {self.protocol.upper()}"
        if include_latency and self.latency is not None:
            base += f" | {self.latency:.0f}ms"
        return base


# ---------- Чекер через Xray ----------
class XrayChecker:
    def __init__(self, max_concurrent: int = 20, timeout: int = 8):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.xray_path = None
        self._ensure_xray()

    def _ensure_xray(self):
        system = sys.platform
        xray_bin = 'xray'
        if system == 'win32':
            xray_bin += '.exe'
        if Path(xray_bin).exists():
            self.xray_path = str(Path(xray_bin).absolute())
            logger.info(f"✅ Найден Xray: {self.xray_path}")
            return
        logger.info("📥 Xray не найден, скачиваем...")
        import urllib.request
        import zipfile
        platform_key = 'windows' if system == 'win32' else ('darwin' if system == 'darwin' else 'linux')
        url = XRAY_DOWNLOAD_URLS.get(platform_key)
        if not url:
            raise RuntimeError(f"Нет URL для платформы {platform_key}")
        zip_path = 'xray.zip'
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                if member.endswith(xray_bin):
                    source = zf.open(member)
                    with open(xray_bin, 'wb') as f:
                        f.write(source.read())
                    os.chmod(xray_bin, 0o755)
                    break
        Path(zip_path).unlink()
        self.xray_path = str(Path(xray_bin).absolute())
        logger.info(f"✅ Xray установлен: {self.xray_path}")

    def _parse_uri(self, uri: str) -> Optional[ProxyConfig]:
        try:
            proto = uri.split('://')[0].lower()
            if proto not in SUPPORTED_PROTOCOLS:
                return None
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                return None
            cfg = ProxyConfig(raw=uri, protocol=proto, host=host, port=port)
            if proto == 'vmess':
                b64 = uri[8:]
                padding = 4 - (len(b64) % 4)
                if padding != 4:
                    b64 += '=' * padding
                data = json.loads(base64.b64decode(b64).decode('utf-8'))
                cfg.uuid = data.get('id')
                cfg.transport = data.get('net', 'tcp')
                cfg.tls = 'tls' if data.get('tls') else 'none'
                cfg.sni = data.get('sni') or data.get('host')
                cfg.path = data.get('path')
                cfg.remarks = data.get('ps', '')
            elif proto == 'vless':
                cfg.uuid = parsed.username
                params = parse_qs(parsed.query)
                cfg.transport = params.get('type', ['tcp'])[0]
                cfg.tls = params.get('security', ['none'])[0]
                cfg.sni = params.get('sni', [None])[0]
                cfg.path = params.get('path', [None])[0]
            elif proto == 'trojan':
                cfg.password = parsed.username
                params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]
                cfg.tls = 'tls'
            elif proto == 'ss':
                userinfo = parsed.username
                if userinfo:
                    decoded = base64.b64decode(userinfo).decode('utf-8')
                    cfg.method, cfg.password = decoded.split(':', 1)
            return cfg
        except Exception:
            return None

    def _build_xray_config(self, cfg: ProxyConfig, port: int) -> Dict:
        outbound = {
            "protocol": cfg.protocol,
            "settings": {},
            "streamSettings": {
                "network": cfg.transport,
                "security": cfg.tls
            }
        }
        if cfg.sni:
            outbound["streamSettings"]["sni"] = cfg.sni
        if cfg.transport == "ws" and cfg.path:
            outbound["streamSettings"]["wsSettings"] = {"path": cfg.path}

        if cfg.protocol == "vmess":
            outbound["settings"]["vnext"] = [{
                "address": cfg.host,
                "port": cfg.port,
                "users": [{"id": cfg.uuid, "alterId": 0}]
            }]
        elif cfg.protocol == "vless":
            outbound["settings"]["vnext"] = [{
                "address": cfg.host,
                "port": cfg.port,
                "users": [{"id": cfg.uuid, "encryption": "none"}]
            }]
        elif cfg.protocol == "trojan":
            outbound["settings"]["servers"] = [{
                "address": cfg.host,
                "port": cfg.port,
                "password": cfg.password
            }]
        elif cfg.protocol == "ss":
            outbound["settings"]["servers"] = [{
                "address": cfg.host,
                "port": cfg.port,
                "method": cfg.method,
                "password": cfg.password
            }]

        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks"
            }],
            "outbounds": [outbound]
        }

    @staticmethod
    def _find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def test_config(self, cfg: ProxyConfig) -> Tuple[bool, float]:
        port = self._find_free_port()
        xray_config = self._build_xray_config(cfg, port)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(xray_config, f)
            config_path = f.name

        process = None
        try:
            process = subprocess.Popen(
                [self.xray_path, 'run', '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(1.5)

            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'socks5://127.0.0.1:{port}',
                'https': f'socks5://127.0.0.1:{port}'
            })
            opener = urllib.request.build_opener(proxy_handler)
            start = time.time()
            req = urllib.request.Request(
                'http://cp.cloudflare.com/',
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with opener.open(req, timeout=self.timeout) as resp:
                if resp.status in (200, 204):
                    return True, (time.time() - start) * 1000
            return False, 0.0
        except Exception:
            return False, 0.0
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            try:
                Path(config_path).unlink()
            except Exception:
                pass

    async def check_batch(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_one(cfg: ProxyConfig):
            async with semaphore:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    success, latency = await loop.run_in_executor(executor, self.test_config, cfg)
                if success:
                    cfg.working = True
                    cfg.latency = latency
                return cfg

        tasks = [check_one(cfg) for cfg in configs]
        return await asyncio.gather(*tasks)


# ---------- Парсер подписок ----------
class SubscriptionParser:
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.checker = XrayChecker()
        self.russian_filter = RussianFilter()

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_content(self, url: str) -> Optional[str]:
        try:
            async with self.semaphore:
                async with self.session.get(url) as response:
                    response.raise_for_status()
                    return await response.text()
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")
            return None

    def decode_subscription(self, content: str) -> List[str]:
        if content.strip().startswith(('proxies:', 'Proxy:')):
            try:
                data = yaml.safe_load(content)
                proxies = data.get('proxies', [])
                links = []
                for p in proxies:
                    if p.get('type') == 'vmess':
                        b64 = base64.b64encode(json.dumps({
                            "v": "2",
                            "ps": p.get('name', ''),
                            "add": p['server'],
                            "port": str(p['port']),
                            "id": p['uuid'],
                            "aid": 0,
                            "net": p.get('network', 'tcp')
                        }).encode()).decode()
                        links.append(f"vmess://{b64}")
                    elif p.get('type') == 'ss':
                        userinfo = base64.b64encode(
                            f"{p['cipher']}:{p['password']}".encode()
                        ).decode().rstrip('=')
                        links.append(f"ss://{userinfo}@{p['server']}:{p['port']}#{p.get('name', '')}")
                return links
            except Exception:
                pass
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            if any(p in decoded for p in SUPPORTED_PROTOCOLS):
                return decoded.splitlines()
        except Exception:
            pass
        return content.splitlines()

    def extract_links(self, text: str) -> List[str]:
        return PROXY_LINK_PATTERN.findall(text)

    async def parse_subscription(self, url: str) -> List[ProxyConfig]:
        content = await self.fetch_content(url)
        if not content:
            return []
        configs = []
        for line in self.decode_subscription(content):
            for link in self.extract_links(line):
                cfg = self.checker._parse_uri(link)
                if cfg:
                    configs.append(cfg)
        logger.info(f"Из {url} извлечено {len(configs)} конфигураций")
        return configs

    async def collect_all(self, sources: List[str]) -> List[ProxyConfig]:
        tasks = [self.parse_subscription(url) for url in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_configs = []
        for result in results:
            if isinstance(result, list):
                all_configs.extend(result)

        # Дедупликация
        seen = set()
        unique = []
        for cfg in all_configs:
            key = f"{cfg.host}:{cfg.port}:{cfg.uuid or cfg.password}"
            if key not in seen:
                seen.add(key)
                unique.append(cfg)

        # Фильтрация РФ
        filtered = []
        for cfg in unique:
            if self.russian_filter.is_russian(cfg.host):
                logger.debug(f"🇷🇺 Отфильтрован российский хост: {cfg.host}")
                continue
            filtered.append(cfg)

        logger.info(f"Всего собрано {len(unique)} уникальных конфигураций, после фильтра РФ: {len(filtered)}")
        return filtered


# ---------- Сохранение подписок ----------
def save_subscriptions(configs: List[ProxyConfig], output_dir: str = "."):
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)

    working = [c for c in configs if c.working]
    working.sort(key=lambda x: x.latency if x.latency else 999999)

    logger.info(f"Рабочих конфигураций: {len(working)} из {len(configs)}")

    # Android: все рабочие
    android_file = out_path / "sub_android.txt"
    with open(android_file, "w", encoding="utf-8") as f:
        for cfg in working:
            name = cfg.format_name(include_latency=True)
            uri = cfg.to_uri()
            if '#' in uri:
                uri = uri.split('#')[0]
            f.write(f"{uri}#{name}\n")
    logger.info(f"💾 Android подписка: {android_file} ({len(working)} конфигураций)")

    # iOS: топ-100 быстрых (пинг < 300 мс)
    ios_candidates = [c for c in working if c.latency and c.latency < 300]
    ios_candidates.sort(key=lambda x: x.latency)
    ios_top = ios_candidates[:100]
    ios_file = out_path / "sub_ios.txt"
    with open(ios_file, "w", encoding="utf-8") as f:
        for cfg in ios_top:
            name = cfg.format_name(include_latency=True)
            uri = cfg.to_uri()
            if '#' in uri:
                uri = uri.split('#')[0]
            f.write(f"{uri}#{name}\n")
    logger.info(f"💾 iOS подписка: {ios_file} ({len(ios_top)} конфигураций, пинг < 300мс)")

    # Все проверенные
    all_checked = out_path / "sub_all_checked.txt"
    with open(all_checked, "w", encoding="utf-8") as f:
        for cfg in working:
            uri = cfg.to_uri()
            if '#' in uri:
                uri = uri.split('#')[0]
            f.write(f"{uri}#{cfg.format_name(include_latency=True)}\n")
    logger.info(f"💾 Общая подписка: {all_checked}")

    # По протоколам
    for proto in SUPPORTED_PROTOCOLS:
        proto_configs = [c for c in working if c.protocol == proto]
        if proto_configs:
            proto_file = out_path / f"sub_{proto}.txt"
            with open(proto_file, "w", encoding="utf-8") as f:
                for cfg in proto_configs:
                    uri = cfg.to_uri()
                    if '#' in uri:
                        uri = uri.split('#')[0]
                    f.write(f"{uri}#{cfg.format_name(include_latency=True)}\n")
            logger.info(f"💾 {proto.upper()} подписка: {proto_file} ({len(proto_configs)} конфигураций)")


# ---------- Точка входа ----------
async def main():
    sources = load_sources()
    logger.info(f"🚀 Начинаем сбор с {len(sources)} источников...")

    async with SubscriptionParser(timeout=60, max_concurrent=5) as parser:
        logger.info("📥 Сбор конфигураций...")
        configs = await parser.collect_all(sources)

        logger.info(f"🔍 Проверка {len(configs)} конфигураций...")
        configs = await parser.checker.check_batch(configs)

        working = [c for c in configs if c.working]
        logger.info(f"✅ Проверка завершена. Рабочих: {len(working)} из {len(configs)}")

        save_subscriptions(configs)


if __name__ == "__main__":
    asyncio.run(main())
