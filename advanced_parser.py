#!/usr/bin/env python3
"""
Универсальный асинхронный парсер подписок с четырёхуровневой проверкой (TCP + TLS + Xray),
без фильтрации по РФ (отключено). Генерация подписок для Android и iOS.

Использование:
    python advanced_parser.py [--threads M] [--strategy {diverse,fastest,random}]
                             [--full-check N] [--test-url URL]
                             [--full-check-retries R]
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, unquote

import aiohttp
import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(
    r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s#]+',
    re.IGNORECASE
)

XRAY_DOWNLOAD_URLS = {
    'linux': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip',
    'darwin': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-64.zip',
    'windows': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip',
}

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

TLD_TO_CODE = {tld: tld.upper() for tld in TLD_FLAGS}

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_links.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/yebekhe/TVIP/main/all",
    "https://raw.githubusercontent.com/LalatinaHub/Mineralhe/main/all.txt",
    "https://raw.githubusercontent.com/Lonelystar/v2ray-configs/main/all.txt",
    "https://raw.githubusercontent.com/SamanGoli66/v2ray-configs/main/v2ray-clients",
    "https://raw.githubusercontent.com/Pawel-S-K/free-v2ray-config/main/sub",
    "https://raw.githubusercontent.com/Emsis/v2ray-configs/main/configs.txt",
    "https://raw.githubusercontent.com/Bypass-LAN/V2ray/main/Sub.txt",
]


# ---------- Управление источниками ----------
class SourceManager:
    def __init__(self, sources_file="sources.txt", failed_file="failed_sources.txt"):
        self.sources_file = sources_file
        self.failed_file = failed_file

    def load_sources(self) -> List[str]:
        try:
            with open(self.sources_file, 'r', encoding='utf-8') as f:
                all_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.warning(f"Файл {self.sources_file} не найден, создаю пример")
            all_sources = DEFAULT_SOURCES
            with open(self.sources_file, 'w', encoding='utf-8') as f:
                f.write("# Список источников подписок\n")
                for url in all_sources:
                    f.write(f"{url}\n")

        failed = set()
        if Path(self.failed_file).exists():
            with open(self.failed_file, 'r', encoding='utf-8') as f:
                failed = {line.strip() for line in f if line.strip()}

        active = [url for url in all_sources if url not in failed]
        logger.info(f"Активных источников: {len(active)} (пропущено проблемных: {len(failed)})")
        return active

    def mark_failed(self, url: str):
        try:
            with open(self.failed_file, 'a', encoding='utf-8') as f:
                f.write(f"{url}\n")
            logger.warning(f"Источник {url} добавлен в список проблемных")
        except Exception as e:
            logger.error(f"Не удалось записать {self.failed_file}: {e}")


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
        parts = self.host.split('.')
        tld = parts[-1].lower() if len(parts) >= 2 else ''
        flag = TLD_FLAGS.get(tld, '🏳️')
        country_code = TLD_TO_CODE.get(tld, '??')
        icon = {'vmess': '📦', 'vless': '🔒', 'trojan': '🐴', 'ss': '🕶️', 'hysteria2': '⚡'}.get(self.protocol, '🔗')
        base = f"{flag} {country_code} | {icon} {self.protocol.upper()}"
        if include_latency and self.latency is not None:
            base += f" | {self.latency:.0f}ms"
        return base


# ---------- Умный отбор конфигураций ----------
class ConfigSelector:
    @staticmethod
    def select(configs: List[ProxyConfig], max_count: int, strategy: str = "diverse") -> List[ProxyConfig]:
        if len(configs) <= max_count:
            return configs

        if strategy == "fastest":
            def score(cfg: ProxyConfig) -> int:
                proto_score = {'vless': 100, 'trojan': 90, 'vmess': 70, 'ss': 50}.get(cfg.protocol, 0)
                port_score = 50 if cfg.port in (443, 8443) else (30 if cfg.port == 80 else 0)
                tls_score = 30 if cfg.tls != 'none' else 0
                return proto_score + port_score + tls_score
            sorted_configs = sorted(configs, key=score, reverse=True)
            return sorted_configs[:max_count]

        elif strategy == "diverse":
            seen_hosts = set()
            selected = []
            for proto in SUPPORTED_PROTOCOLS:
                for cfg in configs:
                    if cfg.protocol != proto:
                        continue
                    key = f"{cfg.host}:{cfg.port}"
                    if key not in seen_hosts:
                        seen_hosts.add(key)
                        selected.append(cfg)
                        if len(selected) >= max_count:
                            return selected[:max_count]
            remaining = [c for c in configs if c not in selected]
            random.shuffle(remaining)
            selected.extend(remaining[:max_count - len(selected)])
            return selected

        else:
            shuffled = configs.copy()
            random.shuffle(shuffled)
            return shuffled[:max_count]


# ---------- Чекер (TCP + TLS + Xray с повторами) ----------
class ProxyChecker:
    def __init__(self, max_concurrent: int = 20, timeout: int = 5,
                 full_check_count: int = 500, test_url: str = "http://www.gstatic.com/generate_204",
                 full_check_retries: int = 1):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.full_check_count = full_check_count
        self.test_url = test_url
        self.full_check_retries = full_check_retries
        self.xray_path = None
        self.xray_ready = False

    def _ensure_xray(self):
        if self.xray_ready:
            return
        system = sys.platform
        xray_bin = 'xray' if system != 'win32' else 'xray.exe'
        if Path(xray_bin).exists():
            self.xray_path = str(Path(xray_bin).absolute())
        else:
            logger.info("📥 Скачиваем Xray для финальной проверки...")
            import urllib.request, zipfile
            key = 'windows' if system == 'win32' else ('darwin' if system == 'darwin' else 'linux')
            url = XRAY_DOWNLOAD_URLS.get(key)
            if not url:
                raise RuntimeError(f"Нет URL для {key}")
            zip_path = 'xray.zip'
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for m in zf.namelist():
                    if m.endswith(xray_bin):
                        with open(xray_bin, 'wb') as f:
                            f.write(zf.read(m))
                        os.chmod(xray_bin, 0o755)
                        break
            Path(zip_path).unlink()
            self.xray_path = str(Path(xray_bin).absolute())
        self.xray_ready = True
        logger.info(f"✅ Xray готов: {self.xray_path}")

    def _tcp_check(self, host: str, port: int, timeout: float = 3.0) -> Tuple[bool, float]:
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            latency = (time.time() - start) * 1000
            return result == 0, latency
        except Exception:
            return False, 0.0

    def _tls_check(self, host: str, port: int, sni: Optional[str] = None, timeout: float = 4.0) -> bool:
        if port not in (443, 8443, 2053, 2083, 2087, 2096, 8443):
            return True
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                    return True
        except Exception:
            return False

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
                b64 += '=' * ((4 - len(b64) % 4) % 4)
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
            elif proto == 'hysteria2':
                cfg.password = parsed.username
                params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]
                cfg.tls = 'tls'
                cfg.transport = 'udp'
            elif proto == 'tuic':
                parts = parsed.username.split(':') if parsed.username else []
                if len(parts) >= 2:
                    cfg.uuid = parts[0]
                    cfg.password = parts[1]
                params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]
                cfg.tls = 'tls'
                cfg.transport = 'udp'
            return cfg
        except Exception:
            return None

    def _build_xray_config(self, cfg: ProxyConfig, port: int) -> Dict:
        outbound = {
            "protocol": cfg.protocol,
            "settings": {},
            "streamSettings": {
                "network": cfg.transport,
                "security": cfg.tls if cfg.tls != "none" else None
            }
        }
        if outbound["streamSettings"]["security"] is None:
            del outbound["streamSettings"]["security"]
        if cfg.sni:
            outbound["streamSettings"]["sni"] = cfg.sni
        if cfg.transport == "ws" and cfg.path:
            outbound["streamSettings"]["wsSettings"] = {"path": cfg.path}
        if cfg.protocol == "vmess":
            outbound["settings"]["vnext"] = [{"address": cfg.host, "port": cfg.port, "users": [{"id": cfg.uuid, "alterId": 0}]}]
        elif cfg.protocol == "vless":
            outbound["settings"]["vnext"] = [{"address": cfg.host, "port": cfg.port, "users": [{"id": cfg.uuid, "encryption": "none"}]}]
        elif cfg.protocol == "trojan":
            outbound["settings"]["servers"] = [{"address": cfg.host, "port": cfg.port, "password": cfg.password}]
        elif cfg.protocol == "ss":
            outbound["settings"]["servers"] = [{"address": cfg.host, "port": cfg.port, "method": cfg.method, "password": cfg.password}]
        elif cfg.protocol == "hysteria2":
            outbound["settings"]["servers"] = [{"address": cfg.host, "port": cfg.port, "password": cfg.password}]
        elif cfg.protocol == "tuic":
            outbound["settings"]["servers"] = [{"address": cfg.host, "port": cfg.port, "uuid": cfg.uuid, "password": cfg.password}]
        return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks"}], "outbounds": [outbound]}

    def _find_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _xray_test(self, cfg: ProxyConfig) -> Tuple[bool, float]:
        port = self._find_free_port()
        xray_config = self._build_xray_config(cfg, port)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(xray_config, f)
            config_path = f.name
        process = None
        try:
            process = subprocess.Popen(
                [self.xray_path, 'run', '-c', config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(3.0)  # немного увеличено
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'socks5://127.0.0.1:{port}',
                'https': f'socks5://127.0.0.1:{port}'
            })
            opener = urllib.request.build_opener(proxy_handler)
            start = time.time()
            req = urllib.request.Request(self.test_url, headers={'User-Agent': 'Mozilla/5.0'})
            with opener.open(req, timeout=8) as resp:
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

    def _xray_test_with_retries(self, cfg: ProxyConfig) -> bool:
        if not self.xray_ready:
            self._ensure_xray()
        for attempt in range(self.full_check_retries + 1):
            ok, _ = self._xray_test(cfg)
            if ok:
                return True
            if attempt < self.full_check_retries:
                time.sleep(1.5)  # задержка перед повтором
        return False

    def test_config_basic(self, cfg: ProxyConfig) -> Tuple[bool, float]:
        ok, latency = self._tcp_check(cfg.host, cfg.port)
        if not ok:
            return False, latency
        if cfg.port in (443, 8443, 2053, 2083, 2087, 2096, 8443) and cfg.tls != 'none':
            if not self._tls_check(cfg.host, cfg.port, cfg.sni, timeout=4.0):
                return False, latency
        return True, latency

    async def check_batch(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        total = len(configs)
        checked = 0
        working = []
        start_time = time.time()

        semaphore = asyncio.Semaphore(self.max_concurrent)
        lock = asyncio.Lock()
        heartbeat_task = None

        async def heartbeat():
            while True:
                await asyncio.sleep(30)
                logger.info("⏳ Проверка продолжается...")

        async def check_one(cfg: ProxyConfig):
            nonlocal checked
            async with semaphore:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    ok, latency = await loop.run_in_executor(executor, self.test_config_basic, cfg)
                if ok:
                    cfg.working = True
                    cfg.latency = latency
                async with lock:
                    checked += 1
                    if checked % 500 == 0 or checked == total:
                        elapsed = time.time() - start_time
                        rate = checked / elapsed if elapsed > 0 else 0
                        logger.info(f"📊 Прогресс: {checked}/{total} (рабочих: {len(working)}) | {rate:.1f} конф/сек")
                if ok:
                    async with lock:
                        working.append(cfg)
                return cfg

        if total > 1000:
            heartbeat_task = asyncio.create_task(heartbeat())

        tasks = [check_one(cfg) for cfg in configs]
        await asyncio.gather(*tasks)

        if heartbeat_task:
            heartbeat_task.cancel()

        elapsed = time.time() - start_time
        logger.info(f"✅ Базовая проверка завершена за {elapsed/60:.1f} мин. Рабочих: {len(working)} из {total}")

        # Этап Xray для топ-N
        if self.full_check_count > 0 and len(working) > 0:
            working.sort(key=lambda x: x.latency if x.latency else 999999)
            top_candidates = working[:self.full_check_count]
            logger.info(f"🚀 Запускаем Xray‑верификацию для топ‑{len(top_candidates)} по пингу (повторов: {self.full_check_retries})...")
            self._ensure_xray()

            xray_sem = asyncio.Semaphore(min(10, self.max_concurrent))
            xray_working = []

            async def xray_check(cfg: ProxyConfig):
                async with xray_sem:
                    loop = asyncio.get_event_loop()
                    with ThreadPoolExecutor() as executor:
                        ok = await loop.run_in_executor(executor, self._xray_test_with_retries, cfg)
                    if ok:
                        async with lock:
                            xray_working.append(cfg)
                            logger.info(f"✅ Xray‑OK: {cfg.host}:{cfg.port} ({cfg.protocol}) пинг {cfg.latency:.0f}ms")
                    else:
                        logger.debug(f"❌ Xray‑неудача: {cfg.host}:{cfg.port}")
                    return cfg

            await asyncio.gather(*[xray_check(cfg) for cfg in top_candidates])

            for cfg in top_candidates:
                if cfg not in xray_working:
                    cfg.working = False
            logger.info(f"🔬 После Xray осталось {len(xray_working)} конфигураций")

        return configs


# ---------- Парсер подписок ----------
class SubscriptionParser:
    def __init__(self, timeout: int = 30, max_concurrent: int = 10, strategy: str = "diverse",
                 full_check_count: int = 500, test_url: str = "http://www.gstatic.com/generate_204",
                 full_check_retries: int = 1):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.checker = ProxyChecker(full_check_count=full_check_count, test_url=test_url,
                                   full_check_retries=full_check_retries)
        self.source_manager = SourceManager()
        self.strategy = strategy

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        self.session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout))
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
                    t = p.get('type', '').lower()
                    if t == 'vmess':
                        b64 = base64.b64encode(json.dumps({
                            "v": "2", "ps": p.get('name', ''),
                            "add": p['server'], "port": str(p['port']),
                            "id": p['uuid'], "aid": 0, "net": p.get('network', 'tcp')
                        }).encode()).decode()
                        links.append(f"vmess://{b64}")
                    elif t == 'ss':
                        userinfo = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode().rstrip('=')
                        links.append(f"ss://{userinfo}@{p['server']}:{p['port']}#{p.get('name','')}")
                    elif t == 'trojan':
                        links.append(f"trojan://{p['password']}@{p['server']}:{p['port']}?sni={p.get('sni','')}#{p.get('name','')}")
                    elif t == 'vless':
                        links.append(f"vless://{p['uuid']}@{p['server']}:{p['port']}?security={p.get('security','none')}&type={p.get('network','tcp')}#{p.get('name','')}")
                if links:
                    return links
            except Exception:
                pass
        try:
            decoded = base64.b64decode(content, validate=True).decode('utf-8', errors='ignore')
            if any(p in decoded for p in SUPPORTED_PROTOCOLS):
                return decoded.splitlines()
        except Exception:
            pass
        return content.splitlines()

    def extract_links(self, text: str) -> List[str]:
        try:
            decoded_text = unquote(text)
        except Exception:
            decoded_text = text
        links = []
        for match in PROXY_LINK_PATTERN.finditer(decoded_text):
            link = match.group(0)
            for proto in SUPPORTED_PROTOCOLS:
                idx = link.find(f"{proto}://")
                if idx != -1:
                    link = link[idx:]
                    break
            links.append(link)
        return links

    async def parse_subscription(self, url: str) -> List[ProxyConfig]:
        content = await self.fetch_content(url)
        if not content:
            return []
        configs = []
        lines = self.decode_subscription(content)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            for link in self.extract_links(line):
                cfg = self.checker._parse_uri(link)
                if cfg:
                    configs.append(cfg)
        logger.info(f"Из {url} извлечено {len(configs)} конфигураций")
        if len(configs) == 0 and len(content) > 0:
            preview = content[:200].replace('\n', ' ').replace('\r', '')
            logger.warning(f"Не удалось извлечь конфигурации из {url}. Превью: {preview}")
            self.source_manager.mark_failed(url)
        return configs

    async def collect_all(self) -> List[ProxyConfig]:
        sources = self.source_manager.load_sources()
        tasks = [self.parse_subscription(url) for url in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_configs = []
        for url, result in zip(sources, results):
            if isinstance(result, Exception):
                logger.error(f"Ошибка обработки {url}: {result}")
            elif isinstance(result, list):
                all_configs.extend(result)

        seen = set()
        unique = []
        for cfg in all_configs:
            key = f"{cfg.host}:{cfg.port}:{cfg.uuid or cfg.password or cfg.method}"
            if key not in seen:
                seen.add(key)
                unique.append(cfg)

        logger.info(f"Всего собрано {len(unique)} уникальных конфигураций")
        return unique


# ---------- Сохранение ----------
def save_subscriptions(configs: List[ProxyConfig], output_dir: str = "."):
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)

    working = [c for c in configs if c.working]
    working.sort(key=lambda x: x.latency if x.latency else 999999)

    logger.info(f"Рабочих: {len(working)}")

    HEADER = "# Niyakwi | обновление каждые 6 часов\n"

    if not working:
        logger.warning("Нет рабочих конфигураций. Выходные файлы будут пустыми.")
    else:
        # Android
        with open(out_path / "sub_android.txt", "w", encoding='utf-8') as f:
            f.write(HEADER)
            for c in working:
                f.write(f"{c.to_uri().split('#')[0]}#{c.format_name()}\n")
        # iOS: топ-100 с наименьшим пингом
        ios_candidates = sorted(working, key=lambda x: x.latency if x.latency else 999999)
        with open(out_path / "sub_ios.txt", "w", encoding='utf-8') as f:
            f.write(HEADER)
            for c in ios_candidates[:100]:
                f.write(f"{c.to_uri().split('#')[0]}#{c.format_name()}\n")
        # Все проверенные
        with open(out_path / "sub_all_checked.txt", "w", encoding='utf-8') as f:
            f.write(HEADER)
            for c in working:
                f.write(f"{c.to_uri().split('#')[0]}#{c.format_name()}\n")
        # По протоколам
        for proto in SUPPORTED_PROTOCOLS:
            proto_list = [c for c in working if c.protocol == proto]
            if proto_list:
                with open(out_path / f"sub_{proto}.txt", "w", encoding='utf-8') as f:
                    f.write(HEADER)
                    for c in proto_list:
                        f.write(f"{c.to_uri().split('#')[0]}#{c.format_name()}\n")

    # Ссылки для импорта
    repo_user = "Darkoflox"
    repo_name = "Kfg-analizator"
    branch = "main"
    base = f"https://raw.githubusercontent.com/{repo_user}/{repo_name}/{branch}"
    cdn_statically = f"https://cdn.statically.io/gh/{repo_user}/{repo_name}/{branch}"
    cdn_jsdelivr = f"https://cdn.jsdelivr.net/gh/{repo_user}/{repo_name}@{branch}"

    sub_files = ["sub_android.txt", "sub_ios.txt", "sub_all_checked.txt"] + \
                [f"sub_{proto}.txt" for proto in SUPPORTED_PROTOCOLS if (out_path / f"sub_{proto}.txt").exists()]

    with open(out_path / "subscription_urls.txt", "w", encoding='utf-8') as f:
        f.write("# Прямые ссылки (основные)\n")
        for sf in sub_files:
            f.write(f"{base}/{sf}\n")
        f.write("\n# Обходные ссылки (для регионов с блокировкой raw.githubusercontent.com)\n")
        for sf in sub_files:
            f.write(f"# {sf}\n")
            f.write(f"{cdn_statically}/{sf}\n")
            f.write(f"{cdn_jsdelivr}/{sf}\n")
    logger.info(f"🔗 Файл со ссылками: {out_path / 'subscription_urls.txt'}")


async def main():
    parser_arg = ArgumentParser()
    parser_arg.add_argument('--threads', type=int, default=40, help='Число потоков проверки')
    parser_arg.add_argument('--strategy', choices=['diverse', 'fastest', 'random'], default='diverse')
    parser_arg.add_argument('--full-check', type=int, default=500,
                            help='Количество топ-кандидатов для Xray-верификации (0 - отключить)')
    parser_arg.add_argument('--test-url', default='http://www.gstatic.com/generate_204', help='URL для Xray-проверки')
    parser_arg.add_argument('--full-check-retries', type=int, default=1,
                            help='Количество повторных попыток для Xray-теста')
    args = parser_arg.parse_args()

    async with SubscriptionParser(timeout=60, max_concurrent=5, strategy=args.strategy,
                                 full_check_count=args.full_check, test_url=args.test_url,
                                 full_check_retries=args.full_check_retries) as parser:
        parser.checker.max_concurrent = args.threads

        configs = await parser.collect_all()
        if configs:
            configs = await parser.checker.check_batch(configs)
        save_subscriptions(configs)


if __name__ == "__main__":
    asyncio.run(main())
