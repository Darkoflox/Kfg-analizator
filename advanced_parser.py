#!/usr/bin/env python3
"""
Финальный парсер «БС» с качественной Xray-проверкой.
Оптимизирован для работы за 40-55 минут (80 потоков).
Дедупликация, надёжное GeoIP, приоритет протоколов.
"""

import asyncio, base64, hashlib, json, logging, os, random, re, socket, ssl, subprocess, tempfile, time
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, unquote
import aiohttp, yaml

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s#]+', re.IGNORECASE)

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
    'net': '🌐', 'org': '🌐', 'com': '🌐', 'xyz': '🌐', 'info': '🌐', 'online': '🌐',
    'club': '🌐', 'site': '🌐', 'tech': '🌐', 'dev': '🌐', 'cloud': '🌐', 'blog': '🌐',
    'shop': '🌐', 'store': '🌐', 'pro': '🌐', 'top': '🌐', 'ltd': '🌐', 'biz': '🌐',
}

TLD_TO_CODE = {tld: tld.upper() for tld in TLD_FLAGS}

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
    "https://alley.serv00.net/youtube",
    "https://alley.serv00.net/other",
]

TG_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
]
TG_REQUEST_DELAY = 2.0
TG_MIRRORS = [
    "https://tg.i-c-a.su/s/{}",
    "https://tlgrm.ru/s/{}",
    "https://tg.snowfall.ru/s/{}",
    "https://t.me/s/{}"
]

HEADER = "# profile-title: Niyakwi⚪ | БС | обновление каждые 6 часов\n# profile-update-interval: 6\n"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
IP_SERVICES = ["http://icanhazip.com", "http://ipinfo.io/ip", "http://ifconfig.me"]
GEOIP_DB_URLS = [
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb",
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
    "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb/GeoLite2-Country.mmdb",
]

# ---------- GeoIP ----------
_geoip_reader = None
_geoip_lock = asyncio.Lock()

async def get_geoip_reader():
    global _geoip_reader
    if not GEOIP_AVAILABLE:
        return None
    if _geoip_reader is not None:
        return _geoip_reader
    async with _geoip_lock:
        if _geoip_reader is not None:
            return _geoip_reader
        db_path = Path("GeoLite2-Country.mmdb")
        if db_path.exists():
            try:
                _geoip_reader = geoip2.database.Reader(str(db_path))
                return _geoip_reader
            except Exception:
                pass
        for url in GEOIP_DB_URLS:
            try:
                logger.info(f"📥 Скачиваем GeoIP базу с {url}...")
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: __import__('urllib.request').request.urlretrieve(url, db_path))
                _geoip_reader = geoip2.database.Reader(str(db_path))
                return _geoip_reader
            except Exception:
                continue
        logger.error("Не удалось загрузить GeoIP базу")
        return None

_country_cache: Dict[str, Optional[str]] = {}

async def get_country(ip: str) -> Optional[str]:
    if not ip:
        return None
    if ip in _country_cache:
        return _country_cache[ip]
    reader = await get_geoip_reader()
    if not reader:
        _country_cache[ip] = None
        return None
    try:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, reader.country, ip)
        code = response.country.iso_code
        _country_cache[ip] = code
        return code
    except Exception:
        _country_cache[ip] = None
        return None

# ---------- Xray ----------
def ensure_xray() -> str:
    xray_bin = "xray"
    if Path(xray_bin).exists():
        return str(Path(xray_bin).absolute())
    logger.info("📥 Скачиваем Xray...")
    import urllib.request, zipfile
    urllib.request.urlretrieve(XRAY_URL, "xray.zip")
    with zipfile.ZipFile("xray.zip", "r") as zf:
        for m in zf.namelist():
            if m.endswith("xray"):
                zf.extract(m)
                os.chmod("xray", 0o755)
                break
    Path("xray.zip").unlink()
    return str(Path("xray").absolute())

def build_xray_config(cfg: dict, socks_port: int) -> dict:
    outbound = {
        "protocol": cfg["protocol"],
        "settings": {},
        "streamSettings": {
            "network": cfg.get("transport", "tcp"),
            "security": cfg.get("tls", "none") if cfg.get("tls") != "none" else None,
        },
    }
    if outbound["streamSettings"]["security"] is None:
        del outbound["streamSettings"]["security"]
    if cfg.get("sni"):
        outbound["streamSettings"]["sni"] = cfg["sni"]
    if cfg.get("transport") == "ws" and cfg.get("path"):
        outbound["streamSettings"]["wsSettings"] = {"path": cfg["path"]}
    if cfg["protocol"] == "vmess":
        outbound["settings"]["vnext"] = [{"address": cfg["host"], "port": cfg["port"], "users": [{"id": cfg.get("uuid", ""), "alterId": 0}]}]
    elif cfg["protocol"] == "vless":
        outbound["settings"]["vnext"] = [{"address": cfg["host"], "port": cfg["port"], "users": [{"id": cfg.get("uuid", ""), "encryption": "none"}]}]
    elif cfg["protocol"] == "trojan":
        outbound["settings"]["servers"] = [{"address": cfg["host"], "port": cfg["port"], "password": cfg.get("password", "")}]
    elif cfg["protocol"] == "ss":
        outbound["settings"]["servers"] = [{"address": cfg["host"], "port": cfg["port"], "method": cfg.get("method", ""), "password": cfg.get("password", "")}]
    return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}], "outbounds": [outbound]}

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

async def _wait_for_socks(port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass
        await asyncio.sleep(0.3)
    return False

async def proxy_test(cfg: dict, xray_path: str) -> Tuple[bool, Optional[str]]:
    socks_port = _find_free_port()
    config = build_xray_config(cfg, socks_port)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    proc = None
    try:
        proc = subprocess.Popen([xray_path, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not await _wait_for_socks(socks_port, timeout=3.0):
            return False, None
        for service_url in IP_SERVICES:
            try:
                curl_cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{socks_port}", "--max-time", "5", service_url]
                result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=8)
                ip = result.stdout.strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    return True, ip
            except Exception:
                continue
        return False, None
    except Exception:
        return False, None
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except: proc.kill()
        try: Path(config_path).unlink()
        except: pass

# ---------- Модель ----------
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
    resolved_ip: Optional[str] = None
    country_code: Optional[str] = None
    remarks: Optional[str] = None
    id: str = field(default_factory=lambda: hashlib.md5(str(random.random()).encode()).hexdigest()[:8])

    def __post_init__(self):
        if not self.remarks:
            self.remarks = f"{self.protocol.upper()}-{self.host}"

    def to_uri(self) -> str:
        return self.raw

    async def format_name_async(self) -> str:
        if self.country_code is None and self.resolved_ip:
            self.country_code = await get_country(self.resolved_ip)
        if self.country_code:
            flag = TLD_FLAGS.get(self.country_code.lower(), '🏳️')
            return f"{flag} {self.country_code.upper()}"
        parts = self.host.split('.')
        tld = parts[-1].lower() if len(parts) >= 2 else ''
        code = TLD_TO_CODE.get(tld)
        if code:
            flag = TLD_FLAGS.get(tld, '🏳️')
            return f"{flag} {code}"
        return "🏳️ ??"

PROTO_PRIORITY = {
    'vless': 100, 'vmess': 90, 'trojan': 80,
    'hysteria2': 70, 'tuic': 60, 'ss': 50, 'ssr': 40,
}

def protocol_sort_key(cfg):
    priority = PROTO_PRIORITY.get(cfg.protocol, 0)
    latency = cfg.latency if cfg.latency else 999999
    return (-priority, latency)

# ---------- Чекер ----------
class ProxyChecker:
    def __init__(self, max_concurrent: int = 20, xray_max_concurrent: int = 80):
        self.max_concurrent = max_concurrent
        self.xray_max_concurrent = xray_max_concurrent
        self.xray_path = ensure_xray()

    def _parse_uri(self, uri: str) -> Optional[ProxyConfig]:
        try:
            proto = uri.split('://')[0].lower()
            if proto not in SUPPORTED_
