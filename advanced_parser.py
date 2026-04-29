#!/usr/bin/env python3
"""
Финальный парсер «БС» с максимальным охватом рабочих конфигураций.
Проверка: Xray (vless/vmess/trojan/ss) + hysteria2 + tuic-client.
Оптимизирован для скорости: асинхронное ожидание SOCKS, уменьшенные таймауты, быстрые IP‑сервисы.
Масштабируемый сбор, надёжное GeoIP, приоритет протоколов.
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
HYSTERIA2_URL = "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64"
TUIC_CLIENT_URL = "https://github.com/EAimTY/tuic/releases/latest/download/tuic-client-linux-amd64"

# Порядок сервисов: самый быстрый первым
IP_SERVICES = [
    "http://icanhazip.com",
    "http://ipinfo.io/ip",
    "http://ifconfig.me",
]
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

# ---------- Инструменты ----------
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

def ensure_hysteria2() -> Optional[str]:
    bin_name = "hysteria2"
    if Path(bin_name).exists():
        return str(Path(bin_name).absolute())
    logger.info("📥 Скачиваем Hysteria2...")
    try:
        import urllib.request
        urllib.request.urlretrieve(HYSTERIA2_URL, bin_name)
        os.chmod(bin_name, 0o755)
        return str(Path(bin_name).absolute())
    except Exception as e:
        logger.error(f"Не удалось загрузить Hysteria2: {e}")
        return None

def ensure_tuic_client() -> Optional[str]:
    bin_name = "tuic-client"
    if Path(bin_name).exists():
        return str(Path(bin_name).absolute())
    logger.info("📥 Скачиваем TUIC-клиент...")
    try:
        import urllib.request
        urllib.request.urlretrieve(TUIC_CLIENT_URL, bin_name)
        os.chmod(bin_name, 0o755)
        return str(Path(bin_name).absolute())
    except Exception as e:
        logger.error(f"Не удалось загрузить TUIC-клиент: {e}")
        return None

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

def build_hysteria2_config(cfg: dict, socks_port: int) -> dict:
    return {
        "server": f"{cfg['host']}:{cfg['port']}",
        "auth": cfg.get("password", ""),
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
        "tls": {
            "sni": cfg.get("sni", cfg["host"]),
            "insecure": True
        }
    }

def build_tuic_config(cfg: dict, socks_port: int) -> dict:
    return {
        "server": f"{cfg['host']}:{cfg['port']}",
        "uuid": cfg.get("uuid", ""),
        "password": cfg.get("password", ""),
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
        "tls": {
            "sni": cfg.get("sni", cfg["host"]),
            "insecure": True
        }
    }

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

async def _wait_for_socks(port: int, timeout: float = 3.0) -> bool:
    """Ожидание открытия SOCKS-порта."""
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

async def proxy_test(cfg: dict, runner_path: str, runner_type: str) -> Tuple[bool, Optional[str]]:
    socks_port = _find_free_port()
    if runner_type == "xray":
        config = build_xray_config(cfg, socks_port)
    elif runner_type == "hysteria2":
        config = build_hysteria2_config(cfg, socks_port)
    elif runner_type == "tuic":
        config = build_tuic_config(cfg, socks_port)
    else:
        return False, None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    proc = None
    try:
        cmd = [runner_path, "run", "-c", config_path] if runner_type == "xray" else [runner_path, "-c", config_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Ожидаем открытия порта вместо фиксированной задержки
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
    def __init__(self, max_concurrent: int = 20, xray_max_concurrent: int = 30):
        self.max_concurrent = max_concurrent
        self.xray_max_concurrent = xray_max_concurrent
        self.xray_path = ensure_xray()
        self.hysteria2_path = ensure_hysteria2()
        self.tuic_client_path = ensure_tuic_client()

    def _parse_uri(self, uri: str) -> Optional[ProxyConfig]:
        try:
            proto = uri.split('://')[0].lower()
            if proto not in SUPPORTED_PROTOCOLS:
                return None
            parsed = urlparse(uri)
            host, port = parsed.hostname, parsed.port
            if not host or not port:
                return None
            cfg = ProxyConfig(raw=uri, protocol=proto, host=host, port=port)
            if proto == 'vmess':
                b64 = uri[8:] + '=' * ((4 - len(uri[8:]) % 4) % 4)
                data = json.loads(base64.b64decode(b64).decode('utf-8'))
                cfg.uuid = data.get('id'); cfg.transport = data.get('net', 'tcp')
                cfg.tls = 'tls' if data.get('tls') else 'none'
                cfg.sni = data.get('sni') or data.get('host'); cfg.path = data.get('path')
            elif proto == 'vless':
                cfg.uuid = parsed.username; params = parse_qs(parsed.query)
                cfg.transport = params.get('type', ['tcp'])[0]; cfg.tls = params.get('security', ['none'])[0]
                cfg.sni = params.get('sni', [None])[0]; cfg.path = params.get('path', [None])[0]
            elif proto == 'trojan':
                cfg.password = parsed.username; params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]; cfg.tls = 'tls'
            elif proto == 'ss':
                userinfo = parsed.username
                if userinfo:
                    decoded = base64.b64decode(userinfo).decode('utf-8')
                    cfg.method, cfg.password = decoded.split(':', 1)
            elif proto == 'hysteria2':
                cfg.password = parsed.username; params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]; cfg.tls = 'tls'; cfg.transport = 'udp'
            elif proto == 'tuic':
                parts = parsed.username.split(':') if parsed.username else []
                if len(parts) >= 2: cfg.uuid, cfg.password = parts[0], parts[1]
                params = parse_qs(parsed.query)
                cfg.sni = params.get('sni', [None])[0]; cfg.tls = 'tls'; cfg.transport = 'udp'
            return cfg
        except Exception:
            return None

    def _tcp_check(self, host: str, port: int, timeout: float = 3.0) -> Tuple[bool, float]:
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True, (time.time() - start) * 1000
        except Exception:
            pass
        return False, 0.0

    def _tls_check(self, host: str, port: int, sni: Optional[str] = None, timeout: float = 4.0) -> bool:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni or host):
                    return True
        except Exception:
            return False

    def test_config_preliminary(self, cfg: ProxyConfig) -> Tuple[bool, float]:
        ok, latency = self._tcp_check(cfg.host, cfg.port)
        if not ok:
            return False, 0.0
        if cfg.tls != 'none' and not self._tls_check(cfg.host, cfg.port, cfg.sni):
            return False, latency
        return True, latency

    async def check_batch(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        total = len(configs)
        passed_prelim = []
        start = time.time()
        sem = asyncio.Semaphore(self.max_concurrent)
        lock = asyncio.Lock()
        checked = 0

        async def pre_check(cfg):
            nonlocal checked
            async with sem:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as ex:
                    ok, lat = await loop.run_in_executor(ex, self.test_config_preliminary, cfg)
                if ok:
                    cfg.latency = lat
                async with lock:
                    checked += 1
                    if checked % 500 == 0:
                        elapsed = time.time() - start
                        logger.info(f"📊 TCP+TLS: {checked}/{total} (прошло: {len(passed_prelim)}) | {checked/elapsed:.1f} конф/сек")
                if ok:
                    async with lock:
                        passed_prelim.append(cfg)
                return cfg

        heartbeat = asyncio.create_task(self._heartbeat("TCP+TLS")) if total > 1000 else None
        await asyncio.gather(*[pre_check(c) for c in configs])
        if heartbeat:
            heartbeat.cancel()
        elapsed = time.time() - start
        logger.info(f"✅ TCP+TLS завершён за {elapsed/60:.1f} мин. Прошло: {len(passed_prelim)} из {total}")

        if not passed_prelim:
            return []

        xray_list = [c for c in passed_prelim if c.protocol in ('vmess', 'vless', 'trojan', 'ss', 'ssr')]
        hysteria2_list = [c for c in passed_prelim if c.protocol == 'hysteria2']
        tuic_list = [c for c in passed_prelim if c.protocol == 'tuic']

        all_results = []

        # Xray
        if xray_list:
            xray_total = len(xray_list)
            xray_working = []
            xray_start = time.time()
            xray_sem = asyncio.Semaphore(self.xray_max_concurrent)
            xray_lock = asyncio.Lock()
            xray_checked = 0

            async def xray_check(cfg):
                nonlocal xray_checked
                async with xray_sem:
                    ok, ip = await proxy_test(vars(cfg), self.xray_path, "xray")
                    cfg.working = ok
                    if ok:
                        cfg.resolved_ip = ip
                    async with xray_lock:
                        xray_checked += 1
                        if xray_checked % 100 == 0:
                            elapsed_x = time.time() - xray_start
                            logger.info(f"📊 Xray: {xray_checked}/{xray_total} (рабочих: {len(xray_working)}) | {xray_checked/elapsed_x:.1f} конф/сек")
                    if ok:
                        async with xray_lock:
                            xray_working.append(cfg)
                    return cfg

            xray_heartbeat = asyncio.create_task(self._heartbeat("Xray")) if xray_total > 50 else None
            await asyncio.gather(*[xray_check(c) for c in xray_list])
            if xray_heartbeat:
                xray_heartbeat.cancel()
            elapsed_x = time.time() - xray_start
            logger.info(f"✅ Xray завершён за {elapsed_x/60:.1f} мин. Рабочих: {len(xray_working)} из {xray_total}")
            all_results.extend(xray_working)

        # Hysteria2
        if hysteria2_list and self.hysteria2_path:
            hyst_total = len(hysteria2_list)
            hyst_working = []
            hyst_start = time.time()
            hyst_sem = asyncio.Semaphore(min(10, self.xray_max_concurrent))  # не более 10, чтобы не перегружать
            hyst_lock = asyncio.Lock()
            hyst_checked = 0

            async def hyst_check(cfg):
                nonlocal hyst_checked
                async with hyst_sem:
                    ok, ip = await proxy_test(vars(cfg), self.hysteria2_path, "hysteria2")
                    cfg.working = ok
                    if ok:
                        cfg.resolved_ip = ip
                    async with hyst_lock:
                        hyst_checked += 1
                        if hyst_checked % 50 == 0:
                            elapsed_h = time.time() - hyst_start
                            logger.info(f"📊 Hysteria2: {hyst_checked}/{hyst_total} (рабочих: {len(hyst_working)}) | {hyst_checked/elapsed_h:.1f} конф/сек")
                    if ok:
                        async with hyst_lock:
                            hyst_working.append(cfg)
                    return cfg

            await asyncio.gather(*[hyst_check(c) for c in hysteria2_list])
            logger.info(f"✅ Hysteria2 завершён. Рабочих: {len(hyst_working)} из {hyst_total}")
            all_results.extend(hyst_working)
        elif hysteria2_list:
            logger.warning("Hysteria2-клиент недоступен – проверка пропущена.")

        # TUIC
        if tuic_list and self.tuic_client_path:
            tuic_total = len(tuic_list)
            tuic_working = []
            tuic_start = time.time()
            tuic_sem = asyncio.Semaphore(min(10, self.xray_max_concurrent))
            tuic_lock = asyncio.Lock()
            tuic_checked = 0

            async def tuic_check(cfg):
                nonlocal tuic_checked
                async with tuic_sem:
                    ok, ip = await proxy_test(vars(cfg), self.tuic_client_path, "tuic")
                    cfg.working = ok
                    if ok:
                        cfg.resolved_ip = ip
                    async with tuic_lock:
                        tuic_checked += 1
                        if tuic_checked % 50 == 0:
                            elapsed_t = time.time() - tuic_start
                            logger.info(f"📊 TUIC: {tuic_checked}/{tuic_total} (рабочих: {len(tuic_working)}) | {tuic_checked/elapsed_t:.1f} конф/сек")
                    if ok:
                        async with tuic_lock:
                            tuic_working.append(cfg)
                    return cfg

            await asyncio.gather(*[tuic_check(c) for c in tuic_list])
            logger.info(f"✅ TUIC завершён. Рабочих: {len(tuic_working)} из {tuic_total}")
            all_results.extend(tuic_working)
        elif tuic_list:
            logger.warning("TUIC-клиент недоступен – проверка пропущена.")

        return all_results

    async def _heartbeat(self, name):
        while True:
            await asyncio.sleep(30)
            logger.info(f"⏳ {name} проверка продолжается...")

# ---------- Парсер ----------
class SubscriptionParser:
    def __init__(self, timeout=30, max_concurrent=10, parse_telegram=False):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.checker = ProxyChecker()
        self.source_manager = SourceManager()
        self.parse_telegram = parse_telegram

    async def __aenter__(self):
        conn = aiohttp.TCPConnector(limit=0, ssl=False)
        self.session = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_content(self, url):
        try:
            async with self.semaphore:
                async with self.session.get(url) as resp:
                    resp.raise_for_status()
                    return await resp.text()
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")
            return None

    def decode_subscription(self, content):
        if content.strip().startswith(('proxies:', 'Proxy:')):
            try:
                data = yaml.safe_load(content)
                proxies = data.get('proxies', [])
                links = []
                for p in proxies:
                    t = p.get('type', '').lower()
                    if t == 'vmess':
                        b64 = base64.b64encode(json.dumps({"v":"2","ps":p.get('name',''),"add":p['server'],"port":str(p['port']),"id":p['uuid'],"aid":0,"net":p.get('network','tcp')}).encode()).decode()
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

    def extract_links(self, text):
        links = []
        for match in PROXY_LINK_PATTERN.finditer(text):
            link = match.group(0)
            for proto in SUPPORTED_PROTOCOLS:
                idx = link.find(f"{proto}://")
                if idx != -1:
                    link = link[idx:]
                    break
            links.append(link)
        return links

    async def parse_subscription(self, url):
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

    async def _fetch_tg_page(self, username):
        for mirror in TG_MIRRORS:
            url = mirror.format(username)
            headers = {'User-Agent': random.choice(TG_USER_AGENTS)}
            try:
                async with self.session.get(url, headers=headers, allow_redirects=True) as resp:
                    if resp.status == 200:
                        return await resp.text()
            except Exception:
                continue
        return None

    async def _parse_telegram_channels(self):
        tg_file = Path("sources_tg.txt")
        if not tg_file.exists():
            return []
        channels = []
        with open(tg_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                username = line
                if username.startswith('@'):
                    username = username[1:]
                elif 't.me/' in username:
                    parts = username.split('/')
                    if len(parts) >= 2:
                        username = parts[-1]
                channels.append(username)
        if not channels:
            return []
        logger.info(f"Начинаем сбор из {len(channels)} Telegram-каналов...")
        all_configs = []
        seen_keys = set()
        for i, channel in enumerate(channels):
            if i > 0:
                await asyncio.sleep(TG_REQUEST_DELAY + random.uniform(0.5, 1.5))
            html = await self._fetch_tg_page(channel)
            if not html:
                continue
            messages = []
            for block in re.findall(r'<div class="tgme_widget_message_text">(.*?)</div>', html, re.DOTALL):
                text = re.sub(r'<[^>]+>', '', block).strip()
                if text:
                    messages.append(text)
            if not messages:
                for block in re.findall(r'<div class="tgme_widget_message_text"[^>]*>(.*?)</div>', html, re.DOTALL):
                    text = re.sub(r'<[^>]+>', '', block).strip()
                    if text:
                        messages.append(text)
            if not messages:
                direct_links = self.extract_links(html)
                for link in direct_links:
                    cfg = self.checker._parse_uri(link)
                    if cfg:
                        key = f"{cfg.host}:{cfg.port}:{cfg.uuid or cfg.password or cfg.method}"
                        if key not in seen_keys:
                            seen_keys.add(key)
                            all_configs.append(cfg)
                continue
            channel_links = []
            for msg in messages[:20]:
                channel_links.extend(self.extract_links(msg))
            for link in channel_links:
                cfg = self.checker._parse_uri(link)
                if cfg:
                    key = f"{cfg.host}:{cfg.port}:{cfg.uuid or cfg.password or cfg.method}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        all_configs.append(cfg)
            logger.info(f"Канал {channel}: всего собрано {len(all_configs)}")
        logger.info(f"Telegram-сбор завершён: {len(all_configs)} конфигураций")
        return all_configs

    async def collect_all(self):
        sources = self.source_manager.load_sources()
        tasks = [self.parse_subscription(url) for url in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_configs = []
        for r in results:
            if isinstance(r, list):
                all_configs.extend(r)
        if self.parse_telegram:
            tg_configs = await self._parse_telegram_channels()
            all_configs.extend(tg_configs)
        seen, unique = set(), []
        for cfg in all_configs:
            key = f"{cfg.host}:{cfg.port}:{cfg.uuid or cfg.password or cfg.method}"
            if key not in seen:
                seen.add(key)
                unique.append(cfg)
        logger.info(f"Всего собрано {len(unique)} уникальных конфигураций")
        return unique

class SourceManager:
    def __init__(self, sources_file="sources.txt", failed_file="failed_sources.txt"):
        self.sources_file = sources_file
        self.failed_file = failed_file

    def load_sources(self):
        try:
            with open(self.sources_file) as f:
                all_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.warning(f"Файл {self.sources_file} не найден, использую примеры")
            all_sources = DEFAULT_SOURCES
            with open(self.sources_file, 'w') as f:
                f.write("# Список источников подписок\n")
                for url in all_sources:
                    f.write(f"{url}\n")
        failed = set()
        if Path(self.failed_file).exists():
            with open(self.failed_file) as f:
                failed = {line.strip() for line in f if line.strip()}
        active = [url for url in all_sources if url not in failed]
        logger.info(f"Активных источников: {len(active)} (пропущено проблемных: {len(failed)})")
        return active

    def mark_failed(self, url):
        try:
            with open(self.failed_file, 'a') as f:
                f.write(f"{url}\n")
        except Exception as e:
            logger.error(f"Не удалось записать {self.failed_file}: {e}")

# ---------- Сохранение ----------
async def save_subscriptions(configs, output_dir="."):
    out_path = Path(output_dir)
    out_path.mkdir(exist_ok=True)
    working = [c for c in configs if c.working]
    working.sort(key=protocol_sort_key)
    logger.info(f"Рабочих (после финальной проверки): {len(working)}")
    if not working:
        logger.warning("Нет рабочих конфигураций. Выходные файлы будут пустыми.")
        return

    # Прогрев кэша GeoIP
    for cfg in working:
        await cfg.format_name_async()

    # Android (5000)
    android_list = working[:5000]
    (out_path / "sub_android.txt").write_text(
        HEADER + "\n".join(f"{c.to_uri().split('#')[0]}#{await c.format_name_async()}" for c in android_list),
        encoding='utf-8'
    )

    # iOS (300)
    ios_list = working[:300]
    (out_path / "sub_ios.txt").write_text(
        HEADER + "\n".join(f"{c.to_uri().split('#')[0]}#{await c.format_name_async()}" for c in ios_list),
        encoding='utf-8'
    )

    # Общий файл
    (out_path / "sub_all_checked.txt").write_text(
        HEADER + "\n".join(f"{c.to_uri().split('#')[0]}#{await c.format_name_async()}" for c in working),
        encoding='utf-8'
    )

    # По протоколам
    for proto in SUPPORTED_PROTOCOLS:
        items = [c for c in working if c.protocol == proto]
        if items:
            items.sort(key=lambda x: x.latency if x.latency else 999999)
            (out_path / f"sub_{proto}.txt").write_text(
                HEADER + "\n".join(f"{c.to_uri().split('#')[0]}#{await c.format_name_async()}" for c in items[:5000]),
                encoding='utf-8'
            )

    # Ссылки
    repo_user = "Darkoflox"
    repo_name = "Kfg-analizator"
    branch = "main"
    base = f"https://raw.githubusercontent.com/{repo_user}/{repo_name}/{branch}"
    cdn_statically = f"https://cdn.statically.io/gh/{repo_user}/{repo_name}/{branch}"
    cdn_jsdelivr = f"https://cdn.jsdelivr.net/gh/{repo_user}/{repo_name}@{branch}"
    sub_files = ["sub_android.txt", "sub_ios.txt", "sub_all_checked.txt"] + \
                [f"sub_{p}.txt" for p in SUPPORTED_PROTOCOLS if (out_path / f"sub_{p}.txt").exists()]
    with open(out_path / "subscription_urls.txt", "w", encoding='utf-8') as f:
        f.write("# Прямые ссылки (основные)\n")
        for sf in sub_files:
            f.write(f"{base}/{sf}\n")
        f.write("\n# Обходные ссылки (для регионов с блокировкой raw.githubusercontent.com)\n")
        for sf in sub_files:
            f.write(f"# {sf}\n{cdn_statically}/{sf}\n{cdn_jsdelivr}/{sf}\n")
    logger.info(f"🔗 Файл со ссылками: {out_path / 'subscription_urls.txt'}")

async def main():
    parser_arg = ArgumentParser()
    parser_arg.add_argument('--threads', type=int, default=30)
    parser_arg.add_argument('--xray-threads', type=int, default=40)  # увеличено
    parser_arg.add_argument('--parse-telegram', action='store_true')
    args = parser_arg.parse_args()

    async with SubscriptionParser(timeout=60, max_concurrent=5, parse_telegram=args.parse_telegram) as parser:
        parser.checker.max_concurrent = args.threads
        parser.checker.xray_max_concurrent = args.xray_threads
        configs = await parser.collect_all()
        if configs:
            working = await parser.checker.check_batch(configs)
            await save_subscriptions(working)

if __name__ == "__main__":
    asyncio.run(main())
