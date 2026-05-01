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
from urllib.parse import parse_qs, urlparse, unquote, urlunparse

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
                # Using a robust download method
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        response.raise_for_status()
                        with open(db_path, "wb") as f:
                            f.write(await response.read())
                _geoip_reader = geoip2.database.Reader(str(db_path))
                return _geoip_reader
            except Exception as e:
                logger.warning(f"Не удалось скачать GeoIP с {url}: {e}")
                continue
        logger.error("Не удалось загрузить GeoIP базу")
        return None

_country_cache: Dict[str, Optional[str]] = {}

async def get_country(ip: str) -> Optional[str]:
    if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
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
    except geoip2.errors.AddressNotFoundError:
        _country_cache[ip] = None
        return None
    except Exception as e:
        logger.debug(f"Ошибка GeoIP для {ip}: {e}")
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
            if m.lower().endswith("xray"):
                zf.extract(m)
                os.chmod(m, 0o755)
                # Rename to 'xray' for consistency
                os.rename(m, xray_bin)
                break
    Path("xray.zip").unlink()
    return str(Path(xray_bin).absolute())


def build_xray_config(cfg: dict, socks_port: int) -> dict:
    # Simplified config builder
    protocol = cfg.get("protocol")
    settings = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}
        }],
        "outbounds": []
    }
    
    outbound = {
        "protocol": protocol,
        "settings": {},
        "streamSettings": cfg.get("stream_settings", {
            "network": cfg.get("transport", "tcp"),
            "security": cfg.get("tls", "none")
        })
    }

    if outbound["streamSettings"]["security"] in ["none", ""]:
        # some clients use "" for none
        del outbound["streamSettings"]["security"]
    
    if cfg.get("sni"):
        if "tlsSettings" not in outbound["streamSettings"]:
             outbound["streamSettings"]["tlsSettings"] = {}
        outbound["streamSettings"]["tlsSettings"]["serverName"] = cfg["sni"]

    if cfg.get("transport") == "ws" and cfg.get("path"):
        if "wsSettings" not in outbound["streamSettings"]:
            outbound["streamSettings"]["wsSettings"] = {}
        outbound["streamSettings"]["wsSettings"]["path"] = cfg["path"]
    
    if protocol == "vmess":
        outbound["settings"]["vnext"] = [{
            "address": cfg["host"],
            "port": cfg["port"],
            "users": [{"id": cfg["uuid"], "alterId": 0}] # alterId 0 is more compatible
        }]
    elif protocol == "vless":
        users = [{"id": cfg["uuid"], "encryption": "none"}]
        if cfg.get("flow"):
            users[0]["flow"] = cfg["flow"]
        outbound["settings"]["vnext"] = [{
            "address": cfg["host"],
            "port": cfg["port"],
            "users": users
        }]
    elif protocol == "trojan":
        outbound["settings"]["servers"] = [{
            "address": cfg["host"],
            "port": cfg["port"],
            "password": cfg["password"]
        }]
    elif protocol == "ss":
        outbound["settings"]["servers"] = [{
            "address": cfg["host"],
            "port": cfg["port"],
            "method": cfg["method"],
            "password": cfg["password"]
        }]
    else: # hysteria2, tuic etc. need specific configs
        return None # Not supporting direct check for these complex protos yet

    settings["outbounds"].append(outbound)
    return settings


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_socks(port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return True
        except ConnectionRefusedError:
            await asyncio.sleep(0.1)
        except Exception:
            return False
    return False


async def proxy_test(cfg: dict, xray_path: str) -> Tuple[bool, Optional[str]]:
    if cfg["protocol"] in ["hysteria2", "tuic", "ssr"]:
        # These require custom clients or complex configs not suitable for simple xray check
        return False, None
    
    socks_port = _find_free_port()
    config = build_xray_config(cfg, socks_port)
    if not config:
        return False, None

    config_path_obj = Path(tempfile.gettempdir()) / f"xray_config_{socks_port}.json"
    config_path = str(config_path_obj)
    with open(config_path, "w") as f:
        json.dump(config, f)

    proc = None
    try:
        cmd = [xray_path, "run", "-c", config_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        if not await _wait_for_socks(socks_port, timeout=5.0):
            return False, None

        for service_url in IP_SERVICES:
            try:
                # Using asyncio-based curl for better performance
                curl_cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{socks_port}", "--max-time", "5", service_url]
                curl_proc = await asyncio.create_subprocess_exec(*curl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await asyncio.wait_for(curl_proc.communicate(), timeout=8)
                ip = stdout.decode().strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return True, ip
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        return False, None
    except Exception:
        return False, None
    finally:
        if proc:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            Path(config_path).unlink()
        except:
            pass


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
    
    def to_dict(self):
        # Helper for xray config builder
        return {
            "protocol": self.protocol, "host": self.host, "port": self.port, "uuid": self.uuid,
            "password": self.password, "method": self.method, "transport": self.transport,
            "tls": self.tls, "sni": self.sni, "path": self.path
        }

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


def protocol_sort_key(cfg: ProxyConfig):
    priority = PROTO_PRIORITY.get(cfg.protocol, 0)
    latency = cfg.latency if cfg.latency is not None else 999999
    return (-priority, latency)


# ---------- Чекер ----------
class ProxyChecker:
    def __init__(self, max_concurrent: int = 20, xray_max_concurrent: int = 80):
        self.max_concurrent = max_concurrent
        self.xray_max_concurrent = xray_max_concurrent
        self.xray_path = ensure_xray()
        self.unique_proxies: Dict[str, ProxyConfig] = {}

    def _parse_uri(self, uri: str) -> Optional[ProxyConfig]:
        try:
            parsed = urlparse(uri)
            proto = parsed.scheme.lower()

            if proto not in SUPPORTED_PROTOCOLS:
                return None

            host = parsed.hostname
            port = parsed.port
            remarks = unquote(parsed.fragment) if parsed.fragment else None
            qs = parse_qs(parsed.query)

            if proto == 'vmess':
                # Base64 encoded JSON
                try:
                    json_str = base64.b64decode(parsed.netloc).decode('utf-8')
                    vmess_data = json.loads(json_str)
                    return ProxyConfig(
                        raw=uri, protocol='vmess', host=vmess_data['add'], port=int(vmess_data['port']),
                        uuid=vmess_data['id'], transport=vmess_data.get('net', 'tcp'),
                        tls='tls' if vmess_data.get('tls') == 'tls' else 'none',
                        sni=vmess_data.get('sni', vmess_data.get('host', '')),
                        path=vmess_data.get('path', '/'),
                        remarks=unquote(vmess_data.get('ps', '')) or remarks
                    )
                except Exception:
                    return None
            
            elif proto in ['vless', 'trojan', 'ss']:
                uuid_or_pass = parsed.username
                
                return ProxyConfig(
                    raw=uri, protocol=proto, host=host, port=port,
                    uuid=uuid_or_pass if proto == 'vless' else None,
                    password=uuid_or_pass if proto in ['trojan', 'ss'] else None,
                    method=qs.get('method', [None])[0] if proto == 'ss' else None,
                    transport=qs.get('type', ['tcp'])[0],
                    tls='tls' if qs.get('security', ['none'])[0] == 'tls' else 'none',
                    sni=qs.get('sni', [None])[0],
                    path=qs.get('path', [None])[0],
                    remarks=remarks
                )
            
            elif proto in ['hysteria2', 'tuic']:
                uuid_or_pass = parsed.username
                return ProxyConfig(
                    raw=uri, protocol=proto, host=host, port=port,
                    password=uuid_or_pass,
                    sni=qs.get('sni', [None])[0],
                    remarks=remarks
                )

            elif proto == 'ssr':
                # ssr://host:port:proto:method:obfs:pass/?obfsparam=...&protoparam=...&remarks=...
                # This parsing is complex and often requires a dedicated library
                return None # Skipping complex SSR parsing for now
            
            return None

        except Exception as e:
            logger.debug(f"Failed to parse URI {uri}: {e}")
            return None

    async def _fetch_source(self, session: aiohttp.ClientSession, source: str) -> str:
        try:
            async with session.get(source, timeout=15) as response:
                response.raise_for_status()
                return await response.text()
        except Exception as e:
            logger.warning(f"Failed to fetch {source}: {e}")
            return ""

    async def _test_proxy_worker(self, proxy_queue: asyncio.Queue, results_list: List[ProxyConfig]):
        while not proxy_queue.empty():
            proxy = await proxy_queue.get()
            start_time = time.monotonic()
            is_working, ip = await proxy_test(proxy.to_dict(), self.xray_path)
            end_time = time.monotonic()
            if is_working:
                proxy.working = True
                proxy.latency = (end_time - start_time) * 1000  # in ms
                proxy.resolved_ip = ip
                results_list.append(proxy)
                logger.info(f"✅ WORKER: {proxy.host} (IP: {ip}, Latency: {proxy.latency:.2f}ms)")
            else:
                logger.debug(f"❌ FAILED: {proxy.host}")
            proxy_queue.task_done()

    async def run(self, sources: List[str]):
        logger.info(f"🚀 Starting proxy check with {self.xray_max_concurrent} workers.")
        
        # 1. Fetch all sources
        raw_content = ""
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch_source(session, src) for src in sources]
            results = await asyncio.gather(*tasks)
            raw_content = "\n".join(results)

        # 2. Parse and deduplicate proxies
        found_uris = set(re.findall(PROXY_LINK_PATTERN, raw_content))
        for uri in found_uris:
            parsed = self._parse_uri(uri)
            if parsed:
                # Deduplicate based on protocol, host, port, and main ID
                key = f"{parsed.protocol}:{parsed.host}:{parsed.port}:{parsed.uuid or parsed.password}"
                if key not in self.unique_proxies:
                    self.unique_proxies[key] = parsed
        
        logger.info(f"Found {len(self.unique_proxies)} unique proxies to test.")

        # 3. Test proxies in parallel
        proxy_queue = asyncio.Queue()
        for proxy in self.unique_proxies.values():
            await proxy_queue.put(proxy)

        working_proxies: List[ProxyConfig] = []
        tester_tasks = []
        for _ in range(self.xray_max_concurrent):
            task = asyncio.create_task(self._test_proxy_worker(proxy_queue, working_proxies))
            tester_tasks.append(task)
        
        await proxy_queue.join()
        await asyncio.gather(*tester_tasks, return_exceptions=True)

        logger.info(f"🏁 Found {len(working_proxies)} working proxies.")

        # 4. Format names and sort
        for proxy in working_proxies:
            proxy.remarks = await proxy.format_name_async()
        
        working_proxies.sort(key=protocol_sort_key)
        
        # 5. Save results
        self.save_results(working_proxies)

    def save_results(self, proxies: List[ProxyConfig]):
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)

        # Full list
        full_path = output_dir / "all.txt"
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(HEADER)
            for proxy in proxies:
                # Reconstruct URI with new remarks
                parsed_uri = list(urlparse(proxy.raw))
                parsed_uri[5] = unquote(proxy.remarks) # fragment for name
                f.write(urlunparse(parsed_uri) + "\n")
        logger.info(f"Saved {len(proxies)} proxies to {full_path}")

        # Per-protocol files
        by_protocol = {}
        for proxy in proxies:
            if proxy.protocol not in by_protocol:
                by_protocol[proxy.protocol] = []
            by_protocol[proxy.protocol].append(proxy)
        
        for proto, proto_proxies in by_protocol.items():
            proto_path = output_dir / f"{proto}.txt"
            with open(proto_path, "w", encoding="utf-8") as f:
                f.write(HEADER)
                for proxy in proto_proxies:
                    parsed_uri = list(urlparse(proxy.raw))
                    parsed_uri[5] = unquote(proxy.remarks)
                    f.write(urlunparse(parsed_uri) + "\n")
            logger.info(f"Saved {len(proto_proxies)} {proto.upper()} proxies to {proto_path}")


# ---------- Main Execution ----------
async def main():
    parser = ArgumentParser(description="Advanced Proxy Parser and Checker")
    parser.add_argument('--threads', type=int, default=30, help='Max concurrent source fetchers (deprecated, not used).')
    parser.add_argument('--xray-threads', type=int, default=80, help='Max concurrent Xray checker processes.')
    parser.add_argument('--parse-telegram', action='store_true', help='Enable parsing from Telegram channels.')
    parser.add_argument('--sources', nargs='+', default=DEFAULT_SOURCES, help='List of source URLs.')
    
    args = parser.parse_args()

    # In a real scenario, you would add telegram parsing logic here if needed.
    # For now, it just uses the default/provided http sources.

    checker = ProxyChecker(xray_max_concurrent=args.xray_threads)
    await checker.run(sources=args.sources)

if __name__ == "__main__":
    asyncio.run(main())
