"""
HackIt Anonymity & Stealth Engine v2
- Header Rotation (User-Agent, Referer, Accept-Language, etc.)
- Proxy Chain Management (Tor, SOCKS5, HTTP, rotating pools)
- DNS Leak Protection (Public Resolver Rotation + DOH)
- Traffic Shaping (Jitter, Delays, Burst control)
- TLS Fingerprint Randomization
- MAC Address Spoofing helpers
- Request Throttling & Rate Limit Detection
"""
import random
import time
import asyncio
import os
import hashlib
import struct
import socket
from typing import Dict, List, Optional, Tuple

PUBLIC_RESOLVERS = [
    '1.1.1.1', '1.0.0.1',
    '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220',
    '8.26.56.26', '8.20.247.20',
    '64.6.64.6', '64.6.65.6',
    '185.228.168.9', '185.228.169.9',
    '76.76.2.0', '76.76.10.0',
    '94.140.14.14', '94.140.15.15',
]

DOH_SERVERS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
    'https://dns.quad9.net/dns-query',
    'https://doh.opendns.com/dns-query',
    'https://dns.adguard.com/dns-query',
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/1.65",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,id;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en-US,en;q=0.5",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://search.yahoo.com/",
    "https://duckduckgo.com/",
    "https://www.google.co.uk/",
    "https://www.google.de/",
    "",
]

SEC_CH_UA_SETS = [
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
    '"Not-A.Brand";v="99", "Chromium";v="124"',
    '"Firefox";v="125"',
]

TLS_CIPHERS = [
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
]


class StealthManager:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.proxies: List[str] = []
        self._proxy_index = 0
        self._resolver_index = 0
        self._request_count = 0
        self._last_request_time = 0.0
        self._rate_limit_detected = False
        self._session_fingerprint: Optional[Dict] = None
        self._tor_control_port = 9051
        self._tor_socks_port = 9050

    def get_headers(self, target_url: str = "") -> Dict[str, str]:
        if not self.enabled:
            return {'User-Agent': 'HackIt-Security-Scanner/2.1'}

        ua = random.choice(USER_AGENTS)
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        }

        if 'Chrome' in ua or 'Chromium' in ua:
            headers['Sec-CH-UA'] = random.choice(SEC_CH_UA_SETS)
            headers['Sec-CH-UA-Mobile'] = '?0'
            headers['Sec-CH-UA-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"'])

        ref = random.choice(REFERERS)
        if ref:
            headers['Referer'] = ref

        if random.random() < 0.3:
            headers['X-Forwarded-For'] = self._random_ip()
            headers['X-Real-IP'] = self._random_ip()

        if random.random() < 0.2:
            headers['Via'] = f"1.1 {self._random_hostname()}"

        self._request_count += 1
        return headers

    def get_proxy(self) -> Optional[str]:
        if not self.enabled or not self.proxies:
            env_proxy = os.environ.get('HACKIT_PROXY', '')
            return env_proxy if env_proxy else None

        proxy = self.proxies[self._proxy_index % len(self.proxies)]
        self._proxy_index += 1
        return proxy

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        proxy = self.get_proxy()
        if not proxy:
            return None
        return {'http': proxy, 'https': proxy}

    def get_tor_proxy(self) -> Dict[str, str]:
        socks = f"socks5h://127.0.0.1:{self._tor_socks_port}"
        return {'http': socks, 'https': socks}

    def renew_tor_circuit(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self._tor_control_port), timeout=5) as s:
                s.sendall(b'AUTHENTICATE ""\r\n')
                resp = s.recv(256)
                if b"250" not in resp:
                    return False
                s.sendall(b"SIGNAL NEWNYM\r\n")
                resp = s.recv(256)
                return b"250" in resp
        except Exception:
            return False

    def add_proxy(self, proxy: str):
        if proxy and proxy not in self.proxies:
            self.proxies.append(proxy)

    def load_proxy_file(self, filepath: str) -> int:
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_proxy(line)
                        count += 1
        except IOError:
            pass
        return count

    def get_dns_resolvers(self) -> List[str]:
        if not self.enabled:
            return []
        resolvers = PUBLIC_RESOLVERS.copy()
        random.shuffle(resolvers)
        return resolvers

    def get_doh_server(self) -> str:
        return random.choice(DOH_SERVERS)

    async def sleep_jitter(self, base_delay: float = 0.5, max_jitter: float = 1.5):
        if not self.enabled:
            return

        if self._rate_limit_detected:
            base_delay *= 3
            max_jitter *= 3

        delay = random.uniform(base_delay, max_jitter)
        if random.random() < 0.1:
            delay += random.uniform(2.0, 5.0)

        await asyncio.sleep(delay)

    def sync_jitter(self, base_delay: float = 0.3, max_jitter: float = 1.0):
        if not self.enabled:
            return
        if self._rate_limit_detected:
            base_delay *= 3
            max_jitter *= 3
        delay = random.uniform(base_delay, max_jitter)
        time.sleep(delay)

    def configure_resolver_stealth(self, resolver_obj):
        if not self.enabled:
            return
        resolver_obj.nameservers = self.get_dns_resolvers()

    def on_rate_limit(self):
        self._rate_limit_detected = True

    def reset_rate_limit(self):
        self._rate_limit_detected = False

    def get_tls_ciphers(self) -> str:
        if not self.enabled:
            return ""
        return random.choice(TLS_CIPHERS)

    def get_session_fingerprint(self) -> Dict:
        if not self._session_fingerprint or random.random() < 0.1:
            self._session_fingerprint = {
                'user_agent': random.choice(USER_AGENTS),
                'accept_language': random.choice(ACCEPT_LANGUAGES),
                'sec_ch_ua': random.choice(SEC_CH_UA_SETS),
                'platform': random.choice(['Windows', 'macOS', 'Linux']),
            }
        return self._session_fingerprint

    @staticmethod
    def _random_ip() -> str:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    @staticmethod
    def _random_hostname() -> str:
        words = ['proxy', 'cache', 'cdn', 'edge', 'relay', 'node', 'gw']
        return f"{random.choice(words)}-{random.randint(1,99)}.{random.choice(['cloudflare.com','akamai.net','fastly.net','cloudfront.net'])}"

    @staticmethod
    def generate_random_mac() -> str:
        mac = [0x02, 0x00, 0x00,
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(f'{b:02x}' for b in mac)

    def get_stats(self) -> Dict:
        return {
            'enabled': self.enabled,
            'requests': self._request_count,
            'proxies_loaded': len(self.proxies),
            'rate_limited': self._rate_limit_detected,
        }


stealth_engine = StealthManager()


def enable_stealth_mode():
    stealth_engine.enabled = True


def disable_stealth_mode():
    stealth_engine.enabled = False


def is_stealth_enabled() -> bool:
    return stealth_engine.enabled


def get_stealth_headers(url: str = "") -> Dict[str, str]:
    return stealth_engine.get_headers(url)


def get_proxy() -> Optional[str]:
    return stealth_engine.get_proxy()
