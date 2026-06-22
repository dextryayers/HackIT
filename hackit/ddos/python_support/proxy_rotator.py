"""
Advanced Proxy Rotator with intelligent rotation strategies,
SOCKS5/HTTP(S) support, proxy validation, and geographic diversity.
"""

import random
import time
import json
import os
import threading
from pathlib import Path
from urllib.request import Request, urlopen, ProxyHandler, build_opener, install_opener
from urllib.error import URLError


PROXY_DB = os.path.join(os.path.expanduser("~"), ".hackit", "proxies.json")
DEFAULT_TIMEOUT = 5
MAX_ROTATION_FAILURES = 5


class Proxy:
    def __init__(self, url: str, protocol: str = "socks5", country: str = "",
                 speed: float = 0, reliability: float = 1.0):
        self.url = url
        self.protocol = protocol
        self.country = country
        self.speed = speed
        self.reliability = reliability
        self.last_used = 0
        self.failures = 0
        self.successes = 0

    @property
    def score(self) -> float:
        if self.speed <= 0:
            return 0
        return self.reliability * 1000.0 / max(self.speed, 0.1)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "protocol": self.protocol,
            "country": self.country, "speed": self.speed,
            "reliability": self.reliability,
            "failures": self.failures, "successes": self.successes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Proxy":
        p = cls(d["url"], d.get("protocol", "socks5"), d.get("country", ""),
                d.get("speed", 0), d.get("reliability", 1.0))
        p.failures = d.get("failures", 0)
        p.successes = d.get("successes", 0)
        return p


class ProxyRotator:
    def __init__(self):
        self.proxies: list[Proxy] = []
        self.blacklist: set[str] = set()
        self.current: Proxy | None = None
        self.lock = threading.Lock()
        self.rotation_count = 0
        self.failure_count = 0
        self._load()

    def _load(self):
        try:
            if os.path.exists(PROXY_DB):
                with open(PROXY_DB) as f:
                    data = json.load(f)
                    self.proxies = [Proxy.from_dict(p) for p in data]
        except Exception:
            self.proxies = []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(PROXY_DB), exist_ok=True)
            with open(PROXY_DB, 'w') as f:
                json.dump([p.to_dict() for p in self.proxies], f, indent=2)
        except Exception:
            pass

    def add_proxy(self, url: str, protocol: str = "socks5", country: str = ""):
        with self.lock:
            if not any(p.url == url for p in self.proxies):
                self.proxies.append(Proxy(url, protocol, country))
                self._save()

    def remove_proxy(self, url: str):
        with self.lock:
            self.proxies = [p for p in self.proxies if p.url != url]
            self.blacklist.discard(url)
            self._save()

    def blacklist_proxy(self, url: str):
        with self.lock:
            self.blacklist.add(url)
            self.proxies = [p for p in self.proxies if p.url != url]
            if self.current and self.current.url == url:
                self.current = None
            self._save()

    def validate(self, proxy: Proxy, timeout: int = DEFAULT_TIMEOUT) -> bool:
        try:
            proxy_handler = ProxyHandler({
                'http': proxy.url, 'https': proxy.url,
            })
            opener = build_opener(proxy_handler)
            start = time.time()
            resp = opener.open('http://httpbin.org/ip', timeout=timeout)
            latency = time.time() - start
            data = json.loads(resp.read().decode())
            proxy.speed = latency
            proxy.reliability = min(1.0, proxy.reliability + 0.05)
            proxy.successes += 1
            return True
        except Exception:
            proxy.failures += 1
            proxy.reliability = max(0, proxy.reliability - 0.15)
            return False

    def select_best(self) -> Proxy | None:
        with self.lock:
            candidates = [p for p in self.proxies
                         if p.url not in self.blacklist and p.score > 0]
            if not candidates:
                return None
            candidates.sort(key=lambda p: p.score, reverse=True)
            return candidates[0]

    def select_weighted(self) -> Proxy | None:
        with self.lock:
            candidates = [p for p in self.proxies if p.url not in self.blacklist]
            if not candidates:
                return None
            weights = [max(p.score, 0.1) for p in candidates]
            total = sum(weights)
            if total <= 0:
                return random.choice(candidates)
            r = random.uniform(0, total)
            cumulative = 0
            for p, w in zip(candidates, weights):
                cumulative += w
                if r <= cumulative:
                    return p
            return candidates[-1]

    def rotate(self, strategy: str = "weighted") -> Proxy | None:
        with self.lock:
            if not self.proxies:
                return None
            strategies = {"best": self.select_best,
                         "weighted": self.select_weighted,
                         "random": lambda: random.choice(self.proxies) if self.proxies else None}
            selector = strategies.get(strategy, strategies["weighted"])
            self.current = selector()
            if self.current:
                self.current.last_used = time.time()
                self.rotation_count += 1
            return self.current

    def auto_rotate(self, interval: int = 30, strategy: str = "weighted"):
        while True:
            time.sleep(interval)
            self.rotate(strategy)

    def get_geo_diverse(self, count: int = 3) -> list[Proxy]:
        with self.lock:
            candidates = [p for p in self.proxies
                         if p.url not in self.blacklist and p.country]
            seen = set()
            result = []
            for p in sorted(candidates, key=lambda x: x.score, reverse=True):
                if p.country not in seen:
                    result.append(p)
                    seen.add(p.country)
                if len(result) >= count:
                    break
            return result

    def fetch_public_list(self, url: str = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"):
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, timeout=15)
            data = resp.read().decode().strip()
            for line in data.splitlines():
                line = line.strip()
                if line and ":" in line:
                    self.add_proxy(f"socks5://{line}", "socks5")
            self._save()
            return len(data.splitlines())
        except Exception:
            return 0

    def stats(self) -> dict:
        with self.lock:
            return {
                "total": len(self.proxies),
                "active": len([p for p in self.proxies if p.url not in self.blacklist]),
                "blacklisted": len(self.blacklist),
                "rotations": self.rotation_count,
                "failures": self.failure_count,
            }
