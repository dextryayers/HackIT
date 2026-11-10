"""Shared network + scope helpers."""
import socket
import time
import os
from typing import Optional, List
from urllib.parse import urlsplit

import httpx
import dns.resolver

DNS_TIMEOUT = 0.8
DNS_LIFETIME = 1.5

dns.resolver.timeout = DNS_TIMEOUT
dns.resolver.lifetime = DNS_LIFETIME

HTTP_TIMEOUT = 15.0
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def build_client(timeout: float = HTTP_TIMEOUT) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        http2=False,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
    )


def fetch_json(client: httpx.Client, url: str, timeout: float, retries: int = 2):
    for attempt in range(retries + 1):
        try:
            r = client.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(3.0 + 2.0 * attempt)
                continue
            return None
        except Exception:
            time.sleep(2.0 + 2.0 * attempt)
    return None


def fetch_text(client: httpx.Client, url: str, timeout: float, retries: int = 2):
    for attempt in range(retries + 1):
        try:
            r = client.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(3.0 + 2.0 * attempt)
                continue
            return None
        except Exception:
            time.sleep(2.0 + 2.0 * attempt)
    return None


def normalize_host(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        v = urlsplit(v).netloc
    else:
        v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    v = v.rstrip(".")
    if not v:
        return ""
    if v.startswith("["):
        end = v.find("]")
        return v[1:end] if end != -1 else v
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False


def detect_wildcard(domain: str) -> bool:
    try:
        rand = f"param-probe-{int(time.time())}.{domain}"
        dns.resolver.resolve(rand, "A")
        return True
    except Exception:
        return False


def resolve_host(host: str) -> bool:
    try:
        dns.resolver.resolve(host, "A")
        return True
    except Exception:
        return False


def in_scope(host: Optional[str], scope: str) -> bool:
    h = (host or "").lower().rstrip(".")
    s = scope.lower().rstrip(".")
    return h == s or h.endswith("." + s)
