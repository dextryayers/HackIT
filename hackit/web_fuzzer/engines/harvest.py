"""Passive parameter mining — wayback CDX (Go fan-out), CommonCrawl, OTX, urlscan."""
import concurrent.futures
import json
import os
import subprocess
import sys
from typing import List, Dict, Optional, Tuple

import httpx

from .net import fetch_json, fetch_text, HTTP_TIMEOUT

CDX_TIMEOUT = 75.0
CC_FALLBACK = ["CC-MAIN-2026-43", "CC-MAIN-2026-39"]
GO_TIMEOUT = 180.0


def _latest_cc_indexes(client: httpx.Client) -> List[str]:
    try:
        data = fetch_json(client, "https://index.commoncrawl.org/collinfo.json", 15.0, retries=1)
        if isinstance(data, list):
            return [item.get("id") for item in data if isinstance(item, dict) and item.get("id")][:3]
    except Exception:
        pass
    return CC_FALLBACK


def src_commoncrawl(client: httpx.Client, host: str) -> List[str]:
    urls: List[str] = []
    for idx in _latest_cc_indexes(client):
        url = f"https://index.commoncrawl.org/{idx}-index?url=*.{host}/*&output=json&limit=1500&fl=original"
        text = fetch_text(client, url, 45.0, retries=1)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                u = obj.get("url") or obj.get("original") or ""
                if u:
                    urls.append(u)
            except json.JSONDecodeError:
                continue
        if len(urls) >= 500:
            break
    return urls


def src_otx(client: httpx.Client, host: str) -> List[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/url_list?limit=500"
    data = fetch_json(client, url, HTTP_TIMEOUT)
    urls: List[str] = []
    if isinstance(data, dict):
        for item in data.get("url_list", []):
            u = item.get("url")
            if u:
                urls.append(u)
    return urls


def src_urlscan(client: httpx.Client, host: str) -> List[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100"
    data = fetch_json(client, url, 8.0)
    urls: List[str] = []
    if isinstance(data, dict):
        for r in data.get("results", []):
            page = r.get("page") or {}
            u = page.get("url")
            if u:
                urls.append(u)
    return urls


def cdxfan_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "go", "cdxfan")


def cdxfan_hosts(hosts: List[str], from_year: int = 2021, to_year: int = 2026, limit: int = 1000) -> List[str]:
    """Concurrent wayback CDX fan-out via the Go engine."""
    binary = cdxfan_path()
    if not os.path.exists(binary):
        go_dir = os.path.dirname(binary)
        try:
            subprocess.run(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "cdxfan", "cdxfan.go"],
                           cwd=go_dir, check=True, capture_output=True, timeout=120)
        except Exception:
            return []
    if not hosts:
        return []
    try:
        proc = subprocess.run(
            [binary, "-from", str(from_year), "-to", str(to_year), "-limit", str(limit)],
            input="\n".join(hosts), capture_output=True, text=True, timeout=GO_TIMEOUT,
        )
        return [u for u in proc.stdout.splitlines() if u.strip()]
    except subprocess.TimeoutExpired:
        return []


def harvest_urls(client: httpx.Client, host: str, subdomains: Optional[List[str]] = None):
    raw: List[str] = []
    stats: Dict[str, int] = {}

    def run(name: str, fn):
        try:
            res = fn(client, host)
            if res:
                stats[name] = len(res)
                raw.extend(res)
        except Exception:
            stats[name] = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(run, n, f) for n, f in
                   [("CommonCrawl", src_commoncrawl),
                    ("AlienVault OTX", src_otx),
                    ("urlscan.io", src_urlscan)]]
        for f in futures:
            f.result()

    # Primary wayback query on the full domain tree via Go fan-out
    scope_hosts = [host] + list(subdomains or [])[:9]
    urls = cdxfan_hosts(scope_hosts, 2021, 2026, 1000)
    if urls:
        stats["Wayback CDX (Go fan-out)"] = len(urls)
        raw.extend(urls)

    # Secondary windows on the root host only (older years, different budget)
    for lo, hi in [(2018, 2020)]:
        w_urls = cdxfan_hosts([host], lo, hi, 1500)
        if w_urls:
            stats[f"Wayback CDX {lo}-{hi}"] = len(w_urls)
            raw.extend(w_urls)

    if subdomains:
        def otx_sub(name):
            sub = name
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{sub}/url_list?limit=100"
                data = fetch_json(client, url, HTTP_TIMEOUT)
                if isinstance(data, dict):
                    out = [i.get("url") for i in data.get("url_list", []) if i.get("url")]
                    if out:
                        stats[f"OTX {sub}"] = len(out)
                        raw.extend(out)
            except Exception:
                pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for _ in pool.map(otx_sub, subdomains[:12]):
                pass

    return raw, stats
