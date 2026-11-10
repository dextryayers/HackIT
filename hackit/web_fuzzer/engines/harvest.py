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
GO_TIMEOUT = 300.0


def _latest_cc_indexes(client: httpx.Client) -> List[str]:
    try:
        data = fetch_json(client, "https://index.commoncrawl.org/collinfo.json", 15.0, retries=1)
        if isinstance(data, list):
            return [item.get("id") for item in data if isinstance(item, dict) and item.get("id")][:3]
    except Exception:
        pass
    return CC_FALLBACK


def src_commoncrawl(client: httpx.Client, host: str) -> List[str]:
    """CommonCrawl with a server-side param filter. Fast-probe first: if the
    gateway is sick, bail in seconds instead of eating 3 x 45s timeouts."""
    indexes = _latest_cc_indexes(client)
    if not indexes:
        return []
    idx = indexes[0]
    filt = "original:.*\\?.*"
    # Probe: one-row query, 8s — decides whether CC is worth the traffic.
    probe_url = f"https://index.commoncrawl.org/{idx}-index?url=www.{host}&matchType=host&output=json&fl=original&limit=1&filter={filt}"
    probe = fetch_text(client, probe_url, 8.0, retries=1)
    if not probe:
        return []
    urls: List[str] = []
    # Domain-wide sweep, only rows carrying a query string.
    url = f"https://index.commoncrawl.org/{idx}-index?url=*.{host}&matchType=domain&output=json&fl=original&limit=2000&filter={filt}"
    text = fetch_text(client, url, 40.0, retries=1)
    if text:
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
    # Supplement: root-host host-level query if the domain sweep under-delivers.
    if len(urls) < 200:
        url2 = f"https://index.commoncrawl.org/{idx}-index?url=www.{host}&matchType=host&output=json&fl=original&limit=1500&filter={filt}"
        text = fetch_text(client, url2, 30.0, retries=1)
        if text:
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
    urls: List[str] = []
    # Lane 1: domain search (scans list)
    url = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100"
    data = fetch_json(client, url, 10.0)
    if isinstance(data, dict):
        for r in data.get("results", []):
            u = (r.get("page") or {}).get("url")
            if u:
                urls.append(u)
    # Lane 2: page.domain term query (anonymous-safe, no wildcards/regex)
    url2 = f"https://urlscan.io/api/v1/search/?q=page.domain:{host}&size=100"
    data2 = fetch_json(client, url2, 10.0)
    if isinstance(data2, dict):
        for r in data2.get("results", []):
            u = (r.get("page") or {}).get("url")
            if u:
                urls.append(u)
    return urls


def cdxfan_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "go", "cdxfan")


def _cdxfan_stats(stderr: str) -> Optional[dict]:
    for line in stderr.splitlines():
        if line.startswith("CDXFAN_STATS:"):
            try:
                return json.loads(line[len("CDXFAN_STATS:"):])
            except Exception:
                return None
    return None


def cdxfan_hosts(hosts: List[str], from_year: int = 2018, to_year: int = 2026, limit: int = 250, domain_sweep: bool = False):
    """Concurrent wayback CDX fan-out via the Go engine. Returns (urls, stats_dict)."""
    binary = cdxfan_path()
    if not os.path.exists(binary):
        go_dir = os.path.dirname(binary)
        try:
            subprocess.run(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "cdxfan", "cdxfan.go"],
                           cwd=go_dir, check=True, capture_output=True, timeout=120)
        except Exception:
            return [], None
    if not hosts:
        return [], None
    try:
        args = [binary, "-from", str(from_year), "-to", str(to_year), "-limit", str(limit)]
        if domain_sweep:
            args.append("-domain")
        proc = subprocess.run(
            args,
            input="\n".join(hosts), capture_output=True, text=True, timeout=GO_TIMEOUT,
        )
        urls = [u for u in proc.stdout.splitlines() if u.strip()]
        return urls, _cdxfan_stats(proc.stderr)
    except subprocess.TimeoutExpired:
        return [], None


def harvest_urls(client: httpx.Client, host: str, subdomains: Optional[List[str]] = None):
    raw: List[str] = []
    stats: Dict[str, int] = {}

    def run(name: str, fn):
        try:
            res = fn(client, host)
            if res:
                stats[name] = len(res)
                raw.extend(res)
            else:
                stats[name] = 0
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
    # Server-side filter means every row returned already carries a query string.
    scope_hosts = [host] + list(subdomains or [])[:100]
    urls, wb_stats = cdxfan_hosts(scope_hosts, 2015, 2026, 500)
    stats["Wayback CDX (Go fan-out)"] = len(urls)
    raw.extend(urls)
    if wb_stats:
        per = wb_stats.get("per_host", [])
        ok = sum(1 for h in per if h.get("status") == "ok")
        empty = sum(1 for h in per if h.get("status") == "empty")
        fails = [h.get("status") for h in per if str(h.get("status", "")).startswith(("http_", "error", "badjson"))]
        if per:
            stats["  . wayback ok/empty/failed hosts"] = f"{ok}/{empty}/{len(fails)}"
        if fails and not urls:
            stats["  . wayback last error"] = fails[0]
    # Domain-wide sweep (matchType=domain) — one query over every subdomain.
    d_urls, _ = cdxfan_hosts([host], 2015, 2026, 1000, domain_sweep=True)
    stats["Wayback CDX (domain sweep)"] = len(d_urls)
    if d_urls:
        raw.extend(d_urls)

    # Per-subdomain OTX expansion only when the root query showed param data exists.
    otx_param_hits = sum(1 for _ in (x for x in raw if "?" in x))
    if subdomains and otx_param_hits > 0:
        def otx_sub(name):
            sub = name
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{sub}/url_list?limit=50"
                data = fetch_json(client, url, HTTP_TIMEOUT)
                if isinstance(data, dict):
                    out = [i.get("url") for i in data.get("url_list", []) if i.get("url")]
                    if out:
                        stats[f"OTX {sub}"] = len(out)
                        raw.extend(out)
            except Exception:
                pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for _ in pool.map(otx_sub, subdomains[:5]):
                pass

    return raw, stats
