"""Subdomain discovery — passive sources + DNS brute."""
import concurrent.futures
from typing import List, Dict, Tuple, Optional

import dns.resolver
import httpx

from .net import fetch_json, fetch_text, is_ip

COMMON_PREFIXES = [
    "www", "mail", "ftp", "webmail", "api", "dev", "staging", "test", "beta", "admin",
    "portal", "vpn", "remote", "app", "apps", "login", "secure", "static", "assets", "cdn",
    "img", "images", "media", "files", "upload", "git", "gitlab", "jenkins", "jira", "confluence",
    "wiki", "docs", "help", "support", "status", "monitor", "dashboard", "grafana", "kibana",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "search", "ns1", "ns2", "ns3",
    "smtp", "imap", "pop", "mx", "owa", "autodiscover", "exchange", "meet", "chat", "forum",
    "shop", "store", "pay", "billing", "sso", "auth", "id", "accounts", "m", "mobile",
    "blog", "news", "events", "careers", "partners", "about", "learn", "cloud", "server",
]
SUBDOMAIN_WORKERS = 32


def sub_crtsh(client: httpx.Client, domain: str) -> List[str]:
    # crt.sh is flaky: try wildcard-match query first, then plain; merge both.
    names: List[str] = []
    for q in (f"%25.{domain}", domain):
        url = f"https://crt.sh/?q={q}&output=json"
        data = fetch_json(client, url, 45.0, retries=3)
        if isinstance(data, list):
            for item in data:
                for field in ("common_name", "name_value"):
                    raw = (item or {}).get(field, "") or ""
                    for line in raw.splitlines():
                        line = line.strip().lower()
                        if line.endswith("." + domain) or line == domain:
                            if "*" not in line:
                                names.append(line)
    return names


def sub_rapiddns(client: httpx.Client, domain: str) -> List[str]:
    import re
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    text = fetch_text(client, url, 20.0)
    if not text:
        return []
    pattern = re.compile(r"([a-z0-9\-\.]+\." + re.escape(domain) + r")\b")
    return list(set(m.group(1).lower() for m in pattern.finditer(text)))


def sub_hackertarget(client: httpx.Client, domain: str) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = fetch_text(client, url, 15.0)
    if not text:
        return []
    names = []
    for line in text.splitlines():
        if "," in line:
            sub = line.split(",", 1)[0].strip().lower()
            if sub.endswith("." + domain) or sub == domain:
                names.append(sub)
    return names


def sub_bruteforce(domain: str) -> List[str]:
    found: List[str] = []

    def check(prefix: str) -> Optional[str]:
        name = f"{prefix}.{domain}"
        try:
            answers = dns.resolver.resolve(name, "A")
            if answers:
                return name
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=SUBDOMAIN_WORKERS) as pool:
        for result in pool.map(check, COMMON_PREFIXES):
            if result:
                found.append(result)
    return found


def gather_subdomains(client: httpx.Client, domain: str, ip_target: bool) -> Tuple[List[str], Dict[str, str]]:
    sources: Dict[str, str] = {}
    if ip_target:
        return [domain], {}
    found: Dict[str, set] = {}

    def run(name: str, fn):
        try:
            res = fn(client, domain)
            if res:
                found[name] = set(res)
                sources[name] = f"{len(res)} names"
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(run, n, f) for n, f in
                   [("crt.sh", sub_crtsh), ("RapidDNS", sub_rapiddns), ("HackerTarget", sub_hackertarget)]]
        for f in futures:
            f.result()

    brute = sub_bruteforce(domain)
    if brute:
        found["DNS brute"] = set(brute)
        sources["DNS brute"] = f"{len(brute)} live hosts"

    all_names = set()
    for name, names in found.items():
        for n in names:
            if n.endswith("." + domain) or n == domain:
                all_names.add(n)

    all_names.add(domain)
    return sorted(all_names), sources
