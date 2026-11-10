"""
web_fuzzer — ParamSpider-grade parameter discovery + hidden parameter hunt.

One tool, one purpose: given a target (domain, subdomain, IP, or a full
URL), mine every historical URL with query parameters from passive sources,
collapse them to a clean unique set, then probe the live target for hidden
(undisclosed) parameters with a dedicated Go engine.

Passive harvesting: crt.sh, RapidDNS, HackerTarget, DNS brute, Wayback CDX
(year-split + per-subdomain), CommonCrawl, AlienVault OTX (domain + per
subdomain), urlscan.io.

Active discovery: baseline-diff probing — reflection markers, status/length
shifts, error signatures — no payloads, no exploitation.
"""

import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from typing import List, Dict, Tuple, Optional
from urllib.parse import parse_qsl, urlunparse, urlencode, urlsplit

import click
import dns.resolver
import httpx

from hackit.ui import _colored
from hackit.ui import GREEN, YELLOW, DIM, B_GREEN, B_CYAN, WHITE, RED

# ── tunables ─────────────────────────────────────────────────────────
CDX_TIMEOUT = 75.0
HTTP_TIMEOUT = 15.0
DNS_TIMEOUT = 0.8
DNS_LIFETIME = 1.5
LIVENESS_WORKERS = 48
SUBDOMAIN_WORKERS = 32

dns.resolver.timeout = DNS_TIMEOUT
dns.resolver.lifetime = DNS_LIFETIME

EXT_BLACKLIST = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".webm", ".wav", ".flac",
    ".zip", ".gz", ".rar", ".7z", ".tar", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".apk", ".ipa", ".dmg", ".exe", ".msi", ".iso", ".bin",
    ".js", ".mjs", ".jsx", ".map",
}
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# ── banner ───────────────────────────────────────────────────────────

def banner():
    art = r"""
  ██╗    ██╗███████╗██████╗     ███████╗██╗   ██╗███████╗███████╗███████╗██████╗
  ██║    ██║██╔════╝██╔══██╗    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
  ██║ █╗ ██║█████╗  ██████╔╝    █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝
  ██║███╗██║██╔══╝  ██╔══██╗    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ╚███╔███╔╝███████╗██████╔╝    ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║
   ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
"""
    print()
    print(_colored(art, B_CYAN, bold=True))
    print(_colored("   H A C K I T   W E B   F U Z Z E R   —   P a r a m S p i d e r   G r a d e", B_CYAN))
    print(_colored("   Passive harvest · full-scope collapse · active hidden-parameter discovery", DIM))
    print(_colored("   " + "─" * 66, DIM))
    print()


# ── helpers ──────────────────────────────────────────────────────────

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


def build_client(timeout: float = HTTP_TIMEOUT) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        http2=False,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
    )


def in_scope(host: Optional[str], scope: str) -> bool:
    h = (host or "").lower().rstrip(".")
    s = scope.lower().rstrip(".")
    return h == s or h.endswith("." + s)


def clean_url(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or not raw.lower().startswith(("http://", "https://")):
        return None
    try:
        p = urlsplit(raw)
    except ValueError:
        return None
    if not p.scheme or not p.netloc:
        return None
    host = p.hostname.lower() if p.hostname else ""
    if not host or "." not in host and not is_ip(host):
        return None
    port = p.port
    netloc = host
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = p.path or "/"
    ext = os.path.splitext(path.lower().rstrip("/"))[1]
    if ext in EXT_BLACKLIST:
        return None
    if not p.query:
        return None
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs = [(k, v) for k, v in pairs if k and len(k) <= 128 and re.match(r"^[A-Za-z0-9_.\-\[\]:]+$", k)]
    if not pairs:
        return None
    query = urlencode(pairs, doseq=True)
    return urlunparse((p.scheme.lower(), netloc, path, "", query, ""))


def param_signature(url: str) -> Tuple[str, str, Tuple[str, ...]]:
    p = urlsplit(url)
    keys = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    return (p.netloc.lower(), p.path, keys)


def fetch_json(client: httpx.Client, url: str, timeout: float, retries: int = 2) -> Optional[object]:
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


def fetch_text(client: httpx.Client, url: str, timeout: float, retries: int = 2) -> Optional[str]:
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


# ── sources ──────────────────────────────────────────────────────────

def _wayback_query(client: httpx.Client, host: str, year_from: int, year_to: int, limit: int = 2500) -> List[str]:
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json"
        f"&fl=original&collapse=urlkey&limit={limit}&from={year_from}&to={year_to}"
    )
    data = fetch_json(client, url, CDX_TIMEOUT, retries=2)
    urls: List[str] = []
    if isinstance(data, list):
        for row in data[1:]:
            if isinstance(row, list) and len(row) >= 1:
                u = row[0] if isinstance(row[0], str) else (row[2] if len(row) > 2 else "")
                if u:
                    urls.append(u)
    return urls


def src_wayback_2018_2020(client: httpx.Client, host: str) -> List[str]:
    return _wayback_query(client, host, 2018, 2020)


def src_wayback_2021_2023(client: httpx.Client, host: str) -> List[str]:
    return _wayback_query(client, host, 2021, 2023)


def src_wayback_2024_now(client: httpx.Client, host: str) -> List[str]:
    return _wayback_query(client, host, 2024, 2026)


def _latest_cc_indexes(client: httpx.Client) -> List[str]:
    try:
        data = fetch_json(client, "https://index.commoncrawl.org/collinfo.json", 15.0, retries=1)
        if isinstance(data, list):
            return [item.get("id") for item in data if isinstance(item, dict) and item.get("id")][:2]
    except Exception:
        pass
    return ["CC-MAIN-2026-43", "CC-MAIN-2026-39"]


def src_commoncrawl(client: httpx.Client, host: str) -> List[str]:
    urls: List[str] = []
    for idx in _latest_cc_indexes(client):
        url = f"https://index.commoncrawl.org/{idx}-index?url=*.{host}/*&output=json&limit=1500"
        text = fetch_text(client, url, 45.0, retries=1)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                u = obj.get("url", "")
                if u:
                    urls.append(u)
            except json.JSONDecodeError:
                continue
        if urls:
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


# ── subdomain discovery ─────────────────────────────────────────────

def sub_crtsh(client: httpx.Client, domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = fetch_json(client, url, 30.0)
    names: List[str] = []
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


# ── liveness ─────────────────────────────────────────────────────────

def resolve_host(host: str) -> bool:
    try:
        dns.resolver.resolve(host, "A")
        return True
    except Exception:
        return False


def detect_wildcard(domain: str) -> bool:
    try:
        rand = f"param-probe-{int(time.time())}.{domain}"
        dns.resolver.resolve(rand, "A")
        return True
    except Exception:
        return False


# ── gathering ─────────────────────────────────────────────────────────

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


def harvest_urls(client: httpx.Client, host: str, subdomains: Optional[List[str]] = None) -> Tuple[List[str], Dict[str, int]]:
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(run, n, f) for n, f in
                   [("Wayback CDX 2018-2020", src_wayback_2018_2020),
                    ("Wayback CDX 2021-2023", src_wayback_2021_2023),
                    ("Wayback CDX 2024-now", src_wayback_2024_now),
                    ("CommonCrawl", src_commoncrawl),
                    ("AlienVault OTX", src_otx),
                    ("urlscan.io", src_urlscan)]]
        for f in futures:
            f.result()

    if subdomains:
        def cdx_sub(sub):
            try:
                url = (
                    f"http://web.archive.org/cdx/search/cdx?url={sub}/*&output=json"
                    f"&fl=original&collapse=urlkey&limit=1000&from=2021&to=2026"
                )
                data = fetch_json(client, url, 45.0, retries=0)
                urls: List[str] = []
                if isinstance(data, list):
                    for row in data[1:]:
                        if isinstance(row, list) and len(row) >= 1:
                            u = row[0] if isinstance(row[0], str) else ""
                            if u:
                                urls.append(u)
                return sub, urls
            except Exception:
                return sub, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            for i, (sub, urls) in enumerate(pool.map(cdx_sub, subdomains[:5])):
                if urls:
                    stats[f"CDX {sub}"] = len(urls)
                    raw.extend(urls)

    if subdomains:
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
            for _ in pool.map(otx_sub, subdomains[:12]):
                pass

    return raw, stats


# ── hidden parameter discovery (active, Go engine) ───────────────────

def run_hidden_prober(target: str) -> List[Dict]:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    prober = os.path.join(base_dir, "go", "prober")
    wordlist = os.path.join(base_dir, "wordlist.txt")

    if not os.path.exists(prober):
        go_dir = os.path.join(base_dir, "go")
        try:
            subprocess.run(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "prober", "prober.go"],
                           cwd=go_dir, check=True, capture_output=True, timeout=120)
        except Exception as e:
            print(_colored(f"      prober build failed: {e}", YELLOW))
            return []

    if not os.path.exists(wordlist):
        return []

    try:
        proc = subprocess.run(
            [prober, "-target", target, "-list", wordlist, "-c", "24", "-t", "6"],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        proc = None

    findings: List[Dict] = []
    if proc and proc.stdout:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return findings


# ── output ───────────────────────────────────────────────────────────

def evidence_label(ev: str) -> str:
    return {
        "reflected": "REFL-marker (confirmed)",
        "error": "error signature (confirmed)",
        "status": "response differs (status)",
        "length": "response differs (size)",
    }.get(ev, ev)


@click.command(name="fuzz", epilog="Example: hackit web fuzz example.com")
@click.argument("target", nargs=1, required=False, metavar="TARGET")
def fuzzer(target: Optional[str]):
    """Harvest parameter-bearing URLs for a target — main domain and all subdomains.

    Passive reconnaissance, then active hidden-parameter discovery with a Go
    engine (baseline-diff probing: reflection markers, status/length shifts,
    error signatures — no payloads, no exploitation).

    TARGET can be a bare domain, a subdomain, an IP, or a full URL with
    parameters. Omit it and you'll be asked interactively.
    """
    started = time.time()

    if not target:
        banner()
        raw = click.prompt(_colored("  Input Target", B_CYAN, bold=True), default="", show_default=False).strip()
        if raw.lower() in ("exit", "quit", "q", ""):
            click.echo(_colored("  [!] No target provided. Exiting.", DIM))
            return
        target = raw
    else:
        banner()

    raw_input = target.strip()
    host = normalize_host(raw_input)
    if not host:
        click.secho("[!] Could not parse target: " + raw_input, fg="red", err=True)
        sys.exit(2)

    ip_target = is_ip(host)
    wildcard = (not ip_target) and detect_wildcard(host)

    click.echo(_colored(f"[*] Target      : {_colored(host, B_CYAN)}", WHITE))
    click.echo(_colored("[*] Mode        : passive + active hidden-parameter discovery", WHITE))
    if wildcard:
        click.echo(_colored("[!] Wildcard DNS detected — liveness labels will be unreliable", YELLOW))
    print()

    # Phase 1: subdomain discovery
    click.echo(_colored("[Phase 1/5] Discovering subdomains...", B_CYAN))
    sub_client = build_client(HTTP_TIMEOUT)
    hosts, sub_sources = gather_subdomains(sub_client, host, ip_target)
    sub_client.close()

    if ip_target:
        click.echo(_colored("      IP target — skipping subdomain enumeration", DIM))
    else:
        for name, desc in sorted(sub_sources.items()):
            click.echo(_colored(f"      {name:<14} {desc}", DIM))
        click.echo(_colored(f"      total scope   {len(hosts)} names", GREEN))
    print()

    # Phase 2: passive parameter mining
    click.echo(_colored("[Phase 2/5] Mining parameter URLs from passive sources...", B_CYAN))
    client = build_client(CDX_TIMEOUT)
    all_raw: List[str] = []
    per_host_urls: Dict[str, int] = {}

    if ip_target:
        click.echo(_colored("      Passive archive sources do not apply to bare IPs — skipped.", YELLOW))
        click.echo(_colored("      Use a domain target (example.com) for parameter mining.", DIM))
    else:
        subdomains = [h for h in hosts if h != host]
        raw, stats = harvest_urls(client, host, subdomains)
        all_raw.extend(raw)
        per_host_urls[host] = len(raw)
        for name in sorted(stats):
            cnt = stats.get(name, 0)
            status = "ok" if cnt else "none/failed"
            click.echo(_colored(f"      {name:<24} {cnt:>6} URLs  [{status}]", DIM))

    if "?" in raw_input:
        seed = raw_input if "://" in raw_input else "http://" + raw_input
        all_raw.append(seed)
        click.echo(_colored("      seed URL       included", DIM))
    client.close()
    print()

    # Phase 3: active hidden parameter discovery
    click.echo(_colored("[Phase 3/5] Probing target for hidden parameters (Go engine)...", B_CYAN))
    probe_url = raw_input if "://" in raw_input else "http://" + raw_input
    hidden = run_hidden_prober(probe_url)
    confirmed = [f for f in hidden if f.get("evidence") in ("reflected", "error")]
    candidates = [f for f in hidden if f.get("evidence") in ("status", "length")]
    click.echo(_colored(f"      confirmed hidden params : {len(confirmed)}", GREEN if confirmed else DIM))
    click.echo(_colored(f"      candidate (response Δ)  : {len(candidates)}", DIM))
    print()

    # Phase 4: normalize + collapse + liveness
    click.echo(_colored("[Phase 4/5] Normalizing, filtering, collapsing...", B_CYAN))
    seen: Dict[str, str] = {}
    collapsed = 0
    dropped = 0
    param_counter: Counter = Counter()

    for raw_url in all_raw:
        cleaned = clean_url(raw_url)
        if not cleaned:
            dropped += 1
            continue
        if not in_scope(urlsplit(cleaned).hostname, host):
            dropped += 1
            continue
        sig = param_signature(cleaned)
        if sig in seen:
            collapsed += 1
            continue
        seen[sig] = cleaned
        for k, _ in parse_qsl(urlsplit(cleaned).query, keep_blank_values=True):
            param_counter[k] += 1

    urls = sorted(seen.values())

    click.echo(_colored("[Phase 5/5] Resolving hosts (liveness)...", B_CYAN))
    host_status: Dict[str, str] = {}
    if not ip_target and not wildcard:
        unique_hosts = sorted({urlsplit(u).hostname or "" for u in urls})
        with concurrent.futures.ThreadPoolExecutor(max_workers=LIVENESS_WORKERS) as pool:
            results = list(pool.map(resolve_host, unique_hosts))
        for h, alive in zip(unique_hosts, results):
            host_status[h] = "live" if alive else "stale"
    else:
        for u in urls:
            host_status[urlsplit(u).hostname or ""] = "live"

    # ── results ──────────────────────────────────────────────────────
    print()
    width = min(max((len(u) for u in urls), default=40), 200)
    print(_colored("  " + "─" * min(width + 30, 110), DIM))
    for u in urls:
        h = urlsplit(u).hostname or ""
        alive = host_status.get(h, "live") == "live"
        if alive:
            print(_colored("  " + u, GREEN))
        else:
            print(_colored("  " + u + _colored("  [stale]", DIM), DIM))
    if confirmed or candidates:
        print()
        print(_colored("  Hidden / undocumented parameters:", B_CYAN))
        for f in confirmed + candidates:
            tag = "[CONFIRMED]" if f.get("evidence") in ("reflected", "error") else "[candidate]"
            print(_colored(f"    {tag:<11} {f.get('param'):<28} {evidence_label(f.get('evidence', ''))}  (Δ{f.get('delta') if f.get('delta') is not None else 0}B, http {f.get('status')})", GREEN if f.get("evidence") in ("reflected", "error") else YELLOW))
    print(_colored("  " + "─" * min(width + 30, 110), DIM))
    print()

    total_live = sum(1 for h, s in host_status.items() if s == "live")
    summary = [
        ("Target", host),
        ("Subdomains discovered", str(len(hosts) - 1) if not ip_target else "0 (IP target)"),
        ("Raw URLs collected", str(len(all_raw))),
        ("Dropped (static/invalid/scope)", str(dropped)),
        ("Collapsed (param signature)", str(collapsed)),
        ("Unique parameter URLs", str(len(urls))),
        ("Hidden params (confirmed/candidates)", f"{len(confirmed)}/{len(candidates)}"),
        ("Hosts (live / stale)", f"{total_live} / {len(host_status) - total_live}"),
        ("Elapsed", f"{time.time() - started:.1f}s"),
    ]
    for k, v in summary:
        print(_colored(f"  {k:<38} {v}", WHITE))
    print()

    top_params = param_counter.most_common(20)
    if top_params:
        print(_colored("  Parameter inventory (top 20):", B_CYAN))
        items = [f"{n}({c})" for n, c in top_params]
        line = "  "
        for item in items:
            if len(line) + len(item) + 2 > 110:
                print(_colored(line, DIM))
                line = "  "
            line += item + "  "
        if line.strip():
            print(_colored(line, DIM))
        print()

    os.makedirs("results", exist_ok=True)
    out_file = os.path.join("results", f"{host}.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 64 + "\n")
        f.write(f"web_fuzzer report — {host}\n")
        f.write(f"generated {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 64 + "\n\n")
        f.write("[PASSIVE PARAMETER URLs]\n")
        if urls:
            for u in urls:
                f.write(u + "\n")
        else:
            f.write("(none found in passive sources)\n")
        f.write("\n[HIDDEN PARAMETERS (active probe)]\n")
        if confirmed or candidates:
            for f_ in confirmed + candidates:
                f.write(f"{f_.get('param')}\t{f_.get('evidence')}\tstatus={f_.get('status')}\tdelta={f_.get('delta')}\n")
        else:
            f.write("(none detected)\n")
    click.echo(_colored(f"  [+] Report saved  →  {out_file}", B_GREEN))
    print()
