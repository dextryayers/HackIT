"""
web_fuzzer — ParamSpider-grade parameter discovery.

One tool, one purpose: given a target (domain, subdomain, IP, or full URL),
mine every historical URL with query parameters from passive sources,
collapse duplicates by parameter signature, and report precisely what it
found — never anything invented.

Sources (passive only): crt.sh, RapidDNS, HackerTarget, DNS brute force,
wayback CDX (2018-2020 window + concurrent Go fan-out for 2021+),
CommonCrawl (latest indexes), AlienVault OTX (domain + per subdomain),
urlscan.io.
"""

import concurrent.futures
import sys
import os
import time
from collections import Counter
from typing import Optional, List
from urllib.parse import urlsplit, parse_qsl

import click
from hackit.ui import _colored
from hackit.ui import GREEN, YELLOW, DIM, B_GREEN, B_CYAN, WHITE

from .engines.net import build_client, normalize_host, is_ip, detect_wildcard, resolve_host, in_scope
from .engines.subs import gather_subdomains
from .engines.harvest import harvest_urls, GO_TIMEOUT
from .engines.process import clean_url, param_signature

HTTP_TIMEOUT = 15.0
CDX_TIMEOUT = 75.0
LIVENESS_WORKERS = 48


def banner():
    art = r"""
  ██╗    ██╗███████╗██████╗     ███████╗██╗   ██╗███████╗███████╗███████╗██████╗
  ██║    ██║██╔════╝██╔══██╗    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
  ██║ █╗ ██║█████╗  ██████╔╝    █████╗  ██║   ██║  ███╔╝   ███╔╝ ███████╗██║  ██║
  ██║███╗██║██╔══╝  ██╔══██╗    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██║  ██║
  ╚███╔███╔╝███████╗██████╔╝    ██║     ╚██████╔╝███████╗███████╗███████╗██████╔╝
   ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═════╝
"""
    print()
    print(_colored(art, B_CYAN, bold=True))
    print(_colored("   H A C K I T   W E B   F U Z Z E R   —   P a r a m S p i d e r   G r a d e", B_CYAN))
    print(_colored("   passive harvest, concurrent engines, real results — nothing invented", DIM))
    print(_colored("   " + "─" * 78, DIM))
    print()


@click.command(name="fuzz", epilog="Example: hackit web fuzz example.com")
@click.argument("target", nargs=1, required=False, metavar="TARGET")
@click.option("-v", "--verbose", default=True, help="Verbose output (default: on)")
@click.option("-q", "--quiet", is_flag=True, help="Quiet output (suppress progress)")
def fuzzer(target: Optional[str], verbose: bool, quiet: bool):
    """Harvest parameter-bearing URLs for a target — main domain + all subdomains.

    Passive reconnaissance only. TARGET can be a bare domain, a subdomain,
    an IP, or a full URL (https://example.com/search?q=x). Omit it and
    you'll be prompted interactively.
    """
    def out(msg=""):
        if not quiet:
            click.echo(msg)

    started = time.time()

    if not target:
        banner()
        if not quiet:
            raw = click.prompt(_colored("  Input Target", B_CYAN, bold=True), default="", show_default=False).strip()
        else:
            raw = input().strip()
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

    out(_colored(f"[*] Target      : {_colored(host, B_CYAN)}", WHITE))
    out(_colored("[*] Mode        : passive parameter discovery (no wordlists, no probing)", WHITE))
    if wildcard:
        out(_colored("[!] Wildcard DNS detected — liveness labels will be unreliable", YELLOW))
    print()

    # Phase 1: subdomain discovery
    out(_colored("[Phase 1/5] Subdomain discovery...", B_CYAN))
    sub_client = build_client(HTTP_TIMEOUT)
    hosts, sub_sources = gather_subdomains(sub_client, host, ip_target)
    sub_client.close()

    if ip_target:
        out(_colored("      IP target — skipping subdomain enumeration", DIM))
    else:
        for name, desc in sorted(sub_sources.items()):
            out(_colored(f"      {name:<14} {desc}", DIM))
        out(_colored(f"      scope         {len(hosts)} names", GREEN))

    elapsed_p1 = time.time() - started
    out(_colored(f"      [{elapsed_p1:.1f}s]", DIM))
    print()

    # Phase 2: passive parameter mining
    out(_colored("[Phase 2/5] Mining parameter URLs (passive sources)...", B_CYAN))
    client = build_client(CDX_TIMEOUT)
    all_raw: List[str] = []

    if ip_target:
        out(_colored("      Passive archive sources do not apply to bare IPs — skipped.", YELLOW))
    else:
        subdomains = [h for h in hosts if h != host]
        raw, stats = harvest_urls(client, host, subdomains)
        all_raw.extend(raw)
        for name in sorted(stats):
            cnt = stats.get(name, 0)
            status = "ok" if cnt else "none/failed"
            out(_colored(f"      {name:<26} {cnt:>6} URLs  [{status}]", DIM))

    if "?" in raw_input:
        seed = raw_input if "://" in raw_input else "http://" + raw_input
        all_raw.append(seed)
        out(_colored("      seed URL       included", DIM))
    client.close()

    elapsed_p2 = time.time() - started
    out(_colored(f"      [{elapsed_p2:.1f}s, {len(all_raw)} raw URLs collected]", DIM))
    print()

    # Phase 3: normalize + collapse + scope filter
    out(_colored("[Phase 3/5] Normalizing, filtering, collapsing...", B_CYAN))
    seen = {}
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
    out(_colored(f"      raw {len(all_raw)}  →  unique {len(urls)}  (dropped {dropped}, collapsed {collapsed})", DIM))
    print()

    # Phase 4: liveness
    out(_colored("[Phase 4/5] Resolving hosts (liveness)...", B_CYAN))
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
    print()

    # Phase 5: results
    out(_colored("[Phase 5/5] Results", B_CYAN))
    print()
    if not urls:
        click.secho("  [!] No parameter-bearing URLs found for this target.", fg="yellow")
        click.secho("      Passive sources may not have archived this target yet.", fg="white")
        return

    width = min(max((len(u) for u in urls), default=40), 200)
    sep = _colored("  " + "─" * min(width + 30, 110), DIM)
    if not quiet:
        print(sep)
        for u in urls:
            h = urlsplit(u).hostname or ""
            alive = host_status.get(h, "live") == "live"
            if alive:
                print(_colored("  " + u, GREEN))
            else:
                print(_colored("  " + u + _colored("  [stale]", DIM), DIM))
        print(sep)
        print()

    total_live = sum(1 for h, s in host_status.items() if s == "live")
    summary = [
        ("Target", host),
        ("Subdomains discovered", str(len(hosts) - 1) if not ip_target else "0 (IP target)"),
        ("Unique parameter URLs", str(len(urls))),
        ("Hosts (live / stale)", f"{total_live} / {len(host_status) - total_live}"),
        ("Elapsed", f"{time.time() - started:.1f}s"),
    ]
    for k, v in summary:
        out(_colored(f"  {k:<28} {v}", WHITE))
    print()

    top_params = param_counter.most_common(20)
    if top_params:
        out(_colored("  Parameter inventory (top 20):", B_CYAN))
        items = [f"{n}({c})" for n, c in top_params]
        line = "  "
        for item in items:
            if len(line) + len(item) + 2 > 110:
                out(_colored(line, DIM))
                line = "  "
            line += item + "  "
        if line.strip():
            out(_colored(line, DIM))
        print()

    os.makedirs("results", exist_ok=True)
    out_file = os.path.join("results", f"{host}.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 64 + "\n")
        f.write(f"web_fuzzer report — {host}\n")
        f.write(f"generated {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 64 + "\n\n")
        f.write("[PARAMETER URLS — one per line, paramsignature-collapsed]\n")
        for u in urls:
            f.write(u + "\n")
    out(_colored(f"  [+] Report saved  →  {out_file}", B_GREEN))
    print()
