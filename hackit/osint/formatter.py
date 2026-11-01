"""HackIT OSINT v4 — result presentation.

One job: turn the scan dict into a readable intelligence brief. Sections are
ordered by trust, not by phase: verified API profiles first, then confirmed
sweep hits, then digital footprint, then leads, then dead ends.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List

import click

from hackit.ui import (
    _colored,
    B_CYAN as ANSI_CYAN, B_GREEN as ANSI_GREEN, B_YELLOW as ANSI_YELLOW,
    CYAN as ANSI_DIMCYAN, DIM as ANSI_DIM,
)

from rich import box
from rich.console import Console
from rich.table import Table

_console = Console()

# Rich markup uses style *names*; hackit.ui exports raw ANSI escapes, so the
# palette is redeclared here in rich's vocabulary.
B_CYAN = "bright_cyan"
B_GREEN = "bright_green"
B_YELLOW = "bright_yellow"
B_RED = "bright_red"
B_WHITE = "bright_white"
CYAN = "cyan"
DIM = "dim"
GREEN = "green"
RED = "red"
YELLOW = "yellow"

DEFAULT_SHOW = 25
SHOW_SUBDOMAINS = 45


# ───────────────────────────── primitives ─────────────────────────────

def _status_color(status: str) -> str:
    return {"hit": B_GREEN, "possible": B_YELLOW,
            "unknown": CYAN}.get(status, DIM)


def _rule(title: str, color: str = B_CYAN) -> None:
    """Section header: a labelled rule sized to the terminal."""
    width = max(min(_console.width, 100), 40)
    label = f" {title} "
    pad = max(width - len(label) - 2, 4)
    _console.print(f"[bold {color}]{'─' * 2}{label}{'─' * pad}[/]")


def _bar(value: int, total: int, width: int = 28, char: str = "█") -> str:
    if total <= 0:
        return "░" * width
    filled = max(0, min(width, round(width * value / total)))
    return char * filled + "░" * (width - filled)


def print_live_finding(finding) -> None:
    """One-line live stream while the sweep runs."""
    url = getattr(finding, "url", "")
    platform = getattr(finding, "platform", "")
    code = getattr(finding, "http_status", None)
    status = getattr(finding, "status", "")
    title = getattr(finding, "title", "")
    elapsed = getattr(finding, "response_time", 0.0)

    prefix = {
        "hit": _colored("  [+]", ANSI_GREEN, bold=True),
        "possible": _colored("  [?]", ANSI_YELLOW, bold=True),
        "unknown": _colored("  [!]", ANSI_DIMCYAN, bold=True),
    }.get(status, _colored("  [-] ", ANSI_DIM, bold=True))

    meta = _colored(f" {platform}", ANSI_DIM)
    code_part = _colored(f" {code or '-'}", ANSI_DIM)
    time_part = _colored(f"{elapsed * 1000:.0f}ms", ANSI_DIM) if elapsed else ""
    url_part = _colored(f" {url[:88]}{'..' if len(url) > 88 else ''}", ANSI_CYAN)
    title_part = f" :: {_colored(title[:56], ANSI_DIM)}" if title else ""
    click.echo(f"{prefix}{meta}{code_part} {time_part}{url_part}{title_part}")


# ───────────────────────────── sections ─────────────────────────────

def _header(data: Dict[str, object]) -> None:
    summary = data.get("summary", {})
    analysis = data.get("analysis", {})
    live = data.get("live_intel") or {}
    verified = summary.get("verified") or analysis.get("verified_hits") or 0
    checked = summary.get("checked", 0)
    sources = data.get("source_count", 0)
    live_sources = live.get("sources_checked", 0)

    _console.print()
    _console.print(f"[bold {B_CYAN}]OSINT BRIEF[/]  "
                   f"[bold white]{data.get('query', '')}[/]")
    _console.print(f"[{DIM}]engine {data.get('engine', 'python')} · "
                   f"{sources} profile sources · {live_sources} live collectors · "
                   f"{checked} probes · {data.get('elapsed', 0)}s[/]")

    total = max(checked, 1)
    hits = summary.get("hits", 0)
    possible = summary.get("possible", 0)
    unknown = summary.get("unknown", 0)
    misses = summary.get("miss", max(checked - hits - possible - unknown, 0))
    _console.print()
    _console.print(
        f"  [{B_GREEN}]confirmed {_bar(hits, total, 20)}[/] {hits:>4}   "
        f"[{B_CYAN}]verified {verified:>3}[/]")
    _console.print(
        f"  [{B_YELLOW}]possible  {_bar(possible, total, 20)}[/] {possible:>4}   "
        f"[{DIM}]blocked  {unknown:>3}[/]")
    _console.print(
        f"  [{DIM}]dead ends {_bar(misses, total, 20)}[/] {misses:>4}")

    confidence = analysis.get("confidence", "NONE")
    score = analysis.get("confidence_score", 0)
    color = {"HIGH": B_GREEN, "MEDIUM": B_YELLOW}.get(confidence, DIM)
    _console.print(f"\n  confidence [{color}]{confidence}[/] "
                   f"[{DIM}]({score}/100)[/] · "
                   f"personae {analysis.get('cross_platform_personae', 0)} · "
                   f"categories {len(analysis.get('top_categories') or [])}")


def _identity(data: Dict[str, object]) -> None:
    rows = []
    for key, label in (("name_format", "Name"), ("first_name", "First"),
                       ("middle_name", "Middle"), ("last_name", "Last"),
                       ("initials", "Initials"), ("reversed_name", "Reversed"),
                       ("title", "Title"), ("suffix", "Suffix")):
        if data.get(key):
            rows.append((label, str(data[key])))
    if data.get("aliases"):
        rows.append(("Aliases", ", ".join(str(a) for a in data["aliases"][:12])))
    handles = data.get("handles") or []
    if handles:
        rows.append(("Handles", ", ".join(handles[:10])))
    if not rows:
        return
    _rule("IDENTITY", B_CYAN)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    table.add_column("k", style=f"bold {B_WHITE}", no_wrap=True)
    table.add_column("v", overflow="fold")
    for key, value in rows:
        table.add_row(key, value)
    _console.print(table)


def _verified_profiles(live: Dict[str, object]) -> None:
    profiles = live.get("profiles") or []
    if not profiles:
        return
    _rule(f"VERIFIED PROFILES  ({len(profiles)})", B_GREEN)
    by_kind: Dict[str, List[dict]] = {}
    for profile in profiles:
        by_kind.setdefault(profile.get("kind", "other"), []).append(profile)

    order = ["identity", "social", "code", "messaging", "media", "gaming",
             "security", "forum", "blog", "books", "writing", "other"]
    for kind in order:
        group = by_kind.get(kind)
        if not group:
            continue
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False,
                      title=f"[{DIM}]{kind}[/]", title_justify="left",
                      title_style=f"bold {DIM}")
        table.add_column("source", style=f"bold {B_GREEN}", no_wrap=True)
        table.add_column("identity", overflow="fold")
        table.add_column("facts", overflow="fold", style=DIM)
        for profile in group:
            identity = profile.get("name") or "—"
            url = profile.get("url") or ""
            facts = []
            for key, label in (("location", "loc"), ("company", "org"),
                               ("followers", "followers"), ("created", "since"),
                               ("repos", "repos"), ("karma", "karma"),
                               ("proofs", "proofs"), ("accounts", "accounts"),
                               ("steamid64", "steam64"), ("statuses", "posts"),
                               ("instance", "instance"), ("handle", "handle"),
                               ("top_ratings", "ratings"), ("bio", "bio")):
                value = (profile.get("facts") or {}).get(key)
                if value not in (None, "", 0):
                    facts.append(f"{label}: {str(value)[:70]}")
            if not facts and profile.get("bio"):
                facts.append(str(profile["bio"])[:90])
            table.add_row(profile.get("source", "?"),
                          f"{identity}\n[{B_CYAN}]{url}[/]",
                          "\n".join(facts[:4]) or "—")
        _console.print(table)


def _confirmed_hits(data: Dict[str, object], show: int, all_rows: bool) -> None:
    profiles = data.get("profiles") or []
    hits = [p for p in profiles if p.get("status") == "hit"]
    if not hits:
        return
    _rule(f"CONFIRMED PROFILES  ({len(hits)})", B_GREEN)

    by_cat: Dict[str, List[dict]] = {}
    for item in hits:
        by_cat.setdefault(item.get("category", "Other"), []).append(item)

    limit = len(hits) if all_rows else show
    rendered = 0
    for category in sorted(by_cat, key=lambda c: (-len(by_cat[c]), c)):
        group = by_cat[category]
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False,
                      title=f"[{DIM}]{category} · {len(group)}[/]",
                      title_justify="left", title_style=f"bold {DIM}")
        table.add_column("platform", style=f"bold {B_WHITE}", no_wrap=True)
        table.add_column("handle", no_wrap=True, style=DIM)
        table.add_column("url", overflow="fold")
        table.add_column("evidence", overflow="fold", style=DIM)
        for item in group:
            if rendered >= limit:
                break
            flag = " [bold green]verified[/]" if item.get("verified") else ""
            table.add_row(
                item.get("platform", ""),
                item.get("handle", "") + flag,
                f"[{B_CYAN}]{item.get('url', '')}[/]",
                (item.get("note") or item.get("title") or "")[:70])
            rendered += 1
        if table.row_count:
            _console.print(table)
        if rendered >= limit and not all_rows:
            break

    if not all_rows and len(hits) > limit:
        _console.print(f"[{DIM}]  … {len(hits) - limit} more confirmed rows — "
                       f"use --show {len(hits)} or --all-rows[/]")


def _personae(data: Dict[str, object], live: Dict[str, object]) -> None:
    rows = []
    corr = data.get("correlation") if isinstance(data.get("correlation"), dict) else {}
    for cluster in (corr.get("shared_title_clusters") or [])[:6]:
        rows.append((f"{cluster.get('count')}× platforms",
                     ", ".join(cluster.get("platforms", [])[:8])))
    for profile in live.get("profiles") or []:
        proofs = (profile.get("facts") or {}).get("proofs")
        if proofs:
            rows.append((f"{profile.get('source')} proofs", proofs))
        accounts = (profile.get("facts") or {}).get("accounts")
        if accounts:
            rows.append((f"{profile.get('source')} accounts", accounts))
    if not rows:
        return
    _rule("CROSS-PLATFORM LINKS", B_CYAN)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    table.add_column("k", style=f"bold {B_CYAN}", no_wrap=True)
    table.add_column("v", overflow="fold")
    for key, value in rows:
        table.add_row(key, value)
    _console.print(table)


def _footprint(live: Dict[str, object]) -> None:
    rdap = live.get("rdap") or {}
    dns = live.get("dns") or {}
    geo = live.get("geo") or {}
    mail = live.get("mail") or {}
    subdomains = live.get("subdomains") or []
    wayback = live.get("wayback") or {}
    urlscan = live.get("urlscan") or []
    otx = live.get("otx") or {}
    idb = live.get("internetdb") or {}
    pdns = live.get("passive_dns") or []
    hsts = live.get("hstspreload") or {}
    ssl = live.get("ssllabs") or {}
    checks = live.get("domain_checks") or {}

    if not any((rdap, dns, geo, subdomains, wayback, urlscan, otx, idb)):
        return

    _rule("DIGITAL FOOTPRINT", B_CYAN)

    if rdap:
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
        table.add_column("k", style=f"bold {B_WHITE}", no_wrap=True)
        table.add_column("v", overflow="fold")
        for label, key in (("Registrar", "registrar"), ("Created", "created"),
                           ("Updated", "updated"), ("Expires", "expires"),
                           ("Status", "status"), ("Nameservers", "nameservers")):
            value = rdap.get(key)
            if isinstance(value, list):
                value = ", ".join(value[:5])
            if value:
                table.add_row(label, str(value))
        if checks.get("age_days"):
            table.add_row("Domain age", f"{checks['age_days']} days "
                                        f"(~{round(checks['age_days'] / 365, 1)}y)")
        _console.print(table)

    if dns:
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
        table.add_column("k", style=f"bold {B_WHITE}", no_wrap=True)
        table.add_column("v", overflow="fold")
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
            values = dns.get(rtype) or []
            if values:
                table.add_row(rtype, ", ".join(str(v)[:80] for v in values[:4]))
        if geo:
            table.add_row("IP", geo.get("ip", ""))
            table.add_row("Geo", " / ".join(x for x in (
                geo.get("city"), geo.get("region"), geo.get("country")) if x))
            table.add_row("Network", f"{geo.get('asn') or geo.get('isp', '')}"
                                     + (" · hosting" if geo.get("hosting") else "")
                                     + (" · proxy" if geo.get("proxy") else ""))
        if mail.get("spf"):
            table.add_row("SPF", str(mail["spf"])[:90])
        if mail.get("dmarc"):
            table.add_row("DMARC", str(mail["dmarc"])[:90])
        if ssl.get("grade"):
            table.add_row("TLS grade", f"{ssl['grade']} ({ssl.get('status', '')})")
        if hsts.get("status"):
            table.add_row("HSTS", str(hsts["status"]))
        _console.print(table)

    if idb.get("ports"):
        _console.print(f"  [{B_WHITE}]Exposed ports[/] "
                       f"[{B_YELLOW}]{', '.join(str(p) for p in idb['ports'][:20])}[/]"
                       + (f"  [{B_RED}]{idb.get('cves', 0)} CVEs[/]"
                          if idb.get("cves") else ""))
    if idb.get("hostnames"):
        _console.print(f"  [{DIM}]Hostnames: {', '.join(idb['hostnames'][:6])}[/]")

    if subdomains:
        from rich.columns import Columns
        _console.print(f"\n  [bold {B_WHITE}]Subdomains[/] [{DIM}]({len(subdomains)})[/]")
        shown = subdomains[:SHOW_SUBDOMAINS]
        cells = [f"[{B_CYAN}]{item.get('host', '')}[/]" for item in shown]
        _console.print(Columns(cells, padding=(0, 3), expand=False))
        if len(subdomains) > SHOW_SUBDOMAINS:
            _console.print(f"  [{DIM}]… {len(subdomains) - SHOW_SUBDOMAINS} more hosts "
                           f"(full list with --json / --output)[/]")

    if wayback:
        _console.print(f"\n  [bold {B_WHITE}]Wayback[/]  {wayback.get('snapshots', 0)} "
                       f"snapshots · {wayback.get('first', '?')} → "
                       f"{wayback.get('last', '?')}")
    if otx.get("pulses"):
        _console.print(f"  [bold {B_WHITE}]OTX[/]  {otx['pulses']} threat pulses"
                       + (f" · {otx.get('tags')}" if otx.get("tags") else ""))
    if urlscan:
        _console.print(f"\n  [bold {B_WHITE}]Recent urlscan.io scans[/]")
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False)
        table.add_column("date", no_wrap=True, style=DIM)
        table.add_column("ip", no_wrap=True)
        table.add_column("server", overflow="fold", style=DIM)
        table.add_column("url", overflow="fold")
        for row in urlscan[:8]:
            table.add_row(row.get("scanned", ""), row.get("ip", ""),
                          row.get("server", "")[:30], row.get("url", "")[:80])
        _console.print(table)
    if pdns:
        _console.print(f"  [{DIM}]Passive DNS: {len(pdns)} records · "
                       f"e.g. {pdns[0].get('host', '')} → {pdns[0].get('ip', '')}[/]")


def _email(data: Dict[str, object], live: Dict[str, object]) -> None:
    email = data.get("email") or {}
    checks = live.get("email_checks") or {}
    pgp = live.get("pgp")
    if not email:
        return
    rows = []
    if email.get("is_email"):
        rows.append(("Address", email.get("input", "")))
        rows.append(("Domain", email.get("domain", "")))
        mx = email.get("mx_records") or []
        rows.append(("MX", ", ".join(mx[:3]) if mx else "none"))
        rows.append(("Mail provider", "secure" if email.get("mx_secure") else "custom"))
        grav = email.get("gravatar") or {}
        rows.append(("Gravatar", "exists" if grav.get("exists") else "none"))
        breaches = email.get("breaches") or []
        if breaches:
            rows.append(("Breaches", f"{len(breaches)} known"))
            for breach in breaches[:6]:
                if isinstance(breach, dict):
                    rows.append(("  · " + str(breach.get("source", "?")),
                                 str(breach.get("data_class", ""))[:70]))
        else:
            rows.append(("Breaches", "none from keyless sources"))
    else:
        rows.append(("Candidates", f"{len(email.get('candidates', []))} generated"))
        signals = email.get("candidate_signals") or []
        if signals:
            rows.append(("Live emails", ", ".join(
                s.get("email", "") for s in signals[:6])))

    disify = checks.get("disify") or {}
    if disify:
        rows.append(("Disposable", "yes" if disify.get("disposable") else "no"))
        rows.append(("Role account", "yes" if disify.get("role") else "no"))
        rows.append(("Free provider", "yes" if disify.get("free") else "no"))
    ucheck = checks.get("usercheck_email") or {}
    if ucheck.get("mx_records"):
        rows.append(("MX host", str((ucheck["mx_records"][0] or {}).get("hostname", ""))))
    if pgp:
        rows.append(("PGP key", f"{pgp.get('server')} · "
                                f"{', '.join(pgp.get('uids', [])[:2])}"))

    _rule("EMAIL & CREDENTIAL EXPOSURE", B_YELLOW)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    table.add_column("k", style=f"bold {B_WHITE}", no_wrap=True)
    table.add_column("v", overflow="fold")
    for key, value in rows:
        if value:
            table.add_row(key, str(value))
    _console.print(table)


def _phone(data: Dict[str, object]) -> None:
    phone = data.get("phone") or {}
    if not phone or "error" in phone:
        return
    _rule("PHONE INTELLIGENCE", B_CYAN)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    table.add_column("k", style=f"bold {B_WHITE}", no_wrap=True)
    table.add_column("v", overflow="fold")
    for label, key in (("Number", "number"), ("Country", "country"),
                       ("Carrier", "carrier"), ("Line type", "line_type"),
                       ("Valid", "valid")):
        if phone.get(key) not in (None, ""):
            table.add_row(label, str(phone[key]))
    social = phone.get("social_found") or []
    if social:
        table.add_row("Social", ", ".join(social[:8]))
    _console.print(table)


def _leads(data: Dict[str, object], show: int, all_rows: bool) -> None:
    leads = data.get("trace_leads") or []
    if not leads:
        return
    groups: Dict[str, List[dict]] = {}
    for lead in leads:
        name = str(lead.get("name", ""))
        group = "SEARCH"
        for prefix, label in (("🔍", "SEARCH"), ("💻", "CODE"), ("📋", "PASTES"),
                              ("📧", "EMAIL"), ("📱", "PHONE"), ("📍", "LOCATION"),
                              ("💼", "WORK"), ("🎓", "EDUCATION"), ("📰", "NEWS"),
                              ("🔒", "BREACH"), ("🕸", "DEEP WEB"), ("📄", "DOCUMENTS"),
                              ("💬", "FORUMS"), ("🏛", "RECORDS"), ("🌐", "SOCIAL"),
                              ("🎮", "GAMING"), ("💰", "CRYPTO"), ("✈", "TRAVEL"),
                              ("🍔", "FOOD"), ("🎨", "DESIGN"), ("🎬", "MEDIA"),
                              ("🏥", "HEALTH"), ("🏢", "BUSINESS"), ("⚖", "COURT"),
                              ("🔄", "USERNAME"), ("📊", "RECORDS")):
            if name.startswith(prefix):
                group = label
                break
        groups.setdefault(group, []).append(lead)

    _rule(f"TRACE LEADS  ({len(leads)})", B_YELLOW)
    limit = len(leads) if all_rows else show
    rendered = 0
    for group in sorted(groups, key=lambda g: -len(groups[g])):
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False,
                      title=f"[{DIM}]{group} · {len(groups[group])}[/]",
                      title_justify="left", title_style=f"bold {DIM}")
        table.add_column("lead", style=f"bold {B_YELLOW}", overflow="fold")
        table.add_column("url", overflow="fold")
        for lead in groups[group]:
            if rendered >= limit:
                break
            table.add_row(lead.get("name", ""), lead.get("url", ""))
            rendered += 1
        if table.row_count:
            _console.print(table)
        if rendered >= limit and not all_rows:
            break
    if not all_rows and len(leads) > limit:
        _console.print(f"[{DIM}]  … {len(leads) - limit} more leads — "
                       f"use --show {len(leads)} or --all-rows[/]")


def _dead_ends(data: Dict[str, object], show_misses: bool, show: int) -> None:
    profiles = data.get("profiles") or []
    misses = [p for p in profiles if p.get("status") in ("miss", "unknown")]
    if not misses:
        return
    if not show_misses:
        _console.print(f"\n[{DIM}]  {len(misses)} dead ends hidden — "
                       f"use --show-misses to list them[/]")
        return
    _rule(f"DEAD ENDS  ({len(misses)})", DIM)
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False, show_edge=False)
    table.add_column("status", no_wrap=True, style=DIM)
    table.add_column("platform", no_wrap=True, style=DIM)
    table.add_column("reason", overflow="fold", style=DIM)
    for item in misses[:show]:
        table.add_row(item.get("status", ""), item.get("platform", ""),
                      (item.get("note") or "")[:80])
    _console.print(table)
    if len(misses) > show:
        _console.print(f"[{DIM}]  … {len(misses) - show} more[/]")


def _errors(live: Dict[str, object]) -> None:
    errors = live.get("errors") or []
    if not errors:
        return
    names = sorted({str(e.get("source", "?")) for e in errors})
    _console.print(f"\n[{DIM}]  {len(errors)} collector errors: "
                   f"{', '.join(names[:10])}[/]")


# ───────────────────────────── entry point ─────────────────────────────

def print_results(data: Dict[str, object], show_misses: bool = False,
                  only_live: bool = False, show: int = DEFAULT_SHOW,
                  all_rows: bool = False) -> None:
    live = data.get("live_intel") or {}

    _header(data)
    _identity(data)
    _verified_profiles(live)
    _confirmed_hits(data, show, all_rows)
    _personae(data, live)
    _footprint(live)
    _email(data, live)
    _phone(data)
    if not only_live:
        _leads(data, show, all_rows)
    _dead_ends(data, show_misses, show)
    _errors(live)
    _console.print()


def save_json(data: Dict[str, object], output: str) -> None:
    path = Path(output)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    click.echo(_colored(f"\n  [+] OSINT report saved: {path}", ANSI_GREEN))
