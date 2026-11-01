from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_RED, B_WHITE, B_YELLOW, CYAN, DIM, GREEN, RED, YELLOW

from rich import box
from rich.console import Console
from rich.table import Table

_console = Console()


def _status_color(status: str) -> str:
    if status == "hit": return B_GREEN
    if status == "possible": return B_YELLOW
    if status == "unknown": return CYAN
    return DIM


def print_live_finding(finding) -> None:
    url = getattr(finding, "url", "")
    platform = getattr(finding, "platform", "")
    code = getattr(finding, "http_status", None)
    status = getattr(finding, "status", "")
    title = getattr(finding, "title", "")
    elapsed = getattr(finding, "response_time", 0.0)

    if status == "hit":
        prefix = _colored("  [+]", B_GREEN, bold=True)
    elif status == "possible":
        prefix = _colored("  [?]", B_YELLOW, bold=True)
    elif status == "unknown":
        prefix = _colored("  [!]", CYAN, bold=True)
    else:
        prefix = _colored("  [-] ", B_RED, bold=True)

    meta = _colored(f" {platform}", DIM)
    code_part = _colored(f" {code or '-'}", DIM)
    time_part = _colored(f"{elapsed * 1000:.0f}ms", DIM) if elapsed else ""
    url_part = _colored(f" {url[:90]}{'..' if len(url) > 90 else ''}", B_CYAN)
    title_part = f" :: {_colored(title[:60], DIM)}" if title else ""
    click.echo(f"{prefix}{meta}{code_part} {time_part}{url_part}{title_part}")


def _kv_table(title: str, rows: list[tuple[str, str]], border: str = "cyan") -> Table:
    table = Table(title=title, box=box.ROUNDED, show_header=False, border_style=border,
                  title_justify="left", pad_edge=False)
    table.add_column("key", style="bold white", no_wrap=True)
    table.add_column("value", overflow="fold")
    for key, value in rows:
        if value:
            table.add_row(key, str(value))
    return table


def _live_intel_tables(live: Dict[str, object]) -> None:
    profiles = live.get("profiles") or []
    if profiles:
        table = Table(title="VERIFIED PUBLIC PROFILES", box=box.ROUNDED,
                      border_style="green", title_justify="left", pad_edge=False)
        table.add_column("Source", style="bold green", no_wrap=True)
        table.add_column("Identity", overflow="fold")
        table.add_column("Details", overflow="fold")
        for p in profiles:
            facts = []
            for key, label in (("bio", "bio"), ("location", "loc"), ("company", "company"),
                               ("followers", "followers"), ("public_repos", "repos"),
                               ("karma", "karma"), ("created_at", "since")):
                value = p.get(key)
                if value not in (None, "", 0):
                    facts.append(f"{label}: {str(value)[:60]}")
            proofs = p.get("proofs") or []
            if proofs:
                facts.append("proofs: " + ", ".join(proofs[:6]))
            accounts = p.get("accounts") or []
            if accounts:
                facts.append("accounts: " + ", ".join(accounts[:6]))
            table.add_row(p.get("source", "?"),
                          f"{p.get('name', '')}\n{p.get('url', '')}",
                          "\n".join(facts) or "-")
        _console.print(table)

    subdomains = live.get("subdomains") or []
    if subdomains:
        table = Table(title=f"CERTIFICATE TRANSPARENCY ({len(subdomains)} hosts)",
                      box=box.ROUNDED, border_style="magenta", title_justify="left",
                      pad_edge=False)
        table.add_column("Host", style="bold magenta", overflow="fold")
        table.add_column("First seen", no_wrap=True)
        for entry in subdomains[:30]:
            table.add_row(entry.get("host", ""), entry.get("first_seen", ""))
        if len(subdomains) > 30:
            table.add_row(f"... {len(subdomains) - 30} more", "")
        _console.print(table)

    dns = live.get("dns") or {}
    geo = live.get("geo") or {}
    if dns or geo:
        rows = []
        for rtype in ("A", "MX", "NS", "TXT"):
            values = dns.get(rtype) or []
            if values:
                rows.append((rtype, ", ".join(values[:4])))
        if geo:
            rows.append(("IP", geo.get("ip", "")))
            rows.append(("Geo", " / ".join(x for x in (geo.get("city"), geo.get("region"),
                                                       geo.get("country")) if x)))
            rows.append(("ASN", geo.get("asn") or geo.get("isp", "")))
        _console.print(_kv_table("PUBLIC DNS & NETWORK", rows, border="blue"))


def print_results(data: Dict[str, object], show_misses: bool = True,
                  only_live: bool = False) -> None:
    summary = data.get("summary", {})
    analysis = data.get("analysis", {})

    overview = [
        ("Query", data.get("query", "")),
        ("Engine", data.get("engine", "python")),
        ("Sources", data.get("source_count", 0)),
        ("Handles", ", ".join(data.get("handles", [])[:6])),
        ("Hits", summary.get("hits", 0)),
        ("Verified", analysis.get("verified_hits", 0)),
        ("Possible", summary.get("possible", 0)),
        ("Probed", summary.get("checked", 0)),
    ]
    if analysis:
        overview.append(("Confidence", f"{analysis.get('confidence', 'NONE')} "
                                       f"({analysis.get('confidence_score', 0)}/100)"))
    _console.print(_kv_table("OSINT SCAN RESULTS", overview, border="cyan"))

    name_rows = []
    for key, label in (("name_format", "Name"), ("first_name", "First"),
                       ("middle_name", "Middle"), ("last_name", "Last"),
                       ("initials", "Initials"), ("reversed_name", "Reversed")):
        if data.get(key):
            name_rows.append((label, data.get(key)))
    if data.get("aliases"):
        name_rows.append(("Aliases", ", ".join(str(a) for a in data["aliases"][:10])))
    if name_rows:
        _console.print(_kv_table("TARGET IDENTITY", name_rows))

    email = data.get("email", {})
    if email:
        rows = []
        if email.get("is_email"):
            rows.append(("Email", email.get("input", "")))
            rows.append(("Domain", email.get("domain", "")))
            mx = email.get("mx_records") or []
            rows.append(("MX", ", ".join(mx[:3]) if mx else "none"))
            rows.append(("MX secure", "yes" if email.get("mx_secure") else "no"))
            grav = email.get("gravatar") or {}
            rows.append(("Gravatar", "exists" if grav.get("exists") else "none"))
            if email.get("pgp_key"):
                rows.append(("PGP", "key found"))
        else:
            rows.append(("Candidates", f"{len(email.get('candidates', []))} generated"))
            signals = email.get("candidate_signals") or []
            if signals:
                rows.append(("Live emails", ", ".join(s.get("email", "") for s in signals[:5])))
        breaches = email.get("breaches") or []
        if breaches:
            rows.append(("Breaches", f"{len(breaches)} found"))
            for b in breaches[:5]:
                if isinstance(b, dict):
                    rows.append(("  " + str(b.get("source", "?")), str(b.get("data_class", ""))[:70]))
        _console.print(_kv_table("EMAIL INTELLIGENCE", rows))

    phone = data.get("phone", {})
    if phone and "error" not in phone:
        rows = [
            ("Number", phone.get("number", "")),
            ("Country", phone.get("country", "")),
            ("Carrier", phone.get("carrier", "")),
            ("Line type", phone.get("line_type", "")),
        ]
        social = phone.get("social_found") or []
        if social:
            rows.append(("Social", ", ".join(social)))
        _console.print(_kv_table("PHONE INTELLIGENCE", rows))

    domain = data.get("domain", {})
    if domain:
        rows = [
            ("Domain", domain.get("domain", "")),
            ("Registrar", domain.get("registrar", "")),
            ("Created", domain.get("creation_date", "")),
            ("Name servers", ", ".join((domain.get("name_servers") or [])[:3])),
        ]
        _console.print(_kv_table("DOMAIN INTELLIGENCE", rows))

    live = data.get("live_intel") or {}
    if live:
        _live_intel_tables(live)

    profiles = data.get("profiles", [])
    if only_live:
        visible = [p for p in profiles if p.get("status") in {"hit", "possible", "unknown"}]
    else:
        visible = [p for p in profiles if show_misses or p.get("status") in {"hit", "possible", "unknown"}]
    if visible:
        table = Table(title="PROFILE PROBES", box=box.ROUNDED, border_style="green",
                      title_justify="left", pad_edge=False)
        table.add_column("Status", no_wrap=True)
        table.add_column("Platform", style="bold white", no_wrap=True)
        table.add_column("Category", style="dim", no_wrap=True)
        table.add_column("URL", overflow="fold")
        table.add_column("Title", overflow="fold", style="dim")
        style = {"hit": "green", "possible": "yellow", "unknown": "cyan"}
        for item in visible[:80]:
            status = item.get("status", "")
            label = status.upper() + (" ✓" if item.get("verified") else "")
            table.add_row(f"[{style.get(status, 'dim')}]{label}[/]",
                          item.get("platform", ""), item.get("category", ""),
                          item.get("url", ""), item.get("title", "")[:70])
        if len(visible) > 80:
            table.add_row("", f"... {len(visible) - 80} more", "", "", "")
        _console.print(table)

    corr = data.get("correlation", {}) if isinstance(data.get("correlation"), dict) else {}
    personae = corr.get("shared_title_clusters", []) or []
    if personae:
        rows = [(f"{p.get('count')}x platforms", ", ".join(p.get("platforms", [])[:6]))
                for p in personae[:5]]
        _console.print(_kv_table("CROSS-PLATFORM PERSONAE", rows, border="green"))

    leads = data.get("trace_leads", [])
    if leads:
        table = Table(title="TRACE LEADS", box=box.ROUNDED, border_style="yellow",
                      title_justify="left", pad_edge=False)
        table.add_column("Lead", style="bold yellow", overflow="fold")
        table.add_column("URL", overflow="fold")
        for lead in leads[:15]:
            table.add_row(lead.get("name", ""), lead.get("url", ""))
        if len(leads) > 15:
            table.add_row(f"... {len(leads) - 15} more", "")
        _console.print(table)


def save_json(data: Dict[str, object], output: str) -> None:
    path = Path(output)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    click.echo(_colored(f"\n  [+] OSINT report saved: {path}", B_GREEN))
