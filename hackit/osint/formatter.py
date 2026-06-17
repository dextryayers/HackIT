from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import click

from hackit.ui import (
    _colored, B_CYAN, B_GREEN, B_RED, B_WHITE, B_YELLOW, CYAN, DIM,
    GREEN, RED, WHITE, YELLOW, TablePrinter,
)


def _status_color(status: str) -> str:
    if status == "hit": return B_GREEN
    if status == "possible": return B_YELLOW
    if status == "unknown": return CYAN
    return DIM


def print_live_finding(finding) -> None:
    url = getattr(finding, "url", "")
    platform = getattr(finding, "platform", "")
    handle = getattr(finding, "handle", "")
    code = getattr(finding, "http_status", None)
    status = getattr(finding, "status", "")
    title = getattr(finding, "title", "")

    if status == "hit":
        prefix = _colored("  [+] FOUND", B_GREEN, bold=True)
    elif status == "possible":
        prefix = _colored("  [?] POSSIBLE", B_YELLOW, bold=True)
    elif status == "unknown":
        prefix = _colored("  [!] UNKNOWN", CYAN, bold=True)
    else:
        prefix = _colored("  [-] MISS", B_RED, bold=True)

    meta = _colored(f" | {platform}", DIM)
    t = f" :: {title[:80]}" if title and status in {"hit", "possible"} else ""
    click.echo(f"{prefix}{meta}{t}")


def print_results(data: Dict[str, object], show_misses: bool = False) -> None:
    summary = data.get("summary", {})
    analysis = data.get("analysis", {})

    click.echo()
    click.echo(_colored("  ╔═══════════════════════════════════════════════╗", B_CYAN))
    click.echo(_colored("  ║            OSINT SCAN RESULTS                 ║", B_CYAN))
    click.echo(_colored("  ╚═══════════════════════════════════════════════╝", B_CYAN))
    click.echo()

    click.echo(_colored("  ┌── TARGET IDENTITY ──────────────────────────┐", B_WHITE))
    click.echo(f"  │ Query      : {_colored(str(data.get('query', '')), WHITE, bold=True)}")
    display_name = data.get("display_name", "")
    name_format = data.get("name_format", "")
    if display_name:
        click.echo(f"  │ Name       : {_colored(name_format or display_name, B_WHITE, bold=True)}")
    first = data.get("first_name", "")
    last = data.get("last_name", "")
    if first or last:
        click.echo(f"  │ Split      : {_colored(first, GREEN)} {_colored(last, B_GREEN) if last else ''}")
    mid = data.get("middle_name", "")
    if mid:
        click.echo(f"  │ Middle     : {_colored(mid, YELLOW)}")
    title = data.get("title", "")
    suffix = data.get("suffix", "")
    if title or suffix:
        click.echo(f"  │ Title/Sfx  : {_colored(title, YELLOW)} / {_colored(suffix, YELLOW)}")
    initials = data.get("initials", "")
    if initials:
        click.echo(f"  │ Initials   : {_colored(initials, YELLOW)}")
    reversed_name = data.get("reversed_name", "")
    if reversed_name:
        click.echo(f"  │ Reversed   : {_colored(reversed_name, YELLOW)}")
    aliases = data.get("aliases") or []
    if aliases:
        click.echo(f"  │ Aliases    : {_colored(', '.join(str(a) for a in aliases[:10]), GREEN)}")
    click.echo(_colored("  └────────────────────────────────────────────────┘", B_WHITE))

    click.echo()
    click.echo(_colored("  ┌── SCAN OVERVIEW ───────────────────────────┐", B_WHITE))
    click.echo(f"  │ Sources    : {_colored(str(data.get('source_count', 0)), B_CYAN)}")
    handles = data.get("handles", [])
    click.echo(f"  │ Handles    : {_colored(', '.join(handles[:8]) or 'N/A', YELLOW)}")
    click.echo(f"  │ Hits       : {_colored(str(summary.get('hits', 0)), B_GREEN, bold=True)}")
    click.echo(f"  │ Possible   : {_colored(str(summary.get('possible', 0)), B_YELLOW)}")
    click.echo(f"  │ Probed     : {_colored(str(summary.get('checked', 0)), CYAN)}")
    if analysis:
        conf = analysis.get("confidence", "NONE")
        score = analysis.get("confidence_score", 0)
        click.echo(f"  │ Confidence : {_colored(f'{conf} ({score}/100)', B_GREEN if conf == 'HIGH' else B_YELLOW)}")
    click.echo(_colored("  └────────────────────────────────────────────────┘", B_WHITE))

    email = data.get("email", {})
    if email:
        click.echo()
        click.echo(_colored("  ┌── EMAIL INTELLIGENCE ─────────────────────┐", B_CYAN))
        if email.get("is_email"):
            click.echo(f"  │ Domain     : {_colored(email.get('domain', 'N/A'), YELLOW)}")
            mx = email.get("mx_records") or []
            click.echo(f"  │ MX Records : {_colored(', '.join(mx[:3]) if mx else 'none', GREEN if mx else RED)}")
            if email.get("mx_secure"):
                click.echo(f"  │ MX Secure  : {_colored('✓ Yes', B_GREEN)}")
            grav = email.get("gravatar", {})
            gs = grav.get("exists")
            click.echo(f"  │ Gravatar   : {_colored('✓ EXISTS' if gs else '✗ None', B_GREEN if gs else DIM)}")
            pgp = email.get("pgp_key")
            if pgp:
                click.echo(f"  │ PGP Key    : {_colored('✓ Found', B_GREEN)}")
        else:
            click.echo(f"  │ Candidates : {_colored(str(len(email.get('candidates', []))), YELLOW)} generated")
            signals = email.get("candidate_signals") or []
            if signals:
                click.echo(f"  │ Live       : {_colored(str(len(signals)), GREEN)} confirmed")
                for s in signals[:5]:
                    click.echo(f"  │   → {s.get('email')}")

        breaches = email.get("breaches") or []
        if breaches:
            click.echo(f"  │ Breaches   : {_colored(str(len(breaches)), B_RED)} found")
            for b in breaches[:8]:
                if isinstance(b, dict):
                    src = b.get("source", "?")
                    cls = b.get("data_class", "")[:60]
                    click.echo(f"  │   ⚠ {_colored(src, YELLOW)}: {cls}")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_CYAN))

    phone = data.get("phone", {})
    if phone and "error" not in phone:
        click.echo()
        click.echo(_colored("  ┌── PHONE INTELLIGENCE ─────────────────────┐", B_CYAN))
        click.echo(f"  │ Number    : {_colored(phone.get('number', ''), YELLOW)}")
        click.echo(f"  │ Country   : {_colored(phone.get('country', 'N/A'), YELLOW)}")
        click.echo(f"  │ Carrier   : {_colored(phone.get('carrier', 'N/A'), YELLOW)}")
        click.echo(f"  │ Type      : {_colored(phone.get('line_type', 'N/A'), YELLOW)}")
        soc = phone.get("social_found", [])
        if soc:
            click.echo(f"  │ Social    : {_colored(', '.join(soc), GREEN)}")
        mentions = phone.get("google_mentions", 0)
        if mentions:
            click.echo(f"  │ Web       : {_colored(f'~{mentions} mentions', YELLOW)}")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_CYAN))

    domain = data.get("domain", {})
    if domain:
        click.echo()
        click.echo(_colored("  ┌── DOMAIN INTELLIGENCE ────────────────────┐", B_CYAN))
        click.echo(f"  │ Domain    : {_colored(domain.get('domain', ''), YELLOW)}")
        click.echo(f"  │ Registrar : {_colored(domain.get('registrar', 'N/A'), YELLOW)}")
        click.echo(f"  │ Created   : {_colored(domain.get('creation_date', 'N/A'), YELLOW)}")
        ns = domain.get("name_servers", [])
        if ns:
            click.echo(f"  │ NS        : {_colored(', '.join(ns[:3]), YELLOW)}")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_CYAN))

    metadata = data.get("metadata", {})
    if metadata:
        click.echo()
        click.echo(_colored("  ┌── METADATA & HISTORY ─────────────────────┐", B_WHITE))
        wb = metadata.get("wayback", {})
        if wb.get("total_archived"):
            cnt = wb.get("total_archived", 0)
            click.echo(f"  │ Wayback   : {_colored(str(cnt) + ' snapshots', GREEN)}")
            o = wb.get("oldest", "")[:10]; n = wb.get("newest", "")[:10]
            click.echo(f"  │   Range   : {_colored(o + ' → ' + n, DIM)}")
        gc = metadata.get("google_cache", {})
        if gc.get("available"):
            click.echo(f"  │ Cache     : {_colored('Available', GREEN)} ({gc.get('cached_date','')})")
        pb = metadata.get("pastebin", {})
        pastes = pb.get("pastes_found", [])
        if pastes:
            click.echo(f"  │ Pastebin  : {_colored(str(len(pastes)) + ' pastes', YELLOW)}")
        gh = metadata.get("github", {})
        if gh.get("code_results", "0") != "0":
            cr = gh.get("code_results", "0")
            click.echo(f"  │ GitHub    : {_colored(cr + ' code results', YELLOW)}")
        gm = metadata.get("google_mentions", {})
        if gm.get("total_results", "0") != "0":
            tr = gm.get("total_results", "0")
            click.echo(f"  │ Google    : {_colored('~' + tr + ' results', YELLOW)}")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_WHITE))

    profiles = data.get("profiles", [])
    visible = [p for p in profiles if show_misses or p.get("status") in {"hit", "possible", "unknown"}]
    if visible:
        click.echo()
        click.echo(_colored("  ┌── PROFILE RESULTS ─────────────────────────┐", B_GREEN))
        for item in visible[:60]:
            s = item.get("status", "")
            p = item.get("platform", "")
            u = item.get("url", "")
            label = _colored(s.upper(), _status_color(s), bold=s in {"hit", "possible"})
            click.echo(f"  │ {label}  {_colored(p, DIM)} → {u[:80]}")
        if len(visible) > 60:
            click.echo(f"  │ ... and {len(visible) - 60} more")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_GREEN))

    clusters = analysis.get("clusters", {}) if isinstance(analysis, dict) else {}
    if clusters:
        click.echo()
        click.echo(_colored("  ┌── CATEGORY BREAKDOWN ──────────────────────┐", B_WHITE))
        for cat, items in list(clusters.items())[:8]:
            click.echo(f"  │ {_colored(cat, B_WHITE)} ({len(items)} hits)")
            for item in items[:4]:
                title_part = f" :: {item.get('title')}"[:60] if item.get("title") else ""
                click.echo(f"  │   • {item.get('platform')}{title_part}")
        click.echo(_colored("  └────────────────────────────────────────────────┘", B_WHITE))

    click.echo()
    click.echo(_colored("  ┌── TRACE LEADS ──────────────────────────────┐", B_YELLOW))
    for lead in data.get("trace_leads", [])[:20]:
        click.echo(f"  │ {_colored(lead.get('name', ''), DIM)}")
        click.echo(f"  │   {lead.get('url', '')}")
    click.echo(_colored("  └────────────────────────────────────────────────┘", B_YELLOW))
    click.echo()


def save_json(data: Dict[str, object], output: str) -> None:
    path = Path(output)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    click.echo(_colored(f"\n  [+] OSINT report saved: {path}", B_GREEN))
