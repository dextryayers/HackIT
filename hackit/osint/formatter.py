"""
Terminal formatting helpers for the OSINT module.
"""

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
    if status == "hit":
        return B_GREEN
    if status == "possible":
        return B_YELLOW
    if status == "unknown":
        return CYAN
    return DIM


def print_live_finding(finding) -> None:
    url = getattr(finding, "url", "")
    platform = getattr(finding, "platform", "")
    handle = getattr(finding, "handle", "")
    code = getattr(finding, "http_status", None)
    status = getattr(finding, "status", "")

    if status == "hit":
        prefix = _colored("[+] Found     :", B_GREEN, bold=True)
    elif status == "possible":
        prefix = _colored("[?] Possible  :", B_YELLOW, bold=True)
    elif status == "unknown":
        prefix = _colored("[!] Unknown   :", CYAN, bold=True)
    else:
        prefix = _colored("[-] Not Found :", B_RED, bold=True)

    meta = _colored(f" [{platform} | {handle} | {code if code is not None else 'ERR'}]", DIM)
    title = getattr(finding, "title", "")
    title_part = _colored(f" :: {title[:70]}", DIM) if title and status in {"hit", "possible"} else ""
    click.echo(f"  {prefix} {url}{meta}{title_part}")


def print_results(data: Dict[str, object], show_misses: bool = False) -> None:
    summary = data.get("summary", {})
    click.echo(_colored("\n  [ TARGET SUMMARY ]", B_CYAN, bold=True))
    click.echo(f"  Query       : {_colored(str(data.get('query', '')), WHITE, bold=True)}")
    click.echo(f"  Sources     : {_colored(str(data.get('source_count', 0)), YELLOW)}")
    click.echo(f"  Probes      : {_colored(str(data.get('planned_probes', 0)), YELLOW)}")
    click.echo(f"  Handles     : {_colored(', '.join(data.get('handles', [])) or 'N/A', YELLOW)}")
    click.echo(
        "  Profiles    : "
        + _colored(str(summary.get("hits", 0)), B_GREEN, bold=True)
        + " hits | "
        + _colored(str(summary.get("possible", 0)), B_YELLOW, bold=True)
        + " possible | "
        + _colored(str(summary.get("unknown", 0)), CYAN, bold=True)
        + f" unknown / {summary.get('checked', 0)} checked"
    )
    analysis = data.get("analysis", {})
    if analysis:
        click.echo(
            "  Confidence  : "
            + _colored(str(analysis.get("confidence", "NONE")), B_GREEN if analysis.get("confidence") == "HIGH" else B_YELLOW)
            + f" ({analysis.get('confidence_score', 0)}/100)"
        )
        top_handles = analysis.get("top_handles") or []
        if top_handles:
            click.echo(f"  Best Handles : {_colored(', '.join(top_handles), GREEN)}")

        top_categories = analysis.get("top_categories") or []
        if top_categories:
            cat_text = ", ".join(f"{item['category']}={item['hits']}" for item in top_categories[:8])
            click.echo(f"  Hit Clusters : {_colored(cat_text, YELLOW)}")

    email = data.get("email", {})
    click.echo(_colored("\n=============================== EMAIL ===============================", B_CYAN, bold=True))
    candidates = email.get("candidates") or []
    if candidates:
        for candidate in candidates[:30]:
            click.echo(f"  {candidate}")

    if email.get("is_email"):
        click.echo(f"  Domain      : {_colored(email.get('domain', 'N/A'), YELLOW)}")
        mx = email.get("mx_records") or []
        click.echo(f"  MX Records  : {_colored(', '.join(mx) if mx else 'not found', GREEN if mx else RED)}")
        gravatar = email.get("gravatar") or {}
        g_status = gravatar.get("exists")
        click.echo(f"  Gravatar    : {_colored(str(g_status), B_GREEN if g_status else DIM)} {gravatar.get('url', '')}")
    signals = email.get("candidate_signals") or []
    if signals:
        click.echo(_colored("\n  [ POSSIBLE EMAIL SIGNALS ]", B_CYAN, bold=True))
        for signal in signals:
            click.echo(f"  [+] {signal.get('email')} -> {signal.get('source')} :: {signal.get('url')}")

    visible = [
        item for item in data.get("profiles", [])
        if show_misses or item.get("status") in {"hit", "possible", "unknown"}
    ]
    if visible:
        click.echo(_colored("\n  [ PUBLIC PROFILE CHECKS ]", B_CYAN, bold=True))
        table = TablePrinter(["STATUS", "PLATFORM", "HANDLE", "URL"], max_col_width=24)
        table.print_header()
        for item in visible[:80]:
            status = item.get("status", "")
            label = _colored(status.upper(), _status_color(status), bold=status in {"hit", "possible"})
            table.print_row([
                label,
                item.get("platform", ""),
                item.get("handle", ""),
                item.get("url", ""),
            ])
        table.print_footer()

    click.echo(_colored("\n  [ TRACE LEADS ]", B_CYAN, bold=True))
    for lead in data.get("trace_leads", [])[:40]:
        click.echo(f"  - {_colored(lead.get('name', ''), YELLOW)}: {lead.get('url', '')}")

    analysis = data.get("analysis", {})
    clusters = analysis.get("clusters", {}) if isinstance(analysis, dict) else {}
    if clusters:
        click.echo(_colored("\n  [ CATEGORY CLUSTERS ]", B_CYAN, bold=True))
        for category, items in list(clusters.items())[:10]:
            click.echo(_colored(f"  {category}", B_WHITE, bold=True))
            for item in items[:6]:
                title = f" :: {item.get('title')}" if item.get("title") else ""
                click.echo(f"    - {item.get('platform')} / {item.get('handle')} -> {item.get('url')}{title}")


def save_json(data: Dict[str, object], output: str) -> None:
    path = Path(output)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    click.echo(_colored(f"\n  [+] OSINT report saved: {path}", B_GREEN))
