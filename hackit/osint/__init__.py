from __future__ import annotations

import sys
import time

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_YELLOW, DIM, RED, YELLOW
from .banner import display_osint_banner
from .core import normalize_handles, run_full_scan
from .formatter import print_live_finding, print_results, save_json
from .history import append_history, load_history, save_auto_report
from .sources import get_social_sources


def _engine_info(use_rust: bool) -> dict:
    if not use_rust:
        return {"engine": "python", "detail": "forced (--no-rust)"}
    try:
        from .go_bridge import engine_status
        return engine_status()
    except Exception as exc:
        return {"engine": "python", "detail": str(exc)}


def _announce_matrix(target: str, deep: bool, verbose: bool, use_rust: bool = True,
                     category: str = "") -> dict:
    handles = normalize_handles(target, deep=deep)
    sources = get_social_sources()
    if category:
        sources = [s for s in sources if s["category"].lower() == category.lower()]
    engine = _engine_info(use_rust)
    mode = "DEEP (variants+years)" if deep else "standard"

    live_collectors = 0
    try:
        from .live_sources import HANDLE_COLLECTORS
        live_collectors = len(HANDLE_COLLECTORS)
    except Exception:
        pass

    click.echo(_colored("\n  [*] Crawling public intelligence matrix...", B_YELLOW, bold=True))
    click.echo(f"  [*] Canonical handle : {_colored(handles[0] if handles else 'N/A', B_CYAN)}")
    if len(handles) > 1:
        click.echo(f"  [*] Handle variants  : {_colored(', '.join(handles[1:8]), DIM)}"
                   + (_colored(f" (+{len(handles) - 8} more)", DIM) if len(handles) > 8 else ""))
    click.echo(f"  [*] Source count     : {_colored(str(len(sources)), B_CYAN)} platforms"
               + (f" + {live_collectors} keyless live collectors" if live_collectors else ""))
    detail = engine.get("detail", "")
    suffix = _colored(f" ({detail})", DIM) if detail else ""
    click.echo(f"  [*] Sweep engine     : "
               f"{_colored(engine['engine'].upper(), B_GREEN if engine['engine'] == 'rust' else YELLOW)}{suffix}")
    click.echo(f"  [*] Mode             : {_colored(mode, B_CYAN)}  ·  "
               f"verbose steps {_colored('ON' if verbose else 'OFF', B_GREEN if verbose else YELLOW)}")
    if category:
        click.echo(f"  [*] Category filter  : {_colored(category, B_CYAN)}")
    click.echo(_colored("  [*] Live profile probe stream enabled.\n", DIM))
    return engine


def start_osint_console() -> None:
    display_osint_banner()
    recent = load_history(limit=3)
    if recent:
        click.echo(_colored("  Recent intelligence runs:", DIM))
        for item in recent:
            click.echo(_colored(
                f"  - {item.get('time')} :: {item.get('query')} :: "
                f"hits={item.get('hits')} checked={item.get('checked')}", DIM))
        click.echo()

    target = click.prompt(_colored("  Target", B_CYAN), default="",
                          show_default=False).strip()
    if not target:
        click.echo(_colored("\n  [*] Returning to main console.", DIM))
        return

    deep = click.confirm(_colored("  Deep variant expansion?", B_CYAN), default=False)
    engine = _announce_matrix(target, deep=deep, verbose=True)

    started = time.time()
    try:
        data = run_full_scan(target, on_result=print_live_finding, use_rust=True,
                             check_phone=True, check_domain=True, generate_html=True,
                             verbose=True, deep=deep)
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] OSINT scan interrupted.", YELLOW))
        return
    except Exception as exc:
        click.echo(_colored(f"\n  [!] OSINT engine error: {exc}", RED))
        return

    data.setdefault("engine", engine["engine"])
    data["elapsed"] = round(time.time() - started, 1)
    print_results(data)
    if data.get("html_report"):
        click.echo(_colored(f"\n  [*] HTML report: {data['html_report']}", B_CYAN))

    append_history(data)
    try:
        report_path = save_auto_report(data)
        click.echo(_colored(f"\n  [*] Auto report: {report_path}", DIM))
    except Exception:
        pass

    click.echo(_colored("\n  [+] OSINT scan complete.", B_GREEN, bold=True))


@click.command(name="osint")
@click.argument("target", required=False)
@click.option("--proxy", "-p", default="", help="Proxy URL")
@click.option("--retry", "-r", default=1, type=int, help="Retry count per probe")
@click.option("--timeout", "-t", default=15, type=int, help="HTTP timeout in seconds")
@click.option("--workers", "-w", default=50, type=int, help="Concurrent workers")
@click.option("--no-rust", is_flag=True, help="Use the built-in sweep instead of the native engine")
@click.option("--phone", is_flag=True, help="Phone intelligence")
@click.option("--domain", is_flag=True, help="Domain RDAP/DNS/subdomain footprint")
@click.option("--html", is_flag=True, help="Generate an HTML report")
@click.option("--output", "-o", default="", help="Output file for --html / --json")
@click.option("--json", "json_out", is_flag=True, help="Emit JSON only on stdout (banner suppressed)")
@click.option("--all", "all_flag", is_flag=True, help="Enable every check")
@click.option("--deep", is_flag=True, help="Expand handle variants (separators, years, affixes)")
@click.option("--category", "-c", default="", help="Only probe sources in this category (e.g. Developer)")
@click.option("--only-live", is_flag=True, help="Hide trace leads in the report")
@click.option("--show", "show", default=25, type=int, show_default=True,
              help="Rows per section before pagination")
@click.option("--all-rows", is_flag=True, help="Print every row, no pagination")
@click.option("--show-misses", is_flag=True, help="List dead ends (miss / blocked)")
@click.option("--no-banner", "no_banner", is_flag=True, help="Suppress the startup banner")
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode: findings + summary only")
def osint(target: str | None = None, proxy: str = "", retry: int = 1, timeout: int = 15,
          workers: int = 50, no_rust: bool = False, phone: bool = False,
          domain: bool = False, html: bool = False, output: str = "",
          json_out: bool = False, all_flag: bool = False, deep: bool = False,
          category: str = "", only_live: bool = False, show: int = 25,
          all_rows: bool = False, show_misses: bool = False,
          no_banner: bool = False, quiet: bool = False) -> None:
    """Launch OSINT profile discovery across 800+ platforms plus keyless live APIs."""
    if not target and not all_flag:
        start_osint_console()
        return

    if all_flag:
        phone = True
        domain = True

    # An HTML report needs an .html path; a JSON dump needs .json.
    if output:
        suffix = ".html" if html else ".json"
        if not output.lower().endswith((".html", ".htm", ".json")):
            output += suffix

    # Machine output must be pure: no banner, no chatter, no progress on stdout.
    if json_out or no_banner:
        import os
        os.environ["HACKIT_NO_BANNER"] = "1"

    verbose = not quiet and not json_out
    engine = {"engine": "python", "detail": "json mode"}
    if not json_out:
        engine = _announce_matrix(target, deep=deep, verbose=verbose,
                                  use_rust=not no_rust, category=category)

    # Resolve the domain/email implied by the target so the collectors run even
    # when the user did not pass --domain explicitly.
    check_domain = domain
    if target and not check_domain:
        stripped = target.strip().lstrip("@")
        if "." in stripped and "@" not in stripped and not stripped.replace(".", "").isdigit():
            if not stripped.split(".")[-1].isdigit():
                check_domain = True

    started = time.time()
    try:
        data = run_full_scan(
            target,
            on_result=None if json_out else print_live_finding,
            use_rust=not no_rust, proxy=proxy or None,
            retry=retry, timeout=timeout, workers=workers,
            check_phone=phone, check_domain=check_domain,
            generate_html=html, html_output=output,
            verbose=verbose, deep=deep, category=category,
        )
    except KeyboardInterrupt:
        if json_out:
            raise SystemExit(130)
        return
    except Exception as error:
        if json_out:
            import json as _json
            click.echo(_json.dumps({"error": str(error)}))
            raise SystemExit(1)
        click.echo(_colored(f"\n  [!] Engine error: {error}", RED))
        return

    data.setdefault("engine", engine["engine"])
    data["elapsed"] = round(time.time() - started, 1)

    if json_out:
        import json as _json
        payload = _json.dumps(data, indent=2, default=str)
        if output:
            from pathlib import Path
            Path(output).write_text(payload, encoding="utf-8")
        click.echo(payload)
        return

    print_results(data, show_misses=show_misses, only_live=only_live,
                  show=show, all_rows=all_rows)

    # --output follows the format: HTML when --html is set, JSON otherwise.
    if output and not html:
        save_json(data, output)

    append_history(data)
    try:
        save_auto_report(data)
    except Exception:
        pass

    if data.get("html_report"):
        click.echo(_colored(f"  [*] HTML report: {data['html_report']}", B_CYAN))
