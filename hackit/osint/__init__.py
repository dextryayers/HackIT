from __future__ import annotations

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_YELLOW, DIM, RED, YELLOW
from .banner import display_osint_banner
from .core import normalize_handles, run_full_scan
from .formatter import print_live_finding, print_results
from .history import append_history, load_history, save_auto_report
from .sources import get_social_sources, SOCIAL_SOURCES


def _announce_matrix(target: str, deep: bool, verbose: bool) -> None:
    handles = normalize_handles(target, deep=deep)
    sources = get_social_sources()
    mode = "DEEP (variants+years)" if deep else "standard"
    click.echo(_colored("\n  [*] Crawling public intelligence matrix...", B_YELLOW, bold=True))
    click.echo(f"  [*] Canonical handle : {_colored(handles[0] if handles else 'N/A', B_CYAN)}")
    if len(handles) > 1:
        click.echo(f"  [*] Handle variants  : {_colored(', '.join(handles[1:8]), DIM)}{_colored(f' (+{len(handles) - 8} more)' if len(handles) > 8 else '', DIM)}")
    click.echo(f"  [*] Source count     : {_colored(str(len(sources)), B_CYAN)} platforms")
    click.echo(f"  [*] Mode             : {_colored(mode, B_CYAN)}  ·  verbose steps {_colored('ON' if verbose else 'OFF', B_GREEN if verbose else YELLOW)}")
    click.echo(_colored("  [*] Live profile probe stream enabled.\n", DIM))


def start_osint_console() -> None:
    display_osint_banner()
    recent = load_history(limit=3)
    if recent:
        click.echo(_colored("  Recent intelligence runs:", DIM))
        for item in recent:
            click.echo(_colored(f"  - {item.get('time')} :: {item.get('query')} :: hits={item.get('hits')} checked={item.get('checked')}", DIM))
        click.echo()

    target = click.prompt(_colored("  Target", B_CYAN), default="", show_default=False).strip()
    if not target:
        click.echo(_colored("\n  [*] Returning to main console.", DIM))
        return

    deep = click.confirm(_colored("  Deep variant expansion?", B_CYAN), default=False)
    _announce_matrix(target, deep=deep, verbose=True)

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
@click.option("--retry", "-r", default=1, type=int, help="Retry count")
@click.option("--timeout", "-t", default=15, type=int, help="HTTP timeout")
@click.option("--workers", "-w", default=50, type=int, help="Concurrent workers")
@click.option("--no-rust", is_flag=True, help="Use built-in sweep instead of native engine")
@click.option("--phone", is_flag=True, help="Phone intelligence")
@click.option("--domain", is_flag=True, help="Domain WHOIS/DNS")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--output", "-o", default="", help="Output file")
@click.option("--json", "json_out", is_flag=True, help="JSON output")
@click.option("--all", "all_flag", is_flag=True, help="Enable all checks")
@click.option("--deep", is_flag=True, help="Expand handle variants (separators, years, affixes)")
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode: findings + summary only")
def osint(target: str | None = None, proxy: str = "", retry: int = 1, timeout: int = 15,
          workers: int = 50, no_rust: bool = False, phone: bool = False, domain: bool = False,
          html: bool = False, output: str = "", json_out: bool = False, all_flag: bool = False,
          deep: bool = False, quiet: bool = False) -> None:
    """Launch OSINT profile discovery across 800+ platforms."""
    if not target and not all_flag:
        start_osint_console()
        return

    if all_flag:
        phone = True; domain = True; html = True

    verbose = not quiet
    _announce_matrix(target, deep=deep, verbose=verbose)

    try:
        data = run_full_scan(target, on_result=print_live_finding,
            use_rust=not no_rust, proxy=proxy or None,
            retry=retry, timeout=timeout, workers=workers,
            check_phone=phone, check_domain=domain,
            generate_html=html, html_output=output,
            verbose=verbose, deep=deep)
    except KeyboardInterrupt:
        return
    except Exception as exc:
        click.echo(_colored(f"\n  [!] Engine error: {exc}", RED))
        return

    if json_out:
        import json as j
        click.echo(j.dumps(data, indent=2, default=str))
        return

    print_results(data)
    append_history(data)
    save_auto_report(data)
