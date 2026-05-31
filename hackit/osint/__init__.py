"""
HackIt OSINT interactive module.
"""

from __future__ import annotations

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_YELLOW, DIM, RED, YELLOW
from .banner import display_osint_banner
from .core import normalize_handles, run_full_scan
from .formatter import print_live_finding, print_results
from .history import append_history, load_history, save_auto_report
from .sources import get_social_sources


def start_osint_console() -> None:
    """Run the OSINT tool in guided one-input mode."""
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

    handles = normalize_handles(target)
    source_count = len(get_social_sources())
    click.echo(_colored("\n  [*] Crawling public intelligence matrix...", B_YELLOW, bold=True))
    click.echo(f"  [*] Source templates : {_colored(str(source_count), B_CYAN)}")
    click.echo(f"  [*] Canonical handle : {_colored(handles[0] if handles else 'N/A', B_CYAN)}")
    click.echo(f"  [*] Planned probes   : {_colored(str(source_count * len(handles)), B_GREEN, bold=True)}")
    click.echo(_colored("  [*] Live profile probe stream enabled.\n", DIM))

    try:
        data = run_full_scan(target, on_result=print_live_finding)
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] OSINT scan interrupted.", YELLOW))
        return
    except Exception as exc:
        click.echo(_colored(f"\n  [!] OSINT engine error: {exc}", RED))
        return

    print_results(data)
    append_history(data)
    try:
        report_path = save_auto_report(data)
        click.echo(_colored(f"\n  [*] Auto report: {report_path}", DIM))
    except Exception:
        pass

    click.echo(_colored("\n  [+] OSINT scan complete.", B_GREEN, bold=True))


@click.command(name="osint")
def osint() -> None:
    """Launch guided OSINT profile discovery."""
    start_osint_console()
