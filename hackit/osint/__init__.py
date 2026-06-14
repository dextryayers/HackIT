from __future__ import annotations

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_YELLOW, DIM, RED, YELLOW
from .banner import display_osint_banner
from .core import normalize_handles, run_full_scan
from .formatter import print_live_finding, print_results
from .history import append_history, load_history, save_auto_report
from .sources import get_social_sources


def start_osint_console() -> None:
    """Run the OSINT tool in guided one-input mode (used by hackit console)."""
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
    click.echo(_colored("\n  [*] Crawling public intelligence matrix...", B_YELLOW, bold=True))
    click.echo(f"  [*] Canonical handle : {_colored(handles[0] if handles else 'N/A', B_CYAN)}")
    click.echo(_colored("  [*] Engine            : Rust (native) | Python fallback", B_GREEN))
    click.echo(_colored("  [*] Live profile probe stream enabled.\n", DIM))

    try:
        data = run_full_scan(target, on_result=print_live_finding, use_rust=True,
                             check_phone=True, check_domain=True, generate_html=True)
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
@click.option("--no-rust", is_flag=True, help="Use Python fallback")
@click.option("--phone", is_flag=True, help="Phone intelligence")
@click.option("--domain", is_flag=True, help="Domain WHOIS/DNS")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--output", "-o", default="", help="Output file")
@click.option("--json", "json_out", is_flag=True, help="JSON output")
@click.option("--all", "all_flag", is_flag=True, help="Enable all checks")
def osint(target: str | None = None, proxy: str = "", retry: int = 1, timeout: int = 15,
          workers: int = 50, no_rust: bool = False, phone: bool = False, domain: bool = False,
          html: bool = False, output: str = "", json_out: bool = False, all_flag: bool = False) -> None:
    """Launch guided OSINT profile discovery."""
    if not target and not all_flag:
        start_osint_console()
        return

    if all_flag:
        phone = True; domain = True; html = True

    handles = normalize_handles(target)
    source_count = len(get_social_sources())
    click.echo(_colored("\n  [*] Crawling public intelligence matrix...", B_YELLOW, bold=True))
    click.echo(f"  [*] Source templates : {_colored(str(source_count), B_CYAN)}")
    click.echo(f"  [*] Engine            : {_colored('Rust' if not no_rust else 'Python', B_GREEN)}")

    try:
        data = run_full_scan(target, on_result=print_live_finding,
            use_rust=not no_rust, proxy=proxy or None,
            retry=retry, timeout=timeout, workers=workers,
            check_phone=phone, check_domain=domain,
            generate_html=html, html_output=output)
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
