"""
Advanced Open Redirect Finder — Interactive Dual Engine (Go + Python)
"""
import click
import json
import threading
import itertools
import time
import sys
from typing import Dict, Any, List, Optional

from hackit.ui import display_tool_banner, _colored, B_CYAN, B_GREEN, B_RED, B_YELLOW, B_WHITE, DIM, RED, GREEN, RESET
from .go_bridge import GoEngine

SSL_BANNER = """
===================================
>>>>  R  E  D  I  R  E  C  T  <<<<
>>>>  H  a  c  k  I  T  V  2  <<<<
===================================
[*] PARAMETERS LOADED: 25
[*] BYPASS TECHNIQUES: ACTIVE
[*] TARGET: [ PARAM REDIRECT ]
===================================
[01] Query Param    [02] Body POST
[03] Header Inject  [04] Path Inject
[05] DOM/Client     [06] WAF Bypass
[07] Blind Redirect [08] Deep Payload
[09] Cookie Inject  [10] Encoding Matrix
===================================
"""


class _Spinner:
    def __init__(self, msg="[*] Scanning..."):
        self.msg = msg
        self._stop = threading.Event()

    def __enter__(self):
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
        return self

    def __exit__(self, *args):
        self._stop.set()
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()

    def _spin(self):
        chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        while not self._stop.is_set():
            for c in chars:
                sys.stdout.write(f'\r  {c} {self.msg}')
                sys.stdout.flush()
                time.sleep(0.08)
                if self._stop.is_set():
                    return


def _display_results(target: str, results: List[Dict[str, Any]], duration: float, total_requests: int):
    if not results:
        click.echo(f"\n  {_colored('[-] NOT FOUND', B_RED, bold=True)}  >  {_colored(target, DIM)}")
        click.echo(f"\n  {_colored('=' * 55, DIM)}")
        click.echo(f"  {_colored('No open redirect vulnerabilities detected.', DIM)}")
        click.echo(f"  Duration: {_colored(str(round(duration, 2)) + 's', B_WHITE)}  |  "
                    f"Requests: {_colored(str(total_requests), B_WHITE)}")
        click.echo(f"  {_colored('=' * 55, DIM)}")
        return

    total = len(results)
    engine_count = len(set(r.get('engine', 'Unknown') for r in results))

    click.echo(f"\n  {_colored('=' * 55, DIM)}")
    click.echo(f"  {_colored('OPEN REDIRECT VULNERABILITY REPORT', B_RED, bold=True)}")
    click.echo(f"  {_colored('=' * 55, DIM)}")
    click.echo(f"  Target    : {_colored(target, B_CYAN, bold=True)}")
    click.echo(f"  Found     : {_colored(str(total), B_RED, bold=True)} vulnerabilities across "
                f"{_colored(str(engine_count), B_WHITE)} engines")
    click.echo(f"  Duration  : {_colored(str(round(duration, 2)) + 's', B_WHITE)}  |  "
                f"Requests: {_colored(str(total_requests), B_WHITE)}")

    engines = {}
    for r in results:
        eng = r.get('engine', 'Unknown')
        engines.setdefault(eng, []).append(r)

    for eng, vulns in engines.items():
        click.echo(f"\n  {_colored('[ENGINE]', B_CYAN)} {_colored(eng, B_WHITE, bold=True)} ({len(vulns)})")
        for v in vulns:
            url = v.get('url', 'N/A')
            param = v.get('parameter', '')
            payload = v.get('payload', '')
            location = v.get('location', '')
            confidence = v.get('confidence', 'MEDIUM')

            conf_color = B_GREEN if confidence == 'HIGH' else (B_YELLOW if confidence == 'MEDIUM' else DIM)
            click.echo(f"\n    {_colored('[+] FOUND VULNERABILITY', B_GREEN, bold=True)}  >  {_colored(url, DIM)}")
            if param:
                click.echo(f"        Parameter   : {_colored(param, B_CYAN)}")
            if payload:
                click.echo(f"        Payload     : {_colored(payload, B_YELLOW)}")
            if location:
                click.echo(f"        Redirects   : {_colored(location[:120], B_CYAN)}")
            click.echo(f"        Status      : {v.get('http_status', 'N/A')}")
            click.echo(f"        Confidence  : {_colored(confidence, conf_color, bold=True)}")

    click.echo(f"\n  {_colored('=' * 55, DIM)}")


@click.command()
@click.pass_context
def find_redirects(ctx):
    """Advanced Open Redirect Vulnerability Scanner — Interactive Mode"""

    click.echo(SSL_BANNER)
    click.echo(f"\n  {_colored('Example:', DIM)} https://example.com/?view=")
    click.echo()

    engine_obj = GoEngine()
    if not engine_obj.available:
        click.echo(_colored("  [!] Go is not installed. Please install Go 1.21+.", RED))
        return

    while True:
        raw = click.prompt(f"  {_colored('Input Target', B_CYAN, bold=True)}", default="", show_default=False)
        raw = raw.strip()
        if raw.lower() in ('exit', 'quit', 'q', ''):
            click.echo(f"\n  {_colored('[!] Exiting...', DIM)}")
            return

        click.echo()
        start = time.time()

        try:
            with _Spinner(f"Scanning {raw}..."):
                results = engine_obj.run(raw, timeout=15)
        except Exception as e:
            click.echo(f"\r  {_colored(f'[!] Go engine error: {e}', RED)}")
            continue

        duration = time.time() - start
        total_req = len(results)

        error_only = results and len(results) == 1 and 'error' in results[0]
        if error_only:
            click.echo(_colored(f"\n  [!] Error: {results[0]['error']}", RED))
            continue

        _display_results(raw, results, duration, total_req)

        click.echo(f"\n  {_colored('─' * 55, DIM)}")
        click.echo(f"  {_colored('Press Enter to scan another target, or type exit to quit.', DIM)}")
        click.echo(f"  {_colored('─' * 55, DIM)}")
        click.echo()
