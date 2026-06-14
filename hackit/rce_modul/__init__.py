import os, sys, json, click, asyncio, re, ssl, urllib.request, urllib.parse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

from go_bridge import GoEngine
from rust_bridge import RustEngine
from cpp_bridge import CPPEngine
from c_bridge import CEngine

console = Console()

BANNER = """
[bold red]
   ███████╗ ██████╗███████╗    ███████╗██╗  ██╗███████╗
   ██╔════╝██╔════╝██╔════╝    ██╔════╝╚██╗██╔╝██╔════╝
   █████╗  ██║     █████╗      █████╗   ╚███╔╝ █████╗  
   ██╔══╝  ██║     ██╔══╝      ██╔══╝   ██╔██╗ ██╔══╝  
   ██║     ╚██████╗███████╗    ███████╗██╔╝ ██╗███████╗
   ╚═╝      ╚═════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝
   ┌───────────────────────────────────────────────────┐
   │  [yellow][🔪] CHAINSAW ACTIVATED. CUTTING THROUGH FIREWALL[/yellow]│
   │  [red][💀] RCE.EXE — SLASH. EXECUTE. DESTROY.[/red]            │
   │  [cyan][X]  HackIT V2.1 - By AniipID[/cyan]                    │
   │  [green][+] 4 Engines: Go | Rust | C++ | C[/green]                │
   │  [green][+] 150+ Payloads · 12 Techniques[/green]                 │
   │  [green][+] WAF Bypass · OOB · Blind · SSTI[/green]               │
   └───────────────────────────────────────────────────┘
[/bold red]"""

def _colored(msg, color=None):
    if color:
        return f"[{color}]{msg}[/{color}]"
    return msg

def display_banner():
    console.print(BANNER)
    console.print("[dim]Advanced RCE detection with 4-engine correlation[/dim]\n")

def pick_engine(preferred: str = "go"):
    engines = {
        "go": GoEngine(),
        "rust": RustEngine(),
        "cpp": CPPEngine(),
        "c": CEngine(),
    }
    if preferred in engines:
        return engines[preferred]
    return engines["go"]

def correlate_results(all_results: list) -> list:
    by_url_param = {}
    for engine_name, results in all_results:
        for r in results:
            if not isinstance(r, dict) or r.get('error'):
                continue
            key = (r.get('url', ''), r.get('parameter', ''))
            if key not in by_url_param:
                by_url_param[key] = {'results': [], 'max_conf': 0.0}
            by_url_param[key]['results'].append(r)
            conf = r.get('confidence', 0)
            if conf > by_url_param[key]['max_conf']:
                by_url_param[key]['max_conf'] = conf

    correlated = []
    for (url, param), data in by_url_param.items():
        engine_count = len(data['results'])
        avg_conf = sum(r.get('confidence', 0) for r in data['results']) / max(engine_count, 1)
        if engine_count >= 2:
            avg_conf = min(1.0, avg_conf + 0.15)
        best = max(data['results'], key=lambda r: r.get('confidence', 0))
        best['confidence'] = avg_conf
        best['correlation_count'] = engine_count
        correlated.append(best)

    correlated.sort(key=lambda r: r.get('confidence', 0), reverse=True)
    return correlated

def display_results(results: list, show_raw: bool = False):
    vuln_results = [r for r in results if r.get('vulnerable') and not r.get('error')]
    safe_results = [r for r in results if not r.get('vulnerable') and not r.get('error')]
    errors = [r for r in results if r.get('error')]

    if vuln_results:
        table = Table(
            title=f"[bold red]⚠ {len(vuln_results)} RCE Vulnerability(ies) Detected[/bold red]",
            box=box.HEAVY,
            border_style="red",
            header_style="bold white on red"
        )
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Parameter", style="yellow")
        table.add_column("Technique", style="magenta")
        table.add_column("Confidence", justify="center")
        table.add_column("Engine(s)", justify="center")
        table.add_column("Output", style="dim")

        for r in vuln_results:
            engines = r.get('engine', '?')
            if r.get('correlation_count', 1) > 1:
                engines += f" (+{r['correlation_count']-1})"
            conf_str = f"{r.get('confidence', 0)*100:.0f}%"
            output = r.get('output', '')[:80]
            table.add_row(
                r.get('url', '')[:50],
                r.get('parameter', '?'),
                r.get('technique', '?'),
                conf_str,
                engines,
                output
            )
        console.print(table)

        for r in vuln_results:
            if r.get('command') and r.get('output'):
                output_text = r['output']
                if len(output_text) > 500:
                    output_text = output_text[:500] + "..."
                console.print(Panel(
                    f"[bold green]Command:[/bold green] {r['command']}\n\n[dim]{output_text}[/dim]",
                    title=f"Exploit Output [{r.get('engine','?')}]",
                    border_style="green",
                    box=box.ROUNDED
                ))
    else:
        console.print("[bold yellow]⚠ No RCE vulnerabilities detected.[/bold yellow]")
        if safe_results:
            console.print(f"[dim]{len(safe_results)} parameter(s) tested, all clean.[/dim]")

    if errors:
        console.print(f"\n[red]{len(errors)} engine error(s):[/red]")
        for e in errors:
            console.print(f"  [red]✗ {e.get('error', 'Unknown error')}[/red]")

def discover_params(url: str, timeout: int = 10) -> list:
    params = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        html = resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        console.print(f"[yellow]⚠ Page fetch failed: {e}[/yellow]")
        html = ""

    parsed = urllib.parse.urlparse(url)
    for k in urllib.parse.parse_qs(parsed.query):
        params.add(k)
    for m in re.finditer(r'<input[^>]*name="([^"]+)"', html, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'<select[^>]*name="([^"]+)"', html, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'<textarea[^>]*name="([^"]+)"', html, re.I):
        params.add(m.group(1))
    for m in re.finditer(r'href="[^"]*\?([^"]+)"', html, re.I):
        for pair in m.group(1).split('&'):
            if '=' in pair:
                params.add(pair.split('=')[0].strip())

    common = ['q','id','cmd','exec','command','url','host','file','input','search',
        'c','code','lang','debug','action','process','run','system','shell',
        'page','dir','folder','path','cat','read','include','require','open',
        'doc','document','template','view','load','import','config','setting',
        'option','opt','key','token','pass','password','user','username','email']
    for d in common:
        params.add(d)

    return sorted(params)

def scan_rce(
    url: str,
    cmd: Optional[str] = None,
    data: Optional[str] = None,
    param: Optional[str] = None,
    method: str = "GET",
    timeout: int = 10,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    ua: Optional[str] = None,
    blind: bool = False,
    all_params: bool = False,
    threads: int = 10,
    engines: str = "go,rust,cpp",
    exploit: bool = False,
    detect: bool = True,
    verbose: bool = False
) -> list:
    selected_engines = [e.strip().lower() for e in engines.split(',') if e.strip()]
    all_results = []

    engine_map = {
        'go': ('Go', GoEngine()),
        'rust': ('Rust', RustEngine()),
        'cpp': ('C++', CPPEngine()),
        'c': ('C', CEngine()),
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Initializing RCE engines...", total=len(selected_engines))

        for eng_name in selected_engines:
            if eng_name not in engine_map:
                continue
            name, eng = engine_map[eng_name]
            progress.update(task, description=f"[cyan]Running {name} engine...")

            if not eng.available:
                console.print(f"[yellow]⚠ {name} compiler not found, skipping[/yellow]")
                all_results.append((name, [{"error": f"{name} compiler not available"}]))
                progress.advance(task)
                continue

            if not eng.ensure_compiled():
                console.print(f"[yellow]⚠ {name} engine compilation failed, skipping[/yellow]")
                all_results.append((name, [{"error": f"{name} compilation failed"}]))
                progress.advance(task)
                continue

            try:
                kwargs = {
                    'data': data, 'param': param, 'method': method,
                    'timeout': timeout, 'proxy': proxy, 'cookie': cookie,
                    'ua': ua, 'blind': blind, 'verbose': verbose,
                    'json': True,
                }
                if threads:
                    kwargs['threads'] = threads
                if all_params:
                    kwargs['all_params'] = True

                if exploit or cmd:
                    kwargs['exploit'] = True
                    kwargs['cmd'] = cmd or 'id'
                else:
                    kwargs['detect'] = True

                results = eng.run(url, **kwargs)
                all_results.append((name, results))
            except Exception as e:
                all_results.append((name, [{"error": str(e)}]))
                console.print(f"[red]✗ {name} engine error: {e}[/red]")

            progress.advance(task)

    correlated = correlate_results(all_results) if detect else []
    for r in correlated:
        if 'correlation_count' in r:
            engines_used = ', '.join(e for e, _ in all_results if not any(x.get('error') for x in _))
            r['engine'] = engines_used
    return correlated if detect else all_results

def scan_rce_api(
    url: str,
    cmd: Optional[str] = None,
    method: str = "GET",
    timeout: int = 10,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    engines: str = "go"
) -> list:
    return scan_rce(
        url=url, cmd=cmd, method=method, timeout=timeout,
        proxy=proxy, cookie=cookie, engines=engines,
        exploit=bool(cmd), detect=not bool(cmd),
        verbose=False
    )


@click.command(name="rce")
@click.option('-u', '--url', required=True, help='Target URL (with parameters)')
@click.option('-c', '--cmd', help='Command to execute (exploit mode)')
@click.option('-d', '--data', help='POST data body')
@click.option('-p', '--param', help='Specific parameter to test')
@click.option('-m', '--method', default='GET', help='HTTP method (GET/POST), default: GET')
@click.option('--timeout', default=10, type=int, help='Request timeout in seconds')
@click.option('--proxy', help='HTTP proxy (e.g. http://127.0.0.1:8080)')
@click.option('--cookie', help='Cookie header value')
@click.option('--ua', help='Custom User-Agent')
@click.option('--blind', is_flag=True, help='Use blind/time-based detection')
@click.option('--all-params', is_flag=True, help='Test all URL/body parameters')
@click.option('--threads', default=10, type=int, help='Concurrent threads (Go engine)')
@click.option('--engines', default='go,rust,cpp,c', help='Engines to use: go,rust,cpp,c (comma-separated)')
@click.option('--exploit', is_flag=True, help='Force exploit mode')
@click.option('--detect', is_flag=True, help='Force detection mode')
@click.option('--output', help='Save results to JSON file')
@click.option('--find', is_flag=True, help='Discover & test all parameters from page for RCE')
@click.option('--verbose', is_flag=True, help='Verbose output')
def rce_command(url, cmd, data, param, method, timeout, proxy, cookie, ua, blind, all_params, threads, engines, exploit, detect, output, verbose, find):
    """Advanced RCE Detection & Exploitation Engine (Go · Rust · C++ · C)

    Detects Remote Code Execution vulnerabilities using multi-engine correlation.
    Supports time-based, output-based, error-based, and blind boolean techniques.
    """
    display_banner()

    if proxy:
        os.environ['HTTP_PROXY'] = proxy
        os.environ['HTTPS_PROXY'] = proxy

    if find:
        console.print("[cyan][*] Parameter discovery mode[/cyan]")
        console.print(f"[cyan][*] Discovering parameters from page content + common names...[/cyan]")
        params = discover_params(url, timeout)
        console.print(f"[green][+] Testing {len(params)} unique parameters[/green]\n")

        selected = [e.strip().lower() for e in engines.split(',') if e.strip()]
        engine_map = {
            'go': ('Phase 1', GoEngine()),
            'rust': ('Phase 2', RustEngine()),
            'cpp': ('Phase 3', CPPEngine()),
            'c': ('Phase 4', CEngine()),
        }

        total = len(params) * len(selected)
        count = 0
        all_find_results = []

        import subprocess
        eng_bins = {}
        for eng_name in selected:
            if eng_name not in engine_map:
                continue
            label, eng = engine_map[eng_name]
            if not eng.available or not eng.ensure_compiled():
                continue
            eng_bins[eng_name] = (label, eng.binary_path)

        for param_name in params:
            procs = []
            for eng_name, (label, bin_path) in eng_bins.items():
                count += 1
                console.print(f"\r[cyan][*] Testing parameter [bold]{param_name}[/bold] on {label} ({count}/{total})...[/cyan]", end="")
                cmd = [bin_path, '-u', url, '-p', param_name, '--detect', '--json',
                       '--timeout', str(timeout)]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                procs.append((eng_name, p, label))
                sys.stdout.flush()
            for eng_name, p, label in procs:
                try:
                    stdout, _ = p.communicate(timeout=timeout + 15)
                    if stdout:
                        eng_results = json.loads(stdout)
                        for r in eng_results:
                            if isinstance(r, dict) and r.get('vulnerable'):
                                r['parameter'] = param_name
                                r['engine'] = eng_name
                                all_find_results.append(r)
                except subprocess.TimeoutExpired:
                    p.kill()
                except Exception:
                    pass

        console.print("\n")
        find_results = all_find_results

        if find_results:
            table = Table(
                title=f"[bold red]⚠ {len(find_results)} RCE Parameter(s) Discovered[/bold red]",
                box=box.HEAVY, border_style="red", header_style="bold white on red"
            )
            table.add_column("Parameter", style="yellow")
            table.add_column("Engine", justify="center")
            table.add_column("Technique", style="magenta")
            table.add_column("Confidence", justify="center")
            table.add_column("Output", style="dim")
            for r in find_results:
                conf_str = f"{r.get('confidence', 0)*100:.0f}%"
                output = r.get('output', '')[:60]
                table.add_row(
                    r.get('parameter', '?'),
                    r.get('engine', '?'),
                    r.get('technique', '?'),
                    conf_str, output
                )
            console.print(table)
        else:
            console.print("[bold yellow]⚠ No vulnerable parameters discovered.[/bold yellow]")

        if any(r.get('vulnerable') for r in find_results):
            console.print("\n[bold red]⚠ VULNERABILITY CONFIRMED: Remote Code Execution[/bold red]")
        return

    if not detect and cmd:
        exploit = True

    results = scan_rce(
        url=url, cmd=cmd, data=data, param=param,
        method=method, timeout=timeout, proxy=proxy,
        cookie=cookie, ua=ua, blind=blind,
        all_params=all_params, threads=threads,
        engines=engines, exploit=exploit or bool(cmd),
        detect=detect or not bool(cmd),
        verbose=verbose
    )

    display_results(results)

    if output:
        try:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"\n[green]✓ Results saved to {output}[/green]")
        except Exception as e:
            console.print(f"\n[red]✗ Failed to save results: {e}[/red]")

    if results and any(r.get('vulnerable') for r in results):
        console.print("\n[bold red]⚠ VULNERABILITY CONFIRMED: Remote Code Execution[/bold red]")
        console.print("[dim]Recommended action: Validate and patch immediately.[/dim]")
    else:
        console.print("\n[bold green]✓ Target appears secure against tested RCE vectors.[/bold green]")
