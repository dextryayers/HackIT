#!/usr/bin/env python3
"""
HackIt - Security Testing CLI Tool Suite
Main CLI interface combining all tools
"""
import click
import sys
import os

from hackit.header_audit import check as check_headers
from hackit.dir_finder import dirfinder as expert_dir_finder
from hackit.subdomain import enumerate as scan_subdomains
from hackit.network_scanner import scan_range
from hackit.tech_hunter import detect as detect_tech
from hackit.ssl_tool import scan_ssl as analyze_ssl
from hackit.web_fuzzer import fuzzer as industrial_fuzzer

from hackit.params import fuzz_params
from hackit.xss import scan_xss
from hackit.sqli import test_sqli
from hackit.redirect import find_redirects
from hackit.js import analyze_js
from hackit.cve import check_cve
from hackit.osint import osint as osint_console
from hackit.agent import agent
from hackit.ddos import ddos as ddos_attack
from hackit.ui import display_banner, _colored, YELLOW, GREEN, B_GREEN, B_CYAN, B_WHITE, DIM, RED, MAGENTA, BLUE, CYAN, B_MAGENTA, B_RED, B_BLUE, B_YELLOW, WHITE, BG_BLUE, BG_CYAN, BG_MAGENTA
from hackit.config import load_config, save_config, set_theme, DEFAULT_CONFIG


@click.group(invoke_without_command=True)
@click.version_option(version='2.1.0', prog_name='HackIt')
@click.option('--proxy', default=None, help='[HACKIT] Proxy URL for tools (e.g., http://127.0.0.1:8080)')
@click.option('--no-verify', is_flag=True, help='[HACKIT] Disable SSL certificate verification globally')
@click.option('--no-banner', is_flag=True, help='[HACKIT] Disable startup banner')
@click.option('--verbose', is_flag=True, help='[HACKIT] Enable verbose logging (DEBUG)')
@click.pass_context
def cli(ctx, proxy, no_verify, no_banner, verbose):
    """
    🚀 HackIt - Hexa-Engine Penetration Testing Framework 🚀


    
    A professional-grade security suite for research and vulnerability assessment.
    Combines Go, Rust, C, Python, Ruby, and Lua for unmatched speed and precision.

    ⚠️ AUTHORIZED USE ONLY.

    Usage: hackit [options]
    """
    # Export chosen global settings to environment so modules can read them.
    if proxy:
        os.environ['HACKIT_PROXY'] = proxy
    # HACKIT_VERIFY: '1' or '0'
    os.environ['HACKIT_VERIFY'] = '0' if no_verify else '1'
    if no_banner:
        os.environ['HACKIT_NO_BANNER'] = '1'
    # Set global logging verbosity
    import logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    # Display a fancy banner on startup
    try:
        display_banner()
    except Exception:
        # don't fail CLI on banner errors
        pass

    # If no subcommand was provided, enter console automatically
    if ctx.invoked_subcommand is None:
        from hackit.console import start_console
        start_console(cli)
        return


# Top-level commands
cli.add_command(expert_dir_finder, name='dirfinder')

# Port Scanning
@cli.group()
def ports():
    """Port scanning tools (Nmap-Inspired Penta-Engine)"""
    pass

from hackit.port_scanner import scan_ports as nmap_scan
ports.add_command(nmap_scan, name='scan')


# HTTP/Web Tools
@cli.group()
def web():
    """Web scanning and analysis tools"""
    pass

web.add_command(check_headers, name='headers')
web.add_command(detect_tech, name='tech')
web.add_command(industrial_fuzzer, name='fuzz')
web.add_command(analyze_js, name='js')
web.add_command(fuzz_params, name='params')

import importlib
run_bypass_cli = importlib.import_module("hackit.403bypass").run_bypass_cli
web.add_command(run_bypass_cli, name='403bypass')


# Vulnerability Scanners
@cli.group()
def vuln():
    """Vulnerability scanning tools"""
    pass

vuln.add_command(scan_xss, name='xss')
vuln.add_command(test_sqli, name='sqli')
vuln.add_command(find_redirects, name='redirect')

from hackit.rce_modul import rce_command
vuln.add_command(rce_command, name='rce')

from hackit.atomix import atomix_command
vuln.add_command(atomix_command, name='atomix')


# Recon Tools
@cli.group()
def recon():
    """Reconnaissance tools"""
    pass

recon.add_command(scan_subdomains, name='subdomains')
recon.add_command(scan_range, name='ips')
recon.add_command(detect_tech, name='tech-hunter')
recon.add_command(osint_console, name='osint')
cli.add_command(osint_console, name='osint')


# SSL/TLS Tools
@cli.group()
def ssl():
    """SSL/TLS analysis tools"""
    pass

ssl.add_command(analyze_ssl, name='check')


# DDoS Tools
cli.add_command(ddos_attack, name='ddos')

# Utility Tools
@cli.group()
def util():
    """Utility and analysis tools"""
    pass

util.add_command(check_cve, name='cve')
cli.add_command(agent, name='agent')

# Wireless Tools
@cli.command()
def wireless():
    """Launch the Interactive Wireless Penetration Console"""
    from hackit.wireless.console import start_wireless_console
    start_wireless_console()

@cli.command()
def whoami():
    """Display the current system user info"""
    import getpass
    import platform
    user = getpass.getuser()
    system = platform.system()
    node = platform.node()
    click.echo(_colored("\n  [ USER IDENTITY ]", B_CYAN))
    click.echo(f"  • User     : " + _colored(user, B_GREEN))
    click.echo(f"  • Device   : " + _colored(node, B_GREEN))
    click.echo(f"  • Platform : " + _colored(system, YELLOW))
    click.echo()

@cli.command()
def banner():
    """Display the main HackIt banner"""
    from hackit.ui import display_banner
    # We clear the environment flag temporarily to ensure it prints
    old_flag = os.environ.get('HACKIT_NO_BANNER')
    if 'HACKIT_NO_BANNER' in os.environ:
        del os.environ['HACKIT_NO_BANNER']
    
    display_banner(force=True)
    
    # Restore the flag if it was there
    if old_flag:
        os.environ['HACKIT_NO_BANNER'] = old_flag


# Example usage command
@cli.command()
def examples():
    """Show usage examples"""
    examples_text = """
    EXAMPLES:
    • Ports:    $ hackit ports scan -p 80,443 --targets example.com
    • Recon:    $ hackit recon subdomains -d target.com
    • OSINT:    $ hackit recon osint
    • Web:      $ hackit web headers --url https://example.com
    • Web UI:   $ hackit run                 # Launch web dashboard
    • Web UI:   $ hackit run --dev           # Dev mode with live-reload
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --dbs
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --dump-all
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" scan
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" crawl --mode full
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" extract --technique blind
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" dump mydb users
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" readfile --file /etc/passwd
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" exec --cmd "id"
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" network --target 10.0.0.1
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" bypass --user admin
    • Vuln:     $ hackit vuln rce -u "http://site.com?cmd=ls" --detect
    • Vuln:     $ hackit vuln rce -u "http://site.com?cmd=ls" -c "whoami" --exploit
    • Vuln:     $ hackit vuln atomix -u "https://example.com"
    • Vuln:     $ hackit vuln atomix -u "https://example.com" --severity critical
    • CVE:      $ hackit util cve --software apache --version 2.4.49
    • Wireless: $ hackit wireless sniff -i wlan0 --monitor
    • DDoS:     $ hackit ddos
    """
    click.echo(examples_text)


@cli.command()
@click.option('--theme', type=click.Choice(['kali', 'cyberpunk', 'minimalist', 'retro', 'gacor', 'powerline', 'modern', 'pill', 'nexus', 'zinc', 'vault', 'storm', 'drift', 'pulse', 'slash']), help='Change terminal theme')
@click.option('--user', help='Change display username')
@click.option('--host', help='Change display hostname')
@click.option('--accent', type=click.Choice(['cyan', 'magenta', 'green', 'blue', 'red', 'yellow', 'white']), help='Set accent color')
@click.option('--border', type=click.Choice(['double', 'single', 'rounded', 'block', 'ascii', 'none']), help='Set border character style')
@click.option('--prompt', type=click.Choice(['arrow', 'hash', 'dollar', 'lambda', 'skull', 'none']), help='Set prompt style')
@click.option('--reset', is_flag=True, help='Reset to factory defaults')
@click.pass_context
def config(ctx, theme, user, host, accent, border, prompt, reset):
    """Configure HackIt terminal CLI theme (15 modes)"""
    cfg = load_config()
    changed = False

    if reset:
        cfg = DEFAULT_CONFIG.copy()
        save_config(cfg)
        click.echo(_colored("  [+] All settings reset to factory defaults.", B_GREEN))
        return

    if theme:
        cfg["theme"] = theme
        click.echo(_colored(f"  [+] Theme changed to: {theme.upper()}", B_GREEN))
        changed = True

    if user:
        cfg["user"] = user
        click.echo(_colored(f"  [+] Username changed to: {user}", B_CYAN))
        changed = True

    if host:
        cfg["hostname"] = host
        click.echo(_colored(f"  [+] Hostname changed to: {host}", B_CYAN))
        changed = True

    if accent:
        cfg["accent"] = accent
        click.echo(_colored(f"  [+] Accent color set to: {accent.upper()}", B_GREEN))
        changed = True

    if border:
        cfg["border"] = border
        click.echo(_colored(f"  [+] Border style set to: {border.upper()}", B_GREEN))
        changed = True

    if prompt:
        cfg["prompt"] = prompt
        click.echo(_colored(f"  [+] Prompt style set to: {prompt.upper()}", B_GREEN))
        changed = True

    if changed:
        save_config(cfg)
        click.echo(_colored("  [*] Configuration updated.", DIM))
    else:
        accent_map = {
            'cyan': CYAN, 'magenta': MAGENTA, 'green': GREEN,
            'blue': BLUE, 'red': RED, 'yellow': YELLOW, 'white': B_WHITE
        }
        ac = accent_map.get(cfg['accent'], CYAN)

        border_chars = {
            'double':  {'tl':'╔','tr':'╗','bl':'╚','br':'╝','h':'═','v':'║'},
            'single':  {'tl':'┌','tr':'┐','bl':'└','br':'┘','h':'─','v':'│'},
            'rounded': {'tl':'╭','tr':'╮','bl':'╰','br':'╯','h':'─','v':'│'},
            'block':   {'tl':'█','tr':'█','bl':'█','br':'█','h':'█','v':'█'},
            'ascii':   {'tl':'+','tr':'+','bl':'+','br':'+','h':'-','v':'|'},
            'none':    {'tl':' ','tr':' ','bl':' ','br':' ','h':' ','v':' '},
        }
        bc = border_chars.get(cfg['border'], border_chars['double'])

        prompt_chars = {
            'arrow': '└─$', 'hash': '#', 'dollar': '$',
            'lambda': 'λ', 'skull': '☠', 'none': ''
        }
        pp = prompt_chars.get(cfg['prompt'], '└─$')

        BOX_W = 52

        import re as _re
        _strip_ansi = _re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

        def _bx(line):
            visible = len(_strip_ansi.sub('', line))
            pad = BOX_W - visible
            if pad < 0:
                pad = 0
            return f"  {_colored(bc['v'], ac)} {line}{' '*pad} {_colored(bc['v'], ac)}"

        click.echo(f"\n  {_colored(bc['tl'], ac)}{_colored(bc['h']*BOX_W, ac)}{_colored(bc['tr'], ac)}")
        click.echo(_bx(f"  {_colored('H A C K I T   T H E M E   C O N F I G', B_WHITE)}"))
        click.echo(f"  {_colored(bc['bl'], ac)}{_colored(bc['h']*BOX_W, ac)}{_colored(bc['br'], ac)}")
        click.echo()

        click.echo(_bx(f"{_colored('Theme', B_WHITE)}  {_colored('»', DIM)}  {_colored(cfg['theme'].upper(), YELLOW)}"))
        click.echo(_bx(f"{_colored('User', B_WHITE)}   {_colored('»', DIM)}  {_colored(cfg['user'], ac)}"))
        click.echo(_bx(f"{_colored('Host', B_WHITE)}   {_colored('»', DIM)}  {_colored(cfg['hostname'], ac)}"))
        click.echo(_bx(f"{_colored('Accent', B_WHITE)} {_colored('»', DIM)}  {_colored(cfg['accent'].upper(), ac)}"))
        click.echo(_bx(f"{_colored('Border', B_WHITE)} {_colored('»', DIM)}  {_colored(cfg['border'].upper(), ac)}"))
        click.echo(_bx(f"{_colored('Prompt', B_WHITE)} {_colored('»', DIM)}  {_colored(cfg['prompt'].upper(), ac)}"))

        click.echo(_bx(f"{_colored('─'*BOX_W, DIM)}"))

        u = cfg['user']
        h = cfg['hostname']
        ctx = 'main'
        t = cfg['theme']

        theme_previews = {
            'kali':       f"{_colored('┌──(', DIM)}{_colored(u, ac)}{_colored('㉿', DIM)}{_colored(h, ac)}{_colored(')-[', DIM)}{_colored('10:00', DIM)}{_colored(']-[', DIM)}{_colored(ctx, B_MAGENTA)}{_colored(']', DIM)} {_colored('└─$', ac)}",
            'cyberpunk':  f"{_colored(u, B_CYAN)}{_colored(' ❯❯ ', B_MAGENTA)}{_colored(f'[{ctx}]', B_GREEN)}",
            'minimalist': f"{_colored(f'hackit({ctx}) > ', DIM)}",
            'retro':      f"{_colored(f'{u}@{h}:{ctx}$ ', B_GREEN)}",
            'gacor':      f"{_colored('🔥 ', YELLOW)}{_colored(f'[{u}@{h}]', B_MAGENTA)}{_colored(f' ⚙️  {ctx}', B_CYAN)}{_colored(' 🚀 ', B_GREEN)}",
            'powerline':  f"{_colored(f' {u} ', BG_BLUE+WHITE)}{_colored(f' {ctx} ', BG_CYAN+WHITE)}{_colored(f' 10:00 ', BG_MAGENTA+WHITE)} {_colored('❯', DIM)}",
            'modern':     f"{_colored(f'{u} ', B_CYAN)}{_colored('❯ ', B_MAGENTA)}{_colored(ctx, B_GREEN)}{_colored(' ❯ ', B_MAGENTA)}",
            'pill':       f"{_colored(f'({u}) ', BG_BLUE+WHITE)}{_colored(f'({ctx}) ', B_GREEN)} {_colored('➜', DIM)}",
            'nexus':      f"{_colored('❯❯', B_CYAN)} {_colored(f'[{u}]', B_BLUE)} {_colored(f'[{ctx}]', B_CYAN)} {_colored('>>', B_BLUE)}",
            'zinc':       f"{_colored(f'[{u}@HackIT]', B_GREEN)} {_colored('➜', WHITE)} {_colored(ctx, B_GREEN)} {_colored('➜', WHITE)}",
            'vault':      f"{_colored('[[', B_WHITE)} {_colored(f'{u}@HackIT', B_CYAN)} {_colored(']]', B_WHITE)} {_colored('[[', B_WHITE)} {_colored(ctx, B_CYAN)} {_colored(']]', B_WHITE)} {_colored('$', B_WHITE)}",
            'storm':      f"{_colored('[⚡', B_YELLOW)} {_colored(u, B_MAGENTA)} {_colored('⚡]', B_YELLOW)} {_colored(f'[{ctx}]', B_MAGENTA)} {_colored('#', B_YELLOW)}",
            'drift':      f"{_colored(f'[{u}@hackit:', B_CYAN)}{_colored(ctx, B_MAGENTA)}{_colored(']', B_CYAN)} {_colored('➤', B_WHITE)}",
            'pulse':      f"{_colored(f'[{u}]', B_GREEN)} {_colored('←', B_BLUE)} {_colored(f'[{ctx}]', B_GREEN)} {_colored('->', B_BLUE)} {_colored('$', B_GREEN)}",
            'slash':      f"{_colored('//', B_RED)} {_colored(u, WHITE)} {_colored('//', B_RED)} {_colored(ctx, WHITE)} {_colored('//', B_RED)} {_colored('#', WHITE)}",
        }
        prompt_str = theme_previews.get(t, f"{_colored(u, ac)}{_colored('@', DIM)}{_colored(h, ac)} {_colored(pp, B_GREEN)} {_colored('command', DIM)}")
        click.echo(_bx(f"{_colored('Preview', B_WHITE)} {_colored('»', DIM)}  {prompt_str}"))

        click.echo(f"  {_colored(bc['tl'], ac)}{_colored(bc['h']*BOX_W, ac)}{_colored(bc['tr'], ac)}")
        click.echo()

        click.echo(_colored(f"  {_colored('Help', B_WHITE)}", DIM))
        click.echo(f"  {_colored('config', YELLOW)}                                    {_colored('show current config', DIM)}")
        click.echo(f"  {_colored('config --theme <name>', YELLOW)}                      {_colored('switch terminal visual theme', DIM)}")
        click.echo(f"  {_colored('config --user <name>', YELLOW)}                       {_colored('set display username', DIM)}")
        click.echo(f"  {_colored('config --host <name>', YELLOW)}                       {_colored('set display hostname', DIM)}")
        click.echo(f"  {_colored('config --accent <color>', YELLOW)}                    {_colored('set accent highlight color', DIM)}")
        click.echo(f"  {_colored('config --border <style>', YELLOW)}                    {_colored('set border box style', DIM)}")
        click.echo(f"  {_colored('config --prompt <style>', YELLOW)}                    {_colored('set prompt symbol', DIM)}")
        click.echo(f"  {_colored('config --reset', YELLOW)}                             {_colored('restore factory defaults', DIM)}")
        click.echo()

        click.echo(_colored(f"  {_colored('Options', B_WHITE)}", DIM))
        click.echo(f"  {_colored('Theme', B_WHITE)}  : {_colored('kali, cyberpunk, minimalist, retro, gacor, powerline, modern, pill, nexus, zinc, vault, storm, drift, pulse, slash', DIM)}")
        click.echo(f"  {_colored('Accent', B_WHITE)} : {_colored('cyan, magenta, green, blue, red, yellow, white', DIM)}")
        click.echo(f"  {_colored('Border', B_WHITE)} : {_colored('double, single, rounded, block, ascii, none', DIM)}")
        click.echo(f"  {_colored('Prompt', B_WHITE)} : {_colored('arrow, hash, dollar, lambda, skull, none', DIM)}")
        click.echo()


@cli.command()
def help_tools():
    """Show detailed tool information"""
    tools_text = """
    QUICK REFERENCE:
    • run           - Launch web UI dashboard (Astro + Python)
    • ports scan    - Async TCP port scanner
    • dirfinder     - Expert directory finder
    • web headers   - Security header audit
    • web tech      - Tech stack detection
    • web dirs      - Recursive directory bruteforce
    • web fuzz      - Parameter reflection fuzzer
    • web js        - JavaScript endpoint analysis
    • vuln xss      - Reflected XSS scanner (Go + Python engines)
    • vuln sqli     - SQLi scanner (997 payloads, 16 DBMS)
    • vuln redirect - Open redirect finder
    • vuln atomix   - Nuclei-style YAML template scanner
    • recon subs    - Subdomain bruteforcer
    • recon osint   - Interactive public footprint scanner
    • ssl check     - TLS/SSL certificate audit
    • util cve      - Vulnerability lookup
    • wireless sniff- Monitor mode sniffing & PCAP
    • wireless crack- High-speed dictionary attack
    • ddos         - DDoS stress testing (SYN/UDP/ACK/RST/ICMP/DNS/NTP)
    """
    click.echo(tools_text)


@cli.command()
@click.pass_context
def console(ctx):
    """Launch interactive HackIt console"""
    from hackit.console import start_console
    start_console(cli)


@cli.command()
@click.option('--dev', is_flag=True, help='Start Astro dev server (live-reload) instead of static build')
@click.option('--port', default=8080, type=int, help='Port for the web UI (default: 8080)')
@click.option('--no-open', is_flag=True, help="Don't auto-open browser")
def run(dev, port, no_open):
    """Launch the HackIT Unified Intelligence Web UI Dashboard (Astro + Python)

    Starts the full web interface on localhost with the Python/FastAPI backend
    and the Astro frontend (static build or dev server).

    Examples:

      hackit run                    # Production mode (static build)

      hackit run --dev              # Development mode (live-reload)

      hackit run --port 3000        # Custom port

    """
    import subprocess
    import os
    import sys
    import time
    import webbrowser
    from hackit.ui import B_GREEN, B_CYAN, B_YELLOW, RED, DIM
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    webui_dir = os.path.join(root_dir, 'webUI')
    webui_main = os.path.join(webui_dir, 'main.py')
    dist_dir = os.path.join(webui_dir, 'dist')
    src_dir = os.path.join(webui_dir, 'src')
    python_dir = os.path.join(webui_dir, 'python')
    
    click.echo(_colored(f"\n  {'='*54}", B_CYAN))
    click.echo(_colored(f"  >>>  HACKIT UNIFIED INTELLIGENCE WEB UI  <<<", B_CYAN))
    click.echo(_colored(f"  {'='*54}", B_CYAN))
    click.echo()
    
    if not os.path.exists(webui_main):
        click.echo(_colored(f"  [!] NOT FOUND: {webui_main}", RED))
        click.echo(_colored(f"  [!] Run this command from the HackIT root directory.", RED))
        return

    # ── 1. Check environment & install deps ──
    node_ok = False
    npm_ok = False
    try:
        subprocess.run(['node', '--version'], capture_output=True, check=True)
        node_ok = True
        subprocess.run(['npm', '--version'], capture_output=True, check=True)
        npm_ok = True
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    if not node_ok or not npm_ok:
        click.echo(_colored("  [!] Node.js/npm not found. Install Node.js to build the frontend.", B_YELLOW))
        click.echo(_colored("  [*] Attempting to start backend-only (API at /api)...", DIM))

    # ── 2. Install npm deps if missing ──
    astro_process = None
    node_modules_dir = os.path.join(webui_dir, 'node_modules')
    if node_ok and npm_ok and not os.path.exists(node_modules_dir):
        click.echo(_colored("  [*] Installing npm dependencies (npm install)...", B_YELLOW))
        try:
            result = subprocess.run(
                ['npm', 'install'],
                cwd=webui_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                click.echo(_colored("  [+] npm install successful.", B_GREEN))
            else:
                click.echo(_colored(f"  [!] npm install warnings:\n{result.stderr[:300]}", B_YELLOW))
        except subprocess.TimeoutExpired:
            click.echo(_colored("  [!] npm install timed out.", RED))
        except Exception as e:
            click.echo(_colored(f"  [!] npm install failed: {e}", RED))

    # ── 3. Build or start Astro dev server ──
    if node_ok and npm_ok:
        if dev:
            click.echo(_colored("  [*] Starting Astro dev server (live-reload)...", B_GREEN))
            astro_process = subprocess.Popen(
                ['npm', 'run', 'dev', '--', '--port', str(port)],
                cwd=webui_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            click.echo(_colored(f"  [+] Astro dev server starting on http://localhost:{port}", B_CYAN))
        else:
            needs_build = not os.path.exists(dist_dir)
            if not needs_build and os.path.exists(src_dir):
                dist_index = os.path.join(dist_dir, 'index.html')
                if os.path.exists(dist_index):
                    dist_mtime = os.path.getmtime(dist_index)
                    for root, dirs, files in os.walk(src_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            if os.path.getmtime(fp) > dist_mtime:
                                needs_build = True
                                break
                        if needs_build:
                            break

            if needs_build:
                click.echo(_colored("  [*] Building Astro frontend (npm run build)...", B_YELLOW))
                try:
                    result = subprocess.run(
                        ['npm', 'run', 'build'],
                        cwd=webui_dir,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        click.echo(_colored("  [+] Frontend build successful.", B_GREEN))
                    else:
                        click.echo(_colored(f"  [!] Build failed:\n{result.stderr[:500]}", RED))
                        click.echo(_colored(f"  [!] Build stdout:\n{result.stdout[:500]}", B_YELLOW))
                except subprocess.TimeoutExpired:
                    click.echo(_colored("  [!] Frontend build timed out.", RED))
            else:
                click.echo(_colored("  [*] Frontend build is up to date.", DIM))
    else:
        click.echo(_colored("  [*] Skipping frontend build (Node.js not available).", DIM))

    # ── 3. Install Python dependencies ──
    req_file = os.path.join(python_dir, 'requirements.txt')
    if os.path.exists(req_file):
        click.echo(_colored("  [*] Checking Python dependencies...", DIM))
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-q', '-r', req_file],
                cwd=python_dir, capture_output=True, timeout=60,
            )
        except Exception:
            pass

    # ── 4. Start Python backend ──
    click.echo(_colored(f"\n  [+] Starting Python backend on http://localhost:{port}", B_GREEN))
    click.echo(_colored(f"  [+] API endpoint: http://localhost:{port}/api", B_CYAN))
    click.echo()

    backend_env = os.environ.copy()
    if dev:
        backend_env['DEBUG_MODE'] = 'True'
    else:
        backend_env.pop('DEBUG_MODE', None)

    try:
        backend = subprocess.Popen(
            [sys.executable, 'main.py'],
            cwd=python_dir,
            env=backend_env,
        )

        # Wait for backend to start
        for i in range(10):
            time.sleep(0.5)
            if backend.poll() is not None:
                break
            try:
                import httpx
                r = httpx.get(f'http://localhost:{port}/api/ping', timeout=2)
                if r.status_code == 200:
                    click.echo(_colored(f"  [+] Backend is ready! Open your browser to:", B_GREEN))
                    click.echo(_colored(f"      http://localhost:{port}", B_CYAN))
                    click.echo()
                    if not no_open:
                        webbrowser.open(f'http://localhost:{port}')
                    break
            except Exception:
                continue

        click.echo(_colored("  [*] Press Ctrl+C to stop all services.", DIM))
        click.echo(_colored(f"  {'─'*54}", DIM))
        click.echo()

        backend.wait()

    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Shutting down services...", B_YELLOW))
    finally:
        if astro_process and astro_process.poll() is None:
            astro_process.terminate()
            try:
                astro_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                astro_process.kill()
        if backend and backend.poll() is None:
            backend.terminate()
            try:
                backend.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend.kill()
        click.echo(_colored("  [+] All services stopped. Goodbye!", B_GREEN))



if __name__ == '__main__':
    cli()
