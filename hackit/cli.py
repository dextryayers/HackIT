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
from hackit.ui import display_banner, _colored, YELLOW, B_GREEN, B_CYAN, DIM
from hackit.config import load_config, save_config, set_theme


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


# Vulnerability Scanners
@cli.group()
def vuln():
    """Vulnerability scanning tools"""
    pass

vuln.add_command(scan_xss, name='xss')
vuln.add_command(test_sqli, name='sqli')
vuln.add_command(find_redirects, name='redirect')


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
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --params id
    • CVE:      $ hackit util cve --software apache --version 2.4.49
    • Wireless: $ hackit wireless sniff -i wlan0 --monitor
    """
    click.echo(examples_text)


@cli.command()
@click.option('--theme', type=click.Choice(['kali', 'cyberpunk', 'minimalist', 'retro', 'gacor', 'powerline', 'modern', 'pill']), help='Change CLI theme')
@click.option('--user', help='Change display username')
@click.option('--host', help='Change display hostname')
def config(theme, user, host):
    """Configure HackIt settings and themes"""
    cfg = load_config()
    changed = False
    
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
        
    if changed:
        save_config(cfg)
        click.echo(_colored("  [*] Configuration updated successfully.", DIM))
    else:
        # Show current config
        click.echo(_colored("\n  [ HACKIT CONFIGURATION ]", B_CYAN))
        click.echo(f"  • Current Theme : " + _colored(cfg['theme'].upper(), YELLOW))
        click.echo(f"  • Username      : " + _colored(cfg['user'], B_GREEN))
        click.echo(f"  • Hostname      : " + _colored(cfg['hostname'], B_GREEN))
        click.echo(_colored("\n  Available Themes: kali, cyberpunk, minimalist, retro, gacor", DIM))
        click.echo(_colored("  Usage: config --theme <name>\n", DIM))


@cli.command()
def help_tools():
    """Show detailed tool information"""
    tools_text = """
    QUICK REFERENCE:
    • ports scan    - Async TCP port scanner
    • dirfinder     - Expert directory finder
    • web headers   - Security header audit
    • web tech      - Tech stack detection
    • web dirs      - Recursive directory bruteforce
    • web fuzz      - Parameter reflection fuzzer
    • web js        - JavaScript endpoint analysis
    • vuln xss      - Reflected XSS scanner
    • vuln sqli     - SQLi boolean tester
    • vuln redirect - Open redirect finder
    • recon subs    - Subdomain bruteforcer
    • recon osint   - Interactive public footprint scanner
    • ssl check     - TLS/SSL certificate audit
    • util cve      - Vulnerability lookup
    • wireless sniff- Monitor mode sniffing & PCAP
    • wireless crack- High-speed dictionary attack
    """
    click.echo(tools_text)


@cli.command()
@click.pass_context
def console(ctx):
    """Launch interactive HackIt console"""
    from hackit.console import start_console
    start_console(cli)


@cli.command()
def run():
    """Launch the HackIT Unified Intelligence Web UI Dashboard"""
    import subprocess
    import os
    import sys
    from hackit.ui import B_GREEN, B_CYAN, RED
    
    # Path to the unified main.py in webUI
    root_dir = os.path.dirname(os.path.abspath(__file__))
    webui_main = os.path.join(root_dir, 'webUI', 'main.py')
    
    click.echo(_colored("\n  [+] INITIALIZING HACKIT UNIFIED INTELLIGENCE CLUSTER...", B_CYAN))
    click.echo(_colored("  [*] Mode: Unified Python + Astro (Port 8080)", B_CYAN))
    
    if not os.path.exists(webui_main):
        click.echo(_colored(f"  [!] ERROR: Unified entry point not found at {webui_main}", RED))
        return

    try:
        # Execute the unified root main.py
        # Using a quoted string for better Windows compatibility with shell=True
        cmd = f'"{sys.executable}" "{webui_main}"'
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] SESSION TERMINATED BY USER.", RED))
    except Exception as e:
        click.echo(_colored(f"  [!] CRITICAL ERROR: {e}", RED))



if __name__ == '__main__':
    cli()
