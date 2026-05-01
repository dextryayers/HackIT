#!/usr/bin/env python3
"""
HackIt - Security Testing CLI Tool Suite
Main CLI interface combining all tools
"""
import click
import sys
import os

# Import all modules
from hackit.port_scanner import scan_ports as nmap_scan
from hackit.dir_finder import dirfinder as expert_dir_finder
from hackit.header_audit import check as check_headers
from hackit.subdomain import enumerate as scan_subdomains
from hackit.network_scanner import scan_range
from hackit.tech_hunter import detect as detect_tech
from hackit.ssl_tool import scan_ssl as analyze_ssl
from hackit.web_fuzzer import fuzz as bruteforce_dirs

from hackit.params import fuzz_params
from hackit.xss import scan_xss
from hackit.sqli import test_sqli
from hackit.redirect import find_redirects
from hackit.js import analyze_js
from hackit.cve import check_cve
from hackit.ui import display_banner


@click.group(invoke_without_command=True)
@click.version_option(version='2.1.0', prog_name='HackIt')
@click.option('--proxy', default=None, help='Proxy URL for tools (e.g., http://127.0.0.1:8080)')
@click.option('--no-verify', is_flag=True, help='Disable SSL certificate verification globally')
@click.option('--no-banner', is_flag=True, help='Disable startup banner')
@click.option('--verbose', is_flag=True, help='Enable verbose logging (DEBUG)')
@click.pass_context
def cli(ctx, proxy, no_verify, no_banner, verbose):
    """
    🚀 HackIt - Hexa-Engine Penetration Testing Framework 🚀

    A professional-grade security suite for research and vulnerability assessment.
    Combines Go, Rust, C, Python, Ruby, and Lua for unmatched speed and precision.

    ⚠️ AUTHORIZED USE ONLY.
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
web.add_command(bruteforce_dirs, name='dirs')
web.add_command(analyze_js, name='js')
web.add_command(fuzz_params, name='fuzz')


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


# Example usage command
@cli.command()
def examples():
    """Show usage examples"""
    examples_text = """
    EXAMPLES:
    • Ports:    $ hackit ports scan -p 80,443 --targets example.com
    • Recon:    $ hackit recon subdomains -d target.com
    • Web:      $ hackit web headers --url https://example.com
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --params id
    • CVE:      $ hackit util cve --software apache --version 2.4.49
    """
    click.echo(examples_text)


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
    • ssl check     - TLS/SSL certificate audit
    • util cve      - Vulnerability lookup
    """
    click.echo(tools_text)


@cli.command()
@click.pass_context
def console(ctx):
    """Launch interactive HackIt console"""
    from hackit.console import start_console
    # We pass the main cli group to the console
    start_console(cli)


if __name__ == '__main__':
    cli()
