#!/usr/bin/env python3
"""
HackIt - Security Testing CLI Tool Suite
Main CLI interface combining all tools
"""
import click
import sys
import os

# Import all modules
from hackit.port_scanner import scan_ports
from hackit.header_checker import check_headers
from hackit.subdomain_bruteforcer import brute_subdomains
from hackit.ip_scanner import scan_range
from hackit.tech_detector import detect_tech
from hackit.ssl_analyzer import analyze_ssl
from hackit.dir_bruteforcer import bruteforce_dirs
from hackit.param_fuzzer import fuzz_params
from hackit.xss_scanner import scan_xss
from hackit.sqli_tester import test_sqli
from hackit.redirect_finder import find_redirects
from hackit.js_analyzer import analyze_js
from hackit.cve_checker import check_cve
from hackit.ui import display_banner


@click.group(invoke_without_command=True)
@click.version_option(version='1.0.0', prog_name='HackIt')
@click.option('--proxy', default=None, help='Proxy URL for tools (e.g., http://127.0.0.1:8080)')
@click.option('--no-verify', is_flag=True, help='Disable SSL certificate verification globally')
@click.option('--no-banner', is_flag=True, help='Disable startup banner')
@click.option('--verbose', is_flag=True, help='Enable verbose logging (DEBUG)')
@click.pass_context
def cli(ctx, proxy, no_verify, no_banner, verbose):
    """
    HackIt - Security Testing CLI Tool Suite
    
    A comprehensive penetration testing toolkit with multiple vulnerability scanners
    and reconnaissance tools.
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

    # If no subcommand was provided, show help after banner
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        return


# Port Scanning
@cli.group()
def ports():
    """Port scanning tools"""
    pass

ports.add_command(scan_ports, name='scan')


# HTTP/Web Tools
@cli.group()
def web():
    """Web scanning and analysis tools"""
    pass

web.add_command(check_headers, name='headers')
web.add_command(detect_tech, name='tech')
web.add_command(bruteforce_dirs, name='dirs')
web.add_command(fuzz_params, name='fuzz')
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

recon.add_command(brute_subdomains, name='subdomains')
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
    HackIt - Security Testing CLI Tool Suite
    =========================================
    
    PORT SCANNING (nmap-like):
    $ hackit ports scan -p 1-1000 --targets scanme.nmap.org --open-only
    $ hackit ports scan -p 22,80,443 --targets 192.168.1.1 --output results.json
    $ hackit ports scan -A --targets 10.0.0.0/28 --threads 200 --service-detect --output full_scan.json
    $ hackit ports scan --targets @hosts.txt -p 1-1024 --service-detect
    
    SUBDOMAIN ENUMERATION:
    $ hackit recon subdomains --domain target.com --wordlist wordlist.txt --check-wildcard
    
    HTTP HEADER ANALYSIS:
    $ hackit web headers --url https://example.com --all
    
    SSL/TLS ANALYSIS:
    $ hackit ssl check --host example.com --timeout 10
    
    TECHNOLOGY DETECTION:
    $ hackit web tech --url https://example.com
    
    DIRECTORY BRUTEFORCE:
    $ hackit web dirs --url http://example.com/ --wordlist words.txt --recursive
    
    PARAMETER FUZZING:
    $ hackit web fuzz --url "http://example.com/search.php" --method GET --params q,search --payloads fuzz.txt
    
    XSS SCANNING:
    $ hackit vuln xss --url "http://example.com/search.php" --params q --encoding-test
    
    SQL INJECTION TESTING:
    $ hackit vuln sqli --url "http://example.com/product.php?id=1" --params id
    
    OPEN REDIRECT FINDER:
    $ hackit vuln redirect --url "http://example.com/login.php"
    
    JAVASCRIPT ANALYSIS:
    $ hackit web js --url https://example.com --max-files 100
    
    IP RANGE SCANNING:
    $ hackit recon ips --cidr 192.168.1.0/24 --timeout 2
    
    CVE CHECKING:
    $ hackit util cve --software wordpress --version 5.0.0 --severity Critical
    """
    click.echo(examples_text)


@cli.command()
def help_tools():
    """Show detailed tool information"""
    tools_text = """
    AVAILABLE TOOLS
    ===============
    
    PORTS GROUP:
    • ports scan - Multi-threaded async TCP port scanner
    
    WEB GROUP:
    • web headers - Check HTTP security headers and TLS
    • web tech - Detect web technologies (CMS, frameworks)
    • web dirs - Directory and file bruteforcer with recursion
    • web fuzz - HTTP parameter fuzzer with reflection detection
    • web js - JavaScript analyzer for endpoints and secrets
    
    VULN GROUP:
    • vuln xss - Reflected XSS scanner
    • vuln sqli - SQL injection boolean tester
    • vuln redirect - Open redirect vulnerability finder
    
    RECON GROUP:
    • recon subdomains - DNS subdomain bruteforcer
    • recon ips - IP range scanner (CIDR)
    
    SSL GROUP:
    • ssl check - SSL/TLS certificate analyzer
    
    UTIL GROUP:
    • util cve - CVE vulnerability checker
    """
    click.echo(tools_text)


if __name__ == '__main__':
    cli()
