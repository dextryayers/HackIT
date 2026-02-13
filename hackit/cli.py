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
    🚀 HackIt - Ultimate Hexa-Engine Security & Reconnaissance Suite 🚀

    A professional-grade, high-performance penetration testing framework designed 
    for elite security researchers and bug bounty hunters. HackIt leverages a 
    unique Hexa-Engine architecture to deliver unmatched speed and depth.

    🏗️ ARCHITECTURE:
    - Go & Rust Core: Mass scanning and parallel processing at scale.
    - C & C++ Engines: Ultra-fast low-level networking and expert service/OS fingerprinting.
    - Python Intelligence: Advanced logic, WAF bypass, and smart analysis layers.
    - Ruby Orchestrator: Dynamic CLI interaction and task management.
    - Lua Scripting: NSE-inspired modular scripting for custom vulnerability checks.

    🔥 KEY CAPABILITIES:
    - DIR FINDER: Deep discovery with 8 specialized attributes and auto-hidden file detection.
    - PORT SCANNER: Nmap-aligned scanning (SYN Stealth, UDP, OS Detect) with Timing T0-T5.
    - WEB INTEL: Real-time technology profiling, WAF detection, and JS endpoint extraction.
    - VULN ENGINE: Automated testing for XSS, SQLi, Open Redirects, and CVE matching.
    - STEALTH MODE: Integrated proxy rotation, Tor support, and packet fragmentation.

    ⚡ PERFORMANCE:
    Engineered for speed, HackIt can handle massive CIDR ranges and large wordlists 
    using asynchronous I/O and multi-threaded execution across 6 programming languages.

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

    # If no subcommand was provided, show help after banner
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
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
    • dirfinder - Expert Quad-Engine Directory & File Finder (Ruby+Go+Rust+Python)
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
