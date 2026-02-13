"""
Subdomain Enumeration Module (Go-Powered)
"""
import click
import os
import tempfile
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW
from .go_bridge import get_engine

@click.command()
@click.option('-d', '--domain', required=True, help='Target domain (e.g. example.com)')
@click.option('-w', '--wordlist', type=click.Path(exists=True), help='Wordlist for active brute force')
@click.option('--passive-only', is_flag=True, help='Run only passive enumeration (fast)')
@click.option('--active-only', is_flag=True, help='Run only active brute force')
@click.option('--permutations', is_flag=True, help='Run permutation scanning (Altdns style)')
@click.option('--takeover', is_flag=True, help='Check for subdomain takeover vulnerabilities')
@click.option('--recursive', '--deep', is_flag=True, help='Enable deep recursive scanning (scans found subdomains)')
@click.option('--stealth', is_flag=True, help='Enable stealth mode (random UA, public resolvers, traffic shaping)')
@click.option('--fast', is_flag=True, help='Enable Fast Mode (Higher concurrency, shorter timeouts)')
@click.option('--sc', is_flag=True, help='Display Status Code (200, 301, 403, etc)')
@click.option('--ip', is_flag=True, help='Display IP Address')
@click.option('--title', is_flag=True, help='Display Web Page Title')
@click.option('--server', '--web-server', is_flag=True, help='Display Web Server Header')
@click.option('--tech-detect', '--tech', is_flag=True, help='Detect Technologies (CMS, Frameworks, Servers)')
@click.option('--asn', is_flag=True, help='Display ASN Information')
@click.option('--probe', is_flag=True, help='Display Probe Status (Alive/Dead)')
@click.option('-fc', '--filter-codes', help='Filter response with specified status code (e.g. 403,401)')
@click.option('-t', '--threads', default=100, help='Number of threads (Go routines)')
@click.option('-o', '--output', help='Save output to JSON file')
def enumerate(domain, wordlist, passive_only, active_only, permutations, takeover, recursive, stealth, fast, sc, ip, title, server, tech_detect, asn, probe, filter_codes, threads, output):
    """
    Advanced Subdomain Enumeration & Takeover Scanner (Go-Powered).
    Combines passive sources, active brute forcing, permutations, recursion, zone transfers, and HTTP probing.
    Powered by a high-performance Golang engine.
    """
    display_tool_banner('Subdomain Scanner')
    
    engine = get_engine()
    
    if not engine.available:
        click.echo(_colored("[!] Go is not installed or not found in PATH.", RED))
        click.echo("    Please install Go (Golang) to use this module.")
        return

    click.echo(f"[*] Target: {_colored(domain, BLUE, bold=True)}")
    click.echo(f"[*] Engine: {_colored('HackIT', GREEN)}")
    
    # Mode Summary
    modes = []
    if not active_only: modes.append("Passive")
    if not passive_only: modes.append("Active")
    if permutations: modes.append("Permutations")
    if recursive: modes.append("Deep Scan")
    if takeover: modes.append("Takeover")
    if probe or sc or title or tech_detect: modes.append("Probing")
    
    click.echo(f"[*] Modes: {', '.join(modes)}")
    if fast: click.echo(f"[*] Fast Mode: {_colored('ON', YELLOW)}")
    if stealth: click.echo(f"[*] Stealth Mode: {_colored('ON', YELLOW)}")

    # Compile if needed
    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go worker.", RED))
        return

    # Run
    click.echo("-" * 60)
    success = engine.run(
        domain=domain,
        wordlist=wordlist,
        passive_only=passive_only,
        active_only=active_only,
        permutations=permutations,
        takeover=takeover,
        recursive=recursive,
        stealth=stealth,
        fast=fast,
        sc=sc,
        ip=ip,
        title=title,
        server=server,
        tech_detect=tech_detect,
        asn=asn,
        probe=probe,
        filter_codes=filter_codes,
        threads=threads,
        output=output
    )
    click.echo("-" * 60)
    
    if success:
        click.echo(_colored("[+] Scan Completed Successfully.", GREEN))
        if output:
            click.echo(f"[+] Results saved to: {output}")
    else:
        click.echo(_colored("[!] Scan encountered errors.", RED))

if __name__ == '__main__':
    enumerate()
