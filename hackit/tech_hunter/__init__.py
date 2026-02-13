"""
Tech Hunter Module (Hybrid Edition: Rust + Go + Python)
"""
import click
import json
import os
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, CYAN, BLUE, RED
from .go_bridge import GoEngine

@click.command()
# Target Options
@click.option('-u', '--url', help='Target URL, hostname, IP, or CIDR range')
@click.option('-l', '--list', 'target_list', help='File containing list of targets')
@click.option('--cidr', help='Scan targets from CIDR range')
@click.option('-p', '--port', help='Custom port (e.g. 80,443,8080)')
@click.option('--http', is_flag=True, help='Force HTTP connection')
@click.option('--https', is_flag=True, help='Force HTTPS connection')

# Scan Control
@click.option('-f', '--favicon', is_flag=True, help='Fetch and hash favicon (Shodan style)')
@click.option('-d', '--deep', is_flag=True, help='Enable deep scanning (crawling for more techs and contacts)')
@click.option('-t', '--threads', default=50, help='Number of concurrent threads (Default: 50)')
@click.option('--timeout', default=10, help='Timeout per request in seconds (default: 10)')
@click.option('--retries', default=1, help='Number of retries on failure (default: 1)')
@click.option('--rate', default=0, help='Maximum requests per second')
@click.option('--delay', default=0, help='Delay between requests (ms)')
@click.option('--proxy', help='Use proxy (format: http://user:pass@host:port)')
@click.option('--random-agent', is_flag=True, default=True, help='Use random User-Agent (Default: True)')
@click.option('--header', multiple=True, help='Add custom HTTP header (K:V)')

# Detection Options
@click.option('--profile', type=click.Choice(['fast', 'stealth', 'full', 'deep']), default='full', help='Scan profile: fast | stealth | full | deep')
@click.option('--tech-only', is_flag=True, help='Only display detected technologies')
@click.option('--headers-only', is_flag=True, help='Only analyze HTTP headers')
@click.option('--no-body', is_flag=True, help='Do not fetch response body')
@click.option('--detect-waf', is_flag=True, help='Enable WAF detection')
@click.option('--detect-cdn', is_flag=True, help='Enable CDN detection')
@click.option('--detect-cms', is_flag=True, help='Focus on CMS detection (WordPress, Joomla, etc.)')
@click.option('--detect-framework', is_flag=True, help='Focus on framework detection (React, Vue, etc.)')
@click.option('--confidence', is_flag=True, help='Display detection confidence score')
@click.option('--heuristic', is_flag=True, help='Enable heuristic-based detection')

# Intelligence
@click.option('--cve', is_flag=True, help='Map CVEs for discovered technologies')
@click.option('--risk-score', is_flag=True, help='Calculate target security risk score')
@click.option('--fingerprint-db', help='Use custom signature database')
@click.option('--update-signature', is_flag=True, help='Update signature database')

# Output Options
@click.option('-o', '--output', help='Save scan results to file')
@click.option('--format', type=click.Choice(['json', 'table', 'csv', 'ndjson']), default='table', help='Output format: json | table | csv | ndjson')
@click.option('--pretty', is_flag=True, help='Format JSON for readability')
@click.option('--silent', is_flag=True, help='Only show critical results')
@click.option('--raw', is_flag=True, help='Display raw server response')
@click.option('--report-html', is_flag=True, help='Generate HTML report')

# Advanced
@click.option('--path', help='Scan specific path (e.g. /admin)')
@click.option('--brutepath', help='Bruteforce common paths using dictionary file')
@click.option('--tls-info', is_flag=True, help='Display TLS/SSL certificate details')
@click.option('--http2', is_flag=True, help='Force HTTP/2 usage')
@click.option('--follow-redirect', is_flag=True, help='Follow URL redirects')

# Debug
@click.option('-v', '--verbose', count=True, help='Show more detailed information')
@click.option('--debug', is_flag=True, help='Enable debug mode for troubleshooting')
@click.option('--trace', is_flag=True, help='Trace request flow deeply')
@click.option('--dry-run', is_flag=True, help='Simulate without sending real requests')
def detect(**kwargs):
    """
    Tech Hunter - Advanced Hybrid Web Technology Fingerprinter.
    Architecture: Rust (Execution) + Go (Orchestration) + Python (Intelligence).
    """
    if not kwargs.get('silent'):
        display_tool_banner('Tech Hunter (Hybrid Engine)')
        click.echo(_colored("[*] Core: Rust (Async HTTP) | Orchestrator: Go | Brain: Python", CYAN))
        click.echo(_colored("[*] Mode: Anonymous & High-Performance Enabled", GREEN))

    # Check for target
    if not any([kwargs.get('url'), kwargs.get('target_list'), kwargs.get('cidr')]):
        click.echo(_colored("[!] Error: Target (-u, -l, or --cidr) is required", RED))
        return

    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go or Rust not installed. Please install required compilers.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile hybrid engine.", RED))
        return

    # Preparation for Go Engine options
    if kwargs.get('header'):
        kwargs['header'] = ",".join(kwargs['header'])

    # Execution Engine (Rust -> Go -> Python)
    results = engine.run(**kwargs)

    if 'error' in results:
        click.echo(_colored(f"\n[!] Scan Error: {results['error']}", RED))
        return

    # Output based on format
    if kwargs.get('format') == 'json':
        if kwargs.get('pretty'):
            click.echo(json.dumps(results, indent=2))
        else:
            click.echo(json.dumps(results))
        return

    # Human-readable display (WhatWeb Style)
    if not kwargs.get('silent'):
        display_human_results(results, kwargs)

def display_human_results(results, opts):
    """Display scan results in a beautiful format."""
    scan_results = results if isinstance(results, list) else [results]

    for res in scan_results:
        url = res.get('url', 'Unknown')
        status = res.get('status', 0)
        title = res.get('title', 'No Title')
        
        click.echo(f"\nTarget: {_colored(url, BLUE)} [{_colored(str(status), YELLOW)}]")
        if title:
            click.echo(f"Title : {title}")
            
        ip_info = res.get('ip_info', {})
        ip = ip_info.get('ip', 'Unknown')
        isp = ip_info.get('isp', 'Unknown')
        country = ip_info.get('country', 'Unknown')
        click.echo(f"IP    : {ip} ({isp}, {country})")
        
        if opts.get('tls_info') and res.get('tls_info'):
            tls = res.get('tls_info')
            click.echo(f"TLS   : {tls.get('version')} | {tls.get('cipher')} | Issuer: {tls.get('issuer')}")

        techs = res.get('technologies', {})
        if techs:
            click.echo("\nDetected Technologies:")
            for name, info in techs.items():
                ver = f" v{info['version']}" if info.get('version') else ""
                conf = f" [{info['confidence']}%]" if opts.get('confidence') else ""
                click.echo(f"  - {_colored(name, GREEN)}{_colored(ver, BLUE)}{conf}")
        else:
            click.echo("\n[!] No specific technologies detected.")

        # Display Contact Info
        contacts = res.get('contact_info', {})
        if contacts:
            emails = contacts.get('emails', [])
            phones = contacts.get('phones', [])
            social = contacts.get('social_links', [])
            
            if emails or phones or social:
                click.echo("\nContact Information:")
                if emails:
                    click.echo(f"  Emails: {', '.join(emails)}")
                if phones:
                    click.echo(f"  Phones: {', '.join(phones)}")
                if social:
                    click.echo(f"  Social: {', '.join(social)}")
        
        if opts.get('verbose') > 0:
            headers = res.get('headers', {})
            if headers:
                click.echo("\nResponse Headers:")
                for k, v in headers.items():
                    click.echo(f"  {k}: {v}")
    
    click.echo("")

if __name__ == "__main__":
    detect()
