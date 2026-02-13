"""
Redirect Finder Module
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE
from .go_bridge import GoEngine

@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--params', help='Specific parameters to test (comma separated) (ignored)')
@click.option('--threads', default=10, help='Number of concurrent threads (ignored)')
@click.option('--timeout', default=10, help='Request timeout (ignored)')
@click.option('--output', help='Save results to JSON file')
def find_redirects(url, params, threads, timeout, output):
    """Open Redirect Vulnerability Finder (Go Engine)"""
    display_tool_banner('REDIRECT FINDER (Go Engine)')
    
    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    click.echo("[*] Scanning for Open Redirects...")
    results = engine.run(url)
    
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(f"[!] Error: {results[0]['error']}")
        return
        
    if not results:
        click.echo("[*] No Open Redirects found.")
    else:
        for r in results:
            click.echo(_colored(f"[+] Open Redirect Found on parameter: {r.get('parameter')}", GREEN))
            click.echo(f"    Payload: {r.get('payload')}")
            click.echo(f"    Location: {r.get('location')}")
            click.echo(f"    URL: {r.get('url')}\n")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"[+] Saved to {output}")
