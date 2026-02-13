"""
XSS Scanner Module
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE
from .go_bridge import GoEngine

@click.command()
@click.option('-u', '--url', required=True, help='Target URL (with parameters)')
@click.option('-o', '--output', help='Save results to JSON')
def scan_xss(url, output):
    """
    Reflected XSS Scanner (Go Engine).
    """
    display_tool_banner('XSS Scanner (Go Engine)')
    
    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    click.echo("[*] Scanning for XSS...")
    results = engine.run(url)
    
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(f"[!] Error: {results[0]['error']}")
        return
        
    if not results:
        click.echo("[*] No XSS found.")
    else:
        for r in results:
            click.echo(_colored(f"[+] XSS Found on parameter: {r.get('parameter')}", GREEN))
            click.echo(f"    Payload: {r.get('payload')}")
            click.echo(f"    URL: {r.get('url')}\n")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"[+] Saved to {output}")
