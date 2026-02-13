"""
JS Analyzer Module
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE
from .go_bridge import GoEngine

@click.command()
@click.option('-u', '--url', required=True, help='Target JS URL')
@click.option('-o', '--output', help='Save results to JSON')
def analyze_js(url, output):
    """JS File Analyzer (Go Engine)"""
    display_tool_banner('JS ANALYZER (Go Engine)')
    
    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    click.echo("[*] Analyzing JS file...")
    results = engine.run(url)
    
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(f"[!] Error: {results[0]['error']}")
        return
        
    if not results:
        click.echo("[*] No interesting findings.")
    else:
        for r in results:
            click.echo(f"[{r.get('type')}] {r.get('content')}")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"[+] Saved to {output}")
