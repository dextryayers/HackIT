"""
XSS Scanner Module
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM, PURPLE
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

    click.echo(_colored("[*] Scanning for XSS (Precision Analysis)...", DIM))
    results = engine.run(url)
    
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(_colored(f"[!] Engine Error: {results[0]['error']}", RED))
        return
        
    if not results:
        click.echo(_colored("[*] Result: No XSS vulnerabilities detected.", GREEN))
    else:
        for r in results:
            confidence = r.get('confidence', 'Medium')
            severity = r.get('severity', 'Low')
            conf_color = B_RED if confidence == 'High' else B_YELLOW
            
            sev_color = B_RED if severity in ['High', 'Critical'] else B_YELLOW
            if severity == 'Low': sev_color = GREEN

            click.echo(f"\n{_colored('┌── XSS VULNERABILITY REPORT', B_WHITE, bold=True)}")
            click.echo(f"{_colored('│', B_WHITE)} Target      : {_colored(url.split('?')[0], B_CYAN)}")
            click.echo(f"{_colored('│', B_WHITE)} Parameter   : {_colored(r.get('parameter', 'N/A'), B_YELLOW)}")
            click.echo(f"{_colored('│', B_WHITE)} Context     : {_colored(r.get('details', 'N/A'), B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Severity', B_WHITE)}    : {_colored(severity, sev_color)} ({_colored(r.get('impact', 'N/A'), DIM)})")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Confidence', B_WHITE)}  : {_colored(confidence, conf_color)} ({r.get('type', 'Reflected')})")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Proof', B_WHITE, bold=True)} :")
            click.echo(f"{_colored('│', B_WHITE)} - Payload     : {_colored(r.get('payload', 'N/A'), DIM)}")
            click.echo(f"{_colored('│', B_WHITE)} - Injection   : {_colored(r.get('url', 'N/A'), B_GREEN)}")
            click.echo(f"{_colored('└' + '─' * 70, B_WHITE)}")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"[+] Saved to {output}")
