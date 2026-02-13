"""
Header Audit Module (Go-Powered)
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE
from .go_bridge import get_engine

@click.command()
@click.option('-u', '--url', required=True, help='Target URL')
@click.option('-o', '--output', help='Save results to JSON')
def check(url, output):
    """
    Advanced Security Header Auditor (Go-Powered).
    Grades security posture (A-F) and identifies missing or dangerous headers.
    """
    display_tool_banner('Header Auditor (Go Engine)')
    
    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    
    engine = get_engine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    results = engine.run(url)

    if 'error' in results:
        click.echo(f"\n[!] Scan Error: {results['error']}")
        return

    # Display Grade
    grade = results.get('grade', 'F')
    score = results.get('score', 0)
    
    grade_color = GREEN
    if grade in ['C', 'D']: grade_color = YELLOW
    if grade == 'F': grade_color = RED
    
    click.echo("\n" + "="*40)
    click.echo(f" SECURITY GRADE: {_colored(grade, grade_color)} ({score}/100)")
    click.echo("="*40 + "\n")

    # Missing
    missing = results.get('missing', [])
    click.echo(f"[-] Missing Security Headers ({len(missing)}):")
    for m in missing:
        click.echo(f"    {_colored(m['header'], RED)}")
        click.echo(f"      -> Desc: {m['description']}")
        click.echo(f"      -> Rec : {m.get('recommendation', 'N/A')}")
        
    # Warnings
    warnings = results.get('warnings', [])
    if warnings:
        click.echo(f"\n[!] Configuration Warnings ({len(warnings)}):")
        for w in warnings:
             click.echo(f"    -> {_colored(w, YELLOW)}")

    # Present
    present = results.get('present', [])
    click.echo(f"\n[+] Present Security Headers ({len(present)}):")
    for p in present:
        val = p['value']
        if len(val) > 60: val = val[:57] + "..."
        click.echo(f"    {_colored(p['header'], GREEN):<30} : {val}")

    # Dangerous
    dangerous = results.get('dangerous', [])
    if dangerous:
        click.echo(f"\n[!] Dangerous Headers Detected ({len(dangerous)}):")
        for d in dangerous:
            click.echo(f"    {_colored(d['header'], YELLOW):<30} : {d['value']} ({d['description']})")
    else:
        click.echo(f"\n[+] No dangerous headers leaked.")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")
