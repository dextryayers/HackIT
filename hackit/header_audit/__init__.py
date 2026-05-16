"""
Header Audit Module (Go-Powered)
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE, WHITE
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

    # 1. Summary Header (Professional Style)
    grade = results.get('grade', 'F')
    score = results.get('score', 0)
    target = results.get('target', url)
    resp_time = results.get('response_time_ms', 0)
    
    grade_color = GREEN
    if 'B' in grade: grade_color = CYAN
    if 'C' in grade or 'D' in grade: grade_color = YELLOW
    if 'F' in grade: grade_color = RED
    
    click.echo("\n" + "═"*50)
    click.echo(f" TARGET: {_colored(target, BLUE, bold=True)}")
    click.echo(f" GRADE : {_colored(grade, grade_color, bold=True)} ({score}/100) | SPEED: {resp_time}ms")
    click.echo("═"*50 + "\n")

    # 2. Server Intelligence
    server = results.get('server_info', 'Unknown')
    powered = results.get('powered_by', 'N/A')
    click.echo(f"[*] SERVER: {_colored(server, YELLOW)} | TECH: {_colored(powered, CYAN)}")

    # 3. Forensic Header Table (The Sultan View)
    all_headers = results.get('all_headers', [])
    if all_headers:
        click.echo(_colored("\n[+] HTTP RESPONSE HEADERS (FULL FORENSIC)", CYAN, bold=True))
        from hackit.ui import TablePrinter
        tp = TablePrinter(["HEADER", "VALUE", "CATEGORY", "DESCRIPTION"])
        tp.print_header()
        for h in all_headers:
            val = h['value']
            if len(val) > 40: val = val[:37] + "..."
            key_color = GREEN if h.get('is_security') else WHITE
            tp.print_row([_colored(h['key'], key_color), val, h['category'], h['description']])
        tp.print_footer()

    # 4. Critical Findings (Missing Security Headers)
    missing = results.get('missing', [])
    if missing:
        click.echo(_colored(f"\n[-] SECURITY GAPS DETECTED ({len(missing)})", RED, bold=True))
        for m in missing:
            sev = m.get('severity', 'Low')
            sev_color = RED if sev in ['High', 'Critical'] else YELLOW
            click.echo(f"    • [{_colored(sev, sev_color)}] {_colored(m['header'], RED)}")
            click.echo(f"      -> {m['description']}")
            click.echo(f"      -> Rec: {_colored(m['recommendation'], GREEN)}")
            
    # 5. Dangerous Leaks
    dangerous = results.get('dangerous', [])
    if dangerous:
        click.echo(_colored(f"\n[!] DANGEROUS INFORMATION LEAKS ({len(dangerous)})", YELLOW, bold=True))
        for d in dangerous:
            click.echo(f"    • [{_colored(d['severity'], YELLOW)}] {_colored(d['header'], RED)}: {d['value']}")
            click.echo(f"      -> Risk: {d['description']}")

    # 6. Deep Cookie Audit
    cookies = results.get('cookie_audit', [])
    if cookies:
        click.echo(_colored(f"\n[!] SESSION COOKIE SECURITY AUDIT ({len(cookies)})", CYAN, bold=True))
        for c in cookies:
            sev_color = RED if c['severity'] == 'Medium' else YELLOW
            click.echo(f"    • Cookie: {_colored(c['name'], WHITE, bold=True)} [{_colored(c['severity'], sev_color)}]")
            for issue in c['issues']:
                click.echo(f"      -> {issue}")

    # 7. CORS Security Audit
    cors = results.get('cors_audit', [])
    if cors:
        click.echo(_colored(f"\n[!] CORS POLICY AUDIT ({len(cors)})", RED, bold=True))
        for f in cors:
            sev_color = RED if f['severity'] == 'High' else YELLOW
            click.echo(f"    • [{_colored(f['severity'], sev_color)}] {f['header']}")
            click.echo(f"      -> {f['description']}")
            click.echo(f"      -> Rec: {_colored(f['recommendation'], GREEN)}")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Powerful++ forensic data exported to: {output}")
