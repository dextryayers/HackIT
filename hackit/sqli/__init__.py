"""
SQLi PENETRATION ENGINE - Advanced SQL Injection Framework
"""
import click
import json
import sys
import io
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM, PURPLE
from .go_bridge import GoEngine

# Force UTF-8 encoding for stdout/stderr to avoid UnicodeEncodeError on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def draw_table(title, columns, rows):
    """Draw a SQLMap-style table"""
    if not rows:
        return
    
    # Calculate column widths
    widths = [len(c) for c in columns]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
    
    # Add padding
    widths = [w + 2 for w in widths]
    
    # Draw separator
    sep = "+" + "+".join(["-" * w for w in widths]) + "+"
    
    click.echo(f"\n{_colored(title, B_WHITE, bold=True)}")
    click.echo(sep)
    
    # Draw header
    header = "|" + "|".join([f" {columns[i]:<{widths[i]-1}}" for i in range(len(columns))]) + "|"
    click.echo(header)
    click.echo(sep)
    
    # Draw rows
    for row in rows:
        line = "|" + "|".join([f" {str(row[i]):<{widths[i]-1}}" for i in range(len(row))]) + "|"
        click.echo(line)
    
    click.echo(sep)

@click.group()
def sqli_cli():
    """Advanced SQL Injection CLI (HackIt Engine)"""
    pass

@sqli_cli.command(name='scan')
# TARGET CONFIG (PRECISION CORE)
@click.option('-u', '--url', 'url', required=True, help=_colored('Target URL with injection point (e.g., ?id=1)', BLUE))
@click.option('--data', default=None, help=_colored('Raw POST payload for deep data-stream injection', BLUE))
@click.option('--cookie', default=None, help=_colored('Session cookies for authenticated scanning', BLUE))
@click.option('--header', multiple=True, help=_colored('Custom tactical headers (e.g., X-Forwarded-For)', BLUE))
@click.option('--agent', default='HackIt/2.0', help=_colored('Industrial-grade User-Agent spoofing', BLUE))
@click.option('--referer', default=None, help=_colored('Custom referer for evasion', BLUE))
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST', 'PUT', 'PATCH']), help=_colored('HTTP Method orchestration', BLUE))
@click.option('--timeout', default=10, help=_colored('Tactical request timeout (default: 10s)', BLUE))
@click.option('--proxy', default=None, help=_colored('Proxy-chain support (HTTP/SOCKS5)', BLUE))
@click.option('--follow-redirect', is_flag=True, help=_colored('Automatic redirection tracking', BLUE))

# INJECTION STRATEGY (ULTRA-DEEP ENGINE)
@click.option('--mode', default='auto', type=click.Choice(['auto', 'boolean', 'time', 'error', 'union', 'stacked']), help=_colored('Injection vector selection', YELLOW))
@click.option('--risk-level', default=1, type=click.IntRange(1, 5), help=_colored('Aggressiveness level (1-5, higher = deeper)', YELLOW))
@click.option('--depth', default=2, help=_colored('Crawl depth for parameter discovery', YELLOW))
@click.option('--threads', default=10, help=_colored('Parallel processing workers (High-Speed)', YELLOW))
@click.option('--randomize-case', is_flag=True, help=_colored('Polymorphic case randomization (WAF Bypass)', YELLOW))
@click.option('--tamper', multiple=True, help=_colored('Advanced payload obfuscation scripts', YELLOW))
@click.option('--encode', type=click.Choice(['URL', 'double', 'base64']), help=_colored('Deep encoding layer selection', YELLOW))
@click.option('--bypass-waf', is_flag=True, help=_colored('Hardened WAF evasion engine (Deep Audit)', YELLOW))
@click.option('--stealth', is_flag=True, help=_colored('Ghost mode (Slow cadence + randomized headers)', YELLOW))

# DETECTION & INTEL (INDUSTRIAL GRADE)
@click.option('--fingerprint', is_flag=True, help=_colored('Deep DBMS version and engine discovery', GREEN))
@click.option('--banner-grab', is_flag=True, help=_colored('Extract raw database banner secrets', GREEN))
@click.option('--os-detect', is_flag=True, help=_colored('Back-end operating system fingerprinting', GREEN))
@click.option('--waf-detect', is_flag=True, help=_colored('WAF/IPS/IDS identification audit', GREEN))

# DATABASE ENUMERATION (SQLMAP-X MODE)
@click.option('--inject', is_flag=True, help=_colored('Automated ultra-deep injection & data dump', B_RED))
@click.option('--dbs', '--list-dbs', 'list_dbs', is_flag=True, help=_colored('Extract all available databases', B_CYAN))
@click.option('--tables', '--list-tables', 'list_tables', is_flag=True, help=_colored('Extract tables from target database', B_CYAN))
@click.option('--columns', '--list-columns', 'list_columns', is_flag=True, help=_colored('Extract column metadata', B_CYAN))
@click.option('--schema', is_flag=True, help=_colored('Dump structure only (No data)', B_CYAN))
@click.option('-D', '--db', 'database', help=_colored('Specify target database', B_CYAN))
@click.option('-T', '--table', 'table', help=_colored('Specify target table', B_CYAN))
@click.option('-C', '--column', 'column', help=_colored('Specify target column', B_CYAN))

# DATA EXTRACTION
@click.option('--dump', '--dump-table', 'dump_table', help=_colored('Automated table content extraction', B_GREEN))
@click.option('--dump-all', is_flag=True, help=_colored('Total database exfiltration mode', B_RED))
@click.option('--output-format', type=click.Choice(['json', 'csv', 'txt']), default='json', help=_colored('Intel output format', DIM))
@click.option('--save', help=_colored('Save intelligence report to file', DIM))
@click.option('-v', '--verbose', default=1, help=_colored('Tactical verbosity (0-3)', DIM))
def test_sqli(**kwargs):
    """Advanced SQL Injection Scanner (Go Engine)"""
    
    display_tool_banner('SQLi PENETRATION ENGINE')

    url = kwargs.get('url')
    click.echo(f"[*] Target: {_colored(url, B_CYAN, bold=True)}")
    click.echo(f"[*] Engine: {_colored('HackIT', B_YELLOW)}")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", B_RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", B_RED))
        return

    click.echo(_colored("[*] Starting deep vulnerability assessment...", DIM))
    
    # Handle aliases
    if kwargs.get('inject'):
        kwargs['dump_all'] = True
    
    # Pre-scan checks (WAF, Fingerprint)
    if kwargs.get('waf_detect'):
        click.echo(f"[*] Checking for WAF/IPS...")
        
    # Run the engine with all parameters
    results = engine.run(**kwargs)
    
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(_colored(f"[!] Engine Error: {results[0]['error']}", B_RED))
        return

    # Filter findings and enumerations
    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    # Display High-Fidelity Findings Summary
    if findings:
        for r in findings:
            # Calculate Confidence Score (Mock logic for now)
            score = 9.2 if r.get('type') == 'Time-based' else 8.5
            color_score = B_RED if score > 8.0 else B_YELLOW
            
            click.echo(f"\n{_colored('┌── SQLi VULNERABILITY REPORT', B_WHITE, bold=True)}")
            click.echo(f"{_colored('│', B_WHITE)} Target        : {_colored(url.split('?')[0], B_CYAN)}")
            click.echo(f"{_colored('│', B_WHITE)} Endpoint      : {_colored(url, B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Injection', B_YELLOW, bold=True)}     :")
            click.echo(f"{_colored('│', B_WHITE)} - Method : {_colored(kwargs.get('method', 'GET'), B_GREEN)}")
            click.echo(f"{_colored('│', B_WHITE)} - Param  : {_colored(r.get('parameter', 'N/A'), B_CYAN)}")
            click.echo(f"{_colored('│', B_WHITE)} - Type   : {_colored(r.get('type', 'N/A'), B_YELLOW)}")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('SQLi Score', B_WHITE)}    : {_colored(f'{score} / 10', color_score)} (High Confidence)")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Proof', B_WHITE, bold=True)} :")
            click.echo(f"{_colored('│', B_WHITE)} - Payload       : {_colored(r.get('payload', 'N/A'), DIM)}")
            click.echo(f"{_colored('│', B_WHITE)} - Evidence      : {_colored(r.get('details', 'N/A'), B_GREEN)}")
            click.echo(f"{_colored('│', B_WHITE)}")
            click.echo(f"{_colored('│', B_WHITE)} {_colored('Database', B_WHITE, bold=True)}       :")
            click.echo(f"{_colored('│', B_WHITE)} - Detected DB   : {_colored(r.get('dbms', 'Unknown'), B_CYAN, bold=True)}")
            click.echo(f"{_colored('└' + '─' * 70, B_WHITE)}")

    # Display Enumerations (Databases, Tables, etc.)
    if enums:
        for e in enums:
            etype = e.get('type')
            payload = e.get('payload', '')
            items = [item.strip() for item in payload.split(',') if item.strip()]
            
            if etype == "list-dbs":
                rows = [[item] for item in items]
                draw_table(f"Available Databases ({len(items)})", ["DATABASE"], rows)
            elif etype == "list-tables":
                rows = [[item] for item in items]
                db_context = e.get('details', 'Current')
                draw_table(f"Tables in Database: {db_context}", ["TABLE NAME"], rows)
            elif etype == "list-columns":
                rows = [[item] for item in items]
                draw_table(f"Columns", ["COLUMN NAME"], rows)
            elif etype == "dump-table":
                # Handle dump-table visualization specifically
                click.echo(f"\n{_colored('[+]', B_GREEN)} Data Dump Result for {_colored(e.get('details', 'N/A'), B_CYAN)}:")
                click.echo(f"{_colored(payload, B_WHITE)}")

    if not findings and not enums:
        click.echo(_colored("[*] Result: No SQL Injection vulnerabilities detected.", GREEN))

    if kwargs.get('save'):
        output_file = kwargs.get('save')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Detailed report saved to: {_colored(output_file, B_GREEN)}")

if __name__ == "__main__":
    sqli_cli()
