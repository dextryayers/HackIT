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
# TARGET CONFIG
@click.option('-u', '--url', 'url', required=True, help='URL target (e.g., http://example.com/page.php?id=1)')
@click.option('--data', default=None, help='Raw POST body')
@click.option('--cookie', default=None, help='Custom cookie')
@click.option('--header', multiple=True, help='Custom header (multi allowed)')
@click.option('--agent', default='HackIt/2.0', help='Custom user-agent')
@click.option('--referer', default=None, help='Custom referer')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST', 'PUT', 'PATCH']), help='HTTP method')
@click.option('--timeout', default=10, help='Timeout request (default: 10)')
@click.option('--proxy', default=None, help='Proxy support (http/socks)')
@click.option('--follow-redirect', is_flag=True, help='Auto follow redirect')

# INJECTION STRATEGY
@click.option('--mode', default='auto', type=click.Choice(['auto', 'boolean', 'time', 'error', 'union', 'stacked']), help='Injection mode')
@click.option('--risk-level', default=1, type=click.IntRange(1, 5), help='1-5 (aggressiveness)')
@click.option('--depth', default=2, help='Scan depth (default: 2)')
@click.option('--threads', default=10, help='Concurrent workers')
@click.option('--delay', default=0, help='Delay antar request (ms)')
@click.option('--randomize-case', is_flag=True, help='Random case payload')
@click.option('--tamper', multiple=True, help='Tamper script (multi allowed)')
@click.option('--encode', type=click.Choice(['URL', 'double', 'base64']), help='Encoding type')
@click.option('--bypass-waf', is_flag=True, help='Enable WAF evasion mode hard')
@click.option('--stealth', is_flag=True, help='Evasive mode (slow + random UA)')

# DETECTION ENGINE
@click.option('--fingerprint', is_flag=True, help='Detect DB engine')
@click.option('--banner-grab', is_flag=True, help='Extract DB banner')
@click.option('--os-detect', is_flag=True, help='Detect OS backend')
@click.option('--waf-detect', is_flag=True, help='Detect WAF')

# DATABASE ENUMERATION
@click.option('--list-dbs', is_flag=True, help='Enumerate databases')
@click.option('--list-tables', is_flag=True, help='Enumerate tables')
@click.option('--list-columns', is_flag=True, help='Enumerate columns')
@click.option('--schema', is_flag=True, help='Dump structure only')

# DATA EXTRACTION
@click.option('--dump-table', help='Dump specific table')
@click.option('--dump-all', is_flag=True, help='Dump everything')
@click.option('--output-format', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
@click.option('--save', help='Save result to file')
@click.option('--verbose', default=1, help='Verbose level (0-3)')
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

    # Display Findings (Summary only if requested or if few findings)
    if findings and kwargs.get('verbose', 1) >= 1:
        # click.echo(_colored(f"\n[!] CRITICAL: Found {len(findings)} injection points!", B_RED, bold=True))
        
        table_rows = []
        for r in findings:
            table_rows.append([
                r.get('parameter', 'N/A'),
                r.get('type', 'N/A'),
                r.get('dbms', 'N/A'),
                "VULNERABLE"
            ])
        
        # Only show the table if verbose >= 2 or if findings are few
        if len(findings) < 5 or kwargs.get('verbose', 1) >= 2:
            draw_table("Injection Summary", ["PARAMETER", "TYPE", "DBMS", "STATUS"], table_rows)
        else:
            click.echo(_colored(f"[*] Total injection points found: {len(findings)} (Use -v 2 to see details)", B_YELLOW))

    # Display Enumerations
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
                draw_table(f"Tables", ["TABLE NAME"], rows)
            elif etype == "list-columns":
                rows = [[item] for item in items]
                draw_table(f"Columns", ["COLUMN NAME"], rows)

    if not findings and not enums:
        click.echo(_colored("[*] Result: No SQL Injection vulnerabilities detected.", GREEN))

    if kwargs.get('save'):
        output_file = kwargs.get('save')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Detailed report saved to: {_colored(output_file, B_GREEN)}")

if __name__ == "__main__":
    sqli_cli()
