"""
Advanced Security Header Auditor (Go-Powered + Rust)
Audits HTTP security headers, CORS, cookies, TLS, caching, policy, and technology fingerprinting.
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE, WHITE, BOLD, DIM, MAGENTA, TablePrinter
from .go_bridge import get_engine, get_rust_engine

# Shared state for event processing (single-scan CLI tool)
_full_result = {}
_findings_count = {
    'missing': 0, 'dangerous': 0, 'cookies': 0,
    'cors': 0, 'tech': 0, 'subdomains': 0,
    'csp': 0, 'policy': 0, 'coop': 0,
}

@click.command()
@click.option('-u', '--url', required=True, help='Target URL')
@click.option('-o', '--output', help='Save results to JSON')
@click.option('--rust/--no-rust', default=True, help='Enable Rust deep analysis tools')
def check(url, output, rust):
    """
    Advanced Security Header Auditor (Go-Powered).
    Full-spectrum HTTP header security analysis including CORS, TLS, caching, cookies, and tech fingerprinting.
    """
    global _full_result, _findings_count
    _full_result = {}
    _findings_count = {k: 0 for k in _findings_count}

    display_tool_banner('Header Auditor (Go Engine + Rust)')
    
    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    
    engine = get_engine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    rust_engine = get_rust_engine() if rust else None
    if rust and not rust_engine.available():
        click.echo(_colored("[!] Rust tools not found (run cargo build --release in rust/ each tool)", YELLOW))

    click.echo(_colored("\n[ Scanning... ]", CYAN, bold=True))
    
    def process_event(event):
        etype = event.get('type', '')
        source = event.get('source', 'go')

        if etype == 'summary':
            return process_summary(event)
        elif etype == 'header':
            return process_header(event)
        elif etype == 'finding':
            return process_finding(event)
        elif etype in ('cookie', 'cookie_detail') and source != 'go':
            return process_rust_cookie(event)
        elif etype == 'cookie':
            return process_go_cookie(event)
        elif etype == 'cors':
            return process_cors(event)
        elif etype == 'tls':
            return process_tls(event)
        elif etype == 'tech':
            return process_tech(event)
        elif etype == 'subdomain':
            return process_subdomain(event)
        elif etype == 'csp_directive':
            return process_csp_directive(event)
        elif etype == 'cors_detail':
            return process_cors_detail(event)
        elif etype == 'policy_report':
            return process_policy_report(event)
        elif etype == 'done':
            return process_done(event)
        elif etype == 'policy_done':
            return None
        elif etype == 'error':
            return process_error(event)

    for event in engine.run(url):
        process_event(event)

    if rust_engine:
        for event in rust_engine.run_all(url):
            process_event(event)

    if output and _full_result:
        with open(output, 'w') as f:
            json.dump(_full_result, f, indent=2, default=str)
        click.echo(f"\n[+] Results exported to: {output}")


def process_summary(event):
    global _full_result
    _full_result = event
    grade = event.get('grade', 'F')
    score = event.get('score', 0)
    target = event.get('target', '')
    ip = event.get('ip', '')
    elapsed = event.get('elapsed_ms', 0)
    server = event.get('server', 'Unknown')
    powered = event.get('powered_by', 'N/A')

    grade_color = GREEN
    if 'B' in grade: grade_color = CYAN
    if 'C' in grade or 'D' in grade: grade_color = YELLOW
    if 'E' in grade or 'F' in grade: grade_color = RED

    click.echo("\n" + "="*55)
    click.echo(f" TARGET: {_colored(target, BLUE, bold=True)}")
    if ip:
        click.echo(f" IP    : {_colored(ip, DIM)}")
    click.echo(f" GRADE : {_colored(grade, grade_color, bold=True)} ({score}/100)")
    click.echo(f" SPEED : {_colored(f'{elapsed}ms', DIM)}")
    click.echo("="*55)

    click.echo(f"\n[*] SERVER: {_colored(server, YELLOW)} | TECH: {_colored(powered, CYAN)}")

def process_header(event):
    global _full_result
    if _full_result:
        _full_result.setdefault('all_headers', []).append(event)
    key = event.get('key', '')
    val = event.get('value', '')
    cat = event.get('category', '')
    sec = event.get('is_security', False)
    if len(val) > 50:
        val = val[:47] + "..."
    key_color = GREEN if sec else WHITE
    click.echo(f"  {_colored(key, key_color)}: {val} {_colored(f'[{cat}]', DIM)}")

def process_finding(event):
    global _findings_count
    ftype = event.get('finding_type', '')
    header = event.get('header', event.get('category', ''))
    desc = event.get('description', '')
    sev = event.get('severity', 'Low')
    sev_color = RED if sev in ['High', 'Critical'] else YELLOW
    rec = event.get('recommendation', '')

    if ftype == 'missing':
        _findings_count['missing'] += 1
        click.echo(f"  {_colored('[-]', RED)} {_colored(header, RED, bold=True)} [{_colored(sev, sev_color)}]")
        click.echo(f"      {desc}")
        if rec:
            click.echo(f"      Fix: {_colored(rec, GREEN)}")
    elif ftype == 'dangerous':
        _findings_count['dangerous'] += 1
        val = event.get('value', '')
        click.echo(f"  {_colored('[!]', YELLOW)} {_colored(header, RED, bold=True)}: {val} [{_colored(sev, sev_color)}]")
        click.echo(f"      {desc}")
    elif ftype in ('weak', 'info', 'medium', 'high', 'critical'):
        _findings_count['csp'] += 1
        click.echo(f"  {_colored('[Policy]', MAGENTA)} {_colored(event.get('category', ''), WHITE, bold=True)} [{_colored(sev, sev_color)}]")
        click.echo(f"      {desc}")
        if rec:
            click.echo(f"      Fix: {_colored(rec, GREEN)}")
    else:
        click.echo(f"  [{ftype}] {header}: {desc} [{_colored(sev, sev_color)}]")

def process_rust_cookie(event):
    global _findings_count
    _findings_count['cookies'] += 1
    name = event.get('name', '')
    issues = event.get('issues', [])
    sev = 'Medium' if issues else 'Low'
    sev_color = RED if sev == 'High' else YELLOW if sev == 'Medium' else GREEN
    click.echo(f"  {_colored('[R-Cookie]', CYAN)} {_colored(name, WHITE, bold=True)}")
    for issue in issues:
        click.echo(f"      -> {_colored(issue, YELLOW)}")

def process_go_cookie(event):
    global _findings_count
    _findings_count['cookies'] += 1
    name = event.get('name', '')
    issues = event.get('issues', [])
    sev = event.get('severity', 'Low')
    sev_color = RED if sev == 'Medium' else YELLOW
    click.echo(f"  {_colored('[Cookie]', CYAN)} {_colored(name, WHITE, bold=True)} [{_colored(sev, sev_color)}]")
    for issue in issues:
        click.echo(f"      -> {issue}")

def process_cors(event):
    global _findings_count
    _findings_count['cors'] += 1
    header = event.get('header', '')
    desc = event.get('description', '')
    sev = event.get('severity', 'Low')
    sev_color = RED if sev in ['High', 'Critical'] else YELLOW
    rec = event.get('recommendation', '')
    click.echo(f"  {_colored('[CORS]', RED)} {_colored(header, RED, bold=True)} [{_colored(sev, sev_color)}]")
    click.echo(f"      {desc}")
    if rec:
        click.echo(f"      Fix: {_colored(rec, GREEN)}")

def process_tls(event):
    click.echo(f"\n[*] TLS: {_colored(event.get('version', '?'), CYAN)} | {_colored(event.get('cipher', '?'), DIM)}")
    click.echo(f"    Cert: {event.get('subject', '?')} ({_colored(event.get('issuer', '?'), DIM)})")
    days = event.get('days_left', 0)
    days_color = GREEN if days > 30 else YELLOW if days > 14 else RED
    click.echo(f"    Expires: {event.get('expiry', '?')} ({_colored(f'{days} days', days_color)})")
    if event.get('self_signed'):
        click.echo(f"    {_colored('[!] Self-signed certificate', RED)}")
    if event.get('wildcard'):
        click.echo(f"    {_colored('[!] Wildcard certificate', YELLOW)}")

def process_tech(event):
    global _findings_count
    _findings_count['tech'] += 1
    name = event.get('name', '')
    ver = event.get('version', '')
    cert = event.get('certainty', '')
    cert_color = GREEN if cert == 'High' else YELLOW
    ver_str = f" {ver}" if ver else ""
    click.echo(f"  {_colored('[Tech]', BLUE)} {name}{ver_str} ({_colored(cert, cert_color)})")

def process_subdomain(event):
    global _findings_count
    _findings_count['subdomains'] += 1
    sub_url = event.get('url', '')
    status = event.get('status', 0)
    grade = event.get('grade', 'F')
    server = event.get('server', '')
    findings = event.get('findings', 0)
    status_color = GREEN if status == 200 else YELLOW
    click.echo(f"  {_colored('[Sub]', BLUE)} {_colored(sub_url, WHITE)} [{_colored(status, status_color)}] Grade: {_colored(grade, CYAN)}")
    if server:
        click.echo(f"       Server: {server} | Issues: {findings}")

def process_csp_directive(event):
    directive = event.get('directive', '')
    sources = event.get('sources', [])
    count = event.get('source_count', 0)
    click.echo(f"  {_colored('[CSP]', MAGENTA)} {_colored(directive, WHITE, bold=True)} ({count} sources): {', '.join(sources[:5])}{'...' if count > 5 else ''}")

def process_cors_detail(event):
    ao = event.get('allow_origin', '')
    if ao:
        click.echo(f"  {_colored('[CORS Detail]', RED)}")
        click.echo(f"      Origin: {_colored(ao, WHITE)} | Methods: {event.get('allow_methods', '?')}")
        click.echo(f"      Credentials: {event.get('allow_credentials', '?')} | Max-Age: {event.get('max_age', '?')}")
        reflection = event.get('origin_reflection')
        if reflection:
            click.echo(f"      {_colored('[!] Origin reflection:', YELLOW)} {reflection}")

def process_policy_report(event):
    ptype = event.get('directive', '')
    pval = event.get('value', '')
    click.echo(f"  {_colored('[Report]', MAGENTA)} {ptype}: {pval}")

def process_done(event):
    global _findings_count
    total = sum(_findings_count.values())
    click.echo(f"\n{'='*55}")
    click.echo(f" Scan Complete -- {total} total findings")
    click.echo(f"   {_colored(str(_findings_count['missing']) + ' Security Gaps', RED)}")
    click.echo(f"   {_colored(str(_findings_count['dangerous']) + ' Info Leaks', YELLOW)}")
    click.echo(f"   {_colored(str(_findings_count['cookies']) + ' Cookie Issues', CYAN)}")
    click.echo(f"   {_colored(str(_findings_count['cors']) + ' CORS Issues', RED)}")
    if _findings_count['csp']:
        click.echo(f"   {_colored(str(_findings_count['csp']) + ' Policy Findings', MAGENTA)}")
    if _findings_count['subdomains']:
        click.echo(f"   {_colored(str(_findings_count['subdomains']) + ' Subdomains', BLUE)}")
    if _findings_count['tech']:
        click.echo(f"   {_colored(str(_findings_count['tech']) + ' Technologies', BLUE)}")

def process_error(event):
    click.echo(f"\n{_colored('[!] Error:', RED)} {event.get('message', 'Unknown')}")
