import click
import json
import ssl
import socket
import datetime
import os
import sys
import threading
import itertools
import time
from typing import Dict, List, Optional, Any
from hackit.ui import display_tool_banner, _colored, B_CYAN, B_GREEN, B_YELLOW, B_RED, DIM, RED, GREEN, YELLOW, B_WHITE, RESET


class _Spinner:
    def __init__(self, msg="[*] Scanning..."):
        self.msg = msg
        self._stop = threading.Event()

    def __enter__(self):
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
        return self

    def __exit__(self, *args):
        self._stop.set()
        self.thread.join()
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()

    def _spin(self):
        chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        while not self._stop.is_set():
            for c in chars:
                sys.stdout.write(f'\r  {_colored(c, B_CYAN)} {_colored(self.msg, DIM)}')
                sys.stdout.flush()
                time.sleep(0.08)
                if self._stop.is_set():
                    return

def _ssl_banner():
    W = 38
    L = '╔' + '═' * (W - 2) + '╗'
    T = '║' + '    <<  SSL SECURITY SUITE  >>    '.center(W - 2) + '║'
    S = '║' + ' ' + '─' * (W - 4) + ' ' + '║'
    R1 = '║' + '  • Encrypt    • Decrypt        '.center(W - 2) + '║'
    R2 = '║' + '  • Verify     • Check          '.center(W - 2) + '║'
    R3 = '║' + '  • Revoke     • Renew          '.center(W - 2) + '║'
    B = '╚' + '═' * (W - 2) + '╝'
    return '\n'.join('  ' + x for x in [L, T, S, R1, R2, R3, B])

SSL_BANNER = _ssl_banner()


def _python_deep_analyze(host: str, port: int, timeout: int) -> Dict[str, Any]:
    from hackit.ssl_tool.core import SSLAnalyzer
    analyzer = SSLAnalyzer(host, port, timeout)
    return analyzer.analyze()


def _display_merged(host: str, port: int, go_result: Optional[Dict], py_result: Optional[Dict]):
    click.echo(f"\n  {_colored('=' * 60, DIM)}")
    click.echo(f"  {_colored('SSL TOOL — ADVANCED SECURITY REPORT', B_WHITE, bold=True)}")
    click.echo(f"  {_colored('=' * 60, DIM)}")

    if go_result:
        grade = go_result.get('grade', 'F')
        score = go_result.get('score', 0)
        grade_colors = {'A': B_GREEN, 'A-': B_GREEN, 'B+': B_YELLOW, 'B': B_YELLOW,
                        'C+': YELLOW, 'C': YELLOW, 'D+': B_RED, 'D': B_RED, 'F': RED}
        gc = grade_colors.get(grade, RED)
        click.echo(f"  Target    : {_colored(f'{host}:{port}', B_CYAN, bold=True)}")
        click.echo(f"  Grade     : {_colored(grade, gc, bold=True)}  ({_colored(str(score) + '/100', gc)})")

        total = go_result.get('all_issues', []) or []
        click.echo(f"  Issues    : {_colored(str(len(total)), B_WHITE, bold=True)} total")

        cert = go_result.get('certificate', {})
        if cert and cert.get('subject_cn'):
            click.echo(f"\n  {_colored('=' * 60, DIM)}")
            click.echo(f"  {_colored('CERTIFICATE DEEP ANALYSIS', B_WHITE, bold=True)}")
            status = 'Valid'
            sc = B_GREEN
            if cert.get('expired'):
                status, sc = 'EXPIRED', RED
            elif cert.get('expires_soon'):
                status, sc = 'Expires Soon', B_YELLOW
            click.echo(f"    Status          : {_colored(status, sc)}")
            click.echo(f"    Subject CN      : {_colored(cert.get('subject_cn', 'N/A'), B_CYAN)}")
            click.echo(f"    Organization    : {cert.get('subject_org', 'N/A')}")
            click.echo(f"    Country         : {cert.get('subject_country', 'N/A')}")
            click.echo(f"    Issuer          : {_colored(cert.get('issuer_cn', 'N/A'), B_CYAN)}")
            click.echo(f"    Valid           : {cert.get('not_before', 'N/A')[:10]} -> {cert.get('not_after', 'N/A')[:10]}")
            days = cert.get('days_remaining')
            if days is not None:
                dc = B_GREEN if days > 90 else (B_YELLOW if days > 30 else RED)
                click.echo(f"    Expires         : {_colored(str(days) + ' days', dc)}")
            click.echo(f"    Public Key      : {cert.get('key_bits', '?')}-bit {cert.get('key_type', 'Unknown')} ({cert.get('key_strength', 'N/A')})")
            click.echo(f"    Signature       : {cert.get('sig_alg', 'N/A')}")
            click.echo(f"    SAN Entries     : {cert.get('san_count', 0)}")
            click.echo(f"    Wildcard        : {_colored(str(cert.get('wildcard', False)), B_YELLOW if cert.get('wildcard') else B_GREEN)}")
            click.echo(f"    Self-Signed     : {cert.get('self_signed', False)}")
            click.echo(f"    SCT Count       : {cert.get('sct_count', 0)}")
            click.echo(f"    Is EV           : {cert.get('is_ev', False)}")
            click.echo(f"    OCSP Must-Staple: {cert.get('ocsp_must_staple', False)}")
            if cert.get('key_usage'):
                click.echo(f"    Key Usage       : {', '.join(cert['key_usage'])}")
            if cert.get('ext_key_usage'):
                click.echo(f"    Extended KU     : {', '.join(cert['ext_key_usage'])}")
            fp = cert.get('fingerprint_sha256', '')
            if fp:
                click.echo(f"    SHA-256 FP      : {fp[:48]}...")

            issues = cert.get('issues', [])
            if issues:
                click.echo(f"\n    {_colored('Certificate Issues:', B_RED)}")
                for issue in issues:
                    ic = RED if any(w in issue.lower() for w in ['expired', 'insecure', 'md5', 'broken']) else B_YELLOW
                    click.echo(f"      {_colored('[!]', ic)} {_colored(issue, ic)}")

        chain = go_result.get('chain', {})
        if chain:
            click.echo(f"\n  {_colored('CHAIN ANALYSIS', B_WHITE, bold=True)}")
            click.echo(f"    Depth           : {chain.get('chain_depth', 0)}")
            if chain.get('root_ca'):
                click.echo(f"    Root CA         : {chain['root_ca']}")
            click.echo(f"    OCSP URLs       : {len(chain.get('ocsp_responders', []) or [])}")
            click.echo(f"    CRL URLs        : {len(chain.get('crl_urls', []) or [])}")
            click.echo(f"    OCSP Reachable  : {chain.get('ocsp_responded', False)}")
            click.echo(f"    Root Expired    : {chain.get('root_expired', False)}")
            if chain.get('root_expiry_days'):
                click.echo(f"    Root Expiry     : {chain['root_expiry_days']} days")
            if chain.get('intermediate_cns'):
                click.echo(f"    Intermediates   : {', '.join(chain['intermediate_cns'])}")
            chain_issues = chain.get('issues', []) or []
            if chain_issues:
                click.echo(f"    Chain Issues    : {_colored(str(len(chain_issues)), B_RED)}")
                for iss in chain_issues:
                    click.echo(f"      {_colored('[!]', B_YELLOW)} {iss}")
            else:
                click.echo(f"    Chain Issues    : {_colored('0', B_GREEN)}")

        ciphers = go_result.get('ciphers', {})
        if ciphers:
            click.echo(f"\n  {_colored('CIPHER SUITE ANALYSIS', B_WHITE, bold=True)}")
            click.echo(f"    Total Ciphers   : {ciphers.get('total_ciphers', 0)}")
            click.echo(f"    PFS Enabled     : {_colored(str(ciphers.get('pfs_enabled', False)), B_GREEN)}")
            if ciphers.get('best_cipher'):
                click.echo(f"    Best Cipher     : {_colored(ciphers['best_cipher'], B_CYAN)}")

            secure = ciphers.get('secure', []) or []
            weak = ciphers.get('weak', []) or []
            insecure = ciphers.get('insecure', []) or []

            if secure:
                click.echo(f"\n    {_colored(f'Secure Ciphers ({len(secure)}):', B_GREEN)}")
                for c in secure[:5]:
                    m = f" [PFS]" if c.get('pfs') else ""
                    click.echo(f"      {_colored('[+]', B_GREEN)} {c.get('name', '')} ({c.get('bits', '?')}-bit{m})")
                if len(secure) > 5:
                    click.echo(f"      ... and {len(secure) - 5} more")
            if weak:
                click.echo(f"\n    {_colored(f'Weak Ciphers ({len(weak)}):', B_YELLOW)}")
                for c in weak:
                    click.echo(f"      {_colored('[-]', B_YELLOW)} {c.get('name', '')}")
            if insecure:
                click.echo(f"\n    {_colored(f'Insecure Ciphers ({len(insecure)}):', B_RED)}")
                for c in insecure:
                    click.echo(f"      {_colored('[!]', RED)} {c.get('name', '')} ({_colored(c.get('reason', ''), DIM)})")

        vulns = go_result.get('vulnerabilities', {})
        findings = vulns.get('findings', [])
        if findings:
            click.echo(f"\n  {_colored('VULNERABILITY ANALYSIS', B_WHITE, bold=True)}")
            crit = vulns.get('critical', 0)
            high = vulns.get('high', 0)
            med = vulns.get('medium', 0)
            low = vulns.get('low', 0)
            if crit:
                click.echo(f"    {_colored(f'[!!] CRITICAL: {crit} finding(s)', RED)}")
            if high:
                click.echo(f"    {_colored(f'[!!] HIGH: {high} finding(s)', RED)}")
            if med:
                click.echo(f"    {_colored(f'[-] MEDIUM: {med} finding(s)', B_YELLOW)}")
            if low:
                click.echo(f"    {_colored(f'[i] LOW: {low} finding(s)', DIM)}")

            for f in findings:
                sev = f.get('severity', '')
                status = f.get('status', '')
                if status in ('NOT VULNERABLE', 'INFO'):
                    continue
                sev_color = {'CRITICAL': RED, 'HIGH': RED, 'MEDIUM': B_YELLOW, 'LOW': DIM}.get(sev, DIM)
                click.echo(f"    {_colored('[!]', sev_color)} {_colored(f['name'], sev_color)}")
                click.echo(f"       Severity: {_colored(sev, sev_color)} | Status: {_colored(status, sev_color)}")
                if f.get('cve'):
                    click.echo(f"       CVE: {f['cve']}")

        tls = go_result.get('tls_features', {})
        if tls:
            click.echo(f"\n  {_colored('TLS FEATURE SIMULATION', B_WHITE, bold=True)}")
            protos = tls.get('protocols', [])
            click.echo(f"    Protocols       : {', '.join(protos) if protos else 'None'}")
            click.echo(f"    TLS 1.3         : {_colored(str(tls.get('tls_13_supported', False)), B_GREEN)}")
            click.echo(f"    HTTP/2 (h2)     : {_colored(str(tls.get('h2', False)), B_GREEN)}")
            click.echo(f"    OCSP Stapling   : {_colored(str(tls.get('ocsp_stapled', False)), B_YELLOW)}")
            click.echo(f"    Session Resume  : {tls.get('session_resumption', False)}")
            if tls.get('key_exchange'):
                click.echo(f"    Key Exchange    : {tls.get('key_exchange', '')}")
            if tls.get('auth_mechanism'):
                click.echo(f"    Auth Mechanism  : {tls.get('auth_mechanism', '')}")
            if tls.get('alpn'):
                click.echo(f"    ALPN            : {', '.join(tls['alpn'])}")

        dns = go_result.get('dns', {})
        if dns:
            click.echo(f"\n  {_colored('DNS SECURITY ANALYSIS', B_WHITE, bold=True)}")
            a_recs = dns.get('a_records', []) or []
            aaaa_recs = dns.get('aaaa_records', []) or []
            mx_recs = dns.get('mx_records', []) or []
            ns_recs = dns.get('ns_servers', []) or []
            click.echo(f"    A Records       : {len(a_recs)}")
            if a_recs:
                click.echo(f"      {', '.join(a_recs[:3])}{'...' if len(a_recs) > 3 else ''}")
            click.echo(f"    AAAA Records    : {len(aaaa_recs)}")
            if aaaa_recs:
                click.echo(f"      {', '.join(aaaa_recs[:3])}{'...' if len(aaaa_recs) > 3 else ''}")
            click.echo(f"    MX Records      : {len(mx_recs)}")
            if mx_recs:
                click.echo(f"      {', '.join(mx_recs)}")
            click.echo(f"    NS Servers      : {len(ns_recs)}")
            if ns_recs:
                click.echo(f"      {', '.join(ns_recs)}")
            click.echo(f"    SPF Record      : {_colored('Yes' if dns.get('spf') else 'No', B_GREEN if dns.get('spf') else B_RED)}")
            if dns.get('spf'):
                click.echo(f"      {dns['spf']}")
            click.echo(f"    DMARC Record    : {_colored('Yes' if dns.get('dmarc') else 'No', B_GREEN if dns.get('dmarc') else B_RED)}")
            if dns.get('dmarc'):
                click.echo(f"      {dns['dmarc']}")
            click.echo(f"    DKIM Detected   : {_colored(str(dns.get('dkim_detect', False)), B_GREEN if dns.get('dkim_detect') else B_RED)}")
            click.echo(f"    DNSSEC          : {_colored(str(dns.get('dnssec', False)), B_GREEN if dns.get('dnssec') else B_RED)}")
            if dns.get('caa'):
                click.echo(f"    CAA Record      : {dns['caa']}")
            dns_issues = dns.get('issues', []) or []
            if dns_issues:
                click.echo(f"    DNS Issues      : {_colored(str(len(dns_issues)), B_RED)}")
                for iss in dns_issues:
                    click.echo(f"      {_colored('[!]', B_YELLOW)} {iss}")
            else:
                click.echo(f"    DNS Issues      : {_colored('0', B_GREEN)}")

        http = go_result.get('http', {})
        if http and http.get('status', 0) > 0:
            click.echo(f"\n  {_colored('HTTP SECURITY HEADERS', B_WHITE, bold=True)}")
            click.echo(f"    Status          : {http.get('status', 0)}")
            hsts_yn = _colored('Yes', B_GREEN) if http.get('hsts') else _colored('No', RED)
            csp_yn = _colored('Yes', B_GREEN) if http.get('csp') else _colored('No', RED)
            xfo_yn = _colored('Yes', B_GREEN) if http.get('x_frame_options') else _colored('No', RED)
            click.echo(f"    HSTS            : {hsts_yn}")
            click.echo(f"    CSP             : {csp_yn}")
            click.echo(f"    X-Frame-Options : {xfo_yn}")
            click.echo(f"    X-Content-Type  : {_colored('Yes' if http.get('x_content_type') else 'No', B_GREEN if http.get('x_content_type') else RED)}")
            click.echo(f"    Cookies Secure  : {_colored(str(http.get('cookies_secure', False)), B_GREEN if http.get('cookies_secure') else RED)}")
            click.echo(f"    Cookies HttpOnly: {_colored(str(http.get('cookies_httponly', False)), B_GREEN if http.get('cookies_httponly') else RED)}")
            if http.get('cors_policy'):
                click.echo(f"    CORS Policy     : {http['cors_policy']}")
            http_issues = http.get('issues', []) or []
            if http_issues:
                click.echo(f"    HTTP Issues     : {_colored(str(len(http_issues)), B_RED)}")
                for iss in http_issues:
                    if 'HSTS' in iss:
                        click.echo(f"      {_colored('[!]', B_RED)} {iss}")
                    elif 'Cookie' in iss or 'CORS' in iss:
                        click.echo(f"      {_colored('[-]', B_YELLOW)} {iss}")
                    else:
                        click.echo(f"      {_colored('[i]', DIM)} {iss}")
            else:
                click.echo(f"    HTTP Issues     : {_colored('0', B_GREEN)}")

        crypto = go_result.get('crypto', {})
        if crypto:
            crypto_curves = crypto.get('ec_curves') or []
            weak_curves = crypto.get('weak_curves') or []
            dh_sizes = crypto.get('dh_sizes') or []
            click.echo(f"\n  {_colored('CRYPTOGRAPHIC ANALYSIS', B_WHITE, bold=True)}")
            click.echo(f"    Key Exchange    : {_colored(crypto.get('key_exchange', 'Unknown'), B_CYAN)}")
            click.echo(f"    ECC Curves      : {len(crypto_curves)}")
            if crypto_curves:
                click.echo(f"      Curves        : {', '.join(crypto_curves)}")
            if weak_curves:
                click.echo(f"    Weak Curves     : {_colored(str(len(weak_curves)), B_RED)}")
                for wc in weak_curves:
                    click.echo(f"      {_colored('[!]', B_RED)} {wc}")
            if dh_sizes:
                click.echo(f"    DH Sizes        : {', '.join(str(s) for s in dh_sizes)}")
            click.echo(f"    Forward Secrecy : {_colored(str(crypto.get('forward_secrecy', False)), B_GREEN if crypto.get('forward_secrecy') else RED)}")
            click.echo(f"    PFS Achieved    : {_colored(str(crypto.get('perfect_forward_secrecy', crypto.get('perfect_forward', False))), B_GREEN if crypto.get('perfect_forward_secrecy', crypto.get('perfect_forward', False)) else RED)}")
            click.echo(f"    Ticket Key Rot  : {_colored(str(crypto.get('ticket_key_rotation', False)), B_GREEN if crypto.get('ticket_key_rotation') else B_YELLOW)}")
            crypto_issues = crypto.get('issues') or []
            if crypto_issues:
                click.echo(f"    Crypto Issues   : {_colored(str(len(crypto_issues)), B_RED)}")
                for iss in crypto_issues:
                    click.echo(f"      {_colored('[!]', B_RED)} {iss}")
            else:
                click.echo(f"    Crypto Issues   : {_colored('0', B_GREEN)}")

        ports = go_result.get('ports', {}) or go_result.get('port_scan', {})
        if ports:
            click.echo(f"\n  {_colored('PORT SCAN RESULTS', B_WHITE, bold=True)}")
            click.echo(f"    Open Ports      : {_colored(str(ports.get('total_open', 0)), B_RED if ports.get('total_open', 0) > 0 else B_GREEN)} / {ports.get('total_scanned', 0)}")
            if ports.get('open_ports'):
                for p in ports['open_ports']:
                    tls_tag = ' [TLS]' if p.get('tls') else ''
                    svc = p.get('service', '?')
                    port_str = f'{p["port"]}/tcp'
                    click.echo(f"      {_colored(port_str, B_CYAN)}  {svc}{tls_tag}")
            else:
                click.echo(f"      {_colored('(none)', DIM)}")
            port_issues = ports.get('issues', []) or []
            if port_issues:
                click.echo(f"    Port Issues     : {_colored(str(len(port_issues)), B_RED)}")
                for iss in port_issues:
                    click.echo(f"      {_colored('[*]', DIM)} {iss}")
            else:
                click.echo(f"    Port Issues     : {_colored('0', B_GREEN)}")

    elif py_result:
        grade = py_result.get('grade', 'F')
        score = py_result.get('score', 0)
        gc = B_RED if grade in ('D', 'F') else (B_YELLOW if grade in ('B', 'C') else B_GREEN)
        click.echo(f"  Host      : {_colored(f'{host}:{port}', B_CYAN)}")
        click.echo(f"  Grade     : {_colored(grade, gc, bold=True)}  ({_colored(str(score) + '/100', gc)})")
        click.echo(f"  Protocol  : {_colored(py_result.get('protocol', 'N/A'), B_CYAN)}")

        cert = py_result.get('certificate', {})
        if cert:
            click.echo(f"\n  {_colored('CERTIFICATE', B_WHITE, bold=True)}")
            click.echo(f"    Subject   : {_colored(cert.get('subject', 'N/A'), B_CYAN)}")
            click.echo(f"    Issuer    : {_colored(cert.get('issuer', 'N/A'), B_CYAN)}")

        vulns = py_result.get('vulnerabilities', [])
        if vulns:
            click.echo(f"\n  {_colored('VULNERABILITIES', B_RED, bold=True)}")
            for v in vulns:
                click.echo(f"    {_colored('[!]', RED)} {v}")

        warnings = py_result.get('warnings', [])
        if warnings:
            click.echo(f"\n  {_colored('WARNINGS', B_YELLOW, bold=True)}")
            for w in warnings:
                click.echo(f"    {_colored('[*]', YELLOW)} {w}")

    click.echo(f"\n  {_colored('=' * 55, DIM)}")


def _display_scan_stats(go_result: Optional[Dict], py_result: Optional[Dict]) -> int:
    total_issues = 0
    lines = []

    if go_result:
        cert_issues = len(go_result.get('certificate', {}).get('issues', []) or [])
        chain_issues = len(go_result.get('chain', {}).get('issues', []) or [])
        ciphers = go_result.get('ciphers', {}) or {}
        weak = len(ciphers.get('weak', []) or [])
        insecure = len(ciphers.get('insecure', []) or [])
        vulns = go_result.get('vulnerabilities', {}) or {}
        findings = vulns.get('findings', []) or []
        active_vulns = sum(1 for f in findings if f.get('status') in ('VULNERABLE', 'WEAK'))
        tls_issues = len(go_result.get('tls_features', {}).get('issues', []) or [])
        dns_issues = len(go_result.get('dns', {}).get('issues', []) or [])
        http_issues = len(go_result.get('http', {}).get('issues', []) or [])
        crypto_issues = len(go_result.get('crypto', {}).get('issues', []) or [])
        port_issues = len((go_result.get('ports', {}) or go_result.get('port_scan', {})).get('issues', []) or [])
        total = cert_issues + chain_issues + weak + insecure + active_vulns + tls_issues + dns_issues + http_issues + crypto_issues + port_issues
        total_issues += total

        lines.append(f"    {_colored(str(cert_issues), B_RED if cert_issues > 0 else B_GREEN)} Certificate Issues")
        lines.append(f"    {_colored(str(chain_issues), B_RED if chain_issues > 0 else B_GREEN)} Chain Issues")
        lines.append(f"    {_colored(str(weak), B_YELLOW if weak > 0 else B_GREEN)} Weak + {_colored(str(insecure), B_RED if insecure > 0 else B_GREEN)} Broken Ciphers")
        lines.append(f"    {_colored(str(active_vulns), B_RED if active_vulns > 0 else B_GREEN)} Active Vulnerabilities")
        lines.append(f"    {_colored(str(tls_issues), B_YELLOW if tls_issues > 0 else B_GREEN)} TLS Feature Issues")
        lines.append(f"    {_colored(str(dns_issues), B_YELLOW if dns_issues > 0 else B_GREEN)} DNS Issues")
        lines.append(f"    {_colored(str(http_issues), B_YELLOW if http_issues > 0 else B_GREEN)} HTTP Issues")
        lines.append(f"    {_colored(str(crypto_issues), B_YELLOW if crypto_issues > 0 else B_GREEN)} Crypto Issues")
        lines.append(f"    {_colored(str(port_issues), B_YELLOW if port_issues > 0 else B_GREEN)} Port Issues")

        click.echo(f"\n  Scan Complete -- {_colored(str(total), B_WHITE, bold=True)} total findings")
        for line in lines:
            click.echo(line)

    elif py_result:
        vulns = py_result.get('vulnerabilities', [])
        warns = py_result.get('warnings', [])
        total = len(vulns) + len(warns)
        total_issues = total
        click.echo(f"\n  Scan Complete -- {_colored(str(total), B_WHITE, bold=True)} total findings")
        click.echo(f"    {_colored(str(len(vulns)), B_RED if vulns else B_GREEN)} Vulnerabilities")
        click.echo(f"    {_colored(str(len(warns)), B_YELLOW if warns else B_GREEN)} Warnings")

    return total_issues


@click.command()
@click.pass_context
def scan_ssl(ctx):
    """Interactive SSL/TLS Analyzer with Dual Engine (Go + Python)"""

    click.echo(SSL_BANNER)
    click.echo(f"\n  {_colored('Example:', DIM)} google.com, 192.168.1.1")
    click.echo()

    while True:
        raw = click.prompt(f"  {_colored('Input Target', B_CYAN, bold=True)}", default="", show_default=False)
        raw = raw.strip()
        if raw.lower() in ('exit', 'quit', 'q', ''):
            click.echo(f"\n  {_colored('[!] Exiting...', DIM)}")
            return

        host = raw
        port = 443
        if ':' in raw:
            parts = raw.rsplit(':', 1)
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                pass

        go_result = None
        py_result = None

        try:
            from hackit.ssl_tool.go_bridge import GoEngine
            engine = GoEngine()
            with _Spinner(f"Scanning {host}:{port}..."):
                go_result = engine.run(host=host, port=port, timeout=15)
        except Exception as e:
            click.echo(f"\r  {_colored(f'[*] Go engine: {e}', DIM)}")

        if go_result is None:
            click.echo(_colored("  [*] Running Python deep SSL analysis...", DIM))
            py_result = _python_deep_analyze(host, port, 15)

        click.echo()
        _display_merged(host, port, go_result, py_result)
        _display_scan_stats(go_result, py_result)

        click.echo(f"\n  {_colored('─' * 55, DIM)}")
        click.echo(f"  {_colored('Press Enter to scan another target, or type exit to quit.', DIM)}")
        click.echo(f"  {_colored('─' * 55, DIM)}")
        click.echo()
