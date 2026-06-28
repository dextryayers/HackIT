import click
import json
import ssl
import socket
import datetime
from typing import Dict, List, Optional, Any
from hackit.ui import display_tool_banner, _colored, B_CYAN, B_GREEN, B_YELLOW, B_RED, DIM, RED, GREEN, YELLOW, B_WHITE, RESET

WEAK_CIPHERS = [
    'RC4', 'DES', 'MD5', '3DES', 'NULL', 'EXPORT', 'anon',
    'RC2', 'IDEA', 'SEED', 'CAMELLIA128',
]

WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

CRITICAL_HEADERS = {
    'Strict-Transport-Security': 'HSTS',
    'Public-Key-Pins': 'HPKP',
}

GRADE_THRESHOLDS = {
    'A+': 100, 'A': 90, 'B': 75, 'C': 60, 'D': 40, 'F': 0
}


def _python_ssl_scan(host: str, port: int, timeout: int) -> Dict[str, Any]:
    result = {
        'host': host,
        'port': port,
        'grade': 'F',
        'score': 0,
        'certificate': {},
        'protocol': '',
        'cipher': {},
        'vulnerabilities': [],
        'warnings': [],
        'info': [],
    }

    score = 100

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert(binary_form=False)
                cipher_info = conn.cipher()
                protocol = conn.version()
                cert_der = conn.getpeercert(binary_form=True)

                result['protocol'] = protocol or 'Unknown'

                if cipher_info:
                    result['cipher'] = {
                        'name': cipher_info[0],
                        'protocol': cipher_info[1],
                        'bits': cipher_info[2],
                    }

                    for weak in WEAK_CIPHERS:
                        if weak.lower() in cipher_info[0].lower():
                            result['vulnerabilities'].append(f"Weak cipher detected: {cipher_info[0]}")
                            score -= 30
                            break

                    if cipher_info[2] and cipher_info[2] < 128:
                        result['vulnerabilities'].append(f"Weak key length: {cipher_info[2]} bits")
                        score -= 25

                if protocol in WEAK_PROTOCOLS:
                    result['vulnerabilities'].append(f"Weak protocol: {protocol}")
                    score -= 30

                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')
                    sans = []
                    for entry_type, entry_val in cert.get('subjectAltName', []):
                        sans.append(entry_val)

                    result['certificate'] = {
                        'subject': subject.get('commonName', ''),
                        'issuer': issuer.get('organizationName', issuer.get('commonName', '')),
                        'issuer_cn': issuer.get('commonName', ''),
                        'not_before': not_before,
                        'not_after': not_after,
                        'serial': cert.get('serialNumber', ''),
                        'version': cert.get('version', ''),
                        'sans': sans,
                        'san_count': len(sans),
                    }

                    if not_after:
                        try:
                            exp = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (exp - datetime.datetime.utcnow()).days
                            result['certificate']['days_remaining'] = days_left
                            if days_left < 0:
                                result['vulnerabilities'].append(f"Certificate EXPIRED ({abs(days_left)} days ago)")
                                score -= 40
                            elif days_left < 30:
                                result['warnings'].append(f"Certificate expires in {days_left} days")
                                score -= 10
                            elif days_left < 90:
                                result['warnings'].append(f"Certificate expires in {days_left} days")
                                score -= 5
                        except ValueError:
                            pass

                    if subject.get('commonName', '') == issuer.get('commonName', ''):
                        if issuer.get('organizationName', '') == '':
                            result['warnings'].append("Self-signed certificate detected")
                            score -= 20

                    if not sans:
                        result['warnings'].append("No Subject Alternative Names (SANs)")
                        score -= 5

    except ssl.SSLCertVerificationError as e:
        result['vulnerabilities'].append(f"Certificate verification failed: {e}")
        score -= 40
    except ssl.SSLError as e:
        result['vulnerabilities'].append(f"SSL error: {e}")
        score -= 50
    except socket.timeout:
        result['vulnerabilities'].append("Connection timed out")
        score = 0
    except ConnectionRefusedError:
        result['vulnerabilities'].append("Connection refused")
        score = 0
    except Exception as e:
        result['vulnerabilities'].append(f"Scan error: {e}")
        score = 0

    protocols_supported = []
    for proto_name, proto_const in [
        ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ('TLSv1.1', getattr(ssl, 'PROTOCOL_TLSv1_1', None)),
        ('TLSv1.2', getattr(ssl, 'PROTOCOL_TLSv1_2', None)),
    ]:
        if proto_const is None:
            continue
        try:
            test_ctx = ssl.SSLContext(proto_const)
            test_ctx.check_hostname = False
            test_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with test_ctx.wrap_socket(raw, server_hostname=host) as conn:
                    protocols_supported.append(proto_name)
        except Exception:
            pass

    result['protocols_supported'] = protocols_supported

    for weak_proto in ['TLSv1.0', 'TLSv1.1']:
        if weak_proto in protocols_supported:
            result['warnings'].append(f"Legacy protocol supported: {weak_proto}")
            score -= 10

    if 'TLSv1.2' not in protocols_supported and not result['protocol']:
        result['vulnerabilities'].append("TLS 1.2 not supported")
        score -= 15

    score = max(0, min(100, score))
    result['score'] = score

    for grade, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
        if score >= threshold:
            result['grade'] = grade
            break

    return result


def _display_results(r: Dict[str, Any]):
    grade = r.get('grade', 'F')
    score = r.get('score', 0)
    grade_colors = {
        'A+': B_GREEN, 'A': B_GREEN, 'B': B_YELLOW, 'C': YELLOW, 'D': B_RED, 'F': RED,
    }
    gc = grade_colors.get(grade, RED)

    click.echo(f"\n  {_colored('SSL/TLS ANALYSIS RESULTS', B_WHITE, bold=True)}")
    click.echo(f"  {_colored('=' * 50, DIM)}")
    click.echo(f"  Host      : {_colored(r['host'] + ':' + str(r['port']), B_CYAN)}")
    click.echo(f"  Grade     : {_colored(grade, gc, bold=True)}  ({_colored(str(score) + '/100', gc)})")
    click.echo(f"  Protocol  : {_colored(r.get('protocol', 'N/A'), B_CYAN)}")

    cipher = r.get('cipher', {})
    if cipher:
        click.echo(f"  Cipher    : {_colored(cipher.get('name', 'N/A'), B_CYAN)} ({cipher.get('bits', '?')} bits)")

    cert = r.get('certificate', {})
    if cert:
        click.echo(f"\n  {_colored('CERTIFICATE', B_WHITE, bold=True)}")
        click.echo(f"  Subject   : {_colored(cert.get('subject', 'N/A'), B_CYAN)}")
        click.echo(f"  Issuer    : {_colored(cert.get('issuer', 'N/A'), B_CYAN)}")
        click.echo(f"  Valid     : {cert.get('not_before', 'N/A')} -> {cert.get('not_after', 'N/A')}")
        days = cert.get('days_remaining')
        if days is not None:
            dc = B_GREEN if days > 90 else (B_YELLOW if days > 30 else RED)
            click.echo(f"  Expires   : {_colored(str(days) + ' days', dc)}")
        click.echo(f"  SANs      : {cert.get('san_count', 0)} entries")

    protos = r.get('protocols_supported', [])
    if protos:
        click.echo(f"\n  {_colored('PROTOCOLS', B_WHITE, bold=True)}")
        for p in protos:
            pc = RED if p in ['TLSv1.0', 'TLSv1.1'] else B_GREEN
            click.echo(f"    {_colored(p, pc)}")

    vulns = r.get('vulnerabilities', [])
    if vulns:
        click.echo(f"\n  {_colored('VULNERABILITIES', B_RED, bold=True)}")
        for v in vulns:
            click.echo(f"    {_colored('[!]', RED)} {v}")

    warnings = r.get('warnings', [])
    if warnings:
        click.echo(f"\n  {_colored('WARNINGS', B_YELLOW, bold=True)}")
        for w in warnings:
            click.echo(f"    {_colored('[*]', YELLOW)} {w}")

    click.echo(f"\n  {_colored('=' * 50, DIM)}")


@click.command()
@click.option('--host', required=True, help='Target Host (e.g. google.com)')
@click.option('--port', default=443, type=int, help='Target Port')
@click.option('--timeout', default=10, type=int, help='Timeout in seconds')
@click.option('--output', help='Save results to JSON file')
@click.option('--no-go', is_flag=True, help='Force Python engine (skip Go)')
@click.option('--full', is_flag=True, help='Full cipher suite enumeration')
@click.option('--json-only', is_flag=True, help='Output JSON only')
def scan_ssl(host, port, timeout, output, no_go, full, json_only):
    """Deep SSL/TLS Analyzer with Grading (Go + Python Dual Engine)"""
    if not json_only:
        display_tool_banner('SSL/TLS ANALYZER')

    go_success = False
    if not no_go:
        try:
            from hackit.ssl_tool.go_bridge import GoEngine
            engine = GoEngine()
            if engine.available if hasattr(engine, 'available') else True:
                engine.run(host=host, port=port, timeout=timeout, output=output)
                go_success = True
        except Exception:
            pass

    if not go_success:
        if not json_only:
            click.echo(_colored("  [*] Using Python SSL analysis engine...", DIM))

        result = _python_ssl_scan(host, port, timeout)

        if json_only:
            click.echo(json.dumps(result, indent=2, default=str))
        else:
            _display_results(result)

        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            if not json_only:
                click.echo(_colored(f"\n  [+] Results saved to {output}", B_GREEN))
