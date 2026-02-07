"""
HTTP Header Checker - Analyze security headers and TLS info
"""
import os
import requests
import ssl
import socket
from datetime import datetime
import click
from urllib.parse import urlparse
import urllib3

from hackit.config import get_proxy, verify_ssl_default
from hackit.logger import get_logger


logger = get_logger(__name__)


class HTTPHeaderChecker:
    """Check HTTP security headers and TLS configuration"""
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'XFO',
        'X-Content-Type-Options': 'XCTO',
        'X-XSS-Protection': 'XSS-Protection',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy'
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Respect global proxy and SSL verify settings
        proxy = get_proxy()
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
            logger.info(f'Using proxy: {proxy}')

        self.verify = verify_ssl_default()
        if not self.verify:
            # suppress insecure request warnings when verification disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning('SSL verification disabled (HACKIT_VERIFY=0)')
    
    def check_headers(self, url: str) -> dict:
        """Check HTTP security headers"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify)
            headers = response.headers
            
            results = {
                "status_code": response.status_code,
                "server": headers.get('Server', 'Not Disclosed'),
                "security_headers": {},
                "missing_headers": []
            }
            
            # Check for security headers
            for header, short_name in self.SECURITY_HEADERS.items():
                if header in headers:
                    results["security_headers"][short_name] = headers[header]
                else:
                    results["missing_headers"].append(short_name)
            
            return results
        except Exception as e:
            logger.exception('Error while checking headers for %s', url)
            return {"error": str(e)}
    
    def check_tls(self, host: str, port: int = 443) -> dict:
        """Check TLS/SSL version and certificate info"""
        try:
            # Create SSL context that respects verification preference
            if self.verify:
                context = ssl.create_default_context()
            else:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    # Get certificate details
                    cert_info = {
                        "protocol": version,
                        "cipher": ssock.cipher()[0],
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "valid_from": cert.get('notBefore', 'N/A'),
                        "valid_to": cert.get('notAfter', 'N/A'),
                        "san": [x[1] for x in cert.get('subjectAltName', [])]
                    }

                    # Check for weak protocols
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                    cert_info["weak"] = version in weak_protocols

                    return cert_info
        except Exception as e:
            logger.exception('Error while checking TLS for %s:%s', host, port)
            return {"error": str(e)}


@click.command()
@click.option('--url', required=True, help='Target URL (e.g., https://example.com)')
@click.option('--tls', is_flag=True, help='Check TLS/SSL info')
@click.option('--headers', is_flag=True, help='Check security headers')
@click.option('--all', 'check_all', is_flag=True, help='Check both headers and TLS')
def check_headers(url, tls, headers, check_all):
    """Check HTTP security headers and TLS configuration"""
    
    checker = HTTPHeaderChecker()
    parsed = urlparse(url)
    host = parsed.netloc
    
    if check_all:
        tls = headers = True
    elif not (tls or headers):
        headers = True
    
    # Check headers
    if headers:
        click.echo(f"[*] Checking HTTP headers for {url}")
        header_results = checker.check_headers(url)
        
        if "error" in header_results:
            click.echo(f"[!] Error: {header_results['error']}")
        else:
            click.echo(f"\n[+] Status Code: {header_results['status_code']}")
            click.echo(f"[+] Server: {header_results['server']}")
            
            click.echo("\n[+] Security Headers Present:")
            for header, value in header_results['security_headers'].items():
                click.echo(f"    {header}: {value[:50]}...")
            
            if header_results['missing_headers']:
                click.echo("\n[!] Missing Headers:")
                for header in header_results['missing_headers']:
                    click.echo(f"    - {header}")
    
    # Check TLS
    if tls:
        click.echo(f"\n[*] Checking TLS/SSL for {host}")
        tls_results = checker.check_tls(host)
        
        if "error" in tls_results:
            click.echo(f"[!] Error: {tls_results['error']}")
        else:
            click.echo(f"[+] Protocol: {tls_results['protocol']}")
            click.echo(f"[+] Cipher: {tls_results['cipher']}")
            click.echo(f"[+] Subject: {tls_results['subject'].get('commonName', 'N/A')}")
            click.echo(f"[+] Issuer: {tls_results['issuer'].get('organizationName', 'N/A')}")
            click.echo(f"[+] Valid: {tls_results['valid_from']} to {tls_results['valid_to']}")
            
            if tls_results['weak']:
                click.echo(f"[!] WEAK PROTOCOL DETECTED: {tls_results['protocol']}")


if __name__ == "__main__":
    check_headers()
