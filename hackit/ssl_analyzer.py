"""
SSL/TLS Info Tool - Certificate analysis and weak protocol detection
"""
import ssl
import socket
from datetime import datetime
import json
import click
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLTLSAnalyzer:
    """Analyze SSL/TLS certificates and protocols"""
    
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
    STRONG_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def get_certificate_info(self, host: str, port: int = 443) -> dict:
        """Get detailed certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get DER certificate
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Parse subject
                    subject = {}
                    for attr in cert.subject:
                        subject[attr.oid._name] = attr.value
                    
                    # Parse issuer
                    issuer = {}
                    for attr in cert.issuer:
                        issuer[attr.oid._name] = attr.value
                    
                    # SAN
                    san = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        for name in san_ext.value:
                            san.append(name.value)
                    except:
                        pass
                    
                    # Get protocol and cipher
                    protocol = ssock.version()
                    cipher = ssock.cipher()[0]
                    
                    # Check expiry
                    not_after = cert.not_valid_after
                    not_before = cert.not_valid_before
                    days_remaining = (not_after - datetime.utcnow()).days
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": not_before.isoformat(),
                        "valid_to": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "expired": days_remaining < 0,
                        "expiring_soon": 0 < days_remaining < 30,
                        "san": san,
                        "protocol": protocol,
                        "protocol_secure": protocol in self.STRONG_PROTOCOLS,
                        "protocol_weak": protocol in self.WEAK_PROTOCOLS,
                        "cipher": cipher,
                        "serial_number": hex(cert.serial_number),
                        "public_key_size": cert.public_key().key_size
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def check_tls_versions(self, host: str, port: int = 443) -> dict:
        """Check which TLS versions are supported"""
        versions = {
            "ssl.PROTOCOL_SSLv3": "SSLv3",
            "ssl.PROTOCOL_TLSv1": "TLSv1.0",
            "ssl.PROTOCOL_TLSv1_1": "TLSv1.1",
            "ssl.PROTOCOL_TLSv1_2": "TLSv1.2",
            "ssl.PROTOCOL_TLS": "TLSv1.3+"
        }
        
        supported = {}
        for protocol_name, label in versions.items():
            try:
                protocol = getattr(ssl, protocol_name.split('.')[-1], None)
                if protocol:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((host, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=host):
                            supported[label] = True
            except:
                supported[label] = False
        
        return supported


@click.command()
@click.option('--host', required=True, help='Target host')
@click.option('--port', default=443, type=int, help='Port number')
@click.option('--timeout', default=10, type=int, help='Connection timeout')
@click.option('--output', default=None, help='Save results to JSON')
def analyze_ssl(host, port, timeout, output):
    """Analyze SSL/TLS certificates and protocols"""
    
    analyzer = SSLTLSAnalyzer(timeout=timeout)
    
    click.echo(f"[*] Analyzing SSL/TLS for {host}:{port}")
    
    # Get certificate info
    cert_info = analyzer.get_certificate_info(host, port)
    
    if "error" in cert_info:
        click.echo(f"[!] Error: {cert_info['error']}")
        return
    
    # Display certificate info
    click.echo("\n[+] Certificate Information:")
    click.echo(f"    Subject: {cert_info['subject'].get('commonName', 'N/A')}")
    click.echo(f"    Issuer: {cert_info['issuer'].get('organizationName', 'N/A')}")
    click.echo(f"    Valid From: {cert_info['valid_from']}")
    click.echo(f"    Valid To: {cert_info['valid_to']}")
    click.echo(f"    Days Remaining: {cert_info['days_remaining']}")
    
    # Alert for expiry
    if cert_info['expired']:
        click.echo("    [!] CERTIFICATE EXPIRED!")
    elif cert_info['expiring_soon']:
        click.echo(f"    [!] EXPIRING SOON ({cert_info['days_remaining']} days)")
    
    # TLS Protocol
    click.echo(f"\n[+] TLS Configuration:")
    click.echo(f"    Protocol: {cert_info['protocol']}")
    if cert_info['protocol_weak']:
        click.echo(f"    [!] WEAK PROTOCOL DETECTED!")
    elif cert_info['protocol_secure']:
        click.echo(f"    [✓] Strong Protocol")
    
    click.echo(f"    Cipher: {cert_info['cipher']}")
    click.echo(f"    Key Size: {cert_info['public_key_size']} bits")
    
    # SAN
    if cert_info['san']:
        click.echo(f"\n[+] Subject Alternative Names:")
        for name in cert_info['san']:
            click.echo(f"    - {name}")
    
    if output:
        with open(output, 'w') as f:
            json.dump(cert_info, f, indent=2, default=str)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    analyze_ssl()
