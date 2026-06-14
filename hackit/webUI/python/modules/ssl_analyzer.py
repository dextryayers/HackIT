import asyncio
import ssl
import socket
from datetime import datetime
from models import IntelligenceFinding
from osint_common import get_ssl_cert_info, parse_cert_to_dict

async def crawl(target: str, client=None):
    findings = []
    hostname = target.strip().lower()
    if hostname.startswith("http"):
        from urllib.parse import urlparse
        hostname = urlparse(hostname).netloc

    for port in [443, 8443, 465, 993, 995, 2525, 587]:
        try:
            cert_info = await get_ssl_cert_info(hostname, port)
            if not cert_info or not cert_info.get("cert"):
                continue

            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)
            is_self_signed = False
            if parsed.get("issuer") and parsed.get("subject"):
                is_self_signed = parsed["issuer"].get("organizationName") == parsed["subject"].get("organizationName")

            port_label = f":{port}" if port != 443 else ""

            findings.append(IntelligenceFinding(
                entity=hostname,
                type=f"SSL Certificate{port_label}",
                source="SSL Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
            ))

            if parsed.get("issuer"):
                org = parsed["issuer"].get("organizationName", "Unknown")
                cn = parsed["issuer"].get("commonName", "")
                findings.append(IntelligenceFinding(
                    entity=f"{org} ({cn})" if cn else org,
                    type=f"SSL Issuer{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=str(parsed["issuer"])
                ))

            if parsed.get("subject"):
                org = parsed["subject"].get("organizationName", "Unknown")
                cn = parsed["subject"].get("commonName", "")
                findings.append(IntelligenceFinding(
                    entity=f"{org} ({cn})" if cn else org,
                    type=f"SSL Subject{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

            if parsed.get("valid_to"):
                findings.append(IntelligenceFinding(
                    entity=f"Expires: {parsed['valid_to']} ({parsed.get('days_remaining', '?')} days)",
                    type=f"SSL Expiry{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="emerald" if (parsed.get('days_remaining') or 0) > 30 else "orange",
                    threat_level="Informational" if (parsed.get('days_remaining') or 0) > 7 else "Elevated Risk",
                    raw_data=f"Valid: {parsed.get('valid_from')} -> {parsed.get('valid_to')}"
                ))

            if is_self_signed:
                findings.append(IntelligenceFinding(
                    entity=f"Self-signed certificate{port_label}",
                    type=f"SSL Self-Signed{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    tags=["security"]
                ))

            protocol = cert_info.get("protocol", "")
            if protocol:
                findings.append(IntelligenceFinding(
                    entity=protocol,
                    type=f"TLS Protocol Version{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="emerald" if "TLSv1.3" in protocol else ("orange" if "TLSv1.2" in protocol else "red"),
                    threat_level="Informational",
                ))

            cipher = cert_info.get("cipher")
            if cipher:
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                bits = cipher[1] if isinstance(cipher, tuple) and len(cipher) > 1 else None
                findings.append(IntelligenceFinding(
                    entity=cipher_name + (f" ({bits} bits)" if bits else ""),
                    type=f"SSL Cipher{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))

            sans = parsed.get("subject_alt_names", [])
            for san in sans[:5]:
                findings.append(IntelligenceFinding(
                    entity=san,
                    type=f"SSL SAN{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                ))
            if len(sans) > 5:
                findings.append(IntelligenceFinding(
                    entity=f"... and {len(sans) - 5} more SANs",
                    type=f"SSL SAN Summary{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

        except Exception as e:
            if port == 443:
                findings.append(IntelligenceFinding(
                    entity=f"No SSL on port {port}: {str(e)[:80]}",
                    type="SSL Not Available",
                    source="SSL Analyzer",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    tags=["security"]
                ))

    return findings
