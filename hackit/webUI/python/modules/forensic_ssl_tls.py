import re
import json
import ssl
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from module_common import safe_fetch_json, make_finding

SSL_PORTS = [443, 8443, 993, 995, 465, 587, 636, 853]

EXTENDED_KEY_USAGE_MAP = {
    "serverAuth": "TLS Web Server Authentication",
    "clientAuth": "TLS Web Client Authentication",
    "codeSigning": "Code Signing",
    "emailProtection": "Email Protection",
    "timeStamping": "Timestamping",
    "ocspSigning": "OCSP Signing",
    "smartcardLogon": "Smart Card Logon",
    "ipsecIKE": "IPsec IKE",
    "msSGC": "Microsoft Server Gated Crypto",
    "nsSGC": "Netscape Server Gated Crypto",
}

KNOWN_CA_KEY_SIZES = {
    "Let's Encrypt": 2048, "DigiCert": 2048, "Sectigo": 2048,
    "GlobalSign": 2048, "GoDaddy": 2048, "Cloudflare": 2048,
}

async def _scan_certificate_chain(hostname: str, port: int, client) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        def get_chain():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(8)
                    s.connect((hostname, port))
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    proto = s.version()
                    cert_chain = []
                    try:
                        chain_data = s.getpeercert(True)
                        if chain_data:
                            cert_chain.append(chain_data)
                    except Exception:
                        pass
                    return {"cert": cert, "cipher": cipher, "protocol": proto, "chain_len": len(cert_chain)}
            except Exception:
                return None
        result = await loop.run_in_executor(None, get_chain)
        if not result:
            return findings

        cert = result.get("cert", {})
        port_label = f":{port}" if port != 443 else ""

        findings.append(make_finding(
            entity=f"SSL/TLS Certificate on port {port}",
            ftype=f"Forensic SSL - Certificate Present{port_label}",
            source="Forensic SSL/TLS",
            confidence="High", color="emerald",
            status="Certificate Found",
            tags=["forensic", "ssl", "tls"]
        ))

        if cert.get("subject"):
            subject_vals = {}
            for item in cert["subject"]:
                for key, val in item:
                    subject_vals[key] = val
            cn = subject_vals.get("commonName", "")
            org = subject_vals.get("organizationName", "")
            country = subject_vals.get("countryName", "")
            if cn:
                findings.append(make_finding(
                    entity=cn[:200],
                    ftype=f"Forensic SSL - Subject CN{port_label}",
                    source="Forensic SSL/TLS",
                    confidence="High", color="slate",
                    tags=["forensic", "subject", "cn"]
                ))
            if org:
                findings.append(make_finding(
                    entity=org[:200],
                    ftype=f"Forensic SSL - Subject Organization{port_label}",
                    source="Forensic SSL/TLS",
                    confidence="High", color="slate",
                    tags=["forensic", "subject", "org"]
                ))
            if country:
                findings.append(make_finding(
                    entity=country,
                    ftype=f"Forensic SSL - Subject Country{port_label}",
                    source="Forensic SSL/TLS",
                    confidence="High", color="slate",
                    tags=["forensic", "subject", "country"]
                ))

        if cert.get("issuer"):
            issuer_vals = {}
            for item in cert["issuer"]:
                for key, val in item:
                    issuer_vals[key] = val
            issuer_org = issuer_vals.get("organizationName", "Unknown")
            issuer_cn = issuer_vals.get("commonName", "")
            findings.append(make_finding(
                entity=f"CA: {issuer_org} ({issuer_cn})",
                ftype=f"Forensic SSL - Issuer / Certificate Authority{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "issuer", "ca"]
            ))

        serial = cert.get("serialNumber", "")
        if serial:
            findings.append(make_finding(
                entity=f"Serial: {serial[:40]}",
                ftype=f"Forensic SSL - Serial Number{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "serial"]
            ))

        valid_from = cert.get("notBefore", "")
        valid_to = cert.get("notAfter", "")
        if valid_from:
            findings.append(make_finding(
                entity=f"Valid from: {valid_from}",
                ftype=f"Forensic SSL - Validity Start{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "validity"]
            ))
        if valid_to:
            try:
                exp = datetime.strptime(valid_to[:19] if len(valid_to) >= 19 else valid_to, "%b %d %H:%M:%S %Y %Z" if " " in valid_to else "%Y-%m-%d")
                days = (exp - datetime.now()).days
            except Exception:
                exp_str = valid_to[:25]
                days = 0
            findings.append(make_finding(
                entity=f"Expires: {valid_to} ({days} days remaining)",
                ftype=f"Forensic SSL - Expiry{port_label}",
                source="Forensic SSL/TLS",
                confidence="High",
                color="emerald" if days > 90 else ("orange" if days > 30 else "red"),
                threat_level="Informational" if days > 90 else ("Elevated Risk" if days > 30 else "High Risk"),
                tags=["forensic", "expiry"]
            ))

        sans = cert.get("subjectAltName", [])
        if sans:
            for san_type, san_val in sans[:15]:
                findings.append(make_finding(
                    entity=san_val[:200],
                    ftype=f"Forensic SSL - Subject Alt Name ({san_type}){port_label}",
                    source="Forensic SSL/TLS",
                    confidence="High", color="blue",
                    tags=["forensic", "san"]
                ))
            if len(sans) > 15:
                findings.append(make_finding(
                    entity=f"... and {len(sans) - 15} more SANs ({len(sans)} total)",
                    ftype=f"Forensic SSL - SAN Summary{port_label}",
                    source="Forensic SSL/TLS",
                    confidence="High", color="slate",
                    tags=["forensic", "san", "summary"]
                ))

        cipher_info = result.get("cipher", ())
        if cipher_info:
            cipher_name = cipher_info[0]
            bits = cipher_info[1]
            findings.append(make_finding(
                entity=f"{cipher_name} ({bits} bits)",
                ftype=f"Forensic SSL - Cipher Suite{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "cipher"]
            ))

        proto = result.get("protocol", "")
        if proto:
            findings.append(make_finding(
                entity=proto,
                ftype=f"Forensic SSL - Protocol Version{port_label}",
                source="Forensic SSL/TLS",
                confidence="High",
                color="emerald" if "TLSv1.3" in proto else ("orange" if "SSL" in proto else "slate"),
                threat_level="Informational" if "TLSv1" in proto else "High Risk",
                tags=["forensic", "protocol"]
            ))

        sig_algo = cert.get("signatureAlgorithm", "")
        if sig_algo:
            findings.append(make_finding(
                entity=f"Signature: {sig_algo}",
                ftype=f"Forensic SSL - Signature Algorithm{port_label}",
                source="Forensic SSL/TLS",
                confidence="High",
                color="orange" if "sha1" in sig_algo.lower() else "emerald",
                tags=["forensic", "signature"]
            ))

        pub_key = cert.get("subjectPublicKeyInfo", {})
        if pub_key:
            algo = pub_key.get("algorithm", "")
            size = 0
            try:
                from cryptography.x509 import load_pem_x509_certificate
            except ImportError:
                pass
            findings.append(make_finding(
                entity=f"Public Key: {algo} ({size or '?'} bits)",
                ftype=f"Forensic SSL - Public Key{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "public-key"]
            ))

        if cert.get("extensions"):
            ext_list = cert["extensions"]
            ext_oids = set()
            for ext in ext_list:
                if hasattr(ext, "oid"):
                    ext_oids.add(ext.oid.dotted_string)
                elif isinstance(ext, tuple) and len(ext) >= 1:
                    ext_oids.add(str(ext[0]))
            findings.append(make_finding(
                entity=f"{len(ext_oids)} certificate extensions present",
                ftype=f"Forensic SSL - Extensions Count{port_label}",
                source="Forensic SSL/TLS",
                confidence="High", color="slate",
                tags=["forensic", "extensions"]
            ))

        fingerprinter = cert.get("fingerprintSHA256", "")
        if not fingerprinter and cert.get("serialNumber"):
            try:
                loop2 = asyncio.get_event_loop()
                def get_fingerprint():
                    try:
                        ctx = ssl.create_default_context()
                        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                            s.settimeout(5)
                            s.connect((hostname, port))
                            der = s.getpeercert(True)
                            if der:
                                import hashlib
                                return hashlib.sha256(der).hexdigest()
                    except Exception:
                        return None
                fp = await loop2.run_in_executor(None, get_fingerprint)
                if fp:
                    findings.append(make_finding(
                        entity=f"SHA256: {fp}",
                        ftype=f"Forensic SSL - SHA256 Fingerprint{port_label}",
                        source="Forensic SSL/TLS",
                        confidence="High", color="slate",
                        tags=["forensic", "fingerprint"]
                    ))
            except Exception:
                pass

    except Exception:
        pass
    return findings

async def crawl(target: str, client) -> list:
    findings = []
    hostname = target.strip().lower()
    if "://" in hostname:
        hostname = urlparse(hostname).netloc

    tasks = [_scan_certificate_chain(hostname, port, client) for port in SSL_PORTS]
    port_results = await asyncio.gather(*tasks)
    for pr in port_results:
        findings.extend(pr)

    if findings:
        findings.append(make_finding(
            entity=f"Forensic SSL/TLS analysis complete: {len(findings)} findings across {len(SSL_PORTS)} ports",
            ftype="Forensic SSL - Summary",
            source="Forensic SSL/TLS",
            confidence="High", color="purple",
            status="Complete",
            tags=["forensic", "ssl", "tls", "summary"]
        ))

    return findings
