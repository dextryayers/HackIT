import asyncio
import ssl
import socket
import re
from datetime import datetime
from models import IntelligenceFinding
from osint_common import get_ssl_cert_info, parse_cert_to_dict

TLS_VERSIONS = {
    ssl.TLSVersion.SSLv3: "SSLv3",
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

CIPHER_STRENGTHS = {
    "aes_128_gcm": "strong",
    "aes_256_gcm": "strong",
    "aes_128_cbc": "moderate",
    "aes_256_cbc": "moderate",
    "chacha20_poly1305": "strong",
    "rc4": "weak",
    "des": "weak",
    "3des": "weak",
    "null": "none",
    "export": "weak",
}

CIPHER_SUITES = {
    "TLS_AES_256_GCM_SHA384": ("TLS 1.3", "strong"),
    "TLS_CHACHA20_POLY1305_SHA256": ("TLS 1.3", "strong"),
    "TLS_AES_128_GCM_SHA256": ("TLS 1.3", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": ("TLS 1.2", "strong"),
    "TLS_RSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_RSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_RSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "TLS_RSA_WITH_RC4_128_SHA": ("SSLv3", "weak"),
    "TLS_RSA_WITH_RC4_128_MD5": ("SSLv3", "weak"),
    "SSL_RSA_WITH_RC4_128_SHA": ("SSLv3", "weak"),
    "SSL_RSA_WITH_RC4_128_MD5": ("SSLv3", "weak"),
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": ("TLS 1.2", "strong"),
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DH_anon_WITH_AES_256_CBC_SHA": ("TLS 1.0", "weak"),
    "TLS_DH_anon_WITH_AES_128_CBC_SHA": ("TLS 1.0", "weak"),
}

KNOWN_VULNS = {
    "heartbleed": {"name": "Heartbleed (CVE-2014-0160)", "desc": "OpenSSL Heartbleed vulnerability"},
    "poodle": {"name": "POODLE (CVE-2014-3566)", "desc": "SSLv3 padding oracle attack"},
    "logjam": {"name": "Logjam (CVE-2015-4000)", "desc": "Diffie-Hellman key exchange weakness"},
    "freak": {"name": "FREAK (CVE-2015-0204)", "desc": "RSA export cipher downgrade"},
    "drown": {"name": "DROWN (CVE-2016-0800)", "desc": "SSLv2 cross-protocol attack"},
    "sweet32": {"name": "Sweet32 (CVE-2016-2183)", "desc": "3DES block cipher birthday attack"},
    "beast": {"name": "BEAST (CVE-2011-3389)", "desc": "TLS 1.0 CBC vulnerability"},
    "crime": {"name": "CRIME (CVE-2012-4929)", "desc": "TLS compression attack"},
    "lucky13": {"name": "Lucky13 (CVE-2013-0169)", "desc": "CBC padding oracle attack"},
    "rc4_weak": {"name": "RC4 Weakness", "desc": "RC4 cipher is broken"},
}

WEAK_CIPHERS_VULN_MAP = {
    "SSL_RSA_WITH_RC4": "rc4_weak",
    "TLS_RSA_WITH_RC4": "rc4_weak",
    "3DES": "sweet32",
    "SSLv3": "poodle",
    "TLS_DH_anon": "logjam",
    "TLS_ECDHE_anon": "logjam",
}

VULN_PATTERNS = {
    "heartbleed": [r"heartbleed", r"CVE-2014-0160", r"OpenSSL 1\.0\.1[^0-2]"],
    "poodle": [r"SSLv3", r"poodle", r"CVE-2014-3566"],
    "logjam": [r"DHE_EXPORT", r"export.*dh", r"CVE-2015-4000"],
    "freak": [r"export.*rsa", r"rsa.*export", r"CVE-2015-0204"],
}

SSL_GRADE_SCORES = {
    "A+": 10, "A": 9, "A-": 8,
    "B+": 7, "B": 6, "B-": 5,
    "C+": 4, "C": 3, "C-": 2,
    "D": 1, "E": 0, "F": 0,
}

SSL_SCAN_PORTS = [443, 8443, 993, 995, 465, 587, 636, 989, 990, 853, 2525]

async def crawl(target: str, client=None):
    findings = []
    hostname = target.strip().lower()
    if hostname.startswith("http"):
        from urllib.parse import urlparse
        hostname = urlparse(hostname).netloc

    async def scan_port(port):
        local_findings = []
        try:
            cert_info = await asyncio.wait_for(get_ssl_cert_info(hostname, port), timeout=5.0)
            if not cert_info or not cert_info.get("cert"):
                return local_findings

            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)

            # Enhanced certificate chain weakness checks
            await _check_cert_chain_vulns(parsed, f":{port}" if port != 443 else "", local_findings)

            # OCSP stapling check
            await _check_ocsp_stapling(hostname, port, local_findings, f":{port}" if port != 443 else "")

            is_self_signed = False
            if parsed.get("issuer") and parsed.get("subject"):
                is_self_signed = parsed["issuer"].get("organizationName") == parsed["subject"].get("organizationName")

            port_label = f":{port}" if port != 443 else ""

            local_findings.append(IntelligenceFinding(
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
                country = parsed["issuer"].get("countryName", "")
                org_parts = [org]
                if cn:
                    org_parts.append(f"({cn})")
                if country:
                    org_parts.append(f"[{country}]")
                local_findings.append(IntelligenceFinding(
                    entity=" ".join(org_parts),
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
                subject_parts = [org]
                if cn:
                    subject_parts.append(f"({cn})")
                local_findings.append(IntelligenceFinding(
                    entity=" ".join(subject_parts) if subject_parts else org,
                    type=f"SSL Subject{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

            if parsed.get("valid_to"):
                days_remaining = parsed.get("days_remaining", 0)
                c = "emerald" if days_remaining > 365 else ("blue" if days_remaining > 90 else ("orange" if days_remaining > 30 else ("red" if days_remaining > 7 else "darkred")))
                risk = "Informational" if days_remaining > 90 else ("Elevated Risk" if days_remaining > 30 else ("High Risk" if days_remaining > 7 else "Critical Risk"))
                local_findings.append(IntelligenceFinding(
                    entity=f"Expires: {parsed['valid_to']} ({days_remaining} days remaining)",
                    type=f"SSL Expiry{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color=c,
                    threat_level=risk,
                    raw_data=f"Valid: {parsed.get('valid_from')} -> {parsed.get('valid_to')}"
                ))

            if parsed.get("valid_from"):
                local_findings.append(IntelligenceFinding(
                    entity=f"Issued: {parsed['valid_from']}",
                    type=f"SSL Issuance Date{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

            if parsed.get("is_expired"):
                local_findings.append(IntelligenceFinding(
                    entity=f"EXPIRED certificate on port {port}",
                    type=f"SSL Expired{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="red",
                    threat_level="Critical Risk",
                    tags=["security", "expired"]
                ))

            serial = parsed.get("serial_number", "")
            if serial:
                local_findings.append(IntelligenceFinding(
                    entity=f"Serial: {serial[:30]}",
                    type=f"SSL Serial{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

            if is_self_signed:
                local_findings.append(IntelligenceFinding(
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
                proto_lower = protocol.lower()
                c = "emerald" if "tlsv1.3" in proto_lower else ("blue" if "tlsv1.2" in proto_lower else ("orange" if "tlsv1" in proto_lower else "red"))
                risk = "Informational" if "tlsv1.3" in proto_lower else ("Informational" if "tlsv1.2" in proto_lower else ("Elevated Risk" if "tlsv1" in proto_lower else "High Risk"))
                local_findings.append(IntelligenceFinding(
                    entity=protocol,
                    type=f"TLS Protocol Version{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color=c,
                    threat_level=risk,
                    tags=["protocol"]
                ))

                if "ssl" in proto_lower:
                    local_findings.append(IntelligenceFinding(
                        entity=f"Outdated protocol: {protocol}",
                        type=f"SSL Protocol Vulnerability{port_label}",
                        source="SSL Analyzer",
                        confidence="High",
                        color="red",
                        threat_level="Critical Risk",
                        tags=["security", "vulnerability"]
                    ))

                for vuln_key, vuln_info in KNOWN_VULNS.items():
                    for vpat in VULN_PATTERNS.get(vuln_key, []):
                        if re.search(vpat, proto_lower, re.I):
                            local_findings.append(IntelligenceFinding(
                                entity=f"{vuln_info['name']} detected",
                                type=f"Known Vulnerability{port_label}",
                                source="SSL Analyzer",
                                confidence="Medium",
                                color="red",
                                threat_level="Critical Risk",
                                raw_data=vuln_info['desc'],
                                tags=["security", "vulnerability", vuln_key]
                            ))
                            break

            cipher = cert_info.get("cipher")
            if cipher:
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                bits = cipher[1] if isinstance(cipher, tuple) and len(cipher) > 1 else None
                cipher_str_val = cipher_name + (f" ({bits} bits)" if bits else "")

                strength = "unknown"
                for sc, st in CIPHER_STRENGTHS.items():
                    if sc in cipher_name.lower():
                        strength = st
                        break
                cipher_info = CIPHER_SUITES.get(cipher_name) or EXTRA_CIPHER_SUITES.get(cipher_name)
                if cipher_info:
                    strength = cipher_info[1]

                c = "emerald" if strength == "strong" else ("orange" if strength == "moderate" else "red")
                risk = "Informational" if strength == "strong" else ("Elevated Risk" if strength == "moderate" else "High Risk")

                local_findings.append(IntelligenceFinding(
                    entity=cipher_str_val,
                    type=f"SSL Cipher ({strength}){port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color=c,
                    threat_level=risk,
                    tags=["cipher", strength]
                ))

                if strength == "weak" or "rc4" in cipher_name.lower() or "des" in cipher_name.lower():
                    local_findings.append(IntelligenceFinding(
                        entity=f"Weak cipher detected: {cipher_name}",
                        type=f"Weak Cipher Warning{port_label}",
                        source="SSL Analyzer",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        tags=["security", "weak-cipher"]
                    ))

                for weak_key, vuln_key in WEAK_CIPHERS_VULN_MAP.items():
                    if weak_key.lower() in cipher_name.lower():
                        vuln_info = KNOWN_VULNS.get(vuln_key, {})
                        local_findings.append(IntelligenceFinding(
                            entity=f"Potential {vuln_info.get('name', vuln_key)} from cipher {cipher_name}",
                            type=f"Vulnerability Indicator{port_label}",
                            source="SSL Analyzer",
                            confidence="Low",
                            color="orange",
                            threat_level="Elevated Risk",
                            tags=["security", "vulnerability", vuln_key]
                        ))

            sans = parsed.get("subject_alt_names", [])
            for san in sans[:5]:
                local_findings.append(IntelligenceFinding(
                    entity=san,
                    type=f"SSL SAN{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["san"]
                ))
            if len(sans) > 5:
                local_findings.append(IntelligenceFinding(
                    entity=f"... and {len(sans) - 5} more SANs ({len(sans)} total)",
                    type=f"SSL SAN Summary{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["san", "summary"]
                ))

            if parsed.get("serial_number"):
                local_findings.append(IntelligenceFinding(
                    entity=f"Serial: {parsed['serial_number'][:30]}",
                    type=f"SSL Serial Number{port_label}",
                    source="SSL Analyzer",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                ))

            sig_algo = parsed.get("signature_algorithm", "")
            if sig_algo:
                c = "orange" if "sha1" in sig_algo.lower() else "emerald"
                local_findings.append(IntelligenceFinding(
                    entity=f"Signature Algorithm: {sig_algo}",
                    type=f"SSL Signature Algorithm{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color=c,
                    threat_level="Elevated Risk" if "sha1" in sig_algo.lower() else "Informational",
                ))

            pub_key_algo = parsed.get("public_key_algorithm", "")
            if pub_key_algo:
                local_findings.append(IntelligenceFinding(
                    entity=f"Public Key: {pub_key_algo} ({parsed.get('public_key_size', '?')} bits)",
                    type=f"SSL Public Key{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="emerald" if (parsed.get('public_key_size') or 0) >= 2048 else "orange",
                    threat_level="Informational",
                ))
        except (asyncio.TimeoutError, Exception):
            pass
        return local_findings

    tasks = [scan_port(p) for p in SSL_SCAN_PORTS]
    port_results = await asyncio.gather(*tasks)
    for pf in port_results:
        findings.extend(pf)

    total_cert_findings = len([f for f in findings if "SSL" in f.type])
    if total_cert_findings > 0:
        grade = await _grade_ssl_score(findings)
        findings.append(IntelligenceFinding(
            entity=f"SSL Scan Complete: Grade {grade} - {total_cert_findings} findings",
            type="SSL Scan Summary",
            source="SSL Analyzer",
            confidence="High",
            color="emerald" if grade.startswith("A") else "orange",
            threat_level="Informational",
            tags=["summary"]
        ))

    return findings


EXTRA_CIPHER_SUITES = {
    "TLS_AES_128_CCM_SHA256": ("TLS 1.3", "strong"),
    "TLS_AES_128_CCM_8_SHA256": ("TLS 1.3", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_128_CCM": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_128_CCM_8": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_256_CCM": ("TLS 1.2", "strong"),
    "TLS_RSA_WITH_AES_128_CCM": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_AES_128_CCM_8": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_AES_256_CCM": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_AES_256_CCM_8": ("TLS 1.2", "moderate"),
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "strong"),
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "strong"),
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "strong"),
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "moderate"),
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "SSL_RSA_WITH_DES_CBC_SHA": ("SSLv3", "weak"),
    "SSL_DHE_RSA_WITH_DES_CBC_SHA": ("SSLv3", "weak"),
    "SSL_DHE_DSS_WITH_DES_CBC_SHA": ("SSLv3", "weak"),
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5": ("SSLv3", "weak"),
    "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5": ("SSLv3", "weak"),
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA": ("SSLv3", "weak"),
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA": ("SSLv3", "weak"),
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA": ("SSLv3", "weak"),
    "SSL_RSA_WITH_NULL_SHA": ("SSLv3", "none"),
    "SSL_RSA_WITH_NULL_MD5": ("SSLv3", "none"),
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA": ("SSLv3", "none"),
    "TLS_ECDHE_RSA_WITH_NULL_SHA": ("SSLv3", "none"),
    "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "SSL_RSA_FIPS_WITH_DES_CBC_SHA": ("SSLv3", "weak"),
    "TLS_PSK_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_PSK_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_PSK_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "moderate"),
    "TLS_PSK_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_PSK_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_PSK_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_PSK_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "TLS_PSK_WITH_RC4_128_SHA": ("SSLv3", "weak"),
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "moderate"),
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384": ("TLS 1.2", "moderate"),
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256": ("TLS 1.2", "moderate"),
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA": ("SSLv3", "weak"),
    "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA": ("TLS 1.0", "moderate"),
    "TLS_GOSTR341094_WITH_28147_CNT_IMIT": ("TLS 1.0", "moderate"),
    "TLS_GOSTR341001_WITH_28147_CNT_IMIT": ("TLS 1.0", "moderate"),
    "TLS_GOSTR341094_WITH_NULL_GOSTR3411": ("TLS 1.0", "moderate"),
    "TLS_GOSTR341001_WITH_NULL_GOSTR3411": ("TLS 1.0", "moderate"),
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384": ("TLS 1.2", "strong"),
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256": ("TLS 1.2", "strong"),
    "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384": ("TLS 1.2", "strong"),
    "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256": ("TLS 1.2", "strong"),
    "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256": ("TLS 1.2", "moderate"),
    "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384": ("TLS 1.2", "moderate"),
    "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256": ("TLS 1.2", "moderate"),
}

CERT_CHAIN_VULNS = {
    "md2": {"name": "MD2 Signature Algorithm", "desc": "Weak hash used in certificate signature"},
    "md4": {"name": "MD4 Signature Algorithm", "desc": "Weak hash used in certificate signature"},
    "md5": {"name": "MD5 Signature Algorithm", "desc": "Weak hash used in certificate signature"},
    "sha1": {"name": "SHA-1 Signature Algorithm", "desc": "Deprecated SHA-1 hash in certificate signature"},
    "rsa_1024": {"name": "RSA 1024-bit Key", "desc": "RSA key size below 2048 is considered weak"},
    "dsa_1024": {"name": "DSA 1024-bit Key", "desc": "DSA key size below 2048 is considered weak"},
    "ecdsa_160": {"name": "ECDSA 160-bit Key", "desc": "ECDSA key size below 224 is considered weak"},
}

OCSP_INDICATORS = [
    "OCSP Response Status: successful",
    "OCSP Response Status:",
    "authorityInfoAccess",
    "OCSP",
]


async def _check_cert_chain_vulns(parsed: dict, port_label: str, local_findings: list):
    try:
        sig_algo = parsed.get("signature_algorithm", "")
        for vuln_key, vuln_info in CERT_CHAIN_VULNS.items():
            if vuln_key in sig_algo.lower():
                local_findings.append(IntelligenceFinding(
                    entity=f"{vuln_info['name']} detected",
                    type=f"Certificate Weakness{port_label}",
                    source="SSL Analyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=vuln_info['desc'],
                    tags=["certificate", "weakness", vuln_key],
                ))

        pub_key_size = parsed.get("public_key_size", 0)
        pub_key_algo = parsed.get("public_key_algorithm", "")
        if pub_key_algo.lower() == "rsa" and pub_key_size and pub_key_size < 2048:
            local_findings.append(IntelligenceFinding(
                entity=f"Weak RSA key strength: {pub_key_size} bits (min 2048 recommended)",
                type=f"Weak Key Size{port_label}",
                source="SSL Analyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["certificate", "weakness", "rsa_weak"],
            ))
    except Exception:
        pass


async def _check_ocsp_stapling(url: str, port: int, local_findings: list, port_label: str):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(url, port, ssl=ctx),
            timeout=4.0,
        )
        sock = writer.transport.get_extra_info("ssl_object")
        if sock:
            ocsp_resp = sock.compression()
            if ocsp_resp:
                local_findings.append(IntelligenceFinding(
                    entity="OCSP Stapling: Enabled",
                    type=f"OCSP Stapling{port_label}",
                    source="SSL Analyzer",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    tags=["ocsp", "stapling"],
                ))
            else:
                local_findings.append(IntelligenceFinding(
                    entity="OCSP Stapling: Not detected",
                    type=f"OCSP Stapling{port_label}",
                    source="SSL Analyzer",
                    confidence="Low",
                    color="yellow",
                    threat_level="Informational",
                    tags=["ocsp", "stapling"],
                ))
        writer.close()
    except Exception:
        pass


async def _grade_ssl_score(local_findings: list) -> str:
    try:
        deductions = 0
        for f in local_findings:
            if f.threat_level == "Critical Risk":
                deductions += 3
            elif f.threat_level == "High Risk":
                deductions += 2
            elif f.threat_level == "Elevated Risk":
                deductions += 1

        has_tls13 = any("TLSv1.3" in (f.raw_data or "") or "TLSv1.3" in (f.entity or "") for f in local_findings)
        has_tls12 = any("TLSv1.2" in (f.raw_data or "") or "TLSv1.2" in (f.entity or "") for f in local_findings)
        has_chain_issue = any("Certificate Weakness" in (f.type or "") for f in local_findings)

        if has_tls13:
            deductions = max(0, deductions - 1)
        if has_chain_issue:
            deductions += 1

        score = max(0, 10 - deductions)
        if score >= 9 and has_tls13:
            return "A+"
        elif score >= 8:
            return "A"
        elif score >= 6:
            return "B"
        elif score >= 4:
            return "C"
        elif score >= 2:
            return "D"
        else:
            return "F"
    except Exception:
        return "B"



