import asyncio
import ssl
import socket
import struct
import httpx
from datetime import datetime
from models import IntelligenceFinding

TLS_VERSIONS = {
    ssl.PROTOCOL_TLSv1_2: "TLS 1.2",
    ssl.PROTOCOL_TLSv1: "TLS 1.0",
}

TLS_VERSION_CODES = {
    "SSLv3": (0x03, 0x00),
    "TLS 1.0": (0x03, 0x01),
    "TLS 1.1": (0x03, 0x02),
    "TLS 1.2": (0x03, 0x03),
    "TLS 1.3": (0x03, 0x04),
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon",
    "IDEA", "SEED", "CAMELLIA", "TLS_RSA", "TLS_DH_anon",
    "TLS_ECDH_anon", "TLS_PSK", "TLS_SRP",
]

HEARTBLEED_PAYLOAD = b"\x18\x03\x02\x00\x03\x01\x40\x00"

CRL_DIST_POINT_REGEX = rb"https?://[^\x00]*\.crl"
OCSP_REGEX = rb"https?://[^\x00]*ocsp[^\x00]*"

KNOWN_CAS = {
    "Let's Encrypt": ["Let's Encrypt", "R3", "ISRG Root X1", "ISRG Root X2"],
    "DigiCert": ["DigiCert", "DigiCert Global Root", "DigiCert High Assurance"],
    "Sectigo": ["Sectigo", "COMODO", "AAA Certificate Services", "USERTrust"],
    "GlobalSign": ["GlobalSign", "GlobalSign Root", "AlphaSSL"],
    "GoDaddy": ["GoDaddy", "Go Daddy", "GoDaddy Secure"],
    "Amazon": ["Amazon", "Amazon Root CA"],
    "Google Trust": ["Google Trust Services", "GTS"],
    "Cloudflare": ["Cloudflare"],
    "Microsoft": ["Microsoft Root"],
    "Verizon": ["Verizon"],
    "Entrust": ["Entrust", "Entrust Root"],
    "GeoTrust": ["GeoTrust", "GeoTrust Global"],
    "Thawte": ["Thawte"],
    "RapidSSL": ["RapidSSL"],
    "Symantec": ["Symantec"],
    "VeriSign": ["VeriSign"],
    "Certum": ["Certum", "Certum Trusted"],
    "IdenTrust": ["IdenTrust", "DST Root"],
    "Comodo": ["Comodo", "Comodo CA", "Comodo RSA"],
    "Network Solutions": ["Network Solutions"],
    "BuyPass": ["BuyPass", "Buypass"],
    "ZeroSSL": ["ZeroSSL"],
    "cPanel": ["cPanel"],
    "SSL.com": ["SSL.com", "SSL Corp"],
    "Trustwave": ["Trustwave"],
    "Secom": ["SECOM", "Security Communication"],
    "Digicert": ["DigiCert"],
    "QuoVadis": ["QuoVadis"],
    "SwissSign": ["SwissSign"],
    "Actalis": ["Actalis"],
    "Telia": ["Telia"],
    "TurkTrust": ["TurkTrust"],
    "CFCA": ["CFCA"],
    "WISeKey": ["WISeKey"],
    "StartCom": ["StartCom", "StartSSL"],
    "WoSign": ["WoSign"],
    "Let's Encrypt": ["Let's Encrypt"],
}

SIGNATURE_ALGORITHM_SCORES = {
    "sha256": "Good",
    "sha384": "Good",
    "sha512": "Good",
    "sha1": "Weak",
    "sha224": "Acceptable",
    "md5": "Critical",
    "md4": "Critical",
    "md2": "Critical",
    "ecdsa": "Good",
    "rsa": "Good",
    "dsa": "Weak",
}

def get_cert_info(cert, label="Subject"):
    if not cert:
        return {}
    info = {}
    for attr in ["commonName", "organizationName", "countryName", "stateOrProvinceName", "localityName", "organizationalUnitName", "emailAddress", "serialNumber", "postalCode", "streetAddress"]:
        try:
            val = getattr(cert.subject if label == "Subject" else cert.issuer, attr, None)
            if val:
                info[attr] = val
        except Exception:
            pass
    return info

def detect_known_ca(cert_dict):
    issuer_info = cert_dict.get("issuer", {})
    org = issuer_info.get("organizationName", "")
    cn = issuer_info.get("commonName", "")
    combined = f"{org} {cn}"
    for ca_name, identifiers in KNOWN_CAS.items():
        for ident in identifiers:
            if ident.lower() in combined.lower():
                return ca_name
    return "Unknown/Private CA"

def cert_to_dict(cert):
    result = {}
    try:
        result["subject"] = get_cert_info(cert, "Subject")
        result["issuer"] = get_cert_info(cert, "Issuer")
        result["serial_number"] = format(cert.serial_number, "X") if hasattr(cert, "serial_number") else ""
        result["not_before"] = str(getattr(cert, "not_valid_before_utc", getattr(cert, "not_valid_before", "")))
        result["not_after"] = str(getattr(cert, "not_valid_after_utc", getattr(cert, "not_valid_after", "")))
        days = 0
        if result.get("not_after"):
            try:
                t = result["not_after"]
                t = t.replace("Z", "").split(".")[0].split("+")[0]
                dt = datetime.fromisoformat(t) if "T" in t else datetime.strptime(t[:10], "%Y-%m-%d")
                days = (dt - datetime.utcnow()).days
            except Exception:
                days = 0
        result["days_remaining"] = days
        result["is_expired"] = days < 0
        result["fingerprint_sha256"] = cert.digest("sha256").decode() if hasattr(cert, "digest") else ""

        sans = []
        try:
            ext = cert.extensions
            for e in ext:
                if e.oid._name == "subjectAltName":
                    for name in e.value:
                        sans.append(str(name))
        except Exception:
            pass
        result["subject_alt_names"] = sans

        try:
            for e in cert.extensions:
                oid_name = getattr(e.oid, "_name", str(e.oid))
                if "keyUsage" in oid_name:
                    result["key_usage"] = str(e.value)
                elif "extendedKeyUsage" in oid_name:
                    result["ext_key_usage"] = str(e.value)
                elif "basicConstraints" in oid_name:
                    result["basic_constraints"] = str(e.value)
                    if "CA" in str(e.value):
                        result["is_ca"] = True
                    if "pathLenConstraint" in str(e.value):
                        result["path_length_constraint"] = str(e.value)
                elif "certificatePolicies" in oid_name:
                    result["cert_policies"] = str(e.value)
                elif "authorityKeyIdentifier" in oid_name:
                    result["authority_key_id"] = str(e.value)
                elif "subjectKeyIdentifier" in oid_name:
                    result["subject_key_id"] = str(e.value)
                elif "CRLDistributionPoints" in oid_name:
                    result["crl_endpoints"] = str(e.value)
                elif "authorityInfoAccess" in oid_name:
                    aia = str(e.value)
                    result["ocsp_responders"] = aia
                    result["ca_issuers"] = aia
                elif "nameConstraints" in oid_name:
                    result["name_constraints"] = str(e.value)
                elif "policyConstraints" in oid_name:
                    result["policy_constraints"] = str(e.value)
                elif "inhibitAnyPolicy" in oid_name:
                    result["inhibit_any_policy"] = str(e.value)
                elif "freshestCRL" in oid_name:
                    result["freshest_crl"] = str(e.value)
        except Exception:
            pass

        try:
            sig_algo = getattr(cert, "signature_hash_algorithm", None)
            if sig_algo:
                result["signature_algorithm"] = sig_algo.name
        except Exception:
            pass

        try:
            result["public_key_algorithm"] = str(getattr(cert, "public_key_algorithm", ""))
        except Exception:
            pass

        try:
            result["public_key_bits"] = cert.public_key().key_size if hasattr(cert, "public_key") else 0
        except Exception:
            pass

        try:
            result["is_self_signed"] = False
            sub = result.get("subject", {}).get("commonName", "")
            iss = result.get("issuer", {}).get("commonName", "")
            if sub and iss and sub == iss:
                result["is_self_signed"] = True
        except Exception:
            pass
    except Exception:
        pass
    return result

async def check_tls_version(host, version_name, version_code):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version_name == "SSLv3":
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif version_name == "TLS 1.0":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif version_name == "TLS 1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif version_name == "TLS 1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif version_name == "TLS 1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        loop = asyncio.get_event_loop()
        _, writer = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        try:
            ssock = ctx.wrap_socket(writer, server_hostname=host)
            ssock.do_handshake()
            cipher = ssock.cipher()
            ssock.close()
            writer.close()
            return True, cipher[0] if cipher else "unknown"
        except Exception:
            writer.close()
            return False, ""
    except Exception:
        return False, ""

async def test_heartbleed(host):
    try:
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        sock.settimeout(3.0)
        sock.send(HEARTBLEED_PAYLOAD)
        resp = sock.recv(4096)
        sock.close()
        if len(resp) > 7:
            return True, f"Responded with {len(resp)} bytes"
        return False, ""
    except Exception:
        return False, ""

async def check_poodle(host):
    try:
        supported, _ = await check_tls_version(host, "SSLv3", (0x03, 0x00))
        return supported
    except Exception:
        return False

async def check_freak(host):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("EXP")
        loop = asyncio.get_event_loop()
        _, writer = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        try:
            ssock = ctx.wrap_socket(writer, server_hostname=host)
            ssock.do_handshake()
            ssock.close()
            writer.close()
            return True
        except Exception:
            writer.close()
            return False
    except Exception:
        return False

async def check_robot(host):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        loop = asyncio.get_event_loop()
        _, writer = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        try:
            ssock = ctx.wrap_socket(writer, server_hostname=host)
            ssock.do_handshake()
            ssock.close()
            writer.close()
            return True
        except Exception:
            writer.close()
            return False
    except Exception:
        return False

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=5.0)),
            timeout=5.0
        )
        sock.settimeout(5.0)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()

        chain = []
        try:
            chain = ssock.get_verified_chain()
        except Exception:
            try:
                chain = [ssock.getpeercert(binary_form=True)]
            except Exception:
                chain = []

        if not chain:
            try:
                chain = [ssock.getpeercert()]
            except Exception:
                chain = []

        cert_dicts = []
        for c in chain:
            if isinstance(c, bytes):
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(c, default_backend())
                    cert_dicts.append(cert_to_dict(cert_obj))
                except Exception:
                    pass
            elif hasattr(c, "to_cryptography"):
                try:
                    cert_dicts.append(cert_to_dict(c.to_cryptography()))
                except Exception:
                    cert_dicts.append(cert_to_dict(c))
            else:
                cert_dicts.append(cert_to_dict(c))

        chain_issues = []
        for i, cd in enumerate(cert_dicts):
            label = "Leaf" if i == 0 else ("Intermediate" if i < len(cert_dicts) - 1 else "Root")
            issuer_info = cd.get("issuer", {})
            subject_info = cd.get("subject", {})
            issuer_cn = issuer_info.get("commonName", "Unknown")
            subject_cn = subject_info.get("commonName", "Unknown")
            org = subject_info.get("organizationName", "")
            days = cd.get("days_remaining", 0)
            sig_algo = cd.get("signature_algorithm", "unknown")
            key_bits = cd.get("public_key_bits", 0)
            is_self_signed = cd.get("is_self_signed", False)
            is_ca = cd.get("is_ca", False)

            known_ca = detect_known_ca(cd)
            sig_strength = SIGNATURE_ALGORITHM_SCORES.get(sig_algo, "Unknown")

            color = "emerald" if days > 30 else ("orange" if days > 0 else "red")
            threat = "Informational" if days > 30 else ("Elevated Risk" if days > 0 else "High Risk")

            findings.append(IntelligenceFinding(
                entity=f"[{label}] {subject_cn} (issued by {issuer_cn})",
                type=f"SSL Certificate - {label}",
                source="SSLChainAnalyzer",
                confidence="High",
                color=color,
                threat_level=threat,
                raw_data=f"Subject: {subject_info} | Issuer: {issuer_info} | Serial: {cd.get('serial_number', '')} | Days remaining: {days} | CA: {known_ca}",
                tags=["ssl", label.lower(), "certificate"]
            ))

            if known_ca and known_ca != "Unknown/Private CA":
                findings.append(IntelligenceFinding(
                    entity=f"CA: {known_ca} ({issuer_cn})",
                    type=f"SSL Certificate Authority - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"Issuer org: {issuer_info.get('organizationName', '')} | CA: {known_ca}",
                    tags=["ssl", "ca", known_ca.lower().replace(" ", "-").replace("'", "")]
                ))

            if is_self_signed and label == "Root":
                findings.append(IntelligenceFinding(
                    entity=f"Self-signed root certificate: {subject_cn}",
                    type="SSL Self-Signed Certificate",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"Root certificate is self-signed: {subject_cn}",
                    tags=["ssl", "self-signed", label.lower()]
                ))

            if key_bits > 0:
                is_weak_key = key_bits < 2048
                findings.append(IntelligenceFinding(
                    entity=f"{label} key: {key_bits}-bit {cd.get('public_key_algorithm', '')}",
                    type=f"SSL Key Strength - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red" if is_weak_key else "emerald",
                    threat_level="High Risk" if is_weak_key else "Informational",
                    raw_data=f"Algorithm: {cd.get('public_key_algorithm', 'unknown')} | Bits: {key_bits}",
                    tags=["ssl", label.lower(), "key-strength"]
                ))

            if sig_strength == "Weak" or sig_strength == "Critical":
                findings.append(IntelligenceFinding(
                    entity=f"{label} uses weak signature algorithm: {sig_algo}",
                    type=f"SSL Weak Signature Algorithm - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Signature algorithm: {sig_algo} ({sig_strength})",
                    tags=["ssl", "weak-signature", label.lower()]
                ))

            if cd.get("key_usage"):
                findings.append(IntelligenceFinding(
                    entity=f"Key Usage: {cd['key_usage'][:200]}",
                    type=f"SSL Key Usage - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=cd["key_usage"],
                    tags=["ssl", label.lower(), "key-usage"]
                ))

            if cd.get("ext_key_usage"):
                ext_ku = cd["ext_key_usage"]
                has_server_auth = "serverAuth" in ext_ku
                has_client_auth = "clientAuth" in ext_ku
                findings.append(IntelligenceFinding(
                    entity=f"Extended Key Usage: {ext_ku[:200]}",
                    type=f"SSL Extended Key Usage - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=ext_ku,
                    tags=["ssl", "ext-key-usage"]
                ))
                if label == "Leaf" and not has_server_auth:
                    findings.append(IntelligenceFinding(
                        entity=f"Leaf cert missing serverAuth EKU",
                        type="SSL Missing Server Authentication",
                        source="SSLChainAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"EKU: {ext_ku}",
                        tags=["ssl", "misconfiguration"]
                    ))

            if cd.get("path_length_constraint"):
                findings.append(IntelligenceFinding(
                    entity=f"Path Length Constraint: {cd['path_length_constraint'][:100]}",
                    type=f"SSL Path Length Constraint - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "path-length"]
                ))

            if cd.get("basic_constraints") and is_ca and label in ("Leaf",):
                findings.append(IntelligenceFinding(
                    entity=f"Leaf certificate has CA flag set: True",
                    type=f"SSL Misconfiguration - CA flag on leaf",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    tags=["ssl", "misconfiguration"]
                ))

            if cd.get("crl_endpoints"):
                findings.append(IntelligenceFinding(
                    entity=cd["crl_endpoints"][:200],
                    type=f"CRL Distribution Point - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["ssl", "crl"]
                ))

            if cd.get("ocsp_responders"):
                findings.append(IntelligenceFinding(
                    entity=cd["ocsp_responders"][:200],
                    type=f"OCSP Responder - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["ssl", "ocsp"]
                ))

            if cd.get("freshest_crl"):
                findings.append(IntelligenceFinding(
                    entity=f"Freshest CRL: {cd['freshest_crl'][:200]}",
                    type=f"SSL Freshest CRL - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "freshest-crl"]
                ))

            if cd.get("name_constraints"):
                findings.append(IntelligenceFinding(
                    entity=f"Name Constraints: {cd['name_constraints'][:200]}",
                    type=f"SSL Name Constraints - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "name-constraints"]
                ))

            if cd.get("cert_policies"):
                findings.append(IntelligenceFinding(
                    entity=f"Cert Policies: {cd['cert_policies'][:200]}",
                    type=f"SSL Certificate Policies - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "cert-policies"]
                ))

            if cd.get("subject_alt_names"):
                for san in cd["subject_alt_names"][:15]:
                    findings.append(IntelligenceFinding(
                        entity=san,
                        type=f"SSL SAN - {label}",
                        source="SSLChainAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        tags=["ssl", "san"]
                    ))
                wildcard_sans = [san for san in cd["subject_alt_names"] if san.startswith("*.")]
                if wildcard_sans:
                    for ws in wildcard_sans[:5]:
                        findings.append(IntelligenceFinding(
                            entity=f"Wildcard SAN: {ws}",
                            type=f"SSL Wildcard SAN - {label}",
                            source="SSLChainAnalyzer",
                            confidence="High",
                            color="orange",
                            threat_level="Elevated Risk",
                            raw_data=f"Wildcard certificate detected: {ws} - broad subdomain coverage",
                            tags=["ssl", "wildcard", "san"]
                        ))

        cipher_info = ssock.cipher()
        if cipher_info:
            cipher_name, tls_ver, bits = cipher_info[0], cipher_info[1], cipher_info[2] if len(cipher_info) > 2 else 0
            is_weak = any(w in cipher_name for w in WEAK_CIPHERS)
            findings.append(IntelligenceFinding(
                entity=f"{cipher_name} ({bits} bits, {tls_ver})",
                type="SSL Cipher - Negotiated",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red" if is_weak else "emerald",
                threat_level="High Risk" if is_weak else "Informational",
                raw_data=f"Cipher: {cipher_name} | Version: {tls_ver} | Bits: {bits}",
                tags=["ssl", "cipher"]
            ))
            if is_weak:
                findings.append(IntelligenceFinding(
                    entity=f"Weak cipher negotiated: {cipher_name}",
                    type="SSL Weak Cipher Warning",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["ssl", "weak-cipher"]
                ))

        for ver_name in ["SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
            supported, cipher = await check_tls_version(host, ver_name, TLS_VERSION_CODES.get(ver_name, (0, 0)))
            if supported:
                is_weak_ver = ver_name in ("SSLv3", "TLS 1.0", "TLS 1.1")
                findings.append(IntelligenceFinding(
                    entity=f"{ver_name} supported - {cipher}",
                    type="SSL/TLS Version",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red" if is_weak_ver else "emerald",
                    threat_level="High Risk" if is_weak_ver else "Informational",
                    raw_data=f"Version: {ver_name} | Cipher: {cipher}",
                    tags=["ssl", "tls-version"]
                ))
                if is_weak_ver:
                    findings.append(IntelligenceFinding(
                        entity=f"Deprecated TLS version active: {ver_name}",
                        type="SSL Deprecated Version Warning",
                        source="SSLChainAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        tags=["ssl", "deprecated-version"]
                    ))

        heartbleed_vuln, hb_detail = await test_heartbleed(host)
        if heartbleed_vuln:
            findings.append(IntelligenceFinding(
                entity=f"Heartbleed vulnerability detected: {hb_detail}",
                type="SSL Vulnerability - Heartbleed",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="Critical",
                raw_data=f"Heartbleed test result: {hb_detail}",
                tags=["ssl", "vulnerability", "heartbleed"]
            ))

        poodle_vuln = await check_poodle(host)
        if poodle_vuln:
            findings.append(IntelligenceFinding(
                entity="POODLE vulnerability (CVE-2014-3566)",
                type="SSL Vulnerability - POODLE",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "poodle"]
            ))

        freak_vuln = await check_freak(host)
        if freak_vuln:
            findings.append(IntelligenceFinding(
                entity="FREAK attack vulnerability (CVE-2015-0204)",
                type="SSL Vulnerability - FREAK",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "freak"]
            ))

        robot_vuln = await check_robot(host)
        if robot_vuln:
            findings.append(IntelligenceFinding(
                entity="ROBOT attack vulnerability (CVE-2017-17382)",
                type="SSL Vulnerability - ROBOT",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "robot"]
            ))

        ssock.close()
        sock.close()

        findings.append(IntelligenceFinding(
            entity=f"Chain length: {len(cert_dicts)} certificates",
            type="SSL Chain Summary",
            source="SSLChainAnalyzer",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"Total certificates in chain: {len(cert_dicts)}",
            tags=["ssl", "summary"]
        ))

        findings.append(IntelligenceFinding(
            entity=f"TLS versions: {sum(1 for f in findings if f.type == 'SSL/TLS Version')} supported | Ciphers: {sum(1 for f in findings if f.type == 'SSL Cipher - Negotiated')} negotiated",
            type="SSL Security Posture Summary",
            source="SSLChainAnalyzer",
            confidence="High",
            color="orange" if any(f.color == "red" for f in findings) else "emerald",
            threat_level="High Risk" if any(f.threat_level == "Critical" or f.threat_level == "High Risk" for f in findings) else "Informational",
            raw_data=f"Chain depth: {len(cert_dicts)} | Heartbleed: {'Vulnerable' if heartbleed_vuln else 'Not vulnerable'} | POODLE: {'Vulnerable' if poodle_vuln else 'Not vulnerable'}",
            tags=["ssl", "summary", "security"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"SSL Chain error: {str(e)[:100]}",
            type="SSL Chain Error",
            source="SSLChainAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
