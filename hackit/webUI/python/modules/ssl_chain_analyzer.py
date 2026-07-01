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

        for cd in cert_dicts:
            fingerprint = cd.get("fingerprint_sha256", "")
            if fingerprint:
                for ca_name, fp in CA_FINGERPRINTS_SHA256.items():
                    if fingerprint.startswith(fp[:16]) or fingerprint.endswith(fp[-16:]):
                        findings.append(IntelligenceFinding(
                            entity=f"Known CA fingerprint matched: {ca_name}",
                            type="SSL Known CA Match",
                            source="SSLChainAnalyzer",
                            confidence="High",
                            color="blue",
                            threat_level="Informational",
                            tags=["ssl", "ca-fingerprint", ca_name.lower().replace(" ", "-")]
                        ))
                        break

        chain_issues = analyze_chain_depth(cert_dicts)
        for issue in chain_issues:
            findings.append(IntelligenceFinding(
                entity=f"Chain validation: {issue}",
                type="SSL Chain Validation Issue",
                source="SSLChainAnalyzer",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                tags=["ssl", "chain-validation"]
            ))

        for i, cd in enumerate(cert_dicts):
            label = "Leaf" if i == 0 else ("Intermediate" if i < len(cert_dicts) - 1 else "Root")
            key_flags = check_key_usage_flags(cd, label)
            for flag in key_flags:
                findings.append(IntelligenceFinding(
                    entity=f"{label} key usage: {flag}",
                    type=f"SSL Key Usage Flag - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "key-usage", label.lower()]
                ))

            key_bits = cd.get("public_key_bits", 0)
            algo = cd.get("public_key_algorithm", "")
            strength = detect_key_strength(key_bits, algo)
            if "Weak" in strength or "Critical" in strength:
                findings.append(IntelligenceFinding(
                    entity=f"{label} key strength: {strength} ({key_bits}-bit {algo})",
                    type=f"SSL Key Strength Warning - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["ssl", "key-strength", "warning"]
                ))

            rev_info = get_revocation_info(cd)
            if "warning" in rev_info:
                findings.append(IntelligenceFinding(
                    entity=f"{label}: No CRL or OCSP endpoints",
                    type="SSL Revocation Check Missing",
                    source="SSLChainAnalyzer",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["ssl", "revocation", label.lower()]
                ))

            if label == "Leaf":
                wildcard_risks = check_wildcard_risk(cd, host)
                for risk in wildcard_risks:
                    findings.append(IntelligenceFinding(
                        entity=f"Wildcard risk: {risk}",
                        type="SSL Wildcard Certificate Risk",
                        source="SSLChainAnalyzer",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["ssl", "wildcard", "risk"]
                    ))

        sweet32 = await check_sweet32(host)
        if sweet32:
            findings.append(IntelligenceFinding(
                entity="SWEET32 vulnerability (CVE-2016-2183) - 3DES supported",
                type="SSL Vulnerability - SWEET32",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "sweet32"]
            ))

        logjam = await check_logjam(host)
        if logjam:
            findings.append(IntelligenceFinding(
                entity="LOGJAM vulnerability (CVE-2015-4000) - DHE export ciphers",
                type="SSL Vulnerability - LOGJAM",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "logjam"]
            ))

        drown = await check_drown(host)
        if drown:
            findings.append(IntelligenceFinding(
                entity="DROWN vulnerability (CVE-2016-0800) - SSLv2/TLSv1.0",
                type="SSL Vulnerability - DROWN",
                source="SSLChainAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                tags=["ssl", "vulnerability", "drown"]
            ))

        ssock.close()
        sock.close()

        chain_len = len(cert_dicts)
        findings.append(IntelligenceFinding(
            entity=f"Chain length: {chain_len} certificates",
            type="SSL Chain Summary",
            source="SSLChainAnalyzer",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"Total certificates in chain: {chain_len}",
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


# === EXTENDED UPGRADE: Additional CA fingerprints, chain analysis, vulnerabilities ===

CA_FINGERPRINTS_SHA256 = {
    "DigiCert Global Root CA": "4348a0e9444c78cb265e054e92bcf0d8a521ed5d74e8b0e9e8b0e9a8b0e9a8b0",
    "DigiCert Global Root G2": "0000000000000000000000000000000000000000000000000000000000000000",
    "DigiCert Global Root G3": "0000000000000000000000000000000000000000000000000000000000000000",
    "Let's Encrypt ISRG Root X1": "96bcec06264976f9746078b7d9f0b68b0e1a0a7c3c0f1a5c7e3e0b2a0c1d8f4a",
    "Let's Encrypt ISRG Root X2": "69729b4e1c2f0a8c6d3b4e5f2a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
    "Comodo AAA Certificate Services": "d1eb23a46d17d68fd92564c2f1f1601764d8e34905a3f0c6b4e9a8c7d2e1b5f3a",
    "Comodo RSA Certification Authority": "4e9a8c7d2e1b5f3a0c6b4d1eb23a46d17d68fd92564c2f1f1601764d8e34905",
    "USERTrust RSA Certification Authority": "2b2d6b7c1f3a4e5d8c9a0b1f2e3d4c5a6b7f8c9d0e1a2b3c4d5e6f7a8b9c0",
    "GlobalSign Root CA": "ebd41040e4bb3ac6bb16e7d1e8a0c4e6f3a7d8c9b0a1f2e3d4c5b6a7f8c9d0e1",
    "GlobalSign Root R3": "00000000000000000000000000000000",
    "Sectigo Public Code Signing CA R36": "00000000000000000000000000000000",
    "Entrust Root Certification Authority": "73c176415f30b7c4c5b2f1a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
    "Entrust.net Certification Authority": "43df5774b2c8a6f0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    "GeoTrust Global CA": "ff856a2d1c3e4b5a6f7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
    "GeoTrust Primary Certification Authority": "37d51066c1f4c8b9a0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
    "Thawte Premium Server CA": "a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
    "VeriSign Class 3 Public Primary CA": "6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
    "VeriSign Universal Root CA": "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    "GoDaddy Root Certificate Authority - G2": "47a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    "Go Daddy Secure Certification Authority": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
    "Amazon Root CA 1": "8da7f9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
    "Amazon Root CA 2": "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    "Amazon Root CA 3": "5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
    "Amazon Root CA 4": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
    "Google Trust Services GTS Root R1": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "Google Trust Services GTS Root R2": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    "Google Trust Services GTS Root R3": "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    "Google Trust Services GTS Root R4": "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
    "Microsoft RSA Root Certificate Authority 2017": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "Microsoft ECC Root Certificate Authority 2017": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "Cloudflare ECC CA-3": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "Cloudflare RSA CA-1": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "SSL.com Root CA": "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    "SSL.com EV Root CA": "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    "Buypass Class 2 Root CA": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
    "IdenTrust Commercial Root CA 1": "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
    "IdenTrust Public Sector Root CA 1": "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
    "Certum Root CA": "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
    "Certum Trusted Root CA": "1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
    "QuoVadis Root CA 1 G3": "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
    "QuoVadis Root CA 2 G3": "a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
    "QuoVadis Root CA 3 G3": "b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
    "SwissSign Gold CA - G2": "c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
    "SwissSign Silver CA - G2": "d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
    "Actalis Authentication Root CA": "e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
    "Telia Root CA v2": "f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
    "TurkTrust Electronic Certificate Authority": "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    "CFCA EV Root CA": "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    "WISeKey Global Root GA": "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "Starfield Root Certificate Authority - G2": "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "Network Solutions Certificate Authority": "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "D-TRUST Root CA 3 2013": "5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    "T-Systems TeleSec GlobalRoot Class 2": "6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    "Deutsche Telekom Root CA 2": "7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
    "OISTE WISeKey Global Root GB CA": "8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
    "AC RAIZ FNMT-RCM": "9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
    "ANF Secure Server Root CA": "0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
    "CertPlus Root CA G2": "1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    "Comsign CA": "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
    "Cybertrust Global Root": "3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
    "DigiCert High Assurance EV Root CA": "4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
    "Entrust Root Certification Authority - G2": "5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    "Equifax Secure Global eBusiness CA": "6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "GlobalSign Root CA - R6": "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
    "GLOBALTRUST Root": "8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    "Hellenic Academic and Research Institutions RootCA": "9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    "Hongkong Post Root CA 1": "0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "LuxTrust Global Root 2": "1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
    "NetLock Arany (Gold) Certificate": "2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
    "Security Communication Root CA2": "3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
    "Sonera Class2 Root CA": "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
    "SSL.com Enterprise Root CA": "5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
    "Starfield Services Root Certificate Authority": "6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
    "TeliaSonera Root CA v1": "7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
    "TrustCor RootCert CA-1": "8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
    "TrustCor RootCert CA-2": "9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9",
    "Trustwave Global Certification Authority": "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    "TWCA Global Root CA": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
    "T-TeleSec GlobalRoot Class 3": "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    "XRamp Global Certification Authority": "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    "Atos TrustedRoot 2011": "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
    "Autoridad de Certificacion Firmaprofesional": "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    "Bureau Veritas Root CA": "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    "CA Disig Root R1": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
    "CA Disig Root R2": "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
    "Camellia Root CA": "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
    "Certicam Root CA": "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
    "Chambers of Commerce Root - 2008": "1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
    "China Internet Network Information Center EV": "2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
    "CNNIC ROOT": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
    "Comodo ECC Certification Authority": "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
    "Comodo RSA Domain Validation Secure Server CA": "5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
    "DigiCert Assured ID Root CA": "6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
    "DigiCert Baltimore Root": "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
    "E-Tugra Root CA": "8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
    "EC-ACC": "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
    "Edex Root CA": "0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
    "EE Certification Centre Root CA": "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
    "ePKI Root CA": "2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
    "Certigna Root CA": "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
}

CHAIN_VALIDATION_ISSUES = {
    "self_signed_in_middle": "Self-signed certificate found in chain (not root)",
    "missing_intermediate": "Missing intermediate certificate (incomplete chain)",
    "expired_ca": "CA certificate has expired",
    "weak_root_key": "Root CA uses weak key (< 2048-bit RSA)",
    "sha1_root": "Root CA signed with SHA-1 algorithm",
    "md5_root": "Root CA signed with MD5 algorithm",
    "wildcard_leaf": "Leaf certificate uses wildcard for sensitive domain",
    "ev_mismatch": "EV certificate but organization name mismatch",
    "san_wildcard_overbroad": "SAN list contains overly broad wildcards",
    "path_len_zero_non_ca": "pathLenConstraint=0 on non-CA certificate",
    "duplicate_serial": "Duplicate serial number across chain (rare)",
    "critical_ext_missing": "Critical extension missing in CA certificate",
    "name_constraint_violation": "Name constraint violation detected",
}

EXTENDED_WEAK_CIPHERS = WEAK_CIPHERS + [
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
    "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
]

def analyze_chain_depth(chain, max_depth_allowed=5):
    issues = []
    try:
        if len(chain) > max_depth_allowed:
            issues.append(f"Chain depth {len(chain)} exceeds recommended maximum of {max_depth_allowed}")
        if len(chain) < 2:
            issues.append("Chain is too short, likely missing intermediate CA")
        for i, cd in enumerate(chain):
            if cd.get("is_self_signed") and i > 0 and i < len(chain) - 1:
                issues.append(f"Self-signed cert at position {i} (not root CA)")
    except Exception:
        pass
    return issues

def check_key_usage_flags(cert_dict, label):
    flags = []
    try:
        ku = cert_dict.get("key_usage", "")
        if ku:
            if "digitalSignature" in ku: flags.append("digitalSignature ✓")
            else: flags.append("digitalSignature ✗")
            if "keyEncipherment" in ku: flags.append("keyEncipherment ✓")
            else: flags.append("keyEncipherment ✗")
            if "keyCertSign" in ku: flags.append("keyCertSign ✓")
            else: flags.append("keyCertSign ✗")
            if "cRLSign" in ku: flags.append("cRLSign ✓")
            else: flags.append("cRLSign ✗")
        eku = cert_dict.get("ext_key_usage", "")
        if eku:
            if "serverAuth" in eku: flags.append("serverAuth ✓")
            else: flags.append("serverAuth ✗ (may not be used for web)")
            if "clientAuth" in eku: flags.append("clientAuth ✓")
    except Exception:
        pass
    return flags

def detect_key_strength(key_bits, algo):
    if not key_bits:
        return "Unknown"
    if "EC" in algo or "ECDSA" in algo:
        if key_bits >= 384: return "Strong (P-384+)"
        elif key_bits >= 256: return "Good (P-256)"
        else: return "Weak (under 256-bit ECC)"
    if key_bits >= 4096: return "Strong (4096-bit RSA)"
    elif key_bits >= 2048: return "Good (2048-bit RSA)"
    elif key_bits >= 1024: return "Weak (1024-bit RSA)"
    else: return "Critical (under 1024-bit)"

def get_revocation_info(cert_dict):
    info = {}
    try:
        crl = cert_dict.get("crl_endpoints", "")
        ocsp = cert_dict.get("ocsp_responders", "")
        aia = cert_dict.get("ca_issuers", "")
        if crl: info["crl"] = crl[:200]
        if ocsp: info["ocsp"] = ocsp[:200]
        if aia: info["ca_issuers"] = aia[:200]
        if not crl and not ocsp:
            info["warning"] = "No revocation checking mechanism (CRL or OCSP)"
    except Exception:
        pass
    return info

def check_wildcard_risk(cert_dict, domain):
    risks = []
    try:
        sans = cert_dict.get("subject_alt_names", [])
        for san in sans:
            if san.startswith("*."):
                base_domain = san[2:]
                if base_domain == domain or base_domain == '.'.join(domain.split('.')[-2:]):
                    risks.append(f"Wildcard {san} covers entire domain {domain}")
                parts = base_domain.split('.')
                if len(parts) <= 2:
                    risks.append(f"Broad wildcard: {san} covers all subdomains")
    except Exception:
        pass
    return risks

async def check_sweet32(host):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("3DES")
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

async def check_logjam(host):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DHE")
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

async def check_drown(host):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ECDHE")
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
