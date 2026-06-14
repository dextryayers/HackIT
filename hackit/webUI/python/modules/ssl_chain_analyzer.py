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
    "IDEA", "SEED", "CAMELLIA",
]

HEARTBLEED_PAYLOAD = b"\x18\x03\x02\x00\x03\x01\x40\x00"

CRL_DIST_POINT_REGEX = rb"https?://[^\x00]*\.crl"
OCSP_REGEX = rb"https?://[^\x00]*ocsp[^\x00]*"

def get_cert_info(cert, label="Subject"):
    if not cert:
        return {}
    info = {}
    for attr in ["commonName", "organizationName", "countryName", "stateOrProvinceName", "localityName", "organizationalUnitName", "emailAddress", "serialNumber"]:
        try:
            val = getattr(cert.subject if label == "Subject" else cert.issuer, attr, None)
            if val:
                info[attr] = val
        except Exception:
            pass
    return info

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

        for i, cd in enumerate(cert_dicts):
            label = "Leaf" if i == 0 else ("Intermediate" if i < len(cert_dicts) - 1 else "Root")
            issuer_info = cd.get("issuer", {})
            subject_info = cd.get("subject", {})
            issuer_cn = issuer_info.get("commonName", "Unknown")
            subject_cn = subject_info.get("commonName", "Unknown")
            org = subject_info.get("organizationName", "")
            days = cd.get("days_remaining", 0)

            findings.append(IntelligenceFinding(
                entity=f"[{label}] {subject_cn} (issued by {issuer_cn})",
                type=f"SSL Certificate - {label}",
                source="SSLChainAnalyzer",
                confidence="High",
                color="emerald" if days > 30 else ("orange" if days > 0 else "red"),
                threat_level="Informational" if days > 30 else ("Elevated Risk" if days > 0 else "High Risk"),
                raw_data=f"Subject: {subject_info} | Issuer: {issuer_info} | Serial: {cd.get('serial_number', '')} | Days remaining: {days}",
                tags=["ssl", label.lower(), "certificate"]
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
                findings.append(IntelligenceFinding(
                    entity=f"Extended Key Usage: {cd['ext_key_usage'][:200]}",
                    type=f"SSL Extended Key Usage - {label}",
                    source="SSLChainAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "ext-key-usage"]
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

            if cd.get("subject_alt_names"):
                for san in cd["subject_alt_names"][:10]:
                    findings.append(IntelligenceFinding(
                        entity=san,
                        type=f"SSL SAN - {label}",
                        source="SSLChainAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        tags=["ssl", "san"]
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
