import ssl
import socket
import struct
import sys
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

class SSLAnalyzer:
    def __init__(self, host: str, port: int = 443, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.grade = "F"
        self.score = 0
        self.issues: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        results = {
            "host": self.host,
            "port": self.port,
            "certificate": {},
            "protocols": {},
            "ciphers": {}, 
            "vulnerabilities": [],
            "grade": "F",
            "score": 0,
            "issues": []
        }
        cert_info = self.get_certificate_info()
        results["certificate"] = cert_info
        if "error" in cert_info:
            results["error"] = cert_info["error"]
            return results
        results["protocols"] = self.check_protocols()
        results["ciphers"] = self.check_ciphers()
        results["tls_features"] = self.check_tls_features()
        self.check_known_vulns(results)
        results["vulnerabilities"] = self.vulnerabilities
        self.calculate_grade(results)
        results["grade"] = self.grade
        results["score"] = self.score
        results["issues"] = self.issues
        return results

    def get_certificate_info(self) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    subject = {attr.oid._name: attr.value for attr in cert.subject}
                    issuer = {attr.oid._name: attr.value for attr in cert.issuer}
                    if hasattr(cert, 'not_valid_before_utc'):
                        not_before = cert.not_valid_before_utc
                        not_after = cert.not_valid_after_utc
                        days_left = (not_after - datetime.now(timezone.utc)).days
                    else:
                        not_before = cert.not_valid_before
                        not_after = cert.not_valid_after
                        days_left = (not_after - datetime.utcnow()).days
                    san = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san = [str(n.value) for n in ext.value]
                    except Exception:
                        pass
                    pub_key = cert.public_key()
                    key_size = pub_key.key_size if hasattr(pub_key, 'key_size') else 0
                    sig_alg = cert.signature_algorithm_oid._name
                    sct_count = 0
                    try:
                        ext = cert.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
                        sct_count = 1
                    except Exception:
                        pass
                    is_ev = False
                    try:
                        ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.CERTIFICATE_POLICIES)
                        for policy in ext.value:
                            if policy.policy_identifier.dotted_string.startswith("2.23.140.1."):
                                is_ev = True
                    except Exception:
                        pass
                    ocsp_urls = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                        for access in ext.value:
                            if access.access_method == AuthorityInformationAccessOID.OCSP:
                                ocsp_urls.append(access.access_location.value)
                    except Exception:
                        pass
                    crl_urls = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
                        for dp in ext.value:
                            for name in dp.full_name:
                                crl_urls.append(name.value)
                    except Exception:
                        pass
                    wildcard = any("*" in s for s in san)
                    self_signed = subject.get("commonName", "") == issuer.get("commonName", "")
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": not_before.isoformat(),
                        "valid_to": not_after.isoformat(),
                        "days_remaining": days_left,
                        "expired": days_left < 0,
                        "expires_soon": 0 <= days_left < 30,
                        "san": san,
                        "san_count": len(san),
                        "wildcard": wildcard,
                        "self_signed": self_signed,
                        "key_size": key_size,
                        "signature_algorithm": sig_alg,
                        "serial_number": hex(cert.serial_number),
                        "serial_bits": cert.serial_number.bit_length(),
                        "sct_count": sct_count,
                        "is_ev": is_ev,
                        "ocsp_urls": ocsp_urls,
                        "crl_urls": crl_urls,
                        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
                    }
        except Exception as e:
            return {"error": str(e)}

    def check_protocols(self) -> Dict[str, bool]:
        supported = {}
        for name, version_attr, version_val in [
            ("SSLv2", None, ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None),
            ("SSLv3", None, ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),
        ]:
            if version_val is not None:
                supported[name] = self._test_version_ctx(version_val)
            else:
                supported[name] = False
        for name, tls_version in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1_0 if hasattr(ssl.TLSVersion, 'TLSv1_0') else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, 'TLSv1_2') else None),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None),
        ]:
            if tls_version is not None:
                supported[name] = self._test_tls_version(tls_version)
            else:
                supported[name] = False
        return supported

    def _test_version_ctx(self, protocol_version) -> bool:
        try:
            ctx = ssl.SSLContext(protocol_version)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except Exception:
            return False

    def _test_tls_version(self, tls_version) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except Exception:
            return False

    def check_ciphers(self) -> Dict[str, Any]:
        results = {
            "supported": [],
            "weak": [],
            "insecure": [],
            "pfs": False,
        }
        cipher_tests = [
            ("NULL", "insecure", "NULL Ciphers (No Encryption)"),
            ("ADH:AECDH", "insecure", "Anonymous Ciphers (No Auth)"),
            ("RC4", "weak", "RC4 (Broken Stream Cipher)"),
            ("3DES", "weak", "3DES (Sweet32 Vulnerable)"),
            ("EXP", "insecure", "Export Grade (FREAK/Logjam)"),
            ("MD5", "weak", "MD5 Hashing"),
        ]
        for cipher_str, category, desc in cipher_tests:
            if self._test_cipher_suite(cipher_str):
                results["supported"].append(desc)
                results[category].append(desc)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher_name = ssock.cipher()
                    if cipher_name:
                        results["best_cipher"] = f"{cipher_name[0]} ({cipher_name[1]})"
                        if "ECDHE" in cipher_name[0] or "DHE" in cipher_name[0]:
                            results["pfs"] = True
        except Exception:
            pass
        return results

    def _test_cipher_suite(self, cipher_string: str) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher_string)
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except Exception:
            return False

    def check_tls_features(self) -> Dict[str, Any]:
        features = {
            "ocsp_stapled": False,
            "h2": False,
            "alpn": [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    alpn = ssock.selected_alpn_protocol()
                    if alpn:
                        features["alpn"].append(alpn)
                        if alpn == "h2":
                            features["h2"] = True
        except Exception:
            pass
        return features

    def check_known_vulns(self, results: Dict[str, Any]):
        self.vulnerabilities = []
        protos = results.get("protocols", {})
        ciphers = results.get("ciphers", {})
        if protos.get("SSLv3"):
            self.vulnerabilities.append({
                "name": "POODLE", "severity": "HIGH",
                "desc": "SSLv3 enabled - vulnerable to POODLE attack (CVE-2014-3566)"
            })
        if protos.get("SSLv2"):
            self.vulnerabilities.append({
                "name": "DROWN", "severity": "CRITICAL",
                "desc": "SSLv2 enabled - vulnerable to DROWN attack (CVE-2016-0800)"
            })
        if any('3DES' in c for c in ciphers.get('weak', [])):
            self.vulnerabilities.append({
                "name": "Sweet32", "severity": "MEDIUM",
                "desc": "3DES ciphers enabled - vulnerable to Sweet32 attack (CVE-2016-2183)"
            })
        if protos.get("TLSv1.0"):
            self.vulnerabilities.append({
                "name": "BEAST", "severity": "LOW",
                "desc": "TLS 1.0 enabled - potential BEAST attack with CBC ciphers (CVE-2011-3389)"
            })
        if any('Export' in c for c in ciphers.get('insecure', [])):
            self.vulnerabilities.append({
                "name": "Logjam/FREAK", "severity": "HIGH",
                "desc": "Export grade ciphers enabled (CVE-2015-4000/CVE-2015-0204)"
            })
        if protos.get("TLSv1.1"):
            self.vulnerabilities.append({
                "name": "TLS 1.1 Deprecated", "severity": "LOW",
                "desc": "TLS 1.1 is deprecated by RFC 8996"
            })

    def calculate_grade(self, results: Dict[str, Any]):
        cert = results.get("certificate", {})
        protocols = results.get("protocols", {})
        ciphers = results.get("ciphers", {})
        vulns = results.get("vulnerabilities", [])
        tls_features = results.get("tls_features", {})

        score = 100
        issues = []

        if cert.get("expired"):
            score = 0
            issues.append("Certificate Expired")
        if protocols.get("SSLv2") or protocols.get("SSLv3"):
            score = min(score, 20)
            issues.append("Insecure Protocol (SSLv2/SSLv3)")
        if ciphers.get("insecure"):
            score = min(score, 30)
            issues.append("Insecure Ciphers (NULL/Export/Anon)")
        if protocols.get("TLSv1.0") or protocols.get("TLSv1.1"):
            score -= 15
            issues.append("Deprecated Protocol (TLS 1.0/1.1)")
        if ciphers.get("weak"):
            score -= 15 * len(ciphers["weak"])
            issues.append(f"Weak Ciphers Enabled ({len(ciphers['weak'])})")
        if cert.get("key_size", 0) < 2048:
            score -= 20
            issues.append("Weak Key Size (<2048 bits)")
        sig_alg = cert.get("signature_algorithm", "")
        if "sha1" in sig_alg.lower() or "sha-1" in sig_alg.lower():
            score -= 20
            issues.append("Weak Signature (SHA1)")
        if cert.get("wildcard"):
            score -= 5
        if cert.get("sct_count", 0) == 0:
            score -= 5
            issues.append("No SCTs found")
        if not tls_features.get("h2"):
            score -= 5
        for v in vulns:
            if v["severity"] == "CRITICAL":
                score -= 35
            elif v["severity"] == "HIGH":
                score -= 25
            elif v["severity"] == "MEDIUM":
                score -= 15
            elif v["severity"] == "LOW":
                score -= 5

        if score < 0:
            score = 0

        if score >= 90:
            self.grade = "A"
        elif score >= 80:
            self.grade = "A-"
        elif score >= 70:
            self.grade = "B+"
        elif score >= 60:
            self.grade = "B"
        elif score >= 50:
            self.grade = "C+"
        elif score >= 40:
            self.grade = "C"
        elif score >= 30:
            self.grade = "D+"
        elif score >= 20:
            self.grade = "D"
        else:
            self.grade = "F"

        if self.grade == "A" and not any("deprecated" in i.lower() or "weak" in i.lower() for i in issues):
            if protocols.get("TLSv1.3") and not protocols.get("SSLv2"):
                self.grade = "A+"

        self.score = score
        self.issues = issues

class TLSClient:
    def __init__(self, host: str, port: int = 443, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def get_certificate(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                return ssock.getpeercert()
