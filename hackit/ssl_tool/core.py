
import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLAnalyzer:
    """
    Enterprise-Grade SSL/TLS Analyzer
    """
    
    def __init__(self, host: str, port: int = 443, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.grade = "F"
        self.issues = []
        self.vulnerabilities = []

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis"""
        results = {
            "host": self.host,
            "port": self.port,
            "certificate": {},
            "protocols": {},
            "ciphers": {},
            "vulnerabilities": [],
            "grade": "F",
            "issues": []
        }

        # 1. Get Certificate Info
        cert_info = self.get_certificate_info()
        results["certificate"] = cert_info
        
        if "error" in cert_info:
            results["error"] = cert_info["error"]
            return results

        # 2. Check Protocols
        results["protocols"] = self.check_protocols()

        # 3. Check Weak Ciphers
        results["ciphers"] = self.check_ciphers()

        # 4. Check Vulnerabilities
        self.check_known_vulns(results)
        results["vulnerabilities"] = self.vulnerabilities

        # 5. Calculate Grade
        self.calculate_grade(results)
        results["grade"] = self.grade
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
                    
                    # Basic Info
                    subject = {attr.oid._name: attr.value for attr in cert.subject}
                    issuer = {attr.oid._name: attr.value for attr in cert.issuer}
                    
                    # Dates
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after
                    days_left = (not_after - datetime.utcnow()).days
                    
                    # SAN
                    san = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san = [n.value for n in ext.value]
                    except:
                        pass

                    # Key Info
                    pub_key = cert.public_key()
                    key_size = pub_key.key_size
                    
                    # Signature Algorithm
                    sig_alg = cert.signature_algorithm_oid._name

                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": not_before.isoformat(),
                        "valid_to": not_after.isoformat(),
                        "days_remaining": days_left,
                        "expired": days_left < 0,
                        "san": san,
                        "key_size": key_size,
                        "signature_algorithm": sig_alg,
                        "serial_number": hex(cert.serial_number)
                    }
        except Exception as e:
            return {"error": str(e)}

    def check_protocols(self) -> Dict[str, bool]:
        """Check supported protocols"""
        supported = {}
        
        # We try to create contexts for specific versions if available.
        # Python's ssl module support depends on OpenSSL version linked.
        
        # 1. SSLv2/SSLv3 (Dangerous)
        # Often removed from modern Python/OpenSSL, but we try
        for name, proto in [("SSLv2", "PROTOCOL_SSLv2"), ("SSLv3", "PROTOCOL_SSLv3")]:
            try:
                if hasattr(ssl, proto):
                    p_const = getattr(ssl, proto)
                    if self._test_connection(p_const):
                        supported[name] = True
                    else:
                        supported[name] = False
                else:
                    supported[name] = False # Not supported by client, assume safe or unknown
            except:
                supported[name] = False

        # 2. TLS 1.0/1.1 (Deprecated)
        for name, proto in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
            if self._test_connection(proto):
                supported[name] = True
            else:
                supported[name] = False

        # 3. TLS 1.2/1.3 (Modern)
        # We use default context which usually tries highest available
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ver = ssock.version()
                    if ver == "TLSv1.3":
                        supported["TLSv1.3"] = True
                        supported["TLSv1.2"] = True # Implied
                    elif ver == "TLSv1.2":
                        supported["TLSv1.2"] = True
                        # TLS 1.3 might be false or just not negotiated
                        supported["TLSv1.3"] = False 
                    else:
                        # If negotiated lower, it means server prefers lower or doesn't support high
                        supported["TLSv1.2"] = False
                        supported["TLSv1.3"] = False
        except:
            supported["TLSv1.2"] = False
            supported["TLSv1.3"] = False

        return supported

    def _test_connection(self, protocol_version) -> bool:
        try:
            context = ssl.SSLContext(protocol_version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Enable all ciphers for this test to ensure handshake succeeds if protocol is supported
            context.set_ciphers('ALL:COMPLEMENTOFDEFAULT') 
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host):
                    return True
        except:
            return False

    def check_ciphers(self) -> Dict[str, List[str]]:
        """Check for Weak Ciphers"""
        results = {
            "weak": [],
            "insecure": [] # Really bad
        }
        
        # Cipher categories to test
        # Note: 'ALL' includes robust ones, we specifically want to test for BAD ones.
        
        # 1. NULL Ciphers (No Encryption)
        if self._test_cipher_suite('NULL'):
            results['insecure'].append('NULL Ciphers (No Encryption)')

        # 2. Anonymous Ciphers (No Auth)
        if self._test_cipher_suite('ADH:AECDH'):
            results['insecure'].append('Anonymous Ciphers (No Authentication)')

        # 3. RC4 (Broken)
        if self._test_cipher_suite('RC4'):
            results['weak'].append('RC4 (Broken Stream Cipher)')

        # 4. 3DES (Weak/Slow)
        if self._test_cipher_suite('3DES'):
            results['weak'].append('3DES (Sweet32 Vulnerable)')

        # 5. Export Grade (FREAK/Logjam)
        if self._test_cipher_suite('EXP'):
            results['insecure'].append('Export Grade Ciphers (FREAK/Logjam)')
            
        # 6. MD5 (Weak Hashing)
        if self._test_cipher_suite('MD5'):
            results['weak'].append('MD5 Signature/Hash')

        return results

    def _test_cipher_suite(self, cipher_string: str) -> bool:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher_string)
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host):
                    return True
        except:
            return False

    def check_known_vulns(self, results: Dict[str, Any]):
        """Check for known vulnerabilities based on configuration"""
        protos = results.get("protocols", {})
        ciphers = results.get("ciphers", {})
        
        # POODLE (SSLv3)
        if protos.get("SSLv3"):
            self.vulnerabilities.append({
                "name": "POODLE",
                "severity": "HIGH",
                "desc": "SSLv3 is enabled, making the server vulnerable to POODLE attack."
            })

        # DROWN (SSLv2)
        if protos.get("SSLv2"):
            self.vulnerabilities.append({
                "name": "DROWN",
                "severity": "CRITICAL",
                "desc": "SSLv2 is enabled, making the server vulnerable to DROWN attack."
            })
            
        # Sweet32 (3DES)
        if any('3DES' in c for c in ciphers.get('weak', [])):
            self.vulnerabilities.append({
                "name": "Sweet32",
                "severity": "MEDIUM",
                "desc": "3DES ciphers are enabled. Vulnerable to collision attacks (Sweet32)."
            })

        # BEAST (TLS 1.0 + CBC)
        # Hard to detect accurately without checking CBC preference, but TLS 1.0 is a flag
        if protos.get("TLSv1.0"):
             self.vulnerabilities.append({
                "name": "BEAST (Potential)",
                "severity": "LOW",
                "desc": "TLS 1.0 enabled. Might be vulnerable to BEAST if CBC ciphers are used."
            })

        # LOGJAM (Export DHE)
        if any('Export' in c for c in ciphers.get('insecure', [])):
             self.vulnerabilities.append({
                "name": "Logjam/FREAK",
                "severity": "HIGH",
                "desc": "Export grade ciphers enabled."
            })

    def calculate_grade(self, results: Dict[str, Any]):
        """Calculate security grade (A-F)"""
        cert = results.get("certificate", {})
        protocols = results.get("protocols", {})
        vulns = results.get("vulnerabilities", [])
        ciphers = results.get("ciphers", {})
        
        grade_val = 100 # Internal score
        issues = []

        # Critical Failures (Automatic F)
        if cert.get("expired"):
            grade_val = 0
            issues.append("Certificate Expired")
        if protocols.get("SSLv2") or protocols.get("SSLv3"):
            grade_val = 0
            issues.append("Insecure Protocol (SSLv2/SSLv3)")
        if ciphers.get("insecure"):
            grade_val = 0
            issues.append("Insecure Ciphers (NULL/Export/Anon)")
        
        # Major Penalties
        if protocols.get("TLSv1.0") or protocols.get("TLSv1.1"):
            grade_val = min(grade_val, 60) # Max C/D
            issues.append("Deprecated Protocol (TLS 1.0/1.1)")
        
        if ciphers.get("weak"):
            grade_val -= 20
            issues.append(f"Weak Ciphers Enabled ({len(ciphers['weak'])})")

        if cert.get("key_size", 0) < 2048:
            grade_val -= 20
            issues.append("Weak Key Size (<2048 bits)")

        if "sha1" in cert.get("signature_algorithm", "").lower():
            grade_val -= 20
            issues.append("Weak Signature (SHA1)")
            
        # Convert Score to Grade
        if grade_val >= 90: self.grade = "A"
        elif grade_val >= 80: self.grade = "B"
        elif grade_val >= 60: self.grade = "C"
        elif grade_val >= 40: self.grade = "D"
        else: self.grade = "F"
        
        # A+ Check
        if self.grade == "A" and protocols.get("TLSv1.3") and not issues:
            self.grade = "A+"
            
        self.issues = issues
