import asyncio
import ssl
import socket
import re
from datetime import datetime
from module_base import BaseScanner
from osint_common import get_ssl_cert_info, parse_cert_to_dict

KNOWN_VULNS = {
    "heartbleed": {"name":"Heartbleed (CVE-2014-0160)","desc":"OpenSSL Heartbleed vulnerability"},
    "poodle": {"name":"POODLE (CVE-2014-3566)","desc":"SSLv3 padding oracle attack"},
    "logjam": {"name":"Logjam (CVE-2015-4000)","desc":"Diffie-Hellman key exchange weakness"},
    "freak": {"name":"FREAK (CVE-2015-0204)","desc":"RSA export cipher downgrade"},
    "sweet32": {"name":"Sweet32 (CVE-2016-2183)","desc":"3DES block cipher birthday attack"},
    "beast": {"name":"BEAST (CVE-2011-3389)","desc":"TLS 1.0 CBC vulnerability"},
    "rc4_weak": {"name":"RC4 Weakness","desc":"RC4 cipher is broken"},
}

CERT_CHAIN_VULNS = {
    "md2":{"name":"MD2 Signature Algorithm","desc":"Weak hash used in certificate signature"},
    "md5":{"name":"MD5 Signature Algorithm","desc":"Weak hash used in certificate signature"},
    "sha1":{"name":"SHA-1 Signature Algorithm","desc":"Deprecated SHA-1 hash in certificate signature"},
}

SSL_SCAN_PORTS = [443, 8443, 993, 995, 465, 587, 636, 989, 990, 853, 2525]

class SslAnalyzerScanner(BaseScanner):
    name = "ssl_analyzer"

    async def scan(self) -> list:
        results = []
        hostname = self.target

        async def scan_port(port):
            local = []
            try:
                cert_info = await asyncio.wait_for(get_ssl_cert_info(hostname, port), timeout=5)
                if not cert_info or not cert_info.get("cert"):
                    return local
                cert = cert_info["cert"]
                parsed = parse_cert_to_dict(cert)
                port_label = f":{port}" if port != 443 else ""

                is_self_signed = (parsed.get("issuer",{}).get("organizationName") ==
                                  parsed.get("subject",{}).get("organizationName")) if parsed.get("issuer") else False

                if parsed.get("issuer"):
                    org = parsed["issuer"].get("organizationName","Unknown")
                    cn = parsed["issuer"].get("commonName","")
                    country = parsed["issuer"].get("countryName","")
                    parts = [org]
                    if cn: parts.append(f"({cn})")
                    if country: parts.append(f"[{country}]")
                    f = self.finding(entity=" ".join(parts), ftype=f"SSL Issuer{port_label}",
                        confidence="High", color="slate", threat_level="Informational",
                        raw_data=str(parsed["issuer"]))
                    if f: local.append(f)

                if parsed.get("valid_to"):
                    days = parsed.get("days_remaining", 0)
                    c = "emerald" if days>365 else ("blue" if days>90 else ("orange" if days>30 else ("red" if days>7 else "darkred")))
                    risk = "Informational" if days>90 else ("Elevated Risk" if days>30 else ("High Risk" if days>7 else "Critical Risk"))
                    f = self.finding(entity=f"Expires: {parsed['valid_to']} ({days} days remaining)",
                        ftype=f"SSL Expiry{port_label}", confidence="High", color=c, threat_level=risk,
                        raw_data=f"Valid: {parsed.get('valid_from')} -> {parsed.get('valid_to')}")
                    if f: local.append(f)

                if parsed.get("is_expired"):
                    f = self.finding(entity=f"EXPIRED certificate on port {port}",
                        ftype=f"SSL Expired{port_label}", confidence="High", color="red",
                        threat_level="Critical Risk", tags=["security","expired"])
                    if f: local.append(f)

                if is_self_signed:
                    f = self.finding(entity=f"Self-signed certificate{port_label}",
                        ftype=f"SSL Self-Signed{port_label}", confidence="High", color="red",
                        threat_level="Elevated Risk", tags=["security"])
                    if f: local.append(f)

                protocol = cert_info.get("protocol","")
                if protocol:
                    pl = protocol.lower()
                    c = "emerald" if "tlsv1.3" in pl else ("blue" if "tlsv1.2" in pl else ("orange" if "tlsv1" in pl else "red"))
                    risk = "Informational" if "tlsv1.3" in pl else ("Informational" if "tlsv1.2" in pl else ("Elevated Risk" if "tlsv1" in pl else "High Risk"))
                    f = self.finding(entity=protocol, ftype=f"TLS Protocol Version{port_label}",
                        confidence="High", color=c, threat_level=risk, tags=["protocol"])
                    if f: local.append(f)
                    if "ssl" in pl:
                        f = self.finding(entity=f"Outdated protocol: {protocol}",
                            ftype=f"SSL Protocol Vulnerability{port_label}", confidence="High",
                            color="red", threat_level="Critical Risk", tags=["security","vulnerability"])
                        if f: local.append(f)

                cipher = cert_info.get("cipher")
                if cipher:
                    cname = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                    bits = cipher[1] if isinstance(cipher, tuple) and len(cipher)>1 else None
                    cstr = cname + (f" ({bits} bits)" if bits else "")
                    weak_keywords = ["rc4","des","null","export"]
                    strength = "weak" if any(w in cname.lower() for w in weak_keywords) else ("strong" if "aes" in cname.lower() or "chacha" in cname.lower() else "moderate")
                    c = "emerald" if strength=="strong" else ("orange" if strength=="moderate" else "red")
                    risk = "Informational" if strength=="strong" else ("Elevated Risk" if strength=="moderate" else "High Risk")
                    f = self.finding(entity=cstr, ftype=f"SSL Cipher ({strength}){port_label}",
                        confidence="High", color=c, threat_level=risk, tags=["cipher",strength])
                    if f: local.append(f)
                    if strength=="weak":
                        f = self.finding(entity=f"Weak cipher detected: {cname}",
                            ftype=f"Weak Cipher Warning{port_label}", confidence="High",
                            color="red", threat_level="High Risk", tags=["security","weak-cipher"])
                        if f: local.append(f)

                sans = parsed.get("subject_alt_names",[])
                for san in sans[:5]:
                    f = self.finding(entity=san, ftype=f"SSL SAN{port_label}",
                        confidence="High", color="blue", threat_level="Informational", tags=["san"])
                    if f: local.append(f)

                sig_algo = parsed.get("signature_algorithm","")
                if sig_algo:
                    f = self.finding(entity=f"Signature Algorithm: {sig_algo}",
                        ftype=f"SSL Signature Algorithm{port_label}", confidence="High",
                        color="orange" if "sha1" in sig_algo.lower() else "emerald",
                        threat_level="Elevated Risk" if "sha1" in sig_algo.lower() else "Informational")
                    if f: local.append(f)

                pub_size = parsed.get("public_key_size",0)
                pub_algo = parsed.get("public_key_algorithm","")
                if pub_algo:
                    f = self.finding(entity=f"Public Key: {pub_algo} ({pub_size} bits)",
                        ftype=f"SSL Public Key{port_label}", confidence="High",
                        color="emerald" if pub_size>=2048 else "orange", threat_level="Informational")
                    if f: local.append(f)

                if pub_algo.lower()=="rsa" and pub_size and pub_size<2048:
                    f = self.finding(entity=f"Weak RSA key strength: {pub_size} bits",
                        ftype=f"Weak Key Size{port_label}", confidence="High", color="red",
                        threat_level="High Risk", tags=["certificate","weakness"])
                    if f: local.append(f)

                for vk, vi in CERT_CHAIN_VULNS.items():
                    if vk in sig_algo.lower():
                        f = self.finding(entity=f"{vi['name']} detected",
                            ftype=f"Certificate Weakness{port_label}", confidence="High",
                            color="red", threat_level="High Risk", raw_data=vi['desc'],
                            tags=["certificate","weakness",vk])
                        if f: local.append(f)
            except:
                pass
            return local

        tasks = [scan_port(p) for p in SSL_SCAN_PORTS]
        port_results = await asyncio.gather(*tasks)
        for pf in port_results:
            results.extend(pf)

        total = len([f for f in results if "SSL" in f.type or "Certificate" in f.type])
        if total > 0:
            deductions = sum(3 if f.threat_level=="Critical Risk" else (2 if f.threat_level=="High Risk" else (1 if f.threat_level=="Elevated Risk" else 0)) for f in results)
            has_tls13 = any("TLSv1.3" in (f.raw_data or "") or "TLSv1.3" in (f.entity or "") for f in results)
            score = max(0, 10 - deductions)
            grade = "A+" if score>=9 and has_tls13 else ("A" if score>=8 else ("B" if score>=6 else ("C" if score>=4 else ("D" if score>=2 else "F"))))
            f = self.finding(entity=f"SSL Scan Complete: Grade {grade} - {total} findings",
                ftype="SSL Scan Summary", confidence="High",
                color="emerald" if grade.startswith("A") else "orange",
                threat_level="Informational", tags=["summary"])
            if f: results.append(f)
        return results


async def crawl(target: str, client=None):
    scanner = SslAnalyzerScanner(target, client)
    return await scanner.scan()
