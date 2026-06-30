import httpx
import re
import asyncio
import json
import hashlib
import ssl
import socket
from datetime import datetime
from typing import List, Optional
from models import IntelligenceFinding
from osint_common import normalize_target, make_finding

CRTSH_URL = "https://crt.sh"
CENSYS_CERT_URL = "https://search.censys.io/api/v2/certificates/search"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
GOOGLE_CT_URL = "https://certificate.transparency.google.com/api/v1"
FACEBOOK_CT_URL = "https://graph.facebook.com/certificate_transparency"
ENTRUST_CT_URL = "https://ct.entrust.com/api/v1"
SSLMATCH_URL = "https://sslmate.com/api/v1/ct"

TRUSTED_CA_ISSUERS = {
    "Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "Comodo",
    "GoDaddy", "Cloudflare", "Amazon", "Google Trust", "Microsoft",
    "Entrust", "GeoTrust", "RapidSSL", "Thawte", "VeriSign",
    "IdenTrust", "Certum", "Network Solutions", "SSL.com", "Buypass",
    "ZeroSSL", "cPanel", "cPanel, Inc.", "GoGetSSL", "SSL.com",
    "TrustCor", "SecureTrust", "Baltimore", "Cybertrust",
}

WILDCARD_RE = re.compile(r"^\*\.[a-zA-Z0-9.-]+$")

def compute_sha256_fingerprint(cert_der: bytes) -> str:
    try:
        return hashlib.sha256(cert_der).hexdigest().upper()
    except Exception:
        return ""

async def query_crtsh(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(f"{CRTSH_URL}/?q=%25.{target}&output=json",
            timeout=20.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    return data
            except (json.JSONDecodeError, ValueError):
                pass
        return []
    except:
        return []

async def query_censys_certs(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(f"{CENSYS_CERT_URL}?q=names:{target}&per_page=50",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("hits", data.get("result", {}).get("hits", []))
        return []
    except:
        return []

async def query_certspotter(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(f"{CERTSPOTTER_URL}?domain={target}&include_subdomains=true&expired=true&expand=dns_names",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

async def query_google_ct(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(f"{GOOGLE_CT_URL}/logentries?domain={target}",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            try:
                data = resp.json()
                return data if isinstance(data, list) else []
            except:
                return []
        return []
    except:
        return []

async def query_entrust_ct(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(f"{ENTRUST_CT_URL}/certificates?domain={target}",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            try:
                data = resp.json()
                return data.get("certificates", [])
            except:
                return []
        return []
    except:
        return []

async def fetch_live_certificate(hostname: str) -> dict:
    result = {}
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(8)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                cert_der = s.getpeercert(binary_form=True)
                cipher = s.cipher()
                version = s.version()
                s.close()

                sha256_fp = ""
                if cert_der:
                    sha256_fp = hashlib.sha256(cert_der).hexdigest().upper()

                return {
                    "issuer": dict(cert.get("issuer", [])),
                    "subject": dict(cert.get("subject", [])),
                    "sans": [v for _, v in cert.get("subjectAltName", [])],
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "serial": cert.get("serialNumber", ""),
                    "sha256_fingerprint": sha256_fp,
                    "cipher": cipher,
                    "protocol": version,
                }
            except:
                return {}
        result = await loop.run_in_executor(None, fetch)
    except Exception:
        pass
    return result

def analyze_certificate_chain(live_cert: dict) -> List[dict]:
    results = []
    try:
        if live_cert.get("issuer"):
            issuer_cn = live_cert["issuer"].get("commonName", "")
            subject_cn = live_cert["subject"].get("commonName", "")
            chain_length = 0

            if issuer_cn:
                chain_length += 1
                is_root = any(root in issuer_cn for root in [
                    "Root", "Root CA", "Trust", "Trust Network", "Global Root"
                ])
                is_intermediate = any(inter in issuer_cn for inter in [
                    "Intermediate", "CA", "Issuer"
                ])
                results.append({
                    "type": "Certificate Chain",
                    "entity": f"Chain link {chain_length}: {issuer_cn[:100]}",
                    "detail": f"Root CA: {is_root}, Intermediate: {is_intermediate}",
                })

            if subject_cn:
                results.append({
                    "type": "Certificate Subject",
                    "entity": f"Subject: {subject_cn[:100]}",
                    "detail": f"Subject CN: {subject_cn}",
                })
    except Exception:
        pass
    return results

def parse_crtsh_entry(entry: dict, target: str) -> List[dict]:
    results = []
    crt_id = entry.get("id", "")
    issuer = entry.get("issuer_name", "")
    subject = entry.get("subject_cn", entry.get("common_name", ""))
    not_before = entry.get("not_before", entry.get("issued_dt", ""))
    not_after = entry.get("not_after", entry.get("expiry_dt", ""))
    serial = entry.get("serial_number", "")
    fingerprint = entry.get("fingerprint", "")
    name_value = entry.get("name_value", "")
    issuer_ca_id = entry.get("issuer_ca_id", "")

    if issuer:
        ca_match = re.search(r"CN=([^,]+)", issuer)
        ca_name = ca_match.group(1).strip() if ca_match else issuer[:80]
        is_trusted = any(trusted.lower() in ca_name.lower() for trusted in TRUSTED_CA_ISSUERS)
        results.append(make_finding(
            ca_name[:200], "Certificate Issuer (CA)", "CertificateSearch",
            confidence="High", color="emerald" if is_trusted else "yellow",
            threat_level="Informational",
            status="Found", resolution=target,
            raw_data=f"Issuer: {issuer[:500]}",
            tags=["ca", "trusted" if is_trusted else "untrusted"]))

    if serial:
        results.append(make_finding(
            serial[:200], "Certificate Serial Number", "CertificateSearch",
            confidence="High", color="slate", threat_level="Informational",
            resolution=target, raw_data=f"Serial: {serial}"))

    if fingerprint:
        fp_type = "SHA256" if len(fingerprint) > 32 else "MD5"
        results.append(make_finding(
            fingerprint[:64], f"Certificate Fingerprint ({fp_type})", "CertificateSearch",
            confidence="High", color="slate", threat_level="Informational",
            resolution=target, raw_data=f"{fp_type}: {fingerprint[:64]}"))

    if not_before and not_after:
        try:
            nb = not_before.replace("T", " ").replace("Z", "").split(".")[0] if "T" in not_before else not_before
            na = not_after.replace("T", " ").replace("Z", "").split(".")[0] if "T" in not_after else not_after
            results.append(make_finding(
                f"Valid: {nb[:10]} to {na[:10]}", "Certificate Validity Period", "CertificateSearch",
                confidence="High", color="emerald" if nb < na else "red",
                threat_level="Informational" if nb < na else "High Risk",
                resolution=target, raw_data=f"Not Before: {not_before}, Not After: {not_after}",
                tags=["validity"]))
            try:
                expiry = datetime.strptime(na[:19], "%Y-%m-%d %H:%M:%S") if "T" not in not_after else datetime.strptime(not_after.replace("T", " ").split(".")[0], "%Y-%m-%d %H:%M:%S")
                days_left = (expiry - datetime.now()).days
                if days_left < 0:
                    results.append(make_finding(
                        "Certificate has EXPIRED", "Certificate Expired", "CertificateSearch",
                        confidence="High", color="red", threat_level="High Risk",
                        resolution=target, raw_data=f"Expired {abs(days_left)} days ago",
                        tags=["expired", "security"]))
                elif days_left < 30:
                    results.append(make_finding(
                        f"Certificate expires in {days_left} days", "Certificate Expiring Soon", "CertificateSearch",
                        confidence="High", color="orange", threat_level="Elevated Risk",
                        resolution=target, raw_data=f"Expires: {na[:10]}",
                        tags=["expiring"]))
                elif days_left < 7:
                    results.append(make_finding(
                        f"Certificate expires in {days_left} days - CRITICAL", "Certificate Expiring Critical", "CertificateSearch",
                        confidence="High", color="red", threat_level="Critical",
                        resolution=target, raw_data=f"Expires: {na[:10]}, Days: {days_left}",
                        tags=["expiring-critical"]))
            except:
                pass
        except:
            pass

    if name_value:
        names = [n.strip() for n in name_value.split("\n") if n.strip()]
        unique_names = set()
        for name in names:
            name_lower = name.lower().lstrip("*.")
            if name_lower.endswith(target) or name_lower == target:
                if name not in unique_names:
                    unique_names.add(name)
                    is_wildcard = name.startswith("*.")
                    results.append(make_finding(
                        name, "Certificate SAN/CN", "CertificateSearch",
                        confidence="High", color="orange" if is_wildcard else "emerald",
                        threat_level="Informational",
                        status="Found", resolution=target,
                        raw_data=f"SAN: {name}",
                        tags=["wildcard" if is_wildcard else "san", "cert-discovery"]))
        if unique_names:
            wildcards = [n for n in unique_names if n.startswith("*.")]
            non_wild = [n for n in unique_names if not n.startswith("*.")]
            wild_count = len(wildcards)
            subdomains = [n for n in non_wild if n != target]
            results.append(make_finding(
                f"Cert ID {crt_id}: {len(unique_names)} names ({len(subdomains)} subdomains, {wild_count} wildcards)",
                "Certificate Name Summary", "CertificateSearch",
                confidence="High", color="purple", threat_level="Informational",
                resolution=target, raw_data=f"Names: {', '.join(sorted(unique_names)[:20])}",
                tags=["cert-summary"]))

    return results

def parse_issuer_details(issuer_str: str) -> dict:
    details = {}
    if not issuer_str:
        return details
    parts = re.findall(r'([A-Za-z]+)=([^,]+)', issuer_str)
    for key, val in parts:
        details[key] = val.strip()
    return details

def analyze_issuer_trust(issuer_name: str) -> tuple:
    issuer_lower = issuer_name.lower()
    if any(trusted.lower() in issuer_lower for trusted in TRUSTED_CA_ISSUERS):
        return ("High", "emerald", "Trusted CA")
    untrusted_keywords = ["self-signed", "self signed", "untrusted", "localhost", "test"]
    if any(kw in issuer_lower for kw in untrusted_keywords):
        return ("Low", "red", "Untrusted CA")
    return ("Medium", "yellow", "Unknown CA")

def parse_censys_cert_hit(hit: dict, target: str) -> List[dict]:
    results = []
    names = hit.get("names", [])
    cn = hit.get("common_name", "")
    issuer = hit.get("issuer", {})
    subject = hit.get("subject", {})
    fingerprint = hit.get("fingerprint", {})
    serial = hit.get("serial_number", "")
    validity = hit.get("validity", {})

    if isinstance(issuer, dict):
        issuer_cn = issuer.get("common_name", "")
        if issuer_cn:
            trust_level, color, label = analyze_issuer_trust(issuer_cn)
            results.append(make_finding(
                f"{issuer_cn} ({label})", "Censys Cert Issuer (CA)", "CertificateSearch",
                confidence="High", color=color, threat_level="Informational",
                resolution=target, raw_data=f"Issuer: {issuer}",
                tags=["ca", label.lower().replace(" ", "-")]))

    if isinstance(fingerprint, dict):
        sha256 = fingerprint.get("sha256", "")
        if sha256:
            results.append(make_finding(
                sha256[:64], "Censys Cert Fingerprint (SHA256)", "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational",
                resolution=target))
        sha1 = fingerprint.get("sha1", "")
        if sha1:
            results.append(make_finding(
                sha1[:40], "Censys Cert Fingerprint (SHA1)", "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational"))
    if serial:
        results.append(make_finding(
            serial, "Censys Cert Serial", "CertificateSearch",
            confidence="High", color="slate", threat_level="Informational"))

    if isinstance(validity, dict):
        start = validity.get("start", "")
        end = validity.get("end", "")
        if start and end:
            results.append(make_finding(
                f"Valid: {start[:10]} to {end[:10]}", "Censys Cert Validity", "CertificateSearch",
                confidence="High", color="emerald", threat_level="Informational",
                resolution=target, raw_data=f"Start: {start}, End: {end}"))

    if isinstance(names, list):
        seen_names = set()
        for name in names:
            if isinstance(name, str) and name.lower().endswith(target.lower()) and name not in seen_names:
                seen_names.add(name)
                results.append(make_finding(
                    name, "Censys Cert SAN", "CertificateSearch",
                    confidence="High", color="emerald", threat_level="Informational",
                    status="Found", resolution=target,
                    tags=["san", "cert-discovery"]))
        if seen_names:
            results.append(make_finding(
                f"{len(seen_names)} SANs from Censys", "Censys Cert SAN Summary", "CertificateSearch",
                confidence="High", color="purple", threat_level="Informational",
                tags=["cert-summary", "censys"]))

    return results

def parse_certspotter_entry(entry: dict, target: str) -> List[dict]:
    results = []
    dns_names = entry.get("dns_names", [])
    issuer = entry.get("issuer", {})
    not_before = entry.get("not_before", "")
    not_after = entry.get("not_after", "")
    id_val = entry.get("id", "")

    if isinstance(issuer, dict):
        issuer_cn = issuer.get("common_name", issuer.get("CN", ""))
        issuer_org = issuer.get("organization", issuer.get("O", ""))
        if issuer_cn:
            is_trusted = any(trusted.lower() in issuer_cn.lower() for trusted in TRUSTED_CA_ISSUERS)
            results.append(make_finding(
                issuer_cn[:200], "CertSpotter Issuer", "CertificateSearch",
                confidence="High", color="emerald" if is_trusted else "yellow",
                threat_level="Informational", resolution=target,
                raw_data=f"Issuer: {issuer_cn}, Org: {issuer_org}",
                tags=["ca", "certspotter"]))

    if isinstance(dns_names, list):
        seen = set()
        for name in dns_names:
            if isinstance(name, str) and name.lower().endswith(target.lower()) and name not in seen:
                seen.add(name)
                is_wild = name.startswith("*.")
                results.append(make_finding(
                    name, "CertSpotter SAN Discovery", "CertificateSearch",
                    confidence="High", color="orange" if is_wild else "emerald",
                    threat_level="Informational", status="Found", resolution=target,
                    tags=["wildcard" if is_wild else "san", "certspotter"]))
        if seen:
            subdomains = [s for s in seen if s != target and not s.startswith("*.")]
            results.append(make_finding(
                f"{len(subdomains)} subdomains from CertSpotter", "CertSpotter SAN Summary", "CertificateSearch",
                confidence="High", color="purple", threat_level="Informational",
                tags=["certspotter-summary"]))

    if not_before and not_after:
        results.append(make_finding(
            f"Valid: {not_before[:10]} to {not_after[:10]}", "CertSpotter Validity", "CertificateSearch",
            confidence="High", color="emerald", threat_level="Informational",
            resolution=target, raw_data=f"From: {not_before}, To: {not_after}"))

    return results

def compare_certificates_across_cas(certs: List[dict], target: str) -> List[dict]:
    results = []
    try:
        ca_certs = {}
        for entry in certs:
            if not isinstance(entry, dict):
                continue
            issuer = entry.get("issuer_name", "")
            ca_match = re.search(r"CN=([^,]+)", issuer)
            ca_name = ca_match.group(1).strip() if ca_match else issuer[:60]
            crt_id = entry.get("id", "")
            if ca_name not in ca_certs:
                ca_certs[ca_name] = []
            ca_certs[ca_name].append(crt_id)

        if len(ca_certs) > 1:
            ca_list = sorted(ca_certs.keys())
            results.append(make_finding(
                f"Multiple CAs ({len(ca_certs)}): {', '.join(c[:30] for c in ca_list[:5])}{'...' if len(ca_list) > 5 else ''}",
                "Certificate CA Comparison", "CertificateSearch",
                confidence="High", color="purple", threat_level="Informational",
                resolution=target,
                raw_data=f"All CAs: {', '.join(ca_list)}",
                tags=["ca-comparison", "multiple-ca"]))

            for ca_name, cert_ids in sorted(ca_certs.items(), key=lambda x: -len(x[1]))[:5]:
                results.append(make_finding(
                    f"{ca_name[:60]}: {len(cert_ids)} certificates",
                    "Certificate CA Breakdown", "CertificateSearch",
                    confidence="High", color="slate", threat_level="Informational",
                    resolution=target,
                    raw_data=f"CA: {ca_name}, Cert IDs: {', '.join(str(c) for c in cert_ids[:5])}",
                    tags=["ca-breakdown"]))
    except Exception:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    crtsh_data = await query_crtsh(normalized, client)
    if crtsh_data:
        seen_certs = set()
        for entry in crtsh_data[:50]:
            if not isinstance(entry, dict):
                continue
            entry_id = entry.get("id", "")
            if entry_id and entry_id not in seen_certs:
                seen_certs.add(entry_id)
                findings.extend(parse_crtsh_entry(entry, normalized))

        ca_count = {}
        for entry in crtsh_data:
            if not isinstance(entry, dict):
                continue
            issuer = entry.get("issuer_name", "")
            ca_match = re.search(r"CN=([^,]+)", issuer)
            ca_name = ca_match.group(1).strip() if ca_match else issuer[:60]
            ca_count[ca_name] = ca_count.get(ca_name, 0) + 1

        total_certs = len(seen_certs)
        seen_all_names = set()
        for entry in crtsh_data:
            if not isinstance(entry, dict):
                continue
            nv = entry.get("name_value", "")
            if nv:
                for n in nv.split("\n"):
                    n = n.strip()
                    if n:
                        seen_all_names.add(n.lstrip("*."))

        subdomains_from_certs = {n for n in seen_all_names if n != normalized and n.endswith("." + normalized)}
        findings.append(make_finding(
            f"crt.sh: {total_certs} certificates, {len(subdomains_from_certs)} subdomains from {len(ca_count)} CAs",
            "Certificate Search Master Summary", "CertificateSearch",
            confidence="High", color="purple", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Certificates: {total_certs}, Subdomains: {len(subdomains_from_certs)}, CAs: {dict(list(ca_count.items())[:10])}",
            tags=["master-summary", "crtsh"]))

        for ca_name, count in sorted(ca_count.items(), key=lambda x: -x[1])[:10]:
            is_trusted = any(trusted.lower() in ca_name.lower() for trusted in TRUSTED_CA_ISSUERS)
            findings.append(make_finding(
                f"{ca_name[:80]}: {count} certs", "Certificate CA Frequency", "CertificateSearch",
                confidence="High", color="emerald" if is_trusted else "yellow",
                threat_level="Informational", resolution=normalized,
                raw_data=f"CA: {ca_name}, Count: {count}",
                tags=["ca-frequency"]))

        wildcard_certs = []
        for entry in crtsh_data:
            if not isinstance(entry, dict):
                continue
            nv = entry.get("name_value", "")
            if nv and any(n.startswith("*.") for n in nv.split("\n") if n.strip()):
                wildcard_certs.append(entry.get("id", ""))
        if wildcard_certs:
            findings.append(make_finding(
                f"{len(wildcard_certs)} wildcard certificates found", "Wildcard Certificate Detection", "CertificateSearch",
                confidence="High", color="orange", threat_level="Informational",
                resolution=normalized,
                raw_data=f"Wildcard cert IDs: {', '.join(wildcard_certs[:10])}",
                tags=["wildcard"]))

        ca_comparison = compare_certificates_across_cas(crtsh_data, normalized)
        findings.extend(ca_comparison)

    censys_data = await query_censys_certs(normalized, client)
    if censys_data:
        for hit in censys_data[:20]:
            if isinstance(hit, dict):
                findings.extend(parse_censys_cert_hit(hit, normalized))

    certspotter_data = await query_certspotter(normalized, client)
    if certspotter_data:
        for entry in certspotter_data[:20]:
            if isinstance(entry, dict):
                findings.extend(parse_certspotter_entry(entry, normalized))

    google_ct_data = await query_google_ct(normalized, client)
    if google_ct_data:
        findings.append(make_finding(
            f"Google CT: {len(google_ct_data)} log entries", "Google CT Log", "CertificateSearch",
            confidence="Medium", color="slate", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Google CT entries: {len(google_ct_data)}",
            tags=["google-ct", "ct-log"]))

    entrust_ct_data = await query_entrust_ct(normalized, client)
    if entrust_ct_data:
        findings.append(make_finding(
            f"Entrust CT: {len(entrust_ct_data)} certificates", "Entrust CT Log", "CertificateSearch",
            confidence="Medium", color="slate", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Entrust CT entries: {len(entrust_ct_data)}",
            tags=["entrust-ct", "ct-log"]))

    live_cert = await fetch_live_certificate(normalized)
    if live_cert:
        if live_cert.get("sha256_fingerprint"):
            findings.append(make_finding(
                live_cert["sha256_fingerprint"][:64], "Live Certificate SHA256 Fingerprint", "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["live-cert", "fingerprint", "sha256"]))

        if live_cert.get("issuer"):
            issuer_cn = live_cert["issuer"].get("commonName", "")
            if issuer_cn:
                is_trusted = any(trusted.lower() in issuer_cn.lower() for trusted in TRUSTED_CA_ISSUERS)
                findings.append(make_finding(
                    issuer_cn[:200], "Live Certificate Issuer", "CertificateSearch",
                    confidence="High", color="emerald" if is_trusted else "yellow",
                    threat_level="Informational", resolution=normalized,
                    tags=["live-cert", "issuer"]))

        if live_cert.get("sans"):
            seen_sans = set()
            for san in live_cert["sans"]:
                if san not in seen_sans:
                    seen_sans.add(san)
                    findings.append(make_finding(
                        san, "Live Certificate SAN", "CertificateSearch",
                        confidence="High", color="blue", threat_level="Informational",
                        resolution=normalized,
                        tags=["live-cert", "san"]))

        if live_cert.get("protocol"):
            findings.append(make_finding(
                live_cert["protocol"], "Live TLS Protocol", "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["live-cert", "tls"]))

        if live_cert.get("cipher"):
            cipher_name = live_cert["cipher"][0] if isinstance(live_cert["cipher"], tuple) else str(live_cert["cipher"])
            findings.append(make_finding(
                cipher_name[:100], "Live TLS Cipher", "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["live-cert", "cipher"]))

        if live_cert.get("not_before") and live_cert.get("not_after"):
            try:
                nb = live_cert["not_before"]
                na = live_cert["not_after"]
                findings.append(make_finding(
                    f"Live cert valid: {nb[:10]} to {na[:10]}", "Live Certificate Validity",
                    "CertificateSearch",
                    confidence="High", color="emerald", threat_level="Informational",
                    resolution=normalized,
                    tags=["live-cert", "validity"]))
                try:
                    expiry = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now()).days
                    if days_left < 0:
                        findings.append(make_finding(
                            "Live certificate is EXPIRED", "Live Certificate Expired",
                            "CertificateSearch",
                            confidence="High", color="red", threat_level="Critical",
                            resolution=normalized,
                            tags=["live-cert", "expired"]))
                    elif days_left < 7:
                        findings.append(make_finding(
                            f"Live certificate expires in {days_left} days",
                            "Live Certificate Expiring Critical",
                            "CertificateSearch",
                            confidence="High", color="red", threat_level="Critical",
                            resolution=normalized,
                            tags=["live-cert", "expiring"]))
                except:
                    pass
            except:
                pass

        chain_analysis = analyze_certificate_chain(live_cert)
        for ca_item in chain_analysis:
            findings.append(make_finding(
                ca_item["entity"], ca_item["type"], "CertificateSearch",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                raw_data=ca_item["detail"],
                tags=["cert-chain"]))

    if not crtsh_data and not censys_data and not certspotter_data and not google_ct_data and not entrust_ct_data and not live_cert:
        findings.append(make_finding(
            normalized, "Certificate Search No Results", "CertificateSearch",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found", resolution=normalized,
            raw_data="No certificate data found from any source",
            tags=["empty"]))

    return findings
