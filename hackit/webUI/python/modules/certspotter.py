import httpx
import re
import asyncio
import json
import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

CERTSPOTTER_API = "https://api.certspotter.com/v1/issuances"
CERTSPOTTER_EXPIRING = "https://api.certspotter.com/v1/issuances/expiring"
CERTSPOTTER_RECENT = "https://api.certspotter.com/v1/issuances/recent"
CERTSPOTTER_DOMAIN = "https://api.certspotter.com/v1/issuances/domain"
CERTSPOTTER_STATS = "https://api.certspotter.com/v1/stats"

TRUSTED_CA_KEYWORDS = [
    "Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "Comodo",
    "GoDaddy", "Cloudflare", "Amazon", "Google Trust", "Microsoft",
    "Entrust", "GeoTrust", "RapidSSL", "Thawte", "VeriSign",
    "IdenTrust", "Certum", "Network Solutions", "SSL.com", "Buypass",
    "ZeroSSL", "cPanel", "GoGetSSL", "SSL.com", "TrustCor",
    "SecureTrust", "Baltimore", "Cybertrust",
]

SELF_SIGNED_KEYWORDS = ["self-signed", "self signed", "localhost", "test ca", "untrusted"]

SSL_CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
]

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "SHA1", "CBC", "EXPORT",
    "NULL", "ANON", "ADH", "AECDH",
]

async def query_issuances(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await safe_fetch(client, 
            f"{CERTSPOTTER_API}?domain={target}&include_subdomains=true&expired=true&expand=dns_names",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

async def query_expiring(target: str, client: httpx.AsyncClient, days: int = 30) -> List[dict]:
    try:
        resp = await safe_fetch(client, 
            f"{CERTSPOTTER_EXPIRING}?domain={target}&days={days}&expand=dns_names",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

async def query_recent(target: str, client: httpx.AsyncClient, limit: int = 50) -> List[dict]:
    try:
        resp = await safe_fetch(client, 
            f"{CERTSPOTTER_RECENT}?domain={target}&limit={limit}&expand=dns_names",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

async def query_domain_issuances(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await safe_fetch(client, 
            f"{CERTSPOTTER_DOMAIN}/{target}?include_subdomains=true&expand=dns_names",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        return []
    except:
        return []

async def query_stats(target: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{CERTSPOTTER_STATS}?domain={target}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            return resp.json()
        return {}
    except:
        return {}

async def sslyze_like_analysis(hostname: str) -> dict:
    result = {
        "tls_version": "",
        "cipher": "",
        "cert_issuer": "",
        "cert_subject": "",
        "cert_serial": "",
        "cert_sha256": "",
        "cert_sans": [],
        "cert_not_before": "",
        "cert_not_after": "",
        "chain_length": 0,
        "cert_chain": [],
        "weak_ciphers": [],
        "strong_ciphers": [],
        "errors": [],
    }
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(10)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                cert_der = s.getpeercert(binary_form=True)
                cipher = s.cipher()
                version = s.version()

                chain = []
                chain_data = []
                try:
                    ps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ps.settimeout(10)
                    ps.connect((hostname, 443))
                    ctx2 = ssl.create_default_context()
                    ctx2.check_hostname = True
                    ctx2.verify_mode = ssl.CERT_REQUIRED
                    s2 = ctx2.wrap_socket(ps, server_hostname=hostname)
                    s2.do_handshake()
                    for i in range(10):
                        try:
                            chain_data.append(s2.getpeercert())
                        except:
                            break
                    s2.close()
                except:
                    pass

                s.close()

                sha256_fp = ""
                if cert_der:
                    sha256_fp = hashlib.sha256(cert_der).hexdigest().upper()

                weak_ciphers_list = []
                strong_ciphers_list = []
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                if any(w in cipher_name for w in WEAK_CIPHERS):
                    weak_ciphers_list.append(cipher_name)
                else:
                    strong_ciphers_list.append(cipher_name)

                return {
                    "tls_version": version,
                    "cipher": cipher,
                    "cert_issuer": dict(cert.get("issuer", [])),
                    "cert_subject": dict(cert.get("subject", [])),
                    "cert_serial": cert.get("serialNumber", ""),
                    "cert_sha256": sha256_fp,
                    "cert_sans": [v for _, v in cert.get("subjectAltName", [])],
                    "cert_not_before": cert.get("notBefore", ""),
                    "cert_not_after": cert.get("notAfter", ""),
                    "chain_length": len(chain_data),
                    "cert_chain": chain_data,
                    "weak_ciphers": weak_ciphers_list,
                    "strong_ciphers": strong_ciphers_list,
                }
            except Exception as e:
                return {"errors": [str(e)]}
        result = await loop.run_in_executor(None, fetch)
    except Exception as e:
        result["errors"].append(str(e))
    return result

async def analyze_ca_issuance_trend(certs: List[dict], target: str, source_label: str) -> List[dict]:
    results = []
    try:
        issuance_by_month = {}
        ca_by_month = {}
        total_by_ca = {}

        for entry in certs:
            if not isinstance(entry, dict):
                continue
            not_before = entry.get("not_before", "")
            if not_before:
                try:
                    month_key = not_before[:7]
                    issuance_by_month[month_key] = issuance_by_month.get(month_key, 0) + 1
                except:
                    pass
            issuer = entry.get("issuer", {})
            if isinstance(issuer, dict):
                ca_name = issuer.get("common_name", issuer.get("CN", "Unknown"))
                total_by_ca[ca_name] = total_by_ca.get(ca_name, 0) + 1

        if issuance_by_month:
            sorted_months = sorted(issuance_by_month.keys())
            trend_parts = []
            for month in sorted_months[-6:]:
                trend_parts.append(f"{month}: {issuance_by_month[month]}")
            results.append(make_finding(
                f"CA Issuance Trend (last 6 months): {' | '.join(trend_parts)}",
                f"{source_label} CA Issuance Trend", source_label,
                confidence="Medium", color="purple", threat_level="Informational",
                resolution=target,
                raw_data=f"All months: {dict(list(issuance_by_month.items())[:12])}",
                tags=["ca-trend", "issuance-analysis"]))

        if total_by_ca:
            top_ca = sorted(total_by_ca.items(), key=lambda x: -x[1])[:5]
            for ca_name, count in top_ca:
                results.append(make_finding(
                    f"{ca_name[:60]}: {count} certs ({count/len(certs)*100:.1f}%)",
                    f"{source_label} CA Market Share", source_label,
                    confidence="High", color="slate", threat_level="Informational",
                    resolution=target,
                    raw_data=f"CA: {ca_name}, Count: {count}, Share: {count/len(certs)*100:.1f}%",
                    tags=["ca-market-share"]))

        months_with_data = len(issuance_by_month)
        if months_with_data > 0:
            avg_per_month = len(certs) / months_with_data if months_with_data > 0 else 0
            results.append(make_finding(
                f"Average {avg_per_month:.1f} certs/month over {months_with_data} months",
                f"{source_label} Issuance Rate", source_label,
                confidence="Medium", color="slate", threat_level="Informational",
                resolution=target,
                tags=["issuance-rate"]))
    except Exception:
        pass
    return results

def extract_issuer_info(issuer: dict) -> dict:
    if not isinstance(issuer, dict):
        return {"name": "Unknown", "org": "Unknown", "trust": "Unknown"}
    cn = issuer.get("common_name", issuer.get("CN", ""))
    org = issuer.get("organization", issuer.get("O", ""))
    country = issuer.get("country", issuer.get("C", ""))

    if not cn:
        for key in ["commonName", "CommonName", "name"]:
            cn = issuer.get(key, "")
            if cn:
                break

    trust_status = evaluate_issuer_trust(cn, org)
    return {"name": cn or "Unknown", "org": org or "Unknown", "country": country or "", "trust": trust_status}

def evaluate_issuer_trust(cn: str, org: str = "") -> str:
    combined = f"{cn} {org}".lower()
    if any(kw.lower() in combined for kw in SELF_SIGNED_KEYWORDS):
        return "Self-Signed/Untrusted"
    for trusted in TRUSTED_CA_KEYWORDS:
        if trusted.lower() in combined:
            return "Trusted CA"
    if cn and org and cn != "Unknown":
        return "Unknown CA"
    return "Unknown"

def get_trust_color(trust: str) -> str:
    return {"Trusted CA": "emerald", "Self-Signed/Untrusted": "red", "Unknown CA": "yellow", "Unknown": "slate"}.get(trust, "slate")

def parse_cert_entry(entry: dict, target: str, source_label: str = "CertSpotter") -> List[dict]:
    results = []
    dns_names = entry.get("dns_names", [])
    issuer = entry.get("issuer", {})
    not_before = entry.get("not_before", "")
    not_after = entry.get("not_after", "")
    cert_id = entry.get("id", "")
    serial = entry.get("serial_number", "")
    fingerprint = entry.get("fingerprint", "")
    revocation = entry.get("revocation", {})

    issuer_info = extract_issuer_info(issuer)
    trust_color = get_trust_color(issuer_info["trust"])

    issuer_display = issuer_info["name"]
    if issuer_info["org"] and issuer_info["org"] != issuer_info["name"]:
        issuer_display = f"{issuer_info['name']} ({issuer_info['org']})"

    results.append(make_finding(
        issuer_display[:200], f"{source_label} Issuer (CA)", source_label,
        confidence="High", color=trust_color, threat_level="Informational",
        status="Found", resolution=target,
        raw_data=f"Issuer: CN={issuer_info['name']}, O={issuer_info['org']}, C={issuer_info['country']}",
        tags=["ca", issuer_info["trust"].lower().replace("/", "-").replace(" ", "-")]))

    if issuer_info["trust"] == "Self-Signed/Untrusted":
        results.append(make_finding(
            f"Self-signed certificate detected: {issuer_info['name']}",
            f"{source_label} Self-Signed Cert", source_label,
            confidence="High", color="red", threat_level="High Risk",
            resolution=target, raw_data=f"Self-signed: {issuer}",
            tags=["security", "self-signed"]))
    elif issuer_info["trust"] == "Unknown CA":
        results.append(make_finding(
            f"Unknown certificate authority: {issuer_info['name']}",
            f"{source_label} Unknown CA", source_label,
            confidence="Medium", color="yellow", threat_level="Elevated Risk",
            resolution=target, raw_data=f"Unknown CA: {issuer}",
            tags=["ca-warning"]))

    if isinstance(dns_names, list) and dns_names:
        seen_names = set()
        subdomains = set()
        wildcards = set()
        for name in dns_names:
            if not isinstance(name, str):
                continue
            name_lower = name.lower()
            clean_name = name_lower.lstrip("*.")
            if clean_name == target.lower() or clean_name.endswith("." + target.lower()):
                if name not in seen_names:
                    seen_names.add(name)
                    is_wildcard = name.startswith("*.")
                    if is_wildcard:
                        wildcards.add(name)
                    elif name != target.lower() and clean_name != target.lower():
                        subdomains.add(name)

                    results.append(make_finding(
                        name, f"{source_label} SAN Discovery", source_label,
                        confidence="High", color="orange" if is_wildcard else "emerald",
                        threat_level="Informational", status="Found",
                        resolution=target, raw_data=f"SAN: {name}",
                        tags=["wildcard" if is_wildcard else "san", "certspotter"]))
        if subdomains:
            results.append(make_finding(
                f"{len(subdomains)} subdomains discovered from SANs",
                f"{source_label} Subdomain Discovery", source_label,
                confidence="High", color="blue", threat_level="Informational",
                resolution=target,
                raw_data=f"Subdomains: {', '.join(sorted(subdomains)[:20])}",
                tags=["subdomain-discovery", "certspotter"]))
        if wildcards:
            results.append(make_finding(
                f"{len(wildcards)} wildcard coverage: {', '.join(sorted(wildcards))[:200]}",
                f"{source_label} Wildcard Coverage", source_label,
                confidence="High", color="orange", threat_level="Informational",
                resolution=target,
                raw_data=f"Wildcards: {', '.join(sorted(wildcards))}",
                tags=["wildcard-mapping"]))

    if serial:
        results.append(make_finding(
            serial, f"{source_label} Serial Number", source_label,
            confidence="High", color="slate", threat_level="Informational",
            resolution=target))

    if fingerprint:
        fp_type = "SHA256" if len(fingerprint) > 32 else "MD5"
        results.append(make_finding(
            fingerprint[:64], f"{source_label} Fingerprint ({fp_type})", source_label,
            confidence="High", color="slate", threat_level="Informational",
            resolution=target, raw_data=f"{fp_type}: {fingerprint[:64]}" if len(fingerprint) > 32 else f"MD5: {fingerprint}"))

    if not_before and not_after:
        try:
            nb_clean = not_before.replace("T", " ").replace("Z", "").split(".")[0] if "T" in not_before else not_before
            na_clean = not_after.replace("T", " ").replace("Z", "").split(".")[0] if "T" in not_after else not_after
            results.append(make_finding(
                f"Valid: {nb_clean[:10]} to {na_clean[:10]}", f"{source_label} Validity Period", source_label,
                confidence="High", color="emerald", threat_level="Informational",
                resolution=target, raw_data=f"Not Before: {not_before}, Not After: {not_after}",
                tags=["validity"]))

            try:
                expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00")) if "T" in not_after else datetime.strptime(not_after, "%Y-%m-%d")
                now = datetime.now(timezone.utc) if expiry.tzinfo else datetime.now()
                days_left = (expiry - now).days
                if days_left < 0:
                    results.append(make_finding(
                        "Certificate has EXPIRED", f"{source_label} Expired Certificate", source_label,
                        confidence="High", color="red", threat_level="High Risk",
                        resolution=target, raw_data=f"Expired {abs(days_left)} days ago on {na_clean[:10]}",
                        tags=["expired", "security"]))
                elif days_left <= 7:
                    results.append(make_finding(
                        f"Certificate expires in {days_left} days - CRITICAL", f"{source_label} Expiring Imminent", source_label,
                        confidence="High", color="red", threat_level="High Risk",
                        resolution=target, raw_data=f"Expires: {na_clean[:10]}, Days left: {days_left}",
                        tags=["expiring-critical"]))
                elif days_left <= 30:
                    results.append(make_finding(
                        f"Certificate expires in {days_left} days", f"{source_label} Expiring Soon", source_label,
                        confidence="High", color="orange", threat_level="Elevated Risk",
                        resolution=target, raw_data=f"Expires: {na_clean[:10]}, Days left: {days_left}",
                        tags=["expiring-soon"]))
            except:
                pass
        except:
            pass

    if isinstance(revocation, dict) and revocation.get("status") == "revoked":
        revoked_at = revocation.get("revoked_at", "unknown")
        results.append(make_finding(
            f"Certificate revoked at {revoked_at}", f"{source_label} Revoked Certificate", source_label,
            confidence="High", color="red", threat_level="High Risk",
            resolution=target, raw_data=f"Revoked: {revoked_at}",
            tags=["revoked", "security"]))

    if dns_names:
        results.append(make_finding(
            f"Cert ID {cert_id}: {len(dns_names)} DNS names", f"{source_label} Cert Summary", source_label,
            confidence="High", color="purple", threat_level="Informational",
            resolution=target, raw_data=f"Cert ID: {cert_id}, DNS names: {len(dns_names)}",
            tags=["cert-summary"]))

    return results

def analyze_ct_monitoring(certs: List[dict], target: str, source_label: str) -> List[dict]:
    results = []
    total_certs = len(certs)
    trusted_count = 0
    self_signed_count = 0
    unknown_ca_count = 0
    total_sans = 0
    all_issuers = {}
    all_subdomains = set()
    all_wildcards = set()

    for entry in certs:
        if not isinstance(entry, dict):
            continue
        issuer = entry.get("issuer", {})
        issuer_info = extract_issuer_info(issuer)
        all_issuers[issuer_info["name"]] = all_issuers.get(issuer_info["name"], 0) + 1

        if issuer_info["trust"] == "Trusted CA":
            trusted_count += 1
        elif issuer_info["trust"] == "Self-Signed/Untrusted":
            self_signed_count += 1
        else:
            unknown_ca_count += 1

        dns_names = entry.get("dns_names", [])
        total_sans += len(dns_names)
        for name in dns_names:
            if isinstance(name, str):
                clean = name.lower().lstrip("*.")
                if clean.endswith("." + target.lower()) and clean != target.lower():
                    all_subdomains.add(clean)
                if name.startswith("*."):
                    all_wildcards.add(name)

    if total_certs > 0:
        results.append(make_finding(
            f"CT Monitor: {total_certs} certs, {trusted_count} trusted, {self_signed_count} self-signed, {unknown_ca_count} unknown CAs",
            f"{source_label} CT Monitoring Summary", source_label,
            confidence="High", color="purple", threat_level="Informational",
            resolution=target,
            raw_data=f"Total: {total_certs}, Trusted: {trusted_count}, Self-Signed: {self_signed_count}, Unknown CA: {unknown_ca_count}, Subdomains: {len(all_subdomains)}, Wildcards: {len(all_wildcards)}",
            tags=["ct-monitor", "certspotter"]))

        if all_issuers:
            top_issuers = sorted(all_issuers.items(), key=lambda x: -x[1])[:5]
            for issuer_name, count in top_issuers:
                results.append(make_finding(
                    f"{issuer_name[:80]}: {count} certs", f"{source_label} Issuer Frequency", source_label,
                    confidence="High", color="slate", threat_level="Informational",
                    resolution=target, raw_data=f"Issuer: {issuer_name}, Count: {count}",
                    tags=["issuer-frequency"]))

        if all_subdomains:
            results.append(make_finding(
                f"{len(all_subdomains)} unique subdomains monitored across all certs",
                f"{source_label} Monitored Subdomains", source_label,
                confidence="High", color="blue", threat_level="Informational",
                resolution=target,
                raw_data=f"Subdomains: {', '.join(sorted(all_subdomains)[:30])}",
                tags=["monitored-subdomains"]))

    if self_signed_count > 0:
        results.append(make_finding(
            f"{self_signed_count} self-signed/untrusted certificates detected", f"{source_label} Self-Signed Alert", source_label,
            confidence="High", color="red", threat_level="High Risk",
            resolution=target, tags=["security", "self-signed-alert"]))

    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    all_certs = await query_issuances(normalized, client)
    if all_certs:
        for entry in all_certs[:40]:
            if isinstance(entry, dict):
                findings.extend(parse_cert_entry(entry, normalized, "CertSpotter"))
        findings.extend(analyze_ct_monitoring(all_certs, normalized, "CertSpotter"))

        trend_analysis = await analyze_ca_issuance_trend(all_certs, normalized, "CertSpotter")
        findings.extend(trend_analysis)

    domain_certs = await query_domain_issuances(normalized, client)
    if domain_certs and domain_certs != all_certs:
        for entry in domain_certs[:10]:
            if isinstance(entry, dict):
                entry_id = entry.get("id", "")
                existing_ids = {f.get("raw_data", "") for f in findings}
                if str(entry_id) not in str(existing_ids):
                    findings.extend(parse_cert_entry(entry, normalized, "CertSpotter"))

    expiring_certs = await query_expiring(normalized, client, days=30)
    if expiring_certs:
        for entry in expiring_certs[:20]:
            if isinstance(entry, dict):
                entry_id = entry.get("id", "")
                existing_ids = {f.get("raw_data", "") for f in findings}
                if str(entry_id) not in str(existing_ids):
                    findings.extend(parse_cert_entry(entry, normalized, "CertSpotter"))

        findings.append(make_finding(
            f"{len(expiring_certs)} certificates expiring within 30 days",
            "CertSpotter Expiring Certs", "CertSpotter",
            confidence="High", color="orange" if len(expiring_certs) < 5 else "red",
            threat_level="Elevated Risk" if len(expiring_certs) < 5 else "High Risk",
            resolution=normalized,
            raw_data=f"Expiring certs: {len(expiring_certs)}",
            tags=["expiring-summary"]))

    recent_certs = await query_recent(normalized, client, limit=30)
    if recent_certs and recent_certs != all_certs:
        for entry in recent_certs[:10]:
            if isinstance(entry, dict):
                entry_id = entry.get("id", "")
                existing_ids = {f.get("raw_data", "") for f in findings}
                if str(entry_id) not in str(existing_ids):
                    findings.extend(parse_cert_entry(entry, normalized, "CertSpotter"))

        findings.append(make_finding(
            f"{len(recent_certs)} recently issued certificates",
            "CertSpotter Recent Issuances", "CertSpotter",
            confidence="High", color="blue", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Recent certs: {len(recent_certs)}",
            tags=["recent-issuances"]))

    stats_data = await query_stats(normalized, client)
    if stats_data:
        findings.append(make_finding(
            f"CertSpotter Stats: {stats_data}",
            "CertSpotter Stats", "CertSpotter",
            confidence="Medium", color="slate", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Stats: {json.dumps(stats_data)[:1000]}" if isinstance(stats_data, dict) else f"Stats: {stats_data}",
            tags=["stats"]))

    ssl_analysis = await sslyze_like_analysis(normalized)
    if ssl_analysis and not ssl_analysis.get("errors"):
        if ssl_analysis.get("tls_version"):
            findings.append(make_finding(
                ssl_analysis["tls_version"], "CertSpotter TLS Version (SSLyze-like)",
                "CertSpotter",
                confidence="High", color="emerald" if "1.2" in ssl_analysis["tls_version"] or "1.3" in ssl_analysis["tls_version"] else "orange",
                threat_level="Informational",
                resolution=normalized,
                tags=["sslyze", "tls-version"]))

        if ssl_analysis.get("cipher"):
            cipher_name = ssl_analysis["cipher"][0] if isinstance(ssl_analysis["cipher"], tuple) else str(ssl_analysis["cipher"])
            is_weak = ssl_analysis.get("weak_ciphers", [])
            findings.append(make_finding(
                cipher_name[:100], "CertSpotter TLS Cipher (SSLyze-like)",
                "CertSpotter",
                confidence="High", color="red" if is_weak else "emerald",
                threat_level="Elevated Risk" if is_weak else "Informational",
                resolution=normalized,
                tags=["sslyze", "cipher"]))

        if ssl_analysis.get("cert_sha256"):
            findings.append(make_finding(
                ssl_analysis["cert_sha256"][:64], "CertSpotter Live Cert SHA256 (SSLyze-like)",
                "CertSpotter",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["sslyze", "fingerprint"]))

        if ssl_analysis.get("cert_issuer"):
            issuer_cn = ssl_analysis["cert_issuer"].get("commonName", "")
            if issuer_cn:
                is_trusted = any(t.lower() in issuer_cn.lower() for t in TRUSTED_CA_KEYWORDS)
                findings.append(make_finding(
                    issuer_cn[:200], "CertSpotter Live Cert Issuer (SSLyze-like)",
                    "CertSpotter",
                    confidence="High", color="emerald" if is_trusted else "yellow",
                    threat_level="Informational",
                    resolution=normalized,
                    tags=["sslyze", "issuer"]))

        if ssl_analysis.get("cert_sans"):
            for san in ssl_analysis["cert_sans"][:5]:
                findings.append(make_finding(
                    san, "CertSpotter Live Cert SAN (SSLyze-like)",
                    "CertSpotter",
                    confidence="High", color="blue", threat_level="Informational",
                    resolution=normalized,
                    tags=["sslyze", "san"]))

        if ssl_analysis.get("chain_length"):
            findings.append(make_finding(
                f"Certificate chain length: {ssl_analysis['chain_length']}",
                "CertSpotter Cert Chain Analysis (SSLyze-like)",
                "CertSpotter",
                confidence="High", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["sslyze", "cert-chain"]))

        if ssl_analysis.get("weak_ciphers"):
            for weak_cipher in ssl_analysis["weak_ciphers"]:
                findings.append(make_finding(
                    f"WEAK cipher detected: {weak_cipher}",
                    "CertSpotter Weak Cipher (SSLyze-like)",
                    "CertSpotter",
                    confidence="High", color="red", threat_level="High Risk",
                    resolution=normalized,
                    tags=["sslyze", "weak-cipher"]))

    if not all_certs and not expiring_certs and not recent_certs and not ssl_analysis:
        findings.append(make_finding(
            normalized, "CertSpotter No Results", "CertSpotter",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found", resolution=normalized,
            raw_data="No certificate data returned from CertSpotter API",
            tags=["empty"]))

    return findings
