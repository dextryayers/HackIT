import httpx
import re
import json
from models import IntelligenceFinding
from collections import defaultdict
from datetime import datetime, timezone

# Known CA patterns for issuer classification
CA_PATTERNS = {
    "Let's Encrypt": ["let's encrypt", "letsencrypt"],
    "DigiCert": ["digicert"],
    "Comodo": ["comodo", "sectigo"],
    "Cloudflare": ["cloudflare", "cloudflare-ssl"],
    "Google Trust": ["google trust", "gts"],
    "Amazon": ["amazon"],
    "Microsoft": ["microsoft"],
    "GlobalSign": ["globalsign"],
    "GoDaddy": ["godaddy"],
    "RapidSSL": ["rapidssl"],
    "GeoTrust": ["geotrust"],
    "Entrust": ["entrust"],
    "Thawte": ["thawte"],
    "Certum": ["certum"],
    "Verizon": ["verizon"],
    "Network Solutions": ["network solutions"],
    "IdenTrust": ["identrust"],
    "Buypass": ["buypass"],
    "SSLMate": ["sslmate"],
    "ZeroSSL": ["zerossl"],
    "Self-Signed": ["self-signed", "self signed"],
}

CERT_LOG_SOURCES = [
    "Google Argon", "Cloudflare Nimbus", "DigiCert Yeti",
    "Sectigo Mammoth", "Let's Encrypt Oak"
]

async def fetch_crtsh_json(domain: str, client: httpx.AsyncClient) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=25.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200 and resp.text.startswith("["):
            return resp.json()
    except:
        pass
    return []

async def fetch_crtsh_html(domain: str, client: httpx.AsyncClient) -> str:
    try:
        url = f"https://crt.sh/?q=%25.{domain}"
        resp = await client.get(url, timeout=25.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return ""

async def fetch_crtsh_identity(domain: str, identity: str, client: httpx.AsyncClient) -> list:
    try:
        url = f"https://crt.sh/?q={identity}&output=json"
        resp = await client.get(url, timeout=25.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and resp.text.startswith("["):
            return resp.json()
    except:
        pass
    return []

async def fetch_crtsh_exclude_expired(domain: str, client: httpx.AsyncClient) -> list:
    try:
        url = f"https://crt.sh/?q=%25.{domain}&excluded=expired&output=json"
        resp = await client.get(url, timeout=25.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and resp.text.startswith("["):
            return resp.json()
    except:
        pass
    return []

def classify_issuer(issuer_name: str) -> str:
    issuer_lower = issuer_name.lower()
    for ca_name, patterns in CA_PATTERNS.items():
        for pattern in patterns:
            if pattern in issuer_lower:
                return ca_name
    return "Unknown/Other"

def parse_html_fallback(html: str, domain: str) -> list:
    findings = []
    try:
        cert_blocks = re.findall(
            r'<tr[^>]*>\s*<td[^>]*>(\d+)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>',
            html, re.DOTALL
        )
        for cert_id, entry_type, name_value, not_before, not_after, cn, issuer in cert_blocks:
            clean_name = re.sub(r'<[^>]+>', '', name_value).strip().lower()
            clean_cn = re.sub(r'<[^>]+>', '', cn).strip().lower()
            clean_issuer = re.sub(r'<[^>]+>', '', issuer).strip()
            clean_nb = re.sub(r'<[^>]+>', '', not_before).strip()
            clean_na = re.sub(r'<[^>]+>', '', not_after).strip()
            for name in [clean_name, clean_cn]:
                if domain in name and name:
                    findings.append({
                        "id": cert_id,
                        "name_value": name,
                        "common_name": clean_cn,
                        "issuer_name": clean_issuer,
                        "not_before": clean_nb[:10],
                        "not_after": clean_na[:10],
                    })
    except:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    # 1. Primary JSON API query
    json_data = await fetch_crtsh_json(domain, client)

    # 2. Exclude expired query variant
    json_active = await fetch_crtsh_exclude_expired(domain, client)

    # 3. HTML fallback if JSON fails
    if not json_data:
        html_data = await fetch_crtsh_html(domain, client)
        if html_data:
            json_data = parse_html_fallback(html_data, domain)

    if not json_data:
        return findings

    name_to_entries = defaultdict(list)
    seen_names = set()
    wildcard_names = set()
    explicit_names = set()
    issuer_counter = defaultdict(int)
    cert_date_map = defaultdict(list)
    cert_year_map = defaultdict(int)
    ca_breakdown = defaultdict(list)

    for item in json_data:
        try:
            name_value = item.get("name_value", "") or ""
            common_name = item.get("common_name", "") or ""
            issuer_name = item.get("issuer_name", "") or ""
            not_before = item.get("not_before", "") or ""
            not_after = item.get("not_after", "") or ""
            id_val = item.get("id", 0)
            entry_type = item.get("entry_type", "") or ""
            min_cert_id = item.get("min_cert_id", 0)
            max_cert_id = item.get("max_cert_id", 0)

            issuer_classified = classify_issuer(issuer_name)
            issuer_counter[issuer_classified] += 1
            if issuer_classified != "Unknown/Other":
                ca_breakdown[issuer_classified].append(id_val)

            for raw_name in [name_value, common_name]:
                if not raw_name:
                    continue
                for sub in raw_name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith("." + domain) or sub == domain:
                        is_wildcard = "*" in sub
                        cert_entry = {
                            "issuer": issuer_name or "Unknown",
                            "issuer_classified": issuer_classified,
                            "id": id_val,
                            "not_before": not_before[:10] if not_before else "",
                            "not_after": not_after[:10] if not_after else "",
                            "entry_type": entry_type,
                        }

                        if is_wildcard:
                            wildcard_names.add(sub)
                            name_to_entries[sub].append(cert_entry)
                        else:
                            if sub not in seen_names:
                                seen_names.add(sub)
                                explicit_names.add(sub)
                            name_to_entries[sub].append(cert_entry)

                        if not_before[:4].isdigit():
                            cert_year_map[not_before[:4]] += 1
                        if not_before[:10]:
                            cert_date_map[sub].append(not_before[:10])
        except:
            continue

    # 5. Per-cert detailed findings
    for sub, entries in name_to_entries.items():
        try:
            ids = [str(e["id"]) for e in entries[:5]]
            issuers_raw = list(set(e["issuer"] for e in entries if e["issuer"] != "Unknown"))
            issuers_classified = list(set(e["issuer_classified"] for e in entries))
            dates_before = sorted(set(e["not_before"] for e in entries if e["not_before"]))
            dates_after = sorted(set(e["not_after"] for e in entries if e["not_after"]))

            earliest = min(dates_before) if dates_before else ""
            latest = max(dates_after) if dates_after else ""
            cert_span = ""
            if earliest and latest:
                try:
                    e_date = datetime.strptime(earliest, "%Y-%m-%d")
                    l_date = datetime.strptime(latest, "%Y-%m-%d")
                    span_days = (l_date - e_date).days
                    cert_span = f"{span_days} days"
                except:
                    pass

            cert_count = len(entries)
            is_wildcard_entry = "*" in sub
            name_type = "Wildcard Certificate" if is_wildcard_entry else "Subdomain (Certificate Transparency)"

            # Age classification
            age_tag = "unknown-age"
            if earliest:
                try:
                    e_date = datetime.strptime(earliest, "%Y-%m-%d")
                    age_days = (datetime.now() - e_date).days
                    if age_days < 90:
                        age_tag = "new-cert"
                    elif age_days < 365:
                        age_tag = "moderate-age"
                    else:
                        age_tag = "old-cert"
                except:
                    pass

            raw_parts = []
            if issuers_raw:
                raw_parts.append(f"Issuers: {', '.join(issuers_raw[:3])}")
            if issuers_classified:
                raw_parts.append(f"CA: {', '.join(issuers_classified[:3])}")
            if earliest:
                raw_parts.append(f"First seen: {earliest}")
            if latest:
                raw_parts.append(f"Last seen: {latest}")
            if cert_span:
                raw_parts.append(f"Cert span: {cert_span}")
            raw_parts.append(f"Cert count: {cert_count}")
            raw_parts.append(f"Cert IDs: {', '.join(ids)}")

            findings.append(IntelligenceFinding(
                entity=sub,
                type=name_type,
                source="crt.sh",
                confidence="High",
                color="emerald",
                category="Domain & DNS Enumeration",
                threat_level="Standard Target",
                status="Logged in CT",
                raw_data=" | ".join(raw_parts),
                tags=["certificate-transparency", "crtsh", "ssl-tls", age_tag, "wildcard" if is_wildcard_entry else "explicit"]
            ))

            # 6. Per-cert issuer details
            for issuer_class in issuers_classified:
                if issuer_class and issuer_class != "Unknown/Other":
                    findings.append(IntelligenceFinding(
                        entity=f"{sub} issued by {issuer_class}",
                        type="Certificate Issuer Detail",
                        source="crt.sh",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"Subdomain {sub} uses certificate from {issuer_class}",
                        tags=["issuer", "ca", issuer_class.lower().replace(" ", "-")]
                    ))
        except:
            continue

    # 7. CA issuer breakdown
    if issuer_counter:
        sorted_cas = sorted(issuer_counter.items(), key=lambda x: -x[1])
        for ca_name, count in sorted_cas[:8]:
            if ca_name == "Unknown/Other":
                continue
            findings.append(IntelligenceFinding(
                entity=f"{ca_name}: {count} certificates for {domain}",
                type="Certificate Authority (CA) Breakdown",
                source="crt.sh",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"CA {ca_name} issued {count} certificates covering {domain}",
                tags=["ca", "issuer-stats", ca_name.lower().replace(" ", "-")]
            ))

    # 8. Self-signed certificate detection
    self_signed_count = issuer_counter.get("Self-Signed", 0)
    if self_signed_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"{self_signed_count} self-signed certificate(s) found for {domain}",
            type="Self-Signed Certificate Alert",
            source="crt.sh",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Self-signed certificates may indicate internal/testing infrastructure: {self_signed_count} found",
            tags=["self-signed", "security-risk"]
        ))

    # 9. Let's Encrypt dominance check
    le_count = issuer_counter.get("Let's Encrypt", 0)
    total_known = sum(v for k, v in issuer_counter.items() if k != "Unknown/Other")
    if total_known > 0 and le_count / total_known > 0.5:
        findings.append(IntelligenceFinding(
            entity=f"Let's Encrypt dominates ({le_count}/{total_known} certs)",
            type="CA Dominance Analysis",
            source="crt.sh",
            confidence="Medium",
            color="yellow",
            threat_level="Informational",
            raw_data=f"Let's Encrypt issued {le_count} of {total_known} classified certificates ({le_count*100//total_known}%)",
            tags=["ca-dominance", "lets-encrypt"]
        ))

    # 10. Certificate temporal analysis by year
    if cert_year_map:
        for year in sorted(cert_year_map.keys()):
            findings.append(IntelligenceFinding(
                entity=f"{year}: {cert_year_map[year]} certificates first seen",
                type="Certificate Temporal Distribution",
                source="crt.sh",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                raw_data=f"In {year}, {cert_year_map[year]} certificates were first observed for {domain}",
                tags=["temporal", f"year-{year}"]
            ))

    # 11. Wildcard certificate summary
    if wildcard_names:
        findings.append(IntelligenceFinding(
            entity=f"{len(wildcard_names)} wildcard cert patterns: {', '.join(sorted(wildcard_names)[:8])}",
            type="Wildcard Certificate Summary",
            source="crt.sh",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            raw_data=f"Wildcard certificates expand the attack surface significantly",
            tags=["wildcard", "summary"]
        ))

    # 12. Certificate Transparency log source coverage
    findings.append(IntelligenceFinding(
        entity=f"Data from crt.sh covering {len(CERT_LOG_SOURCES)} CT log sources",
        type="CT Log Coverage",
        source="crt.sh",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        raw_data=f"CT logs: {', '.join(CERT_LOG_SOURCES)}",
        tags=["ct-logs", "coverage"]
    ))

    # 13. Most recent certificate detection
    all_dates = []
    for entries in name_to_entries.values():
        for e in entries:
            if e["not_after"]:
                all_dates.append(e["not_after"])
    if all_dates:
        try:
            most_recent = max(all_dates)
            findings.append(IntelligenceFinding(
                entity=f"Most recent certificate expires: {most_recent}",
                type="Certificate Expiry Timeline",
                source="crt.sh",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data=f"Latest certificate expiry date for {domain}: {most_recent}",
                tags=["timeline", "expiry"]
            ))
        except:
            pass

    # 14. SAN count analysis per certificate
    san_counts = []
    for item in json_data[:50]:
        try:
            name_val = item.get("name_value", "")
            if name_val:
                count = len(name_val.split("\n"))
                san_counts.append(count)
        except:
            pass
    if san_counts:
        avg_san = sum(san_counts) // len(san_counts)
        max_san = max(san_counts)
        findings.append(IntelligenceFinding(
            entity=f"SAN count: avg={avg_san}, max={max_san} per cert",
            type="SAN Count Analysis",
            source="crt.sh",
            confidence="Medium",
            color="blue",
            threat_level="Informational",
            raw_data=f"Average {avg_san} SANs per certificate, maximum {max_san}",
            tags=["san-analysis"]
        ))

    # 15. Expired certificates count
    expired_count = 0
    recent_expired = []
    import datetime as dt
    now = dt.datetime.now(timezone.utc)
    for item in json_data:
        try:
            na = item.get("not_after", "")
            if na and len(na) >= 10:
                na_dt = datetime.strptime(na[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if na_dt < now:
                    expired_count += 1
                    if len(recent_expired) < 5:
                        recent_expired.append(item.get("name_value", "?")[:60])
        except:
            pass
    if expired_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"{expired_count} expired certificates found",
            type="Expired Certificate Detection",
            source="crt.sh",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Expired certs: {expired_count}. Examples: {', '.join(recent_expired)}",
            tags=["expired", "risk"]
        ))

    # 16. Certificate issuance velocity
    if cert_year_map:
        years_sorted = sorted(cert_year_map.items())
        if len(years_sorted) >= 2:
            try:
                growth_rates = []
                for i in range(1, len(years_sorted)):
                    prev_y, prev_c = years_sorted[i-1]
                    curr_y, curr_c = years_sorted[i]
                    if prev_c > 0:
                        growth = ((curr_c - prev_c) / prev_c) * 100
                        growth_rates.append(f"{curr_y}: {growth:+.0f}%")
                if growth_rates:
                    findings.append(IntelligenceFinding(
                        entity=f"Certificate issuance growth: {'; '.join(growth_rates)}",
                        type="Certificate Issuance Velocity",
                        source="crt.sh",
                        confidence="Low",
                        color="blue",
                        threat_level="Informational",
                        raw_data="Year-over-year certificate issuance trends",
                        tags=["velocity", "growth"]
                    ))
            except:
                pass

    # 17. Subdomain certificate age classification
    new_subs = []
    moderate_subs = []
    old_subs = []
    for sub, entries in name_to_entries.items():
        if "*" in sub:
            continue
        dates = [e["not_before"] for e in entries if e["not_before"]]
        if dates:
            try:
                e_date = datetime.strptime(min(dates), "%Y-%m-%d")
                age_days = (datetime.now() - e_date).days
                if age_days < 90:
                    new_subs.append(sub)
                elif age_days < 365:
                    moderate_subs.append(sub)
                else:
                    old_subs.append(sub)
            except:
                pass

    if new_subs:
        findings.append(IntelligenceFinding(
            entity=f"{len(new_subs)} subdomains with new certs (<90 days): {', '.join(new_subs[:6])}",
            type="Subdomain Age Classification (New)",
            source="crt.sh",
            confidence="Medium",
            color="yellow",
            threat_level="Informational",
            raw_data="Recently obtained certificates may indicate new infrastructure",
            tags=["age-classification", "new-infra"]
        ))
    if moderate_subs:
        findings.append(IntelligenceFinding(
            entity=f"{len(moderate_subs)} subdomains with moderate-age certs (90-365 days)",
            type="Subdomain Age Classification (Moderate)",
            source="crt.sh",
            confidence="Medium",
            color="blue",
            threat_level="Informational",
            raw_data="Established infrastructure",
            tags=["age-classification", "moderate-infra"]
        ))
    if old_subs:
        findings.append(IntelligenceFinding(
            entity=f"{len(old_subs)} subdomains with old certs (>365 days): {', '.join(old_subs[:6])}",
            type="Subdomain Age Classification (Old)",
            source="crt.sh",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            raw_data="Long-standing certificates may indicate stable/legacy infrastructure",
            tags=["age-classification", "old-infra"]
        ))

    # 18. Identity-based queries (substring match)
    identities = ["admin", "api", "dev", "test", "stage", "prod", "vpn", "mail", "cdn", "secure"]
    for identity in identities:
        try:
            ident_data = await fetch_crtsh_identity(domain, f"{identity}.{domain}", client)
            if ident_data:
                findings.append(IntelligenceFinding(
                    entity=f"{identity}.{domain}: {len(ident_data)} cert entries",
                    type=f"Identity Query: {identity}",
                    source="crt.sh",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"Direct identity query for {identity}.{domain} returned {len(ident_data)} results",
                    tags=["identity-query", identity]
                ))
        except:
            pass

    # 19. Check for subdomains with unusual certificate Id (very high)
    all_ids = [item.get("id", 0) for item in json_data if item.get("id", 0) > 0]
    if all_ids:
        max_id = max(all_ids)
        min_id = min(all_ids)
        findings.append(IntelligenceFinding(
            entity=f"Cert ID range: {min_id} to {max_id}",
            type="Certificate ID Range Analysis",
            source="crt.sh",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            raw_data=f"Certificate IDs span from {min_id} to {max_id}, indicating CT log coverage breadth",
            tags=["id-range"]
        ))

    # 20. Summary finding
    total_unique = len([s for s in name_to_entries if "*" not in s])
    if total_unique > 5:
        findings.append(IntelligenceFinding(
            entity=f"Total: {total_unique} unique explicit subdomains + {len(wildcard_names)} wildcard patterns",
            type="Certificate Transparency Summary",
            source="crt.sh",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"{total_unique} subdomains and {len(wildcard_names)} wildcard patterns discovered via crt.sh CT logs",
            tags=["summary", "total"]
        ))

    return findings
