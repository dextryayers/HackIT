import httpx
import asyncio
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
from models import IntelligenceFinding
from osint_common import resolve_dns, get_all_dns_records, get_ssl_cert_info, parse_cert_to_dict, get_ssl_cert_info

CONTENT_CATEGORIES = [
    ("adult|porn|xxx|sex|nsfw", "Adult"),
    ("business|enterprise|corporate|company|llc|inc", "Business"),
    ("tech|technology|software|developer|programming|code|api", "Technology"),
    ("news|media|press|journal|article|blog|magazine", "News/Media"),
    ("shop|store|buy|product|cart|ecommerce|retail|amazon", "E-Commerce"),
    ("bank|finance|invest|trade|capital|money|payment|pay", "Finance"),
    ("health|medical|doctor|hospital|clinic|pharma", "Healthcare"),
    ("gov|government|state|federal|agency|official", "Government"),
    ("edu|school|university|college|academy|learning|course", "Education"),
    ("social|forum|community|chat|group|network", "Social Network"),
    ("game|gaming|play|casino|bet|poker|sport|sports", "Gaming/Sports"),
    ("mail|email|inbox|message|contact", "Communication"),
    ("wiki|knowledge|docs|documentation|howto|tutorial", "Reference"),
    ("cdn|cloud|host|server|infra|vps|dedicated", "Hosting/Infrastructure"),
]

RISK_KEYWORDS = {
    "malware": -10, "phishing": -10, "spam": -8, "scam": -8, "fraud": -8,
    "hack": -6, "exploit": -6, "crack": -6, "warez": -6, "piracy": -6,
    "torrent": -4, "gambling": -3, "casino": -3, "adult": -2, "sex": -2,
}

TRUSTED_KEYWORDS = {
    "ssl": 2, "secure": 2, "privacy": 2, "official": 3, "verified": 3,
    "trust": 3, "safe": 1, "legal": 2, "compliance": 2, "audit": 2,
}

async def get_whois_data(domain: str) -> dict:
    result = {}
    try:
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 43))
        whois_server = "whois.verisign-grs.com"
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(whois_server, 43), timeout=10.0)
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=15.0)
        writer.close()
        text = data.decode("utf-8", errors="ignore")
        if "Creation Date" in text:
            m = re.search(r"Creation Date:\s*(.+)", text)
            if m: result["creation_date"] = m.group(1).strip()
        if "Registry Expiry Date" in text:
            m = re.search(r"Registry Expiry Date:\s*(.+)", text)
            if m: result["expiration_date"] = m.group(1).strip()
        if "Registrar" in text:
            m = re.search(r"Registrar:\s*(.+)", text)
            if m: result["registrar"] = m.group(1).strip()
        if "Name Server" in text:
            ns = re.findall(r"Name Server:\s*(.+)", text)
            if ns: result["nameservers"] = [n.strip() for n in ns]
        result["raw"] = text[:2000]
    except:
        pass
    return result

async def check_http_service(domain: str, client: httpx.AsyncClient) -> dict:
    result = {}
    for scheme in ["https", "http"]:
        try:
            resp = await client.get(f"{scheme}://{domain}", timeout=10.0, follow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            result[f"{scheme}_status"] = resp.status_code
            result[f"{scheme}_server"] = resp.headers.get("server", "")
            result[f"{scheme}_ctype"] = resp.headers.get("content-type", "")
            result[f"{scheme}_title"] = ""
            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if m:
                result[f"{scheme}_title"] = m.group(1).strip()[:200]
            result[f"{scheme}_headers"] = dict(resp.headers)
            if scheme == "https":
                result["html_sample"] = resp.text[:5000]
            break
        except:
            continue
    return result

def categorize_content(domain: str, page_title: str, html_sample: str) -> list:
    matched = []
    text = f"{domain} {page_title} {html_sample or ''}".lower()
    for pattern, category in CONTENT_CATEGORIES:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(category)
    return matched or ["General/Unknown"]

def score_reputation(domain: str, categories: list, whois: dict, dns_records: dict) -> int:
    score = 50
    for kw, val in RISK_KEYWORDS.items():
        if kw in domain.lower():
            score += val
    for kw, val in TRUSTED_KEYWORDS.items():
        if kw in domain.lower():
            score += val
    if whois.get("creation_date"):
        score += 5
    if whois.get("registrar"):
        score += 3
    if dns_records.get("MX"):
        score += 5
    if dns_records.get("TXT"):
        score += 3
    for cat in categories:
        if cat in ("Finance", "Government", "Healthcare"):
            score += 5
        elif cat in ("Adult", "Gaming/Sports"):
            score -= 5
    return max(0, min(100, score))

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    whois_data = await get_whois_data(domain)
    dns_records = await get_all_dns_records(domain)
    http_info = await check_http_service(domain, client)

    for rtype, records in dns_records.items():
        for rec in records[:5]:
            findings.append(IntelligenceFinding(
                entity=str(rec)[:200],
                type=f"DNS: {rtype} Record",
                source="DomainProfileDeep",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Resolved",
                resolution=f"DNS {rtype} lookup",
                tags=["dns", f"dns-{rtype.lower()}"]
            ))

    if whois_data.get("creation_date"):
        findings.append(IntelligenceFinding(
            entity=whois_data["creation_date"],
            type="Domain Creation Date",
            source="DomainProfileDeep",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Domain created: {whois_data['creation_date']}",
            tags=["whois"]
        ))
    if whois_data.get("expiration_date"):
        findings.append(IntelligenceFinding(
            entity=whois_data["expiration_date"],
            type="Domain Expiration Date",
            source="DomainProfileDeep",
            confidence="High",
            color="orange",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Domain expires: {whois_data['expiration_date']}",
            tags=["whois"]
        ))
    if whois_data.get("registrar"):
        findings.append(IntelligenceFinding(
            entity=whois_data["registrar"],
            type="Domain Registrar",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Registrar: {whois_data['registrar']}",
            tags=["whois"]
        ))
    if whois_data.get("nameservers"):
        for ns in whois_data["nameservers"][:5]:
            findings.append(IntelligenceFinding(
                entity=ns,
                type="Name Server (WHOIS)",
                source="DomainProfileDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="WHOIS Data",
                tags=["whois", "nameserver"]
            ))

    https_title = http_info.get("https_title", "")
    html_sample = http_info.get("html_sample", "")
    categories = categorize_content(domain, https_title, html_sample)
    for cat in categories:
        findings.append(IntelligenceFinding(
            entity=f"Content Category: {cat}",
            type="Domain Category",
            source="DomainProfileDeep",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Classified",
            tags=["classification"]
        ))

    for scheme in ["https", "http"]:
        status_key = f"{scheme}_status"
        server_key = f"{scheme}_server"
        if status_key in http_info:
            title_key = f"{scheme}_title"
            title_str = f" - {http_info.get(title_key, '')}" if http_info.get(title_key) else ""
            findings.append(IntelligenceFinding(
                entity=f"{scheme.upper()} {http_info[status_key]}{title_str}",
                type=f"Web Service ({scheme.upper()})",
                source="DomainProfileDeep",
                confidence="High",
                color="emerald" if http_info[status_key] < 400 else "red",
                threat_level="Informational",
                status="Online" if http_info[status_key] < 400 else "Error",
                resolution=f"HTTP {http_info[status_key]}",
                tags=["web-service"]
            ))
        if server_key in http_info and http_info[server_key]:
            findings.append(IntelligenceFinding(
                entity=http_info[server_key],
                type="Web Server",
                source="DomainProfileDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                tags=["web-server", "technology"]
            ))

    try:
        cert_info = await get_ssl_cert_info(domain)
        if cert_info and cert_info.get("cert"):
            parsed = parse_cert_to_dict(cert_info["cert"])
            if parsed.get("issuer"):
                org = parsed["issuer"].get("organizationName", "Unknown")
                cn = parsed["issuer"].get("commonName", "")
                findings.append(IntelligenceFinding(
                    entity=f"{org} ({cn})" if cn else org,
                    type="SSL Certificate Authority",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Valid SSL",
                    resolution=f"Issuer: {org}",
                    tags=["ssl", "certificate"]
                ))
            if parsed.get("days_remaining") is not None:
                days = parsed["days_remaining"]
                color = "emerald" if days > 30 else ("orange" if days > 7 else "red")
                risk = "Informational" if days > 30 else ("Elevated Risk" if days > 7 else "High Risk")
                findings.append(IntelligenceFinding(
                    entity=f"{days} days remaining ({parsed.get('valid_to', '')})",
                    type="SSL Expiry",
                    source="DomainProfileDeep",
                    confidence="High",
                    color=color,
                    threat_level=risk,
                    status="Expiring" if days < 30 else "Valid",
                    tags=["ssl", "certificate"]
                ))
            if parsed.get("is_expired"):
                findings.append(IntelligenceFinding(
                    entity="SSL Certificate EXPIRED",
                    type="SSL Expired",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Expired",
                    tags=["security", "ssl"]
                ))
            if parsed.get("subject_alt_names"):
                for san in parsed["subject_alt_names"][:8]:
                    findings.append(IntelligenceFinding(
                        entity=san, type="SSL SAN", source="DomainProfileDeep",
                        confidence="High", color="blue", threat_level="Informational",
                        status="SAN", tags=["ssl", "san"]
                    ))
    except:
        pass

    email_security = False
    if dns_records.get("MX"):
        for mx in dns_records["MX"][:5]:
            findings.append(IntelligenceFinding(
                entity=str(mx), type="Mail Server (MX)", source="DomainProfileDeep",
                confidence="High", color="slate", threat_level="Informational",
                status="Resolved", tags=["email", "mx"]
            ))
        email_security = True
    if dns_records.get("TXT"):
        for txt in dns_records["TXT"]:
            txt_str = str(txt)
            if txt_str.startswith("v=spf1"):
                findings.append(IntelligenceFinding(
                    entity=txt_str[:200], type="SPF Record", source="DomainProfileDeep",
                    confidence="High", color="emerald", threat_level="Informational",
                    status="Email Security", tags=["email-security"]
                ))
                email_security = True
            if "v=DMARC1" in txt_str or "dmarc" in txt_str.lower():
                continue
        try:
            loop = asyncio.get_event_loop()
            dmarc_records = await loop.run_in_executor(
                None, lambda: __import__("dns").resolver.resolve(f"_dmarc.{domain}", 'TXT'))
            for r in dmarc_records:
                dmarc = str(r)
                if "v=DMARC1" in dmarc:
                    findings.append(IntelligenceFinding(
                        entity=dmarc[:200], type="DMARC Record", source="DomainProfileDeep",
                        confidence="High", color="emerald", threat_level="Informational",
                        status="Email Security", tags=["email-security"]
                    ))
                    email_security = True
                    if "p=reject" in dmarc:
                        findings.append(IntelligenceFinding(
                            entity="DMARC Policy: Reject", type="DMARC Policy",
                            source="DomainProfileDeep", confidence="High", color="emerald",
                            threat_level="Informational", status="Strong", tags=["email-security"]
                        ))
                    elif "p=none" in dmarc:
                        findings.append(IntelligenceFinding(
                            entity="DMARC Policy: None (no protection)", type="DMARC Weakness",
                            source="DomainProfileDeep", confidence="High", color="red",
                            threat_level="Elevated Risk", status="Weak", tags=["email-security"]
                        ))
        except:
            pass
    if not email_security:
        findings.append(IntelligenceFinding(
            entity="No email security configured (SPF/DKIM/DMARC)",
            type="Missing Email Security",
            source="DomainProfileDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Vulnerable",
            tags=["email-security", "vulnerability"]
        ))

    rep_score = score_reputation(domain, categories, whois_data, dns_records)
    rep_level = "Good" if rep_score >= 70 else ("Fair" if rep_score >= 40 else "Poor")
    rep_color = "emerald" if rep_score >= 70 else ("orange" if rep_score >= 40 else "red")
    findings.append(IntelligenceFinding(
        entity=f"Domain Reputation Score: {rep_score}/100 ({rep_level})",
        type="Domain Reputation",
        source="DomainProfileDeep",
        confidence="High",
        color=rep_color,
        threat_level="Informational" if rep_score >= 70 else ("Standard Target" if rep_score >= 40 else "Elevated Risk"),
        status=rep_level,
        tags=["reputation", "summary"]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Domain profile complete: {len(dns_records)} DNS types, {len(categories)} categories, {len(whois_data)} WHOIS fields",
        type="Domain Profile Summary",
        source="DomainProfileDeep",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["summary"]
    ))

    return findings
