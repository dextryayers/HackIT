import httpx
import re
import json
from datetime import datetime
from urllib.parse import urlparse
from models import IntelligenceFinding

WHOIS_HISTORY_SOURCES = [
    {"name": "WhoisXML Sample", "url": "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json", "type": "json"},
    {"name": "ViewDNS History", "url": "https://viewdns.info/whoishistory/?domain={domain}", "type": "html"},
    {"name": "Whois History", "url": "https://whoishistory.com/{domain}", "type": "html"},
]

REGISTRAR_PATTERNS = {
    "GoDaddy": ["godaddy", "GoDaddy"],
    "Namecheap": ["namecheap"],
    "Google Domains": ["google", "domains.google"],
    "Cloudflare": ["cloudflare"],
    "Amazon Registrar": ["amazon", "aws"],
    "Tucows": ["tucows"],
    "Enom": ["enom"],
    "Network Solutions": ["network solutions"],
    "1&1 IONOS": ["1&1", "ionos"],
    "Gandi": ["gandi"],
    "Name.com": ["name.com"],
    "Dynadot": ["dynadot"],
    "Porkbun": ["porkbun"],
    "Hover": ["hover"],
    "DreamHost": ["dreamhost"],
    "HostGator": ["hostgator"],
    "Bluehost": ["bluehost"],
    "OVH": ["ovh"],
    "GMO": ["gmo", "onamae"],
    "Alibaba": ["alibaba", "aliyun"],
    "Squarespace": ["squarespace"],
    "Wix": ["wix"],
}

COUNTRY_NAMES = {
    "US": "United States", "GB": "United Kingdom", "UK": "United Kingdom",
    "DE": "Germany", "FR": "France", "CA": "Canada", "AU": "Australia",
    "JP": "Japan", "NL": "Netherlands", "CN": "China", "RU": "Russia",
    "BR": "Brazil", "IN": "India", "SE": "Sweden", "NO": "Norway",
    "FI": "Finland", "DK": "Denmark", "CH": "Switzerland", "SG": "Singapore",
    "HK": "Hong Kong", "KR": "South Korea", "IE": "Ireland", "IT": "Italy",
    "ES": "Spain", "ZA": "South Africa",
}

async def _fetch_viewdns_whois_history(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://viewdns.info/whoishistory/?domain={domain}",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            entries = re.findall(r'<tr[^>]*>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?</tr>', resp.text, re.DOTALL)
            if entries:
                findings.append(IntelligenceFinding(
                    entity=f"Found {len(entries)} WHOIS history entries from ViewDNS",
                    type="WHOIS History - ViewDNS Summary",
                    source="ViewDNS",
                    confidence="Medium",
                    color="blue",
                    status="Historical",
                    raw_data=f"Total WHOIS history entries: {len(entries)}",
                    tags=["whois-history", "viewdns"]
                ))
                for entry in entries[:30]:
                    date = entry[0].strip()[:20]
                    detail = entry[1].strip()[:200] if len(entry) > 1 else ""
                    findings.append(IntelligenceFinding(
                        entity=detail if detail else f"WHOIS change on {date}",
                        type=f"WHOIS History Change ({date})" if date else "WHOIS History Change",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        status="Historical",
                        resolution=date,
                        raw_data=f"Date: {date}, Detail: {detail}",
                        tags=["whois-history", "change"]
                    ))
    except Exception:
        pass
    return findings

async def _fetch_whoisxml_history(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            whois_record = data.get("whoisRecord", data)
            created = str(whois_record.get("createdDate", ""))[:10]
            updated = str(whois_record.get("updatedDate", ""))[:10]
            expires = str(whois_record.get("expiresDate", ""))[:10]
            registrar = str(whois_record.get("registrarName", ""))
            registrant = whois_record.get("registrant", {})
            if isinstance(registrant, dict):
                org = registrant.get("organization", "")
                country = registrant.get("country", "")
                email = registrant.get("email", "")
                if org:
                    findings.append(IntelligenceFinding(
                        entity=org[:200],
                        type="WHOIS History - Registrant Organization",
                        source="WhoisXML",
                        confidence="High",
                        color="slate",
                        status="Current",
                        tags=["whois-history", "registrant"]
                    ))
                if country:
                    country_full = COUNTRY_NAMES.get(country.upper(), country)
                    findings.append(IntelligenceFinding(
                        entity=country_full,
                        type="WHOIS History - Registrant Country",
                        source="WhoisXML",
                        confidence="High",
                        color="slate",
                        status="Current",
                        tags=["whois-history", "country"]
                    ))
                if email:
                    findings.append(IntelligenceFinding(
                        entity=email[:200],
                        type="WHOIS History - Registrant Email",
                        source="WhoisXML",
                        confidence="High",
                        color="orange",
                        status="Current",
                        tags=["whois-history", "email"]
                    ))
            if registrar:
                findings.append(IntelligenceFinding(
                    entity=registrar[:200],
                    type="WHOIS History - Registrar",
                    source="WhoisXML",
                    confidence="High",
                    color="slate",
                    status="Current",
                    tags=["whois-history", "registrar"]
                ))
            if created:
                try:
                    cd = datetime.strptime(created[:10], "%Y-%m-%d") if created[:10].count("-") == 2 else None
                    if cd:
                        age = (datetime.now() - cd).days
                        findings.append(IntelligenceFinding(
                            entity=f"Domain created: {created[:10]} ({age} days ago)",
                            type="WHOIS History - Creation Date",
                            source="WhoisXML",
                            confidence="High",
                            color="emerald" if age > 365 else "orange",
                            status="Created",
                            tags=["whois-history", "creation"]
                        ))
                except Exception:
                    pass
            if updated:
                findings.append(IntelligenceFinding(
                    entity=f"Last updated: {updated[:10]}",
                    type="WHOIS History - Last Update",
                    source="WhoisXML",
                    confidence="High",
                    color="slate",
                    status="Updated",
                    tags=["whois-history", "updated"]
                ))
            if expires:
                findings.append(IntelligenceFinding(
                    entity=f"Expires: {expires[:10]}",
                    type="WHOIS History - Expiry Date",
                    source="WhoisXML",
                    confidence="High",
                    color="red" if "202" in expires[:7] else "emerald",
                    status="Expiry",
                    tags=["whois-history", "expiry"]
                ))
    except Exception:
        pass
    return findings

async def _detect_registrar_transfers(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            text = resp.text
            registrars_found = []
            for line in text.split("\n"):
                if "Registrar" in line and ":" in line and "URL" not in line and "IANA" not in line:
                    val = line.split(":", 1)[1].strip()
                    if val:
                        registrars_found.append(val)
            if registrars_found:
                unique_regs = list(set(registrars_found))
                findings.append(IntelligenceFinding(
                    entity=f"Current registrar(s): {', '.join(unique_regs[:3])}",
                    type="WHOIS History - Current Registrar",
                    source="WHOIS History",
                    confidence="High",
                    color="slate",
                    status="Current",
                    tags=["whois-history", "registrar"]
                ))
            updated_line = None
            for line in text.split("\n"):
                if "Updated Date" in line and ":" in line:
                    updated_line = line.split(":", 1)[1].strip()[:20]
                    break
            creation_line = None
            for line in text.split("\n"):
                if "Creation Date" in line and ":" in line:
                    creation_line = line.split(":", 1)[1].strip()[:20]
                    break
            if creation_line and updated_line:
                findings.append(IntelligenceFinding(
                    entity=f"Created: {creation_line}, Last Updated: {updated_line}",
                    type="WHOIS History - Timeline Span",
                    source="WHOIS History",
                    confidence="High",
                    color="blue",
                    status="Timeline",
                    raw_data=f"Created: {creation_line}, Updated: {updated_line}",
                    tags=["whois-history", "timeline"]
                ))
            org_name = None
            for line in text.split("\n"):
                if "Registrant Organization" in line and ":" in line:
                    org_name = line.split(":", 1)[1].strip()
                    break
            if org_name:
                findings.append(IntelligenceFinding(
                    entity=org_name[:200],
                    type="WHOIS History - Organization",
                    source="WHOIS History",
                    confidence="High",
                    color="slate",
                    status="Current",
                    tags=["whois-history", "organization"]
                ))
            emails_found = set()
            for line in text.split("\n"):
                if "Email" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if "@" in val:
                        emails_found.add(val)
            for email in emails_found:
                findings.append(IntelligenceFinding(
                    entity=email[:200],
                    type="WHOIS History - Contact Email",
                    source="WHOIS History",
                    confidence="High",
                    color="orange",
                    status="Current",
                    tags=["whois-history", "email"]
                ))
    except Exception:
        pass
    return findings

async def _check_privacy_protection(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            text = resp.text.lower()
            privacy_keywords = ["privacy", "whois guard", "whoisguard", "redacted", "private",
                               "proxy", "data protected", "protection", "GDPR", "REDACTED FOR PRIVACY"]
            for kw in privacy_keywords:
                if kw in text:
                    findings.append(IntelligenceFinding(
                        entity=f"Privacy/Protection service detected: '{kw}' in WHOIS",
                        type="WHOIS History - Privacy Protection",
                        source="WHOIS History",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Privacy Shielded",
                        raw_data=f"Privacy indicator: {kw}",
                        tags=["whois-history", "privacy", "protection"]
                    ))
                    break
            whois_guard = re.search(r'Whois\s*Guard|WhoisGuard|Privacy\s*Protect', resp.text, re.I)
            if whois_guard:
                findings.append(IntelligenceFinding(
                    entity="WhoisGuard/PrivacyProtection service active",
                    type="WHOIS History - Privacy Service Identified",
                    source="WHOIS History",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Privacy Service",
                    tags=["whois-history", "privacy", "service"]
                ))
            registrant_org = ""
            for line in text.split("\n"):
                if "registrant organization" in line and ":" in line:
                    registrant_org = line.split(":", 1)[1].strip()
                    break
            if registrant_org and "privacy" in registrant_org.lower():
                findings.append(IntelligenceFinding(
                    entity=f"Organization field contains privacy wording: '{registrant_org}'",
                    type="WHOIS History - Obfuscated Registrant",
                    source="WHOIS History",
                    confidence="High",
                    color="orange",
                    status="Obfuscated",
                    tags=["whois-history", "obfuscated"]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    findings.append(IntelligenceFinding(
        entity=f"Building WHOIS history timeline for {domain}",
        type="WHOIS History - Start",
        source="WHOIS History",
        confidence="High", color="blue",
        status="Started",
        tags=["whois-history", "start"]
    ))

    vdns_findings = await _fetch_viewdns_whois_history(domain, client)
    findings.extend(vdns_findings)

    xml_findings = await _fetch_whoisxml_history(domain, client)
    findings.extend(xml_findings)

    transfer_findings = await _detect_registrar_transfers(domain, client)
    findings.extend(transfer_findings)

    privacy_findings = await _check_privacy_protection(domain, client)
    findings.extend(privacy_findings)

    if findings:
        entity_types = set(f.type for f in findings)
        findings.append(IntelligenceFinding(
            entity=f"WHOIS History analysis complete: {len(findings)} findings across {len(entity_types)} categories",
            type="WHOIS History - Summary",
            source="WHOIS History",
            confidence="High", color="purple",
            status="Complete",
            tags=["whois-history", "summary"]
        ))

    return findings
