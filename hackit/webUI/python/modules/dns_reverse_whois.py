import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

async def query_viewdns_reverse_whois(query: str, qtype: str, client: httpx.AsyncClient):
    try:
        search_type = {"email": "1", "name": "2", "organization": "3"}.get(qtype, "2")
        resp = await client.get(
            f"https://viewdns.info/reversewhois/?q={quote(query)}&t={search_type}",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=15.0
        )
        if resp.status_code == 200:
            domains = re.findall(r'<tr><td>([^<]+)</td>', resp.text)
            return [d.strip().lower() for d in domains if d.strip() and '.' in d][:50]
    except:
        pass
    return []

async def query_whoxy(query: str, qtype: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://www.whoxy.com/reverse-whois/?q={quote(query)}",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=15.0
        )
        if resp.status_code == 200:
            domains = re.findall(r'<a[^>]*href="https?://(?:www\.)?([^"\']+\.[a-z]+)"[^>]*>', resp.text)
            domains += re.findall(r'([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-z]{2,})', resp.text)
            return [d.strip().lower().lstrip('www.') for d in domains if d.strip() and '.' in d][:50]
    except:
        pass
    return []

async def query_whoisxmlapi_free(domain: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            registrar = ""
            registrant = ""
            emails = []
            whois_data = data.get("WhoisRecord", data)
            rd = whois_data.get("registrantData", whois_data.get("registryData", {}))
            if rd:
                registrant = rd.get("name", rd.get("organization", ""))
                if not registrant:
                    registrant = rd.get("registrantName", "")
            contacts = whois_data.get("contactData", whois_data.get("contacts", {}))
            if contacts:
                if isinstance(contacts, dict):
                    email = contacts.get("email", contacts.get("registrantEmail", ""))
                    if email:
                        emails.append(email)
            return {
                "registrant": registrant,
                "emails": emails,
                "registrar": whois_data.get("registrarName", ""),
                "organization": whois_data.get("registrantOrganization", "")
            }
    except:
        pass
    return {}

async def extract_whois_info(domain: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://www.whois.com/whois/{domain}",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=15.0
        )
        if resp.status_code == 200:
            text = resp.text
            info = {}
            m = re.search(r'Registrant[^:]*:\s*([^\n<]+)', text, re.IGNORECASE)
            if m: info["registrant"] = m.group(1).strip()
            m = re.search(r'Registrant[^:]*Email[^:]*:\s*([^\n<]+)', text, re.IGNORECASE)
            if m: info["email"] = m.group(1).strip().lower()
            m = re.search(r'Registrant[^:]*Organization[^:]*:\s*([^\n<]+)', text, re.IGNORECASE)
            if m: info["organization"] = m.group(1).strip()
            m = re.search(r'Registrant[^:]*Name[^:]*:\s*([^\n<]+)', text, re.IGNORECASE)
            if m and "organization" not in info: info["organization"] = m.group(1).strip()
            m = re.search(r'Registrant[^:]*Phone[^:]*:\s*([^\n<]+)', text, re.IGNORECASE)
            if m: info["phone"] = m.group(1).strip()
            return info
    except:
        pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    whois_info = await extract_whois_info(domain, client)
    whoisxml = await query_whoisxmlapi_free(domain, client)

    registrant_org = whois_info.get("organization", "") or whoisxml.get("organization", "") or whoisxml.get("registrant", "")
    registrant_email = whois_info.get("email", "")
    registrant_name = whois_info.get("registrant", "")
    registrant_phone = whois_info.get("phone", "")
    emails_from_whois = whoisxml.get("emails", [])

    if registrant_org:
        findings.append(IntelligenceFinding(
            entity=registrant_org,
            type="WHOIS Registrant Organization",
            source="DNS Reverse WHOIS",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "organization"]
        ))
    if registrant_email:
        findings.append(IntelligenceFinding(
            entity=registrant_email,
            type="WHOIS Registrant Email",
            source="DNS Reverse WHOIS",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "email"]
        ))
    if registrant_name:
        findings.append(IntelligenceFinding(
            entity=registrant_name,
            type="WHOIS Registrant Name",
            source="DNS Reverse WHOIS",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "name"]
        ))
    if registrant_phone:
        findings.append(IntelligenceFinding(
            entity=registrant_phone,
            type="WHOIS Registrant Phone",
            source="DNS Reverse WHOIS",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "phone"]
        ))

    queries = []
    if registrant_org and len(registrant_org) > 3:
        queries.append(("organization", registrant_org))
    if registrant_email and '@' in registrant_email:
        queries.append(("email", registrant_email))
    if registrant_name and len(registrant_name) > 3:
        queries.append(("name", registrant_name))
    for e in emails_from_whois:
        if e not in [registrant_email] and '@' in e:
            queries.append(("email", e))

    all_related_domains = set()
    sources_for_reverse = []

    for qtype, query in queries[:4]:
        vd_domains = await query_viewdns_reverse_whois(query, qtype, client)
        if vd_domains:
            all_related_domains.update(vd_domains)
            sources_for_reverse.append(f"ViewDNS({qtype})")
            findings.append(IntelligenceFinding(
                entity=f"ViewDNS reverse WHOIS by {qtype}: {len(vd_domains)} domains",
                type="Reverse WHOIS Source",
                source="ViewDNS.info",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(vd_domains)} Domains",
                resolution=query,
                tags=["reverse-whois", "viewdns", qtype]
            ))

        wx_domains = await query_whoxy(query, qtype, client)
        if wx_domains:
            before = len(all_related_domains)
            all_related_domains.update(wx_domains)
            sources_for_reverse.append(f"WhoXY({qtype})")
            findings.append(IntelligenceFinding(
                entity=f"WhoXY reverse WHOIS by {qtype}: {len(wx_domains)} domains",
                type="Reverse WHOIS Source",
                source="WhoXY.com",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(wx_domains)} Domains",
                resolution=query,
                tags=["reverse-whois", "whoxy", qtype]
            ))

    if all_related_domains:
        all_related_domains.discard(domain)
        findings.append(IntelligenceFinding(
            entity=f"Total: {len(all_related_domains)} related domains from {len(set(sources_for_reverse))} source(s)",
            type="Reverse WHOIS Summary",
            source="DNS Reverse WHOIS",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status=f"{len(all_related_domains)} Domains",
            resolution=domain,
            raw_data=f"Sources: {', '.join(set(sources_for_reverse))}",
            tags=["reverse-whois", "summary"]
        ))

        if len(all_related_domains) > 5:
            findings.append(IntelligenceFinding(
                entity=f"Large domain portfolio: {len(all_related_domains)} domains owned by same registrant",
                type="Domain Portfolio Size",
                source="DNS Reverse WHOIS",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                status="Large Portfolio",
                resolution=domain,
                tags=["reverse-whois", "portfolio"]
            ))

        for related in sorted(all_related_domains)[:25]:
            category = "Related Domain"
            threat = "Informational"
            if domain in related and domain != related:
                category = "Sibling Domain (same SLD)"
                threat = "Standard Target"
            findings.append(IntelligenceFinding(
                entity=related,
                type=category,
                source="DNS Reverse WHOIS",
                confidence="Medium",
                color="slate",
                threat_level=threat,
                status="Related",
                resolution=domain,
                tags=["reverse-whois", "sibling"]
            ))

        similar_endings = [d for d in all_related_domains if d.endswith(domain.rsplit('.', 1)[-1]) and d != domain]
        if similar_endings:
            findings.append(IntelligenceFinding(
                entity=f"Same-TLD siblings: {', '.join(similar_endings[:10])}",
                type="Registrant Domain Cluster",
                source="DNS Reverse WHOIS",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Clustered",
                resolution=domain,
                tags=["reverse-whois", "cluster"]
            ))

    if not all_related_domains:
        findings.append(IntelligenceFinding(
            entity=f"No related domains found via reverse WHOIS for {domain}",
            type="Reverse WHOIS No Results",
            source="DNS Reverse WHOIS",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="No Results",
            resolution=domain,
            tags=["reverse-whois", "no-results"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Reverse WHOIS complete for {domain}",
        type="Reverse WHOIS Overall Summary",
        source="DNS Reverse WHOIS",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["reverse-whois", "summary"]
    ))

    return findings
