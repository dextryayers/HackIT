import httpx
from typing import List
from urllib.parse import urlparse
from settings_store import get_api_key
from module_common import safe_fetch_json, make_finding, is_ip

WHOIS_API = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
REVERSE_API = "https://reverse-whois.whoisxmlapi.com/api/v2"
DNS_API = "https://www.whoisxmlapi.com/whoisserver/DNSService"

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc
    domain = t

    api_key = get_api_key("whoisxmlapi")
    if not api_key:
        return findings

    data = await safe_fetch_json(client, WHOIS_API,
        params={"apiKey": api_key, "domainName": domain, "outputFormat": "JSON"})
    if not data:
        return findings

    whois = data.get("WhoisRecord", data)

    if whois.get("registrarName"):
        findings.append(make_finding(
            entity=whois["registrarName"],
            ftype="WHOIS: Registrar",
            source="WHOISXML", confidence="High", color="slate",
            threat_level="Informational", status="Identified",
            tags=["whois", "registrar"],
        ))

    if whois.get("createdDateNormalized"):
        findings.append(make_finding(
            entity=f"Created: {whois['createdDateNormalized']}",
            ftype="WHOIS: Creation Date",
            source="WHOISXML", confidence="High", color="slate",
            threat_level="Informational", status="Historical",
            tags=["whois", "creation"],
        ))

    if whois.get("expiresDateNormalized"):
        findings.append(make_finding(
            entity=f"Expires: {whois['expiresDateNormalized']}",
            ftype="WHOIS: Expiry Date",
            source="WHOISXML", confidence="High", color="slate",
            threat_level="Informational", status="Historical",
            tags=["whois", "expiry"],
        ))

    registrant = whois.get("registrant", {}) or whois.get("contact", {})
    if registrant:
        org = registrant.get("organization", "") or registrant.get("org", "")
        name = registrant.get("name", "") or registrant.get("fullName", "")
        email = registrant.get("email", "")
        country = registrant.get("country", "")

        if org:
            findings.append(make_finding(
                entity=org, ftype="WHOIS: Organization",
                source="WHOISXML", confidence="High", color="slate",
                threat_level="Informational", status="Registered",
                tags=["whois", "org"],
            ))
        if name:
            findings.append(make_finding(
                entity=name, ftype="WHOIS: Registrant Name",
                source="WHOISXML", confidence="High", color="slate",
                threat_level="Informational", status="Identified",
                tags=["whois", "registrant"],
            ))
        if email:
            findings.append(make_finding(
                entity=email, ftype="WHOIS: Registrant Email",
                source="WHOISXML", confidence="High", color="pink",
                threat_level="Informational", status="Discovered",
                tags=["whois", "email"],
            ))
        if country:
            findings.append(make_finding(
                entity=country, ftype="WHOIS: Country",
                source="WHOISXML", confidence="High", color="slate",
                threat_level="Informational", status="Detected",
                tags=["whois", "country"],
            ))

    nameservers = whois.get("nameServers", whois.get("nameServers", {}))
    if isinstance(nameservers, dict):
        ns_list = nameservers.get("hostNames", [])
    elif isinstance(nameservers, list):
        ns_list = nameservers
    else:
        ns_list = []

    for ns in ns_list[:5]:
        ns_name = ns if isinstance(ns, str) else ns.get("hostName", "")
        if ns_name:
            findings.append(make_finding(
                entity=ns_name, ftype="WHOIS: Name Server",
                source="WHOISXML", confidence="High", color="slate",
                threat_level="Informational", status="Authoritative",
                tags=["whois", "nameserver"],
            ))

    if whois.get("audit"):
        audit = whois["audit"]
        findings.append(make_finding(
            entity=f"Updated: {audit.get('updatedDate','?')} | Created: {audit.get('createdDate','?')}",
            ftype="WHOIS: Audit Trail",
            source="WHOISXML", confidence="Medium", color="slate",
            threat_level="Informational", status="Audited",
            tags=["whois", "audit"],
        ))

    if whois.get("registryData"):
        rd = whois["registryData"]
        if rd.get("registrarName"):
            findings.append(make_finding(
                entity=rd["registrarName"], ftype="WHOIS: Registry Registrar",
                source="WHOISXML", confidence="High", color="slate",
                threat_level="Informational", status="Verified",
                tags=["whois", "registry"],
            ))
        statuses = rd.get("status", [])
        if isinstance(statuses, list):
            for s in statuses[:3]:
                findings.append(make_finding(
                    entity=f"Domain Status: {s}",
                    ftype="WHOIS: Domain Status",
                    source="WHOISXML", confidence="High", color="slate",
                    threat_level="Informational", status=s,
                    tags=["whois", "status"],
                ))

    return findings
