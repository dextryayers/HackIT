import httpx
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

DOMAIN_STATUS_CODES = [
    "addPeriod", "autoRenewPeriod", "inactive", "ok", "pendingCreate",
    "pendingDelete", "pendingRenew", "pendingRestore", "pendingTransfer",
    "pendingUpdate", "redemptionPeriod", "renewPeriod", "serverDeleteProhibited",
    "serverHold", "serverRenewProhibited", "serverTransferProhibited",
    "serverUpdateProhibited", "transferPeriod", "clientDeleteProhibited",
    "clientHold", "clientRenewProhibited", "clientTransferProhibited",
    "clientUpdateProhibited", "linked", "unlinked", "purged",
    "pendingDeleteProhibited", "pendingRGP", "serverRenewProhibited",
    "pendingVerification", "serverReview", "pendingReview",
]

async def scrape_whois(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://www.whois.com/whois/{domain}",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.text
    except: pass
    return ""

async def scrape_whois_interface(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, "https://www.whois.com/whois",
            data={"domainName": domain},
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
            timeout=15.0, method="POST")
        if resp.status_code == 200:
            return resp.text
    except: pass
    return ""

async def scrape_whois_json(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://www.whoisjson.com/whois/{domain}",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    whois_text = await scrape_whois(domain, client)
    if not whois_text:
        whois_text = await scrape_whois_interface(domain, client)
    whois_json = await scrape_whois_json(domain, client)

    creation_date = ""
    expiration_date = ""
    updated_date = ""
    registrar = ""
    registrant_name = ""
    registrant_org = ""
    status_codes = []
    name_servers = []
    abuse_email = ""
    dnssec_info = ""

    if whois_json:
        data = whois_json.get("WhoisRecord", whois_json)
        rd = data.get("registryData", {})
        creation_date = rd.get("createdDate", "") or data.get("createdDate", "")
        expiration_date = rd.get("expiresDate", "") or data.get("expiresDate", "")
        updated_date = rd.get("updatedDate", "") or data.get("updatedDate", "")
        registrar = data.get("registrarName", "") or rd.get("registrarName", "")
        status_codes = data.get("status", []) if isinstance(data.get("status"), list) else []
        name_servers = rd.get("nameServers", {}).get("hostNames", []) if isinstance(rd.get("nameServers"), dict) else (rd.get("nameServers", []) if isinstance(rd.get("nameServers"), list) else [])

    if whois_text:
        m = re.search(r'Domain Name:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        m_c = re.search(r'Creation Date:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_c and not creation_date: creation_date = m_c.group(1).strip()
        m_e = re.search(r'Registry Expiry Date:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_e and not expiration_date: expiration_date = m_e.group(1).strip()
        m_e2 = re.search(r'Expiration Date:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_e2 and not expiration_date: expiration_date = m_e2.group(1).strip()
        m_u = re.search(r'Updated Date:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_u and not updated_date: updated_date = m_u.group(1).strip()
        m_r = re.search(r'Registrar:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_r and not registrar: registrar = m_r.group(1).strip()
        m_ro = re.search(r'Registrant[^:]*Organization[^:]*:\s*([^\n\r<]+)', whois_text, re.IGNORECASE)
        if m_ro: registrant_org = m_ro.group(1).strip()
        m_rn = re.search(r'Registrant[^:]*Name[^:]*:\s*([^\n\r<]+)', whois_text, re.IGNORECASE)
        if m_rn: registrant_name = m_rn.group(1).strip()
        m_ae = re.search(r'Abuse[^:]*Email[^:]*:\s*([^\n\r<]+)', whois_text, re.IGNORECASE)
        if m_ae: abuse_email = m_ae.group(1).strip()
        m_dnssec = re.search(r'DNSSEC:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_dnssec: dnssec_info = m_dnssec.group(1).strip()
        m_ns = re.findall(r'Name Server:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_ns: name_servers = [ns.strip().lower() for ns in m_ns if ns.strip()]
        m_sc = re.findall(r'(?:Domain )?Status:\s*([^\n\r]+)', whois_text, re.IGNORECASE)
        if m_sc: status_codes = [s.strip() for s in m_sc if s.strip()]

    if registrar:
        findings.append(make_finding(
            entity=registrar,
            ftype="Domain Registrar",
            source="Domain Expiry Monitor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "registrar"]
        ))

    if creation_date:
        findings.append(make_finding(
            entity=creation_date[:20],
            ftype="Domain Creation Date",
            source="Domain Expiry Monitor",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Created",
            resolution=domain,
            tags=["whois", "creation"]
        ))

    if updated_date:
        findings.append(make_finding(
            entity=updated_date[:20],
            ftype="Domain Last Updated",
            source="Domain Expiry Monitor",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Updated",
            resolution=domain,
            tags=["whois", "updated"]
        ))

    if expiration_date:
        exp_clean = expiration_date[:20]
        findings.append(make_finding(
            entity=exp_clean,
            ftype="Domain Expiration Date",
            source="Domain Expiry Monitor",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Expires",
            resolution=domain,
            tags=["whois", "expiration"]
        ))
        try:
            exp_formats = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d",
                           "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%d %b %Y %H:%M:%S", "%d %B %Y %H:%M:%S",
                           "%Y/%m/%d %H:%M:%S", "%d/%m/%Y", "%d.%m.%Y"]
            exp_dt = None
            for fmt in exp_formats:
                try:
                    exp_dt = datetime.strptime(exp_clean, fmt)
                    break
                except: continue
            if exp_dt is None:
                for fmt in exp_formats:
                    try:
                        exp_dt = datetime.strptime(expiration_date[:25].strip(), fmt)
                        break
                    except: continue
            if exp_dt:
                now = datetime.now()
                days_left = (exp_dt - now).days
                if days_left < 0:
                    findings.append(make_finding(
                        entity=f"Domain EXPIRED {abs(days_left)} days ago!",
                        type="Domain Expiry Alert",
                        source="Domain Expiry Monitor",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Expired",
                        resolution=domain,
                        tags=["whois", "expired", "critical"]
                    ))
                elif days_left < 30:
                    findings.append(make_finding(
                        entity=f"Domain expires in {days_left} days (CRITICAL)",
                        type="Domain Expiry Alert",
                        source="Domain Expiry Monitor",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Expiring Soon",
                        resolution=domain,
                        tags=["whois", "expiring", "critical"]
                    ))
                elif days_left < 90:
                    findings.append(make_finding(
                        entity=f"Domain expires in {days_left} days (Warning)",
                        type="Domain Expiry Alert",
                        source="Domain Expiry Monitor",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Expiring",
                        resolution=domain,
                        tags=["whois", "expiring"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"Domain expires in {days_left} days",
                        ftype="Domain Expiry Countdown",
                        source="Domain Expiry Monitor",
                        confidence="High",
                        color="green",
                        threat_level="Informational",
                        status="Active",
                        resolution=domain,
                        tags=["whois", "expiry-countdown"]
                    ))
        except: pass

    if name_servers:
        findings.append(make_finding(
            entity=f"Nameservers: {', '.join(name_servers[:5])}",
            type="Domain Nameservers",
            source="Domain Expiry Monitor",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Configured",
            resolution=domain,
            tags=["whois", "nameservers"]
        ))

    if status_codes:
        findings.append(make_finding(
            entity=f"Status codes: {', '.join(status_codes[:8])}",
            type="Domain Status Codes",
            source="Domain Expiry Monitor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Active",
            resolution=domain,
            tags=["whois", "status"]
        ))
        dangerous_states = ["pendingDelete", "redemptionPeriod", "pendingRestore", "serverHold", "clientHold"]
        for ds in dangerous_states:
            if any(ds in sc.lower().replace(" ", "") for sc in status_codes):
                findings.append(make_finding(
                    entity=f"Domain in {ds} state - action required!",
                    ftype="Domain Status Warning",
                    source="Domain Expiry Monitor",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status=ds,
                    resolution=domain,
                    tags=["whois", ds.lower()]
                ))

    if dnssec_info:
        findings.append(make_finding(
            entity=f"DNSSEC: {dnssec_info}",
            ftype="Domain DNSSEC Status",
            source="Domain Expiry Monitor",
            confidence="Medium",
            color="emerald" if dnssec_info.lower() == "signed" or "yes" in dnssec_info.lower() else "slate",
            threat_level="Informational",
            status=dnssec_info.upper(),
            resolution=domain,
            tags=["whois", "dnssec"]
        ))

    if registrant_org:
        findings.append(make_finding(
            entity=registrant_org,
            ftype="Registrant Organization",
            source="Domain Expiry Monitor",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Identified",
            resolution=domain,
            tags=["whois", "organization"]
        ))

    findings.append(make_finding(
        entity=f"WHOIS/expiry analysis complete for {domain}",
        ftype="Domain Expiry Summary",
        source="Domain Expiry Monitor",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["whois", "summary"]
    ))

    return findings
