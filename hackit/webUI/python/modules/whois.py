import httpx
import re
import json
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from models import IntelligenceFinding

WHOIS_SOURCES = [
    {
        "name": "HackerTarget",
        "url": "https://api.hackertarget.com/whois/?q={domain}",
        "type": "text",
        "weight": 1,
    },
    {
        "name": "whois.com",
        "url": "https://www.whois.com/whois/{domain}",
        "type": "html",
        "weight": 2,
    },
    {
        "name": "WhoisXMLAPI",
        "url": "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json",
        "type": "json",
        "weight": 3,
    },
    {
        "name": "Verisign",
        "url": "https://whois.verisign.com/?domain={domain}",
        "type": "html",
        "weight": 4,
    },
]

TLD_WHOIS_SERVERS = {
    "com": "whois.verisign.com",
    "net": "whois.verisign.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.neulevel.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "cloud": "whois.nic.cloud",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "store": "whois.nic.store",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "in": "whois.registry.in",
    "eu": "whois.eu",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "jp": "whois.jprs.jp",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "br": "whois.registro.br",
    "cn": "whois.cnnic.cn",
    "ru": "whois.tcinet.ru",
}

RDAP_BOOTSTRAP_URLS = [
    "https://rdap.verisign.com/com/v1/domain/{domain}",
    "https://rdap.verisign.com/net/v1/domain/{domain}",
    "https://rdap.pir.org/domain/{domain}",
    "https://rdap.afilias.net/rdap/domain/{domain}",
    "https://rdap.nic.google/domain/{domain}",
    "https://rdap.nic.xyz/domain/{domain}",
    "https://rdap.nic.cloud/domain/{domain}",
    "https://rdap.nic.io/domain/{domain}",
    "https://rdap.nic.co/domain/{domain}",
    "https://rdap.registry.in/domain/{domain}",
    "https://rdap.denic.de/domain/{domain}",
    "https://rdap.nic.uk/domain/{domain}",
    "https://rdap.auda.org.au/domain/{domain}",
    "https://rdap.cira.ca/domain/{domain}",
    "https://rdap.nic.fr/domain/{domain}",
    "https://rdap.nic.eu/domain/{domain}",
    "https://rdap.nic.tv/domain/{domain}",
    "https://rdap.nic.store/domain/{domain}",
    "https://rdap.nic.tech/domain/{domain}",
    "https://rdap.nic.site/domain/{domain}",
    "https://rdap.nic.online/domain/{domain}",
    "https://rdap.nic.me/domain/{domain}",
]

FIELDS_OF_INTEREST = {
    "Registrar": "Whois Registrar",
    "Registrar Organization": "Whois Organization",
    "Registrant Organization": "Whois Organization",
    "Registrant Name": "Whois Registrant Name",
    "Registrant State": "Whois Location",
    "Registrant Province": "Whois Location",
    "Registrant State/Province": "Whois Location",
    "Registrant City": "Whois City",
    "Registrant Postal Code": "Whois Postal Code",
    "Registrant Country": "Whois Country",
    "Registrant Email": "Whois Email",
    "Registrant Phone": "Whois Phone",
    "Registrant Fax": "Whois Fax",
    "Admin Organization": "Whois Admin Organization",
    "Admin Name": "Whois Admin Name",
    "Admin Email": "Whois Admin Email",
    "Admin Phone": "Whois Admin Phone",
    "Admin Country": "Whois Admin Country",
    "Tech Organization": "Whois Tech Organization",
    "Tech Name": "Whois Tech Name",
    "Tech Email": "Whois Tech Email",
    "Tech Phone": "Whois Tech Phone",
    "Tech Country": "Whois Tech Country",
    "Billing Email": "Whois Billing Email",
    "Name Server": "Whois Nameserver",
    "Creation Date": "Whois Domain Created",
    "Registry Expiry Date": "Whois Domain Expires",
    "Expiration Date": "Whois Domain Expires",
    "Updated Date": "Whois Domain Updated",
    "Domain Status": "Whois Domain Status",
    "Registrar Abuse Contact Email": "Whois Abuse Contact",
    "Registrar Abuse Contact Phone": "Whois Abuse Phone",
    "Registrar URL": "Whois Registrar URL",
    "Registrar IANA ID": "Whois IANA ID",
    "Registrar Abuse Contact Email": "Whois Abuse Email",
    "Registrar Abuse Contact Phone": "Whois Abuse Phone",
    "DNSSEC": "Whois DNSSEC",
    "Zone Email": "Whois Zone Email",
    "OrgName": "Whois Org Name",
    "OrgId": "Whois Org ID",
    "Address": "Whois Address",
    "OrgTechEmail": "Whois Tech Email",
    "OrgTechPhone": "Whois Tech Phone",
    "OrgAbuseEmail": "Whois Abuse Email",
    "OrgAbusePhone": "Whois Abuse Phone",
    "NetName": "Whois Net Name",
    "NetRange": "Whois Net Range",
    "CIDR": "Whois CIDR",
    "Parent": "Whois Parent Range",
}

DOMAIN_STATUS_CODES = {
    "clientTransferProhibited": "Domain locked (transfer prohibited)",
    "clientDeleteProhibited": "Domain locked (delete prohibited)",
    "clientUpdateProhibited": "Domain locked (update prohibited)",
    "serverTransferProhibited": "Registry lock (transfer)",
    "serverDeleteProhibited": "Registry lock (delete)",
    "serverUpdateProhibited": "Registry lock (update)",
    "clientHold": "Domain not resolving (client hold)",
    "serverHold": "Domain not resolving (registry hold)",
    "clientRenewProhibited": "Renewal prohibited",
    "serverRenewProhibited": "Registry renewal prohibited",
    "addPeriod": "Grace period after registration",
    "autoRenewPeriod": "Auto-renew grace period",
    "renewPeriod": "Renewal grace period",
    "redemptionPeriod": "Redemption grace period",
    "pendingDelete": "Pending deletion",
    "pendingTransfer": "Pending transfer",
    "pendingCreate": "Pending creation",
    "pendingRenew": "Pending renewal",
    "pendingUpdate": "Pending update",
    "inactive": "Domain inactive",
    "ok": "Domain active (OK)",
}

IANA_ORG_PATTERN = re.compile(r'IANA ID:\s*(\d+)', re.IGNORECASE)

REGISTRAR_ABUSE_KEYWORDS = ["abuse", "complaint", "report", "legal"]

async def fetch_whois_text(domain: str, client: httpx.AsyncClient, source: dict) -> str | None:
    try:
        url = source["url"].format(domain=domain)
        resp = await client.get(
            url, timeout=12.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        if resp.status_code != 200:
            return None
        text = resp.text
        if "error" in text.lower()[:200] and len(text) < 500:
            return None
        if "not found" in text.lower()[:300] or "no match" in text.lower()[:300]:
            return None
        return text
    except Exception:
        return None

async def fetch_raw_whois_tcp(domain: str) -> str | None:
    try:
        import asyncio
        tld = domain.split(".")[-1] if "." in domain else ""
        whois_server = TLD_WHOIS_SERVERS.get(tld, "whois.verisign-grs.com")

        loop = asyncio.get_event_loop()

        def query():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((whois_server, 43))
                sock.send(f"{domain}\r\n".encode())
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"%" in chunk:
                        continue
                    if len(data) > 65536:
                        break
                sock.close()
                return data.decode("utf-8", errors="ignore")
            except:
                return None

        result = await loop.run_in_executor(None, query)
        return result
    except:
        return None

def parse_rdap(data: dict) -> dict:
    result = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = value
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        sub = parse_rdap(item)
                        result.update(sub)
                    elif isinstance(item, str):
                        result[key] = result.get(key, "") + (" " if result.get(key) else "") + item
            elif isinstance(value, dict):
                sub = parse_rdap(value)
                result.update(sub)
    if "events" in str(data):
        events = data.get("events", []) if isinstance(data, dict) else []
        for event in events:
            if isinstance(event, dict):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action and date:
                    result[f"Event: {action}"] = date
    entities = data.get("entities", []) if isinstance(data, dict) else []
    for entity in entities:
        if isinstance(entity, dict):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 3:
                        field = item[0]
                        val = item[3] if len(item) > 3 else ""
                        if field == "fn":
                            result[f"Contact: {'/'.join(roles)} Name"] = str(val)
                        elif field == "email":
                            result[f"Contact: {'/'.join(roles)} Email"] = str(val)
                        elif field == "tel":
                            result[f"Contact: {'/'.join(roles)} Phone"] = str(val)
                        elif field == "adr" and isinstance(val, dict):
                            result[f"Contact: {'/'.join(roles)} Country"] = val.get("country", "")
    return result

def parse_whois_text(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        line_stripped = line.strip()
        if ":" in line_stripped and not line_stripped.startswith("%") and not line_stripped.startswith("#"):
            key, _, value = line_stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value and len(key) < 60 and len(value) < 500:
                result[key] = value
    return result

def parse_whois_html(html: str) -> dict:
    result = {}
    text = re.sub(r'<[^>]+>', '\n', html)
    for line in text.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("%") and not line.startswith("#"):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value and len(key) < 60 and len(value) < 500:
                result[key] = value
    return result

def extract_contacts(parsed: dict) -> list:
    contact_fields = []
    for raw_key, value in parsed.items():
        lk = raw_key.lower()
        for search_key, ftype in FIELDS_OF_INTEREST.items():
            if search_key.lower() in lk:
                contact_fields.append((ftype, value, raw_key))
                break
    return contact_fields

def extract_domain_statuses(parsed: dict) -> list:
    statuses = []
    for raw_key, value in parsed.items():
        if "status" in raw_key.lower():
            for code, desc in DOMAIN_STATUS_CODES.items():
                if code.lower() in value.lower():
                    statuses.append((code, desc, value))
                    break
            else:
                if value.strip():
                    statuses.append(("unknown", "", value))
    return statuses

def extract_abuse_contacts(parsed: dict) -> dict:
    abuse = {"email": None, "phone": None}
    for raw_key, value in parsed.items():
        lk = raw_key.lower()
        if "abuse" in lk and "email" in lk:
            abuse["email"] = value
        if "abuse" in lk and "phone" in lk:
            abuse["phone"] = value
        if "abuse" in lk and "registrar" in lk:
            if "@" in value:
                abuse["email"] = value
    return abuse

def extract_iana_info(parsed: dict) -> str | None:
    for raw_key, value in parsed.items():
        if "iana" in raw_key.lower() or "iana" in value.lower():
            m = IANA_ORG_PATTERN.search(value)
            if m:
                return m.group(1)
    return None

def extract_organization_details(parsed: dict) -> dict:
    org = {}
    for raw_key, value in parsed.items():
        lk = raw_key.lower()
        if "org" in lk or "organization" in lk:
            if value and len(value) < 200:
                org[raw_key] = value
    return org

def extract_admin_tech_contacts(parsed: dict) -> dict:
    contacts = {"admin": {}, "tech": {}, "billing": {}}
    for raw_key, value in parsed.items():
        lk = raw_key.lower()
        if "admin" in lk:
            subtype = lk.replace("admin", "").strip()
            if subtype:
                contacts["admin"][subtype] = value
            else:
                contacts["admin"]["name"] = value
        if "tech" in lk:
            subtype = lk.replace("tech", "").strip()
            if subtype:
                contacts["tech"][subtype] = value
            else:
                contacts["tech"]["name"] = value
        if "billing" in lk:
            subtype = lk.replace("billing", "").strip()
            if subtype:
                contacts["billing"][subtype] = value
            else:
                contacts["billing"]["name"] = value
    return contacts

def estimate_domain_value(parsed: dict) -> dict:
    value_estimate = {
        "estimated_value": "Unknown",
        "factors": [],
        "score": 0
    }
    score = 0
    factors = []

    for raw_key, value in parsed.items():
        lk = raw_key.lower()
        if "creation" in lk or "created" in lk:
            try:
                year = int(value[:4]) if value[:4].isdigit() else 0
                age = datetime.now().year - year
                if age > 15:
                    score += 30
                    factors.append(f"Domain age: {age} years (premium)")
                elif age > 10:
                    score += 20
                    factors.append(f"Domain age: {age} years (valuable)")
                elif age > 5:
                    score += 10
                    factors.append(f"Domain age: {age} years (established)")
                else:
                    score += 5
                    factors.append(f"Domain age: {age} years (young)")
            except:
                pass

        if "name server" in lk:
            ns_value = value.lower()
            if "cloudflare" in ns_value:
                score += 5
                factors.append("Uses Cloudflare DNS (active)")
            elif "aws" in ns_value or "amazon" in ns_value:
                score += 3
                factors.append("Uses AWS DNS")

    statuses = extract_domain_statuses(parsed)
    for code, desc, raw_val in statuses:
        if code in ("ok",):
            score += 5
            factors.append("Domain active (OK status)")
        elif "prohibit" in code:
            score += 10
            factors.append(f"Domain locked ({code})")

    for raw_key, value in parsed.items():
        if "dnssec" in raw_key.lower():
            if "signed" in value.lower():
                score += 5
                factors.append("DNSSEC signed")

    if score >= 50:
        value_estimate["estimated_value"] = "High ($500+)"
    elif score >= 30:
        value_estimate["estimated_value"] = "Medium ($100-$500)"
    elif score >= 15:
        value_estimate["estimated_value"] = "Low ($10-$100)"
    else:
        value_estimate["estimated_value"] = "Minimal (<$10)"

    value_estimate["score"] = score
    value_estimate["factors"] = factors
    return value_estimate

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        domain = target.strip().lower()
        if domain.startswith("http"):
            domain = urlparse(target).netloc
        domain = domain.strip().lower()

        best_text = None
        best_source_name = None
        best_type = None

        for source in sorted(WHOIS_SOURCES, key=lambda s: s["weight"]):
            text = await fetch_whois_text(domain, client, source)
            if text and len(text) > 100:
                best_text = text
                best_source_name = source["name"]
                best_type = source["type"]
                break

        if not best_text:
            raw_whois = await fetch_raw_whois_tcp(domain)
            if raw_whois and len(raw_whois) > 100:
                best_text = raw_whois
                best_source_name = f"Direct WHOIS (TCP 43)"
                best_type = "text"

        rdap_text = None
        for rdap_url_tpl in RDAP_BOOTSTRAP_URLS:
            rdap_url = rdap_url_tpl.format(domain=domain)
            try:
                rr = await client.get(rdap_url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                )
                if rr.status_code == 200:
                    rdap_text = rr.text
                    if not best_text:
                        best_text = rdap_text
                        best_source_name = "RDAP"
                        best_type = "json"
                    break
            except Exception:
                continue

        if not best_text:
            findings.append(IntelligenceFinding(
                entity=f"No WHOIS data available for {domain}",
                type="Whois No Data",
                source="WHOIS",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="No Data",
                tags=["whois"],
            ))
            return findings

        parsed = {}
        if best_type == "json" or (best_text and best_text.strip().startswith("{")):
            try:
                data = json.loads(best_text)
                if "whoisRecord" in data:
                    data = data["whoisRecord"]
                parsed = parse_rdap(data)
                if not parsed:
                    parsed = parse_whois_text(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                parsed = parse_whois_text(best_text)
        elif best_type == "html":
            parsed = parse_whois_html(best_text)
        else:
            parsed = parse_whois_text(best_text)

        findings.append(IntelligenceFinding(
            entity=f"WHOIS data for {domain} (source: {best_source_name})",
            type="Whois Source",
            source="WHOIS",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Retrieved",
            resolution=f"Source: {best_source_name}",
            raw_data=f"Source: {best_source_name}",
            tags=["whois", "source"],
        ))

        contacts = extract_contacts(parsed)
        seen_contacts = set()
        for ftype, value, raw_key in contacts:
            if value not in seen_contacts:
                seen_contacts.add(value)
                findings.append(IntelligenceFinding(
                    entity=value[:200],
                    type=ftype,
                    source="WHOIS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Extracted",
                    resolution=f"Field: {raw_key}",
                    raw_data=f"{raw_key}: {value[:500]}",
                    tags=["whois", "contact"],
                ))

        statuses = extract_domain_statuses(parsed)
        for code, desc, raw_value in statuses:
            findings.append(IntelligenceFinding(
                entity=f"Status: {code} - {desc}" if desc else f"Status: {raw_value[:100]}",
                type="Whois Domain Status",
                source="WHOIS",
                confidence="High",
                color="orange" if "hold" in code or "prohibit" in code or "pending" in code else "emerald",
                threat_level="Informational",
                status="Status Code",
                resolution=desc if desc else "",
                raw_data=f"Status: {raw_value[:200]}",
                tags=["whois", "domain-status"],
            ))

        dnssec = None
        for raw_key, value in parsed.items():
            if "dnssec" in raw_key.lower():
                dnssec = value
                break
        if dnssec:
            findings.append(IntelligenceFinding(
                entity=f"DNSSEC: {dnssec}",
                type="Whois DNSSEC",
                source="WHOIS",
                confidence="High",
                color="emerald" if "signed" in str(dnssec).lower() else "slate",
                threat_level="Informational",
                status="Detected",
                raw_data=f"DNSSEC: {dnssec}",
                tags=["whois", "dnssec"],
            ))

        abuse = extract_abuse_contacts(parsed)
        if abuse["email"]:
            findings.append(IntelligenceFinding(
                entity=abuse["email"],
                type="Whois Abuse Contact",
                source="WHOIS",
                confidence="High",
                color="red",
                threat_level="Informational",
                status="Abuse Contact",
                raw_data=f"Abuse Email: {abuse['email']}",
                tags=["whois", "abuse"],
            ))
        if abuse["phone"]:
            findings.append(IntelligenceFinding(
                entity=abuse["phone"],
                type="Whois Abuse Phone",
                source="WHOIS",
                confidence="High",
                color="red",
                threat_level="Informational",
                status="Abuse Contact",
                raw_data=f"Abuse Phone: {abuse['phone']}",
                tags=["whois", "abuse"],
            ))

        iana_id = extract_iana_info(parsed)
        if iana_id:
            findings.append(IntelligenceFinding(
                entity=f"IANA ID: {iana_id}",
                type="Whois IANA ID",
                source="WHOIS",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Identified",
                tags=["whois", "iana"],
            ))

        nameservers = []
        for raw_key, value in parsed.items():
            if "name server" in raw_key.lower() or "nameserver" in raw_key.lower():
                ns = value.strip().rstrip(".")
                if ns and ns not in nameservers:
                    nameservers.append(ns)
        if nameservers:
            findings.append(IntelligenceFinding(
                entity=f"Nameservers: {', '.join(nameservers[:5])}{'...' if len(nameservers) > 5 else ''}",
                type="Whois Nameservers",
                source="WHOIS",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Extracted",
                raw_data=", ".join(nameservers),
                tags=["whois", "nameservers"],
            ))

        dates_found = {}
        for raw_key, value in parsed.items():
            lk = raw_key.lower()
            if "creation date" in lk or "created" in lk:
                dates_found["created"] = value
            elif "expir" in lk or "expiration date" in lk:
                dates_found["expires"] = value
            elif "updated" in lk or "modified" in lk or "last modified" in lk:
                dates_found["updated"] = value
        if dates_found:
            date_str = " | ".join(f"{k}: {v}" for k, v in dates_found.items())
            findings.append(IntelligenceFinding(
                entity=f"Dates: {date_str}",
                type="Whois Domain Dates",
                source="WHOIS",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Timeline",
                raw_data=date_str,
                tags=["whois", "dates", "timeline"],
            ))

        org_details = extract_organization_details(parsed)
        if org_details:
            for org_key, org_val in org_details.items():
                findings.append(IntelligenceFinding(
                    entity=org_val[:200],
                    type=f"Whois Organization Detail",
                    source="WHOIS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Extracted",
                    raw_data=f"{org_key}: {org_val}",
                    tags=["whois", "organization"],
                ))

        admin_tech = extract_admin_tech_contacts(parsed)
        for contact_type, contact_data in admin_tech.items():
            if contact_data:
                for subtype, subvalue in contact_data.items():
                    findings.append(IntelligenceFinding(
                        entity=subvalue[:200],
                        type=f"Whois {contact_type.title()} Contact: {subtype.title()}",
                        source="WHOIS",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        status="Extracted",
                        raw_data=f"{contact_type.title()} {subtype.title()}: {subvalue}",
                        tags=["whois", "contact", contact_type],
                    ))

        value_estimate = estimate_domain_value(parsed)
        findings.append(IntelligenceFinding(
            entity=f"Estimated domain value: {value_estimate['estimated_value']} (score: {value_estimate['score']})",
            type="Whois Domain Value Estimate",
            source="WHOIS",
            confidence="Low",
            color="gold" if value_estimate['score'] >= 30 else "slate",
            threat_level="Informational",
            status="Estimated",
            raw_data=f"Score: {value_estimate['score']}, Factors: {'; '.join(value_estimate['factors'][:5])}",
            tags=["whois", "valuation"],
        ))

        registrar_url = None
        for raw_key, value in parsed.items():
            if "registrar url" in raw_key.lower():
                registrar_url = value
                break
        if registrar_url:
            findings.append(IntelligenceFinding(
                entity=registrar_url[:200],
                type="Whois Registrar URL",
                source="WHOIS",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["whois", "registrar"],
            ))

        registrar_name = None
        for raw_key, value in parsed.items():
            if raw_key.lower() == "registrar":
                registrar_name = value
                break
        if registrar_name:
            findings.append(IntelligenceFinding(
                entity=registrar_name[:200],
                type="Whois Registrar Name",
                source="WHOIS",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["whois", "registrar"],
            ))

        if not findings:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="Whois Raw Data",
                source="WHOIS",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Raw",
                raw_data=best_text[:3000],
                tags=["whois"],
            ))

        findings.append(IntelligenceFinding(
            entity=f"WHOIS analysis complete: {len(parsed)} fields extracted, {len(contacts)} contact fields, {len(statuses)} status codes, {len(nameservers)} nameservers",
            type="Whois Summary",
            source="WHOIS",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            tags=["whois", "summary"],
        ))

    except Exception:
        pass
    return findings
