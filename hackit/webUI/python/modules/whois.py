import httpx
import re
import json
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

RDAP_BOOTSTRAP_URLS = [
    "https://rdap.verisign.com/com/v1/domain/{domain}",
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
    "DNSSEC": "Whois DNSSEC",
    "Zone Email": "Whois Zone Email",
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
    return abuse

def extract_iana_info(parsed: dict) -> str | None:
    for raw_key, value in parsed.items():
        if "iana" in raw_key.lower() or "iana" in value.lower():
            m = IANA_ORG_PATTERN.search(value)
            if m:
                return m.group(1)
    return None


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
            entity=f"WHOIS analysis complete: {len(parsed)} fields extracted, {len(contacts)} contact fields, {len(statuses)} status codes",
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
