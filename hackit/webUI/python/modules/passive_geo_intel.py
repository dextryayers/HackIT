import re
import json
from urllib.parse import urlparse
from ..module_common import safe_fetch, make_finding, resolve_ip

ASN_ORG_PATTERNS = {
    "amazon": "Amazon Web Services", "aws": "Amazon Web Services",
    "google": "Google Cloud", "gcp": "Google Cloud",
    "azure": "Microsoft Azure", "microsoft": "Microsoft",
    "cloudflare": "Cloudflare", "digitalocean": "DigitalOcean",
    "linode": "Linode", "vultr": "Vultr", "ovh": "OVH",
    "hetzner": "Hetzner", "scaleway": "Scaleway",
    "oracle": "Oracle Cloud", "ibm": "IBM Cloud",
    "alibaba": "Alibaba Cloud", "tencent": "Tencent Cloud",
    "softlayer": "IBM Cloud", "rackspace": "Rackspace",
}

COUNTRY_RISK = {
    "CN": "Elevated Risk", "RU": "Elevated Risk", "KP": "High Risk",
    "IR": "Elevated Risk", "SY": "High Risk", "CU": "Elevated Risk",
    "SD": "Elevated Risk", "VE": "Standard Target", "IQ": "Elevated Risk",
    "AF": "High Risk", "YE": "High Risk", "LY": "High Risk",
    "MM": "Elevated Risk", "BY": "Elevated Risk",
}

TLD_GEO_HINTS = {
    "us": "United States", "uk": "United Kingdom", "de": "Germany",
    "fr": "France", "jp": "Japan", "cn": "China", "ru": "Russia",
    "br": "Brazil", "in": "India", "au": "Australia", "ca": "Canada",
    "nl": "Netherlands", "se": "Sweden", "no": "Norway", "fi": "Finland",
    "dk": "Denmark", "ch": "Switzerland", "sg": "Singapore",
    "hk": "Hong Kong", "kr": "South Korea", "it": "Italy", "es": "Spain",
    "eu": "European Union", "ie": "Ireland", "nz": "New Zealand",
    "za": "South Africa", "mx": "Mexico", "ar": "Argentina",
    "cl": "Chile", "co": "Colombia", "pe": "Peru",
    "ae": "United Arab Emirates", "sa": "Saudi Arabia",
    "il": "Israel", "tr": "Turkey", "th": "Thailand",
    "vn": "Vietnam", "ph": "Philippines", "my": "Malaysia",
    "id": "Indonesia", "tw": "Taiwan", "pk": "Pakistan",
    "bd": "Bangladesh", "eg": "Egypt", "ng": "Nigeria",
    "ke": "Kenya", "ma": "Morocco",
}

LANGUAGE_TLD_MAP = {
    "de": "German", "fr": "French", "jp": "Japanese", "cn": "Chinese",
    "ru": "Russian", "br": "Portuguese", "in": "Hindi/English",
    "nl": "Dutch", "se": "Swedish", "it": "Italian", "es": "Spanish",
    "pl": "Polish", "tr": "Turkish", "kr": "Korean", "tw": "Chinese (Traditional)",
    "hk": "Chinese (Cantonese)", "ar": "Spanish", "cl": "Spanish",
    "mx": "Spanish", "co": "Spanish", "pe": "Spanish",
    "pt": "Portuguese", "cz": "Czech", "hu": "Hungarian",
    "ro": "Romanian", "vn": "Vietnamese", "th": "Thai",
    "il": "Hebrew", "sa": "Arabic", "ae": "Arabic", "eg": "Arabic",
}

async def _fetch_ip_geo(ip: str, client: AsyncClient) -> dict | None:
    try:
        resp = await safe_fetch(client, f"https://ipapi.co/{ip}/json/", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    try:
        resp = await safe_fetch(client, f"http://ip-api.com/json/{ip}", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

async def _fetch_rdap_ip(ip: str, client: AsyncClient) -> dict | None:
    try:
        resp = await safe_fetch(client, f"https://rdap.arin.net/registry/ip/{ip}", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    try:
        resp = await safe_fetch(client, f"https://rdap.db.ripe.net/ip/{ip}", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

async def _ip_geo_intel(domain: str, client: AsyncClient) -> list:
    findings = []
    ip = resolve_ip(domain)
    if not ip:
        return findings
    findings.append(make_finding(
        entity=ip,
        ftype="IP Geolocation - Resolved IP",
        source="Passive Geo Intel",
        confidence="High",
        color="blue",
        status="Resolved",
        tags=["geo", "ip", "resolution"]
    ))
    geo = await _fetch_ip_geo(ip, client)
    if geo:
        city = geo.get("city", geo.get("city", ""))
        region = geo.get("region", geo.get("regionName", ""))
        country = geo.get("country_name", geo.get("country", ""))
        country_code = geo.get("country_code", geo.get("countryCode", ""))
        org = geo.get("org", geo.get("org", geo.get("isp", "")))
        asn = geo.get("asn", geo.get("as", ""))
        lat = geo.get("latitude", geo.get("lat", ""))
        lon = geo.get("longitude", geo.get("lon", ""))
        timezone = geo.get("timezone", "")
        if country:
            risk = COUNTRY_RISK.get(country_code.upper(), "Informational")
            findings.append(make_finding(
                entity=country,
                ftype="IP Geolocation - Country",
                source="Passive Geo Intel",
                confidence="High",
                color="red" if risk != "Informational" else "slate",
                threat_level=risk,
                status=f"Located in {country}",
                resolution=f"Risk: {risk}",
                raw_data=f"Country: {country} ({country_code}), Risk: {risk}",
                tags=["geo", "country", country_code.lower()]
            ))
        if city:
            location_parts = []
            if city:
                location_parts.append(city)
            if region:
                location_parts.append(region)
            if country:
                location_parts.append(country)
            findings.append(make_finding(
                entity=", ".join(location_parts),
                ftype="IP Geolocation - City/Region",
                source="Passive Geo Intel",
                confidence="High",
                color="slate",
                status="Geolocated",
                raw_data=f"City: {city}, Region: {region}, Country: {country}",
                tags=["geo", "location"]
            ))
        if org:
            findings.append(make_finding(
                entity=org[:200],
                ftype="IP Geolocation - ISP/Organization",
                source="Passive Geo Intel",
                confidence="High",
                color="slate",
                status="Identified",
                raw_data=f"Organization: {org}",
                tags=["geo", "isp", "organization"]
            ))
            for key, label in ASN_ORG_PATTERNS.items():
                if key in org.lower():
                    findings.append(make_finding(
                        entity=label,
                        ftype="IP Geolocation - Cloud Provider",
                        source="Passive Geo Intel",
                        confidence="High",
                        color="orange",
                        status="Cloud Hosted",
                        raw_data=f"Cloud provider: {label} (matched '{key}' in '{org}')",
                        tags=["geo", "cloud", key]
                    ))
                    break
        if asn:
            findings.append(make_finding(
                entity=str(asn)[:100],
                ftype="IP Geolocation - ASN",
                source="Passive Geo Intel",
                confidence="High",
                color="slate",
                status="Identified",
                raw_data=f"ASN: {asn}",
                tags=["geo", "asn"]
            ))
        if lat and lon:
            findings.append(make_finding(
                entity=f"Lat: {lat}, Lon: {lon}",
                ftype="IP Geolocation - Coordinates",
                source="Passive Geo Intel",
                confidence="High",
                color="slate",
                status="Coordinates",
                raw_data=f"Latitude: {lat}, Longitude: {lon}",
                tags=["geo", "coordinates"]
            ))
        if timezone:
            findings.append(make_finding(
                entity=timezone,
                ftype="IP Geolocation - Timezone",
                source="Passive Geo Intel",
                confidence="High",
                color="slate",
                status="Identified",
                tags=["geo", "timezone"]
            ))
    rdap = await _fetch_rdap_ip(ip, client)
    if rdap:
        rdap_entities = []
        if isinstance(rdap, dict):
            for entity in rdap.get("entities", []):
                if isinstance(entity, dict):
                    vcard = entity.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 3:
                                field = item[0]
                                val = item[3]
                                if field == "fn":
                                    rdap_entities.append(str(val))
                                    break
        if rdap_entities:
            for ent in rdap_entities[:3]:
                findings.append(make_finding(
                    entity=ent[:200],
                    ftype="IP Geolocation - RDAP Entity",
                    source="Passive Geo Intel",
                    confidence="High",
                    color="slate",
                    status="RDAP Record",
                    tags=["geo", "rdap"]
                ))
    return findings

async def _tld_geo_analysis(domain: str) -> list:
    findings = []
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in TLD_GEO_HINTS:
        country_hint = TLD_GEO_HINTS[tld]
        findings.append(make_finding(
            entity=f"TLD '.{tld}' suggests {country_hint}",
            ftype="IP Geolocation - TLD Geographic Hint",
            source="Passive Geo Intel",
            confidence="Medium",
            color="slate",
            status="TLD Hint",
            raw_data=f"TLD .{tld} is associated with {country_hint}",
            tags=["geo", "tld", tld]
        ))
    if tld in LANGUAGE_TLD_MAP:
        lang_hint = LANGUAGE_TLD_MAP[tld]
        findings.append(make_finding(
            entity=f"TLD '.{tld}' suggests language: {lang_hint}",
            ftype="IP Geolocation - Language Hint",
            source="Passive Geo Intel",
            confidence="Low",
            color="slate",
            status="Language Hint",
            tags=["geo", "language", tld]
        ))
    return findings

async def _whois_geo_analysis(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://api.hackertarget.com/whois/?q={domain}", timeout=12.0)
        if resp.status_code == 200:
            text = resp.text
            country_match = re.search(r'Registrant\s*Country:\s*(\w+)', text, re.I)
            if country_match:
                cc = country_match.group(1).upper()
                country_full = TLD_GEO_HINTS.get(cc.lower(), cc)
                risk = COUNTRY_RISK.get(cc, "Informational")
                findings.append(make_finding(
                    entity=f"Registrant country: {country_full} ({cc})",
                    ftype="IP Geolocation - WHOIS Country",
                    source="Passive Geo Intel",
                    confidence="High",
                    color="red" if risk != "Informational" else "slate",
                    threat_level=risk,
                    status="WHOIS Geo",
                    raw_data=f"Registrant Country: {cc} - {country_full}",
                    tags=["geo", "whois", cc.lower()]
                ))
            state_match = re.search(r'Registrant\s*State/Province:\s*(.+)', text, re.I)
            if state_match:
                state_val = state_match.group(1).strip()
                findings.append(make_finding(
                    entity=state_val[:200],
                    ftype="IP Geolocation - WHOIS State/Province",
                    source="Passive Geo Intel",
                    confidence="High",
                    color="slate",
                    status="WHOIS Geo",
                    tags=["geo", "whois", "state"]
                ))
            city_match = re.search(r'Registrant\s*City:\s*(.+)', text, re.I)
            if city_match:
                city_val = city_match.group(1).strip()
                findings.append(make_finding(
                    entity=city_val[:200],
                    ftype="IP Geolocation - WHOIS City",
                    source="Passive Geo Intel",
                    confidence="High",
                    color="slate",
                    status="WHOIS Geo",
                    tags=["geo", "whois", "city"]
                ))
    except Exception:
        pass
    return findings

async def _ssl_geo_analysis(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        crt_resp = await safe_fetch(client, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15.0)
        if crt_resp.status_code == 200:
            certs = crt_resp.json() if isinstance(crt_resp.text, str) and crt_resp.text.startswith("[") else []
            countries_found = set()
            for cert in certs[:100]:
                issuer = str(cert.get("issuer_name", ""))
                country_m = re.search(r'C\s*=\s*(\w+)', issuer)
                if country_m:
                    countries_found.add(country_m.group(1).upper())
            for cc in countries_found:
                country_full = TLD_GEO_HINTS.get(cc.lower(), cc)
                findings.append(make_finding(
                    entity=f"SSL Certificate issuer country: {country_full} ({cc})",
                    ftype="IP Geolocation - SSL Issuer Country",
                    source="Passive Geo Intel",
                    confidence="Medium",
                    color="slate",
                    status="SSL Geo Hint",
                    tags=["geo", "ssl", cc.lower()]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    ip_findings = await _ip_geo_intel(domain, client)
    findings.extend(ip_findings)

    tld_findings = await _tld_geo_analysis(domain)
    findings.extend(tld_findings)

    whois_findings = await _whois_geo_analysis(domain, client)
    findings.extend(whois_findings)

    ssl_findings = await _ssl_geo_analysis(domain, client)
    findings.extend(ssl_findings)

    if findings:
        findings.append(make_finding(
            entity=f"IP Geolocation Intelligence complete: {len(findings)} findings",
            ftype="IP Geolocation - Summary",
            source="Passive Geo Intel",
            confidence="High", color="purple",
            status="Complete",
            tags=["geo", "summary"]
        ))

    return findings
