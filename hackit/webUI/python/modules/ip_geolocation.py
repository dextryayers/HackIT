import httpx
import socket
import asyncio
import re
from models import IntelligenceFinding


async def _resolve_dns(domain: str) -> list:
    ips = []
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
        if ip and ip not in ips:
            ips.append(ip)
    except Exception:
        pass
    try:
        _, _, ip_list = await loop.run_in_executor(
            None, lambda: socket.gethostbyname_ex(domain)
        )
        for ip in ip_list:
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


async def _query_ipapi(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


async def _query_ipapi_co(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


async def _query_freegeoip(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://freegeoip.app/json/{ip}",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


async def _query_ipinfo(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


async def _check_tor_exit(ip: str, client: httpx.AsyncClient) -> bool:
    try:
        resp = await client.get(
            "https://check.torproject.org/exit-addresses",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            return ip in resp.text
    except Exception:
        pass
    return False


async def _check_proxy_vpn(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"proxy": False, "vpn": False, "tor": False, "datacenter": False}
    try:
        resp = await client.get(
            f"https://v2.api.iphub.info/ip/{ip}",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0", "X-Key": "free"},
        )
        if resp.status_code == 200:
            data = resp.json()
            block = data.get("block", 0)
            result["proxy"] = block == 1
            result["vpn"] = block == 1
    except Exception:
        pass
    return result


async def _query_asn_rdap(ip: str, client: httpx.AsyncClient) -> dict:
    info = {}
    try:
        resp = await client.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            entities = data.get("entities", [])
            for entity in entities:
                vcard = entity.get("vcardArray", [[]])
                for item in vcard[1] if len(vcard) > 1 else []:
                    if item[0] == "fn":
                        info["org"] = item[3]
                    if item[0] == "adr":
                        info["country"] = item[3].get("country", "")
        events = data.get("events", [])
        for ev in events:
            if ev.get("eventAction") == "last changed":
                info["last_changed"] = ev.get("eventDate", "")
    except Exception:
        pass
    return info


async def _detect_mobile_carrier(ip: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await client.get(
            f"https://ip-api.com/json/{ip}?fields=mobile,org,isp",
            timeout=5.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("mobile"):
                org = data.get("org", "")
                isp = data.get("isp", "")
                return f"{org} ({isp})" if org else isp
    except Exception:
        pass
    return ""


async def _detect_satellite_isp(org: str) -> bool:
    sat_keywords = [
        "starlink", "spacex", "hughesnet", "hughes network", "vianet",
        "echostar", "ses-americom", "intellisat", "skycasters",
        "satellite internet", "tooway", "ka-sat",
    ]
    org_lower = org.lower() if org else ""
    return any(kw in org_lower for kw in sat_keywords)


def _confidence_score(geo_data: list[dict]) -> int:
    score = 0
    fields_checked = ["city", "country", "region", "isp", "org", "as"]
    for data in geo_data:
        if not data:
            continue
        for field in fields_checked:
            if data.get(field):
                score += 10
        if data.get("status") == "success" or data.get("ip"):
            score += 15
    return min(score, 100)


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    ips = await _resolve_dns(domain)
    if not ips:
        try:
            socket.inet_aton(domain)
            ips = [domain]
        except socket.error:
            return findings

    for ip in ips:
        geo_data = await asyncio.gather(
            _query_ipapi(ip, client),
            _query_ipapi_co(ip, client),
            _query_freegeoip(ip, client),
            _query_ipinfo(ip, client),
            return_exceptions=True,
        )
        geo_sources = [g for g in geo_data if isinstance(g, dict) and g.get("ip") or g.get("status") == "success"]

        merged = {}
        for g in geo_sources:
            merged.update(g)

        if not merged.get("country") and not merged.get("city"):
            continue

        field_map = {
            "city": ("Geo: City", "slate"),
            "regionName": ("Geo: Region", "slate"),
            "country": ("Geo: Country", "slate"),
            "countryCode": ("Geo: Country Code", "slate"),
            "continent": ("Geo: Continent", "slate"),
            "zip": ("Geo: Postal Code", "slate"),
            "timezone": ("Geo: Timezone", "purple"),
            "isp": ("Geo: ISP", "orange"),
            "org": ("Geo: Organization", "orange"),
            "as": ("Geo: AS Number", "orange"),
            "asn": ("Geo: AS Number", "orange"),
            "org": ("Geo: Organization", "orange"),
            "lat": ("Geo: Latitude", "slate"),
            "lon": ("Geo: Longitude", "slate"),
        }

        for field, (ftype, color) in field_map.items():
            val = merged.get(field)
            if val:
                findings.append(IntelligenceFinding(
                    entity=str(val)[:200],
                    type=ftype,
                    source="IP Geolocation",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Live",
                    resolution=ip,
                    raw_data=f"{field}: {val}",
                ))

        lat = merged.get("lat") or merged.get("latitude")
        lon = merged.get("lon") or merged.get("longitude")
        if lat and lon:
            findings.append(IntelligenceFinding(
                entity=f"{lat}, {lon}",
                type="Geo: Coordinates",
                source="IP Geolocation",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Live",
                resolution=ip,
                raw_data=f"https://www.google.com/maps?q={lat},{lon}",
            ))

        extra_checks = await asyncio.gather(
            _check_tor_exit(ip, client),
            _check_proxy_vpn(ip, client),
            _query_asn_rdap(ip, client),
            _detect_mobile_carrier(ip, client),
            return_exceptions=True,
        )

        is_tor = extra_checks[0] if isinstance(extra_checks[0], bool) else False
        proxy_info = extra_checks[1] if isinstance(extra_checks[1], dict) else {}
        rdap_info = extra_checks[2] if isinstance(extra_checks[2], dict) else {}
        mobile_carrier = extra_checks[3] if isinstance(extra_checks[3], str) else ""

        if is_tor:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="TOR Exit Node Detected",
                source="IP Geolocation",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Live",
                resolution=ip,
                tags=["tor", "anonymizer"],
            ))

        if proxy_info.get("proxy") or proxy_info.get("vpn"):
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Proxy/VPN Detected",
                source="IP Geolocation",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                status="Live",
                resolution=ip,
                tags=["proxy", "vpn"],
            ))

        org = merged.get("org", "")
        if org and await _detect_satellite_isp(org):
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Satellite ISP Detected",
                source="IP Geolocation",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
                status="Live",
                resolution=ip,
                tags=["satellite", "isp"],
                raw_data=f"Satellite ISP: {org}",
            ))

        if mobile_carrier:
            findings.append(IntelligenceFinding(
                entity=f"{ip} ({mobile_carrier})",
                type="Mobile Network / Carrier",
                source="IP Geolocation",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Live",
                resolution=ip,
                tags=["mobile", "carrier"],
                raw_data=f"Mobile carrier: {mobile_carrier}",
            ))

        if merged.get("hosting") or merged.get("datacenter"):
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Hosting/Datacenter",
                source="IP Geolocation",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Live",
                resolution=ip,
                tags=["hosting", "datacenter"],
                raw_data=f"Hosted by: {org or 'Unknown'}",
            ))

        if rdap_info:
            rdap_org = rdap_info.get("org", "")
            rdap_country = rdap_info.get("country", "")
            if rdap_org:
                findings.append(IntelligenceFinding(
                    entity=rdap_org,
                    type="RDAP: Organization",
                    source="IP Geolocation",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    status="Live",
                    resolution=ip,
                    tags=["rdap"],
                ))
            if rdap_info.get("last_changed"):
                findings.append(IntelligenceFinding(
                    entity=rdap_info["last_changed"],
                    type="RDAP: Last Changed",
                    source="IP Geolocation",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Live",
                    resolution=ip,
                    tags=["rdap"],
                ))

        confidence = _confidence_score(geo_sources)
        findings.append(IntelligenceFinding(
            entity=f"Confidence: {confidence}% ({len(geo_sources)} geo sources)",
            type="Geo: Confidence Score",
            source="IP Geolocation",
            confidence="High" if confidence >= 70 else "Medium",
            color="emerald" if confidence >= 70 else "orange",
            threat_level="Informational",
            status="Live",
            resolution=ip,
        ))

    if len(ips) > 1:
        findings.append(IntelligenceFinding(
            entity=f"{len(ips)} IP addresses resolved: {', '.join(ips[:5])}",
            type="Multi-IP Resolution",
            source="IP Geolocation",
            confidence="High",
            color="purple",
            threat_level="Informational",
            tags=["multi-ip", "dns"],
            raw_data=f"IPs: {', '.join(ips)}",
        ))

    return findings
