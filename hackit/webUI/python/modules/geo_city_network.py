import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

ISP_URLS = [
    "https://ipinfo.io/{}/json",
    "https://ipapi.co/{}/json/",
    "https://isps.ooni.io/",
]

KNOWN_IXPS = {
    "AMS-IX": {"city": "Amsterdam", "country": "NL", "desc": "Amsterdam Internet Exchange (largest IXP in the world)"},
    "DE-CIX": {"city": "Frankfurt", "country": "DE", "desc": "German Commercial Internet Exchange"},
    "LINX": {"city": "London", "country": "GB", "desc": "London Internet Exchange"},
    "Equinix IX": {"city": "Multiple", "country": "Global", "desc": "Equinix Internet Exchange (global)"},
    "NYIIX": {"city": "New York", "country": "US", "desc": "New York International Internet Exchange"},
    "Any2": {"city": "San Jose", "country": "US", "desc": "Any2 Exchange (California)"},
    "DETRIX": {"city": "Detroit", "country": "US", "desc": "Detroit Internet Exchange"},
    "JPNAP": {"city": "Tokyo", "country": "JP", "desc": "Japan Network Access Point"},
    "HKIX": {"city": "Hong Kong", "country": "HK", "desc": "Hong Kong Internet Exchange"},
    "SGIX": {"city": "Singapore", "country": "SG", "desc": "Singapore Internet Exchange"},
    "INX-ZA": {"city": "Johannesburg", "country": "ZA", "desc": "Internet Exchange South Africa"},
    "IX.br": {"city": "Sao Paulo", "country": "BR", "desc": "Brazil Internet Exchange"},
    "Moscow IX": {"city": "Moscow", "country": "RU", "desc": "Moscow Internet Exchange"},
    "Netnod": {"city": "Stockholm", "country": "SE", "desc": "Netnod Internet Exchange (Nordics)"},
    "DIX-IE": {"city": "Dublin", "country": "IE", "desc": "Dublin Internet Exchange"},
    "MIX": {"city": "Milan", "country": "IT", "desc": "Milan Internet Exchange"},
    "EcuIX": {"city": "Quito", "country": "EC", "desc": "Ecuador Internet Exchange"},
    "LACNIC IX": {"city": "Montevideo", "country": "UY", "desc": "LACNIC region IXP"},
    "BCIX": {"city": "Berlin", "country": "DE", "desc": "Berlin Commercial Internet Exchange"},
    "VIX": {"city": "Vienna", "country": "AT", "desc": "Vienna Internet Exchange"},
    "TPIX": {"city": "Tokyo", "country": "JP", "desc": "Tokyo Peering Internet Exchange"},
    "MSK-IX": {"city": "Moscow", "country": "RU", "desc": "Moscow IX (largest in CIS region)"},
    "DATAIX": {"city": "Bratislava", "country": "SK", "desc": "Data Internet Exchange (Slovakia)"},
    "CATNIX": {"city": "Barcelona", "country": "ES", "desc": "Catalan Internet Exchange"},
    "ESPANIX": {"city": "Madrid", "country": "ES", "desc": "Spanish Internet Exchange"},
    "FRANCE-IX": {"city": "Paris", "country": "FR", "desc": "France Internet Exchange (Paris)"},
    "LONAP": {"city": "London", "country": "GB", "desc": "London Access Point"},
    "MANAP": {"city": "Manchester", "country": "GB", "desc": "Manchester Network Access Point"},
    "KIXP": {"city": "Nairobi", "country": "KE", "desc": "Kenya Internet Exchange Point"},
    "MYIX": {"city": "Kuala Lumpur", "country": "MY", "desc": "Malaysia Internet Exchange"},
}

LAST_MILE_TYPES = [
    ("DSL", "ADSL/VDSL over telephone copper lines"),
    ("Cable", "Cable modem over coax TV networks"),
    ("Fiber (FTTH)", "Fiber-to-the-home (GPON, EPON)"),
    ("Fiber (FTTB)", "Fiber-to-the-building"),
    ("FWA (4G/5G)", "Fixed wireless access via cellular"),
    ("Satellite", "Starlink, HughesNet, Viasat"),
    ("Satellite (GEO)", "Traditional GEO satellite internet"),
    ("Satellite (LEO)", "LEO constellation (Starlink, OneWeb)"),
    ("Microwave", "Point-to-point wireless backhaul"),
    ("Ethernet (Metro)", "Metro Ethernet / Carrier Ethernet"),
    ("Copper (EoSDH)", "Ethernet over SDH copper"),
    ("Mobile (LTE/5G)", "Mobile broadband (hotspot/tethering)"),
    ("WiFi (ISP)", "Wireless ISP (WISP) fixed wireless"),
    ("Powerline", "BPL - Broadband over Power Lines"),
]

PEERING_POINTS = {
    "ashburn": {"city": "Ashburn, VA", "desc": "Major peering hub (Equinix DC, CoreSite)"},
    "frankfurt": {"city": "Frankfurt", "desc": "DE-CIX, main European peering hub"},
    "london": {"city": "London", "desc": "LINX, Telehouse, major transatlantic hub"},
    "amsterdam": {"city": "Amsterdam", "desc": "AMS-IX, NL-ix, dense peering fabric"},
    "tokyo": {"city": "Tokyo", "desc": "JPNAP, TPIX, major Asian peering hub"},
    "sanjose": {"city": "San Jose, CA", "desc": "Any2, Equinix SV1, west coast hub"},
    "dallas": {"city": "Dallas, TX", "desc": "Major US peering hub, Equinix DA"},
    "chicago": {"city": "Chicago, IL", "desc": "Major US peering hub (Equinix CH)"},
    "miami": {"city": "Miami, FL", "desc": "Major LATAM peering hub (NAP of the Americas)"},
    "paris": {"city": "Paris", "desc": "France-IX, major continental peering"},
    "stockholm": {"city": "Stockholm", "desc": "Netnod, Nordic peering hub"},
    "hongkong": {"city": "Hong Kong", "desc": "HKIX, major APAC peering hub"},
    "singapore": {"city": "Singapore", "desc": "SGIX, Equinix SG, ASEAN hub"},
    "sydney": {"city": "Sydney", "desc": "IX Australia, major Oceania peering"},
    "saopaulo": {"city": "Sao Paulo", "desc": "IX.br, major LATAM peering hub"},
}

async def _resolve_target(target: str) -> tuple:
    try:
        socket.inet_aton(target)
        return target, True
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, False
    except Exception as e:
        return None, str(e)

async def _get_city_isp_info(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            city = data.get("city", "")
            region = data.get("region", "")
            country = data.get("country", "")
            org = data.get("org", "")
            loc = data.get("loc", "")

            if city:
                findings.append(IntelligenceFinding(
                    entity=f"City: {city}",
                    type="City Network Location",
                    source="CityNetworkScanner",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Located",
                    resolution=ip,
                    raw_data=f"City: {city}, Region: {region}, Country: {country}",
                    tags=["geo", "city", city.lower().replace(" ", "-")]
                ))
            if org:
                findings.append(IntelligenceFinding(
                    entity=f"Local ISP: {org}",
                    type="ISP in City Region",
                    source="CityNetworkScanner",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"Organization/ISP serving this city region: {org}",
                    tags=["geo", "isp", "network"]
                ))
            if loc:
                lat_lon = loc.split(",")
                if len(lat_lon) == 2:
                    findings.append(IntelligenceFinding(
                        entity=f"Region center: {loc}",
                        type="City Coordinates",
                        source="CityNetworkScanner",
                        confidence="High",
                        color="slate",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Locatable",
                        resolution=ip,
                        raw_data=f"Lat/Lon: {loc}",
                        tags=["geo", "coordinates"]
                    ))
    except Exception:
        pass
    return findings

async def _map_city_ixps(city: str, client: httpx.AsyncClient) -> list:
    findings = []
    city_lower = city.lower()
    for ixp_name, ixp_info in KNOWN_IXPS.items():
        if ixp_info["city"].lower() in city_lower or city_lower in ixp_info["city"].lower():
            findings.append(IntelligenceFinding(
                entity=f"{ixp_name} - {ixp_info['city']}, {ixp_info['country']}",
                type="IXP Near Target City",
                source="CityNetworkScanner",
                confidence="High",
                color="purple",
                category="Geo / Network OSINT",
                threat_level="Informational",
                status="Identified",
                raw_data=f"Internet Exchange: {ixp_name} in {ixp_info['city']}, {ixp_info['country']}. {ixp_info['desc']}",
                tags=["geo", "ixp", ixp_name.lower().replace(" ", "-")]
            ))
    for pp_name, pp_info in PEERING_POINTS.items():
        if pp_info["city"].lower() in city_lower:
            findings.append(IntelligenceFinding(
                entity=f"Peering Point: {pp_info['city']}",
                type="City Peering Point",
                source="CityNetworkScanner",
                confidence="Medium",
                color="purple",
                category="Geo / Network OSINT",
                threat_level="Informational",
                status="Mapped",
                raw_data=f"Major peering hub: {pp_info['city']}. {pp_info['desc']}",
                tags=["geo", "peering", pp_name]
            ))
    return findings

async def _list_city_ixps_global(city_hint: str) -> list:
    findings = []
    for ixp_name, ixp_info in KNOWN_IXPS.items():
        findings.append(IntelligenceFinding(
            entity=f"{ixp_name} - {ixp_info['city']}, {ixp_info['country']}",
            type="IXP Reference",
            source="CityNetworkScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"{ixp_name}: {ixp_info['desc']}",
            tags=["geo", "ixp", ixp_name.lower().replace(" ", "-")]
        ))
    for pp_name, pp_info in PEERING_POINTS.items():
        findings.append(IntelligenceFinding(
            entity=f"Peering Hub: {pp_info['city']}",
            type="Global Peering Hub Reference",
            source="CityNetworkScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"{pp_info['city']}: {pp_info['desc']}",
            tags=["geo", "peering", pp_name]
        ))
    return findings

async def _analyze_last_mile(ip: str) -> list:
    findings = []
    for lm_name, lm_desc in LAST_MILE_TYPES:
        findings.append(IntelligenceFinding(
            entity=f"Last Mile: {lm_name}",
            type="Last Mile Infrastructure",
            source="CityNetworkScanner",
            confidence="Low",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Possible",
            raw_data=f"Possible last mile connectivity: {lm_name} - {lm_desc}",
            tags=["geo", "last-mile", lm_name.lower().replace(" ", "-").replace("/", "-").replace("(", "").replace(")", "")]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="CityNetworkScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="CityNetworkScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    city_info = await _get_city_isp_info(ip, client)
    findings.extend(city_info)

    city_name = ""
    for f in findings:
        if f.type == "City Network Location":
            city_name = f.entity.replace("City: ", "")
            break

    findings.extend(await _map_city_ixps(city_name, client))
    findings.extend(await _analyze_last_mile(ip))
    findings.extend(await _list_city_ixps_global(city_name))

    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="City Network Target", source="CityNetworkScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["geo", "target"]))
    findings.append(IntelligenceFinding(entity=f"Total city network findings: {len(findings)}", type="City Network Summary", source="CityNetworkScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["geo", "summary"]))

    return findings
