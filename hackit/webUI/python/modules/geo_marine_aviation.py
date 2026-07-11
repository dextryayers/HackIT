import re
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

MARITIME_PLATFORMS = {
    "MarineTraffic": ["marinetraffic.com", "marinetraffic"],
    "VesselFinder": ["vesselfinder.com", "vesselfinder"],
    "FleetMon": ["fleetmon.com", "fleetmon"],
    "ShipSpotting": ["shipspotting.com"],
    "AIS Hub": ["aishub.net", "aishub"],
    "VTS": ["vts.", "vessel-tracking"],
    "Port Optimizer": ["portoptimizer"],
    "Port Community System": ["portcommunity", "port"],
    "Shipping Line (Maersk)": ["maersk.com", "maersk"],
    "Shipping Line (MSC)": ["msc.com", "msc"],
    "Shipping Line (CMA CGM)": ["cma-cgm.com", "cma-cgm"],
    "Shipping Line (COSCO)": ["cosco.com", "cosco"],
    "Shipping Line (Hapag-Lloyd)": ["hapa.ag", "hapaag", "hapag-lloyd"],
    "Shipping Line (ONE)": ["one-line.com", "one-line"],
    "Shipping Line (Evergreen)": ["evergreen-marine.com", "evergreen"],
    "Shoreside (Port Authority)": ["portauthority", "port"],
    "Port Infrastructure": ["port.org", "port.com"],
}

AVIATION_PLATFORMS = {
    "FlightRadar24": ["flightradar24.com", "flightradar24"],
    "FlightAware": ["flightaware.com", "flightaware"],
    "FlightStats": ["flightstats.com", "flightstats"],
    "Airline (American)": ["aa.com", "americanairlines"],
    "Airline (Delta)": ["delta.com", "delta"],
    "Airline (United)": ["united.com", "united"],
    "Airline (Emirates)": ["emirates.com", "emirates"],
    "Airline (Qatar)": ["qatarairways.com", "qatarairways"],
    "Airline (Singapore)": ["singaporeair.com", "singaporeair"],
    "Airline (Lufthansa)": ["lufthansa.com", "lufthansa"],
    "Airline (British Airways)": ["britishairways.com", "britishairways"],
    "Airport (JFK)": ["jfkairport.com", "jfk"],
    "Airport (LHR)": ["heathrow.com", "heathrow", "lhr"],
    "Airport (DXB)": ["dubaiairports.com", "dxb"],
    "ADS-B Exchange": ["adsbexchange.com", "adsbexchange"],
    "OpenSky Network": ["opensky-network.org", "opensky"],
    "Aviation Weather": ["aviationweather.gov"],
    "NOTAM": ["notam", "notams"],
}

SATCOM_PROVIDERS = {
    "Inmarsat": ["inmarsat.com", "inmarsat"],
    "Iridium": ["iridium.com", "iridium"],
    "VSAT": ["vsat", "iDirect", "comtech", "gilat"],
    "KVH": ["kvh.com", "kvh"],
    "Cobham SATCOM": ["cobham.com", "cobham"],
    "Thuraya": ["thuraya.com", "thuraya"],
    "Viasat (Maritime)": ["viasat.com", "viasat"],
    "Speedcast": ["speedcast.com", "speedcast"],
    "OmniAccess": ["omniaccess.com", "omniaccess"],
}

AVIATION_DNS_PATTERNS = [
    "air", "fly", "flight", "airport", "airline", "aviation", "jet", "plane",
    "aero", "airways", "airbus", "boeing", "atc", "radar", "tower",
    "terminal", "runway", "hangar", "taxiway", "gate",
]

MARITIME_DNS_PATTERNS = [
    "ship", "vessel", "marine", "maritime", "port", "harbor", "dock", "terminal",
    "shipping", "cargo", "container", "tanker", "ferry", "cruise", "boat",
    "fleet", "navy", "seaport", "anchor", "buoy", "ais", "navigation",
]

async def _resolve_target(target: str) -> tuple:
    if is_ip(target):
        return target, True
    try:
        ip = resolve_ip(target)
        if ip:
            return ip, False
        return None, "Resolution failed"
    except Exception as e:
        return None, str(e)

async def _check_marine_aviation(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "").lower()
            for name, pats in MARITIME_PLATFORMS.items():
                for p in pats:
                    if p in org:
                        findings.append(make_finding(
                            entity=name,
                            ftype="Maritime Platform",
                            source="MarineAviationScanner",
                            confidence="High",
                            color="blue",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"Maritime platform: {name} matched via org '{org[:80]}'",
                            tags=["maritime", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                        ))
                        break
            for name, pats in AVIATION_PLATFORMS.items():
                for p in pats:
                    if p in org:
                        findings.append(make_finding(
                            entity=name,
                            ftype="Aviation Platform",
                            source="MarineAviationScanner",
                            confidence="High",
                            color="blue",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"Aviation platform: {name} matched via org '{org[:80]}'",
                            tags=["aviation", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                        ))
                        break
            for name, pats in SATCOM_PROVIDERS.items():
                for p in pats:
                    if p in org:
                        findings.append(make_finding(
                            entity=name,
                            ftype="SATCOM Provider",
                            source="MarineAviationScanner",
                            confidence="High",
                            color="purple",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"SATCOM provider: {name} matched via org '{org[:80]}'",
                            tags=["satcom", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                        ))
                        break
    except Exception:
        pass
    return findings

async def _check_rdns_aviation_marine(target: str) -> list:
    findings = []
    try:
        ptr = socket.gethostbyaddr(target)
        ptr_name = ptr[0].lower()
        for pat in AVIATION_DNS_PATTERNS:
            if pat in ptr_name:
                findings.append(make_finding(
                    entity=f"Aviation rDNS: {ptr_name}",
                    ftype="Aviation DNS Indicator",
                    source="MarineAviationScanner",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Detected",
                    resolution=target,
                    raw_data=f"Aviation-related rDNS pattern '{pat}' in {ptr_name}",
                    tags=["aviation", "rdns"]
                ))
                break
        for pat in MARITIME_DNS_PATTERNS:
            if pat in ptr_name:
                findings.append(make_finding(
                    entity=f"Maritime rDNS: {ptr_name}",
                    ftype="Maritime DNS Indicator",
                    source="MarineAviationScanner",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Detected",
                    resolution=target,
                    raw_data=f"Maritime-related rDNS pattern '{pat}' in {ptr_name}",
                    tags=["maritime", "rdns"]
                ))
                break
    except Exception:
        pass
    return findings

async def _list_all_platforms() -> list:
    findings = []
    for name, pats in MARITIME_PLATFORMS.items():
        findings.append(make_finding(
            entity=name,
            type="Maritime Platform Reference",
            source="MarineAviationScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"Maritime platform: {name}. Patterns: {', '.join(pats)}",
            tags=["maritime", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
        ))
    for name, pats in AVIATION_PLATFORMS.items():
        findings.append(make_finding(
            entity=name,
            type="Aviation Platform Reference",
            source="MarineAviationScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"Aviation platform: {name}. Patterns: {', '.join(pats)}",
            tags=["aviation", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
        ))
    for name, pats in SATCOM_PROVIDERS.items():
        findings.append(make_finding(
            entity=name,
            type="SATCOM Provider Reference",
            source="MarineAviationScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"SATCOM provider: {name}. Patterns: {', '.join(pats)}",
            tags=["satcom", name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="MarineAviationScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="MarineAviationScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_marine_aviation(ip, client))
    findings.extend(await _check_rdns_aviation_marine(ip))
    findings.extend(await _list_all_platforms())

    maritime_count = sum(1 for f in findings if "Maritime" in f.type)
    aviation_count = sum(1 for f in findings if "Aviation" in f.type)
    satcom_count = sum(1 for f in findings if "SATCOM" in f.type)

    findings.append(make_finding(entity=f"Maritime platforms: {maritime_count}", type="Maritime Count", source="MarineAviationScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["maritime", "summary"]))
    findings.append(make_finding(entity=f"Aviation platforms: {aviation_count}", type="Aviation Count", source="MarineAviationScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["aviation", "summary"]))
    findings.append(make_finding(entity=f"SATCOM providers: {satcom_count}", type="SATCOM Count", source="MarineAviationScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["satcom", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="Marine/Aviation Target", source="MarineAviationScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["maritime", "aviation", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="Marine/Aviation IP", source="MarineAviationScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["maritime", "aviation", "ip"]))
    findings.append(make_finding(entity=f"Total marine/aviation findings: {len(findings)}", type="Marine/Aviation Summary", source="MarineAviationScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["maritime", "aviation", "summary"]))

    return findings
