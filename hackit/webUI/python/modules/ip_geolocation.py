import asyncio
import socket
from datetime import datetime
from typing import List, Optional
from module_common import safe_fetch, make_finding, is_ip, resolve_ip

GEO_SOURCES = {
    "ip-api": "http://ip-api.com/json/{}",
    "ipinfo": "https://ipinfo.io/{}/json",
    "ipapi": "https://ipapi.co/{}/json/",
    "ipvigilante": "https://ipvigilante.com/json/{}",
    "extreme-ip": "https://extreme-ip-lookup.com/json/{}",
    "ip2location": "https://api.ip2location.com/v2/?ip={}&format=json",
    "abstractapi": "https://ipgeolocation.abstractapi.com/v1/?ip_address={}",
    "ipdata": "https://api.ipdata.co/{}/",
    "ipgeolocation": "https://api.ipgeolocation.io/ipgeo?ip={}",
    "ipapi.is": "https://api.ipapi.is/?q={}",
}

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def query_source(ip: str, name: str, url_tmpl: str, client) -> Optional[dict]:
    try:
        url = url_tmpl.format(ip)
        resp = await safe_fetch(client, url, timeout=10.0,
            headers={"User-Agent": UA, "Accept": "application/json"})
        if resp and resp.status_code == 200:
            return {"source": name, "data": resp.json()}
    except:
        pass
    return None

async def rdap_lookup(ip: str, client) -> Optional[dict]:
    try:
        resp = await safe_fetch(client, f"https://rdap.arin.net/registry/ip/{ip}", timeout=10.0,
            headers={"Accept": "application/json"})
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def network_boundary(ip: str) -> str:
    try:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.0.0/16"
    except:
        return ""

ADDITIONAL_GEO_SOURCES = {
    "country.is": "https://api.country.is/{}",
    "ip2c": "https://ip2c.org/{}",
    "ipapi.com": "http://api.ipapi.com/api/{}",
}

EXTRA_GEO_SOURCES = {
    "ipapi.is": "https://api.ipapi.is/?q={}",
    "ipapi.co": "https://ipapi.co/{}/region/",
    "ipapi.co.country": "https://ipapi.co/{}/country/",
    "ipapi.co.city": "https://ipapi.co/{}/city/",
    "ipapi.co.lat": "https://ipapi.co/{}/latitude/",
    "ipapi.co.lon": "https://ipapi.co/{}/longitude/",
    "ipapi.co.org": "https://ipapi.co/{}/org/",
    "ipapi.co.postal": "https://ipapi.co/{}/postal/",
    "ipapi.co.timezone": "https://ipapi.co/{}/timezone/",
    "ipapi.co.currency": "https://ipapi.co/{}/currency/",
}

ASN_LOOKUP_URLS = [
    ("BGP.HE", lambda ip: f"https://bgp.he.net/ip/{ip}"),
    ("ASLookup", lambda ip: f"https://aslookup.com/ip/{ip}"),
    ("IPWhois", lambda ip: f"https://ipwhois.io/ip/{ip}"),
]

async def extract_asn_info(ip: str, client) -> list:
    findings = []
    for name, url_builder in ASN_LOOKUP_URLS:
        try:
            url = url_builder(ip)
            resp = await safe_fetch(client, url, timeout=10.0,
                headers={"User-Agent": UA})
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                findings.append(make_finding(
                    f"ASN data available from {name}",
                    ftype=f"IP Geo: ASN Lookup ({name})",
                    source=name,
                    confidence="Medium",
                    color="slate",
                    status="Available",
                    resolution=ip,
                    tags=["geo", "asn", name.lower()]
                ))
        except:
            pass
    return findings

async def calculate_geo_confidence(successful_sources: int) -> list:
    findings = []
    if successful_sources >= 5:
        findings.append(make_finding(
            f"High geo confidence: {successful_sources} sources agree",
            ftype="IP Geo: Confidence Score",
            source="IPGeolocation",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status=f"{successful_sources} sources",
            tags=["geo", "confidence", "high"]
        ))
    elif successful_sources >= 3:
        findings.append(make_finding(
            f"Medium geo confidence: {successful_sources} sources",
            ftype="IP Geo: Confidence Score",
            source="IPGeolocation",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status=f"{successful_sources} sources",
            tags=["geo", "confidence", "medium"]
        ))
    return findings

async def crawl(target: str, client) -> List:
    findings = []
    ip = target.strip().lower()

    if not is_ip(ip):
        resolved = resolve_ip(ip)
        if resolved:
            ip = resolved[0]
        else:
            findings.append(make_finding(
                "Invalid IP target",
                ftype="IP Geo: Invalid",
                source="IPGeolocation",
                confidence="Low",
                color="emerald",
                threat_level="Informational",
                status="Error",
                resolution=ip,
                tags=["geo", "error"]
            ))
            return findings

    all_sources = {**GEO_SOURCES, **ADDITIONAL_GEO_SOURCES, **EXTRA_GEO_SOURCES}
    tasks = [query_source(ip, name, tmpl, client) for name, tmpl in all_sources.items()]
    geo_results = await asyncio.gather(*tasks, return_exceptions=True)
    successful = 0

    for result in geo_results:
        if isinstance(result, dict) and result:
            successful += 1
            source = result.get("source", "Unknown")
            data = result.get("data", {})

            city = data.get("city", data.get("city_name", ""))
            region = data.get("region", data.get("region_name", ""))
            country = data.get("country", data.get("country_name", ""))
            lat = data.get("lat", data.get("latitude", ""))
            lon = data.get("lon", data.get("longitude", ""))
            org = data.get("org", data.get("organization", data.get("asn_description", "")))
            isp = data.get("isp", data.get("as", ""))
            timezone = data.get("timezone", data.get("time_zone", ""))

            loc_parts = [p for p in [city, region, country] if p]
            if loc_parts:
                findings.append(make_finding(
                    f"Location: {', '.join(loc_parts)}",
                    ftype=f"IP Geo: Location ({source})",
                    source=source,
                    confidence="High",
                    color="slate",
                    status="Geolocated",
                    resolution=ip,
                    tags=["geo", "location", source]
                ))

            if lat and lon:
                findings.append(make_finding(
                    f"Coordinates: {lat}, {lon}",
                    ftype=f"IP Geo: Coordinates ({source})",
                    source=source,
                    confidence="High",
                    color="slate",
                    status="Geolocated",
                    resolution=ip,
                    tags=["geo", "coordinates"]
                ))

            if org or isp:
                findings.append(make_finding(
                    f"Network: {org or isp}",
                    ftype=f"IP Geo: Network ({source})",
                    source=source,
                    confidence="Medium",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["geo", "network"]
                ))

            if timezone:
                findings.append(make_finding(
                    f"Timezone: {timezone}",
                    ftype=f"IP Geo: Timezone ({source})",
                    source=source,
                    confidence="Medium",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["geo", "timezone"]
                ))

    if successful:
        findings.append(make_finding(
            f"Geolocation successful from {successful}/{len(all_sources)} sources",
            ftype="IP Geo: Source Coverage",
            source="IPGeolocation",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status=f"{successful} sources",
            resolution=ip,
            tags=["geo", "coverage"]
        ))

        confidence_results = await calculate_geo_confidence(successful)
        findings.extend(confidence_results)

    asn_results = await extract_asn_info(ip, client)
    findings.extend(asn_results)

    rdap_data = await rdap_lookup(ip, client)
    if rdap_data:
        findings.append(make_finding(
            "RDAP data available for IP",
            ftype="IP Geo: RDAP Lookup",
            source="ARIN RDAP",
            confidence="Medium",
            color="slate",
            status="Available",
            resolution=ip,
            tags=["geo", "rdap", "whois"]
        ))

    net_boundary = await network_boundary(ip)
    if net_boundary:
        findings.append(make_finding(
            f"Network boundary: {net_boundary}",
            ftype="IP Geo: Network Boundary",
            source="IPGeolocation",
            confidence="Low",
            color="slate",
            status="Estimated",
            resolution=ip,
            tags=["geo", "network", "boundary"]
        ))

    if not findings:
        findings.append(make_finding(
            "No geolocation data found",
            ftype="IP Geo: Complete",
            source="IPGeolocation",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=ip,
            tags=["geo", "empty"]
        ))

    return findings
