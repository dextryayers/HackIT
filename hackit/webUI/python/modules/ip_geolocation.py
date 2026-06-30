import httpx
import asyncio
import json
import socket
from datetime import datetime
from typing import List, Optional
from models import IntelligenceFinding

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

async def query_source(ip: str, name: str, url_tmpl: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        url = url_tmpl.format(ip)
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": UA, "Accept": "application/json"})
        if resp.status_code == 200:
            return {"source": name, "data": resp.json()}
    except:
        pass
    return None

async def rdap_lookup(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=10.0,
            headers={"Accept": "application/json"})
        if resp.status_code == 200:
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

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    ip = target.strip().lower()

    try:
        socket.inet_aton(ip)
    except:
        try:
            ip = socket.gethostbyname(ip)
        except:
            findings.append(IntelligenceFinding(
                entity="Invalid IP target",
                type="IP Geo: Invalid",
                source="IPGeolocation",
                confidence="Low",
                color="emerald",
                threat_level="Informational",
                status="Error",
                resolution=ip,
                tags=["geo", "error"]
            ))
            return findings

    tasks = [query_source(ip, name, tmpl, client) for name, tmpl in GEO_SOURCES.items()]
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
                findings.append(IntelligenceFinding(
                    entity=f"Location: {', '.join(loc_parts)}",
                    type=f"IP Geo: Location ({source})",
                    source=source,
                    confidence="High",
                    color="slate",
                    status="Geolocated",
                    resolution=ip,
                    tags=["geo", "location", source]
                ))

            if lat and lon:
                findings.append(IntelligenceFinding(
                    entity=f"Coordinates: {lat}, {lon}",
                    type=f"IP Geo: Coordinates ({source})",
                    source=source,
                    confidence="High",
                    color="slate",
                    status="Geolocated",
                    resolution=ip,
                    tags=["geo", "coordinates"]
                ))

            if org or isp:
                findings.append(IntelligenceFinding(
                    entity=f"Network: {org or isp}",
                    type=f"IP Geo: Network ({source})",
                    source=source,
                    confidence="Medium",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["geo", "network"]
                ))

            if timezone:
                findings.append(IntelligenceFinding(
                    entity=f"Timezone: {timezone}",
                    type=f"IP Geo: Timezone ({source})",
                    source=source,
                    confidence="Medium",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["geo", "timezone"]
                ))

    if successful:
        findings.append(IntelligenceFinding(
            entity=f"Geolocation successful from {successful}/{len(GEO_SOURCES)} sources",
            type="IP Geo: Source Coverage",
            source="IPGeolocation",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status=f"{successful} sources",
            resolution=ip,
            tags=["geo", "coverage"]
        ))

    rdap_data = await rdap_lookup(ip, client)
    if rdap_data:
        findings.append(IntelligenceFinding(
            entity="RDAP data available for IP",
            type="IP Geo: RDAP Lookup",
            source="ARIN RDAP",
            confidence="Medium",
            color="slate",
            status="Available",
            resolution=ip,
            tags=["geo", "rdap", "whois"]
        ))

    net_boundary = await network_boundary(ip)
    if net_boundary:
        findings.append(IntelligenceFinding(
            entity=f"Network boundary: {net_boundary}",
            type="IP Geo: Network Boundary",
            source="IPGeolocation",
            confidence="Low",
            color="slate",
            status="Estimated",
            resolution=ip,
            tags=["geo", "network", "boundary"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No geolocation data found",
            type="IP Geo: Complete",
            source="IPGeolocation",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=ip,
            tags=["geo", "empty"]
        ))

    return findings
