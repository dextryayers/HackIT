import httpx
import asyncio
import re
import json
import socket
from datetime import datetime
from typing import List
from models import IntelligenceFinding

GEO_APIS = {
    "ip-api": "http://ip-api.com/json/{}",
    "ipinfo": "https://ipinfo.io/{}/json",
    "ipapi.co": "https://ipapi.co/{}/json/",
    "ipvigilante": "https://ipvigilante.com/json/{}",
    "extreme-ip": "https://extreme-ip-lookup.com/json/{}",
    "ip2location": "https://api.ip2location.com/v2/?ip={}&format=json",
    "abstractapi": "https://ipgeolocation.abstractapi.com/v1/?ip_address={}",
}

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def query_geo(ip: str, name: str, url_tmpl: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_tmpl.format(ip)
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": UA, "Accept": "application/json"})
        if resp.status_code == 200:
            return {"source": name, "data": resp.json()}
    except:
        pass
    return {}

async def reverse_dns(ip: str) -> str:
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except:
        return ""

async def check_proxy_vpn(ip: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(f"https://ipqualityscore.com/api/json/ip/{ip}", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("proxy", False):
                results.append("proxy")
            if data.get("vpn", False):
                results.append("vpn")
            if data.get("tor", False):
                results.append("tor")
    except:
        pass
    return results

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
                entity="Invalid target for geolocation",
                type="Geo Recon: Invalid Target",
                source="GeoRecon",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Error",
                resolution=ip,
                tags=["geo", "error"]
            ))
            return findings

    rdns = await reverse_dns(ip)
    if rdns:
        findings.append(IntelligenceFinding(
            entity=f"Reverse DNS: {rdns}",
            type="Geo Recon: Reverse DNS",
            source="GeoRecon",
            confidence="High",
            color="slate",
            status="Resolved",
            resolution=ip,
            tags=["geo", "rdns", "dns"]
        ))

    proxy_vpn = await check_proxy_vpn(ip, client)
    for pv in proxy_vpn:
        findings.append(IntelligenceFinding(
            entity=f"IP detected as {pv.upper()}",
            type=f"Geo Recon: {pv.upper()} Detection",
            source="GeoRecon",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status=f"Detected as {pv}",
            resolution=ip,
            tags=["geo", pv, "anonymizer"]
        ))

    tasks = [query_geo(ip, name, tmpl, client) for name, tmpl in GEO_APIS.items()]
    geo_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in geo_results:
        if isinstance(result, dict) and result:
            source = result.get("source", "Unknown")
            data = result.get("data", {})
            findings.append(IntelligenceFinding(
                entity=f"Geolocation data from {source}",
                type=f"Geo Recon: {source}",
                source=source,
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Data Retrieved",
                resolution=ip,
                raw_data=json.dumps(data)[:500],
                tags=["geo", source.lower()]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No geolocation data available",
            type="Geo Recon: Complete",
            source="GeoRecon",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=ip,
            tags=["geo", "empty"]
        ))

    return findings
