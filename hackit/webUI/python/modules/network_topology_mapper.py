import httpx
import asyncio
import json
import re
import socket
from datetime import datetime
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

CDN_PROVIDERS = {
    "Cloudflare": ["cloudflare.com", "cdn.cloudflare.net", "cloudflare.net"],
    "Akamai": ["akamai.net", "akamaiedge.net", "akamaitechnologies.com"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "CloudFront": ["cloudfront.net", "amazonaws.com"],
    "CloudFlare": ["cloudflare.com", "cdn.cloudflare.net"],
    "StackPath": ["stackpathcdn.com", "stackpath.com"],
    "KeyCDN": ["keycdn.com", "kxcdn.com"],
    "Google Cloud CDN": ["googleusercontent.com", "gstatic.com", "googleapis.com"],
    "Microsoft Azure CDN": ["azureedge.net", "azure.com", "msftncsi.com"],
    "OVH CDN": ["ovh.net", "ovhcdn.com"],
    "BunnyCDN": ["bunnycdn.com", "b-cdn.net"],
    "CacheFly": ["cachefly.net", "cachefly.com"],
}

async def trace_asn(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def bgp_route(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(f"https://bgp.he.net/ip/{ip}", timeout=10.0)
        if resp.status_code == 200:
            return {"html": resp.text[:2000]}
    except:
        pass
    return None

async def detect_cdn(domain: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(f"https://{domain}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code in (200, 301, 302):
            headers = dict(resp.headers)
            server = headers.get("Server", "")
            via = headers.get("Via", "")
            cf_ray = headers.get("cf-ray", "")
            x_cache = headers.get("X-Cache", "")

            for provider, domains in CDN_PROVIDERS.items():
                for d in domains:
                    if d.lower() in server.lower() or d.lower() in via.lower():
                        results.append(provider)
                        break
            if cf_ray:
                results.append("Cloudflare")
            if x_cache:
                results.append(f"CDN with caching ({x_cache})")
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    try:
        ip = socket.gethostbyname(t)
        findings.append(IntelligenceFinding(
            entity=f"{t} resolves to {ip}",
            type="Network Topology: DNS Resolution",
            source="NetworkTopologyMapper",
            confidence="High",
            color="slate",
            status="Resolved",
            resolution=t,
            tags=["network", "dns", "resolution"]
        ))

        asn_data = await trace_asn(ip, client)
        if asn_data:
            asn = asn_data.get("org", "")
            if asn:
                findings.append(IntelligenceFinding(
                    entity=f"ASN/ISP: {asn}",
                    type="Network Topology: ASN Discovery",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="slate",
                    status="Identified",
                    resolution=t,
                    tags=["network", "asn", "isp"]
                ))
    except:
        pass

    cdns = await detect_cdn(t, client)
    if cdns:
        for cdn in cdns[:3]:
            findings.append(IntelligenceFinding(
                entity=f"CDN: {cdn}",
                type="Network Topology: CDN Detection",
                source="NetworkTopologyMapper",
                confidence="High",
                color="slate",
                status="Identified",
                resolution=t,
                tags=["network", "cdn", cdn.lower().replace(" ", "-")]
            ))

    bgp_data = await bgp_route(t, client)
    if bgp_data:
        findings.append(IntelligenceFinding(
            entity="BGP routing data available",
            type="Network Topology: BGP Route",
            source="NetworkTopologyMapper",
            confidence="Low",
            color="slate",
            status="Available",
            resolution=t,
            tags=["network", "bgp", "routing"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No network topology data found",
            type="Network Topology: Complete",
            source="NetworkTopologyMapper",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["network", "empty"]
        ))

    return findings
