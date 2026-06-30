import httpx
import asyncio
import json
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import List
from models import IntelligenceFinding

SHODAN_API = "https://api.shodan.io"
SHODAN_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def resolve_host(target: str) -> str:
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        return target

async def shodan_host(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{SHODAN_API}/shodan/host/{ip}",
            params={"key": ""},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_search(query: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{SHODAN_API}/shodan/host/search",
            params={"key": "", "query": query, "limit": 10},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_dns_resolve(hostname: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{SHODAN_API}/dns/resolve",
            params={"key": "", "hostnames": hostname},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=10.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    ip = await resolve_host(t)
    host_data = await shodan_host(ip, client)

    if host_data:
        ports = host_data.get("ports", [])
        if ports:
            findings.append(IntelligenceFinding(
                entity=f"Open ports: {len(ports)} ({', '.join(map(str, sorted(ports)[:10]))})",
                type="Shodan Open Ports",
                source="Shodan",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                status="Open",
                resolution=ip,
                tags=["shodan", "ports"]
            ))

        hostnames = host_data.get("hostnames", [])
        if hostnames:
            for hn in hostnames[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Hostname: {hn}",
                    type="Shodan Hostname",
                    source="Shodan",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["shodan", "hostname"]
                ))

        os = host_data.get("os", "")
        if os:
            findings.append(IntelligenceFinding(
                entity=f"OS: {os}",
                type="Shodan Operating System",
                source="Shodan",
                confidence="Medium",
                color="slate",
                status="Detected",
                resolution=ip,
                tags=["shodan", "os"]
            ))

        country = host_data.get("country_name", "")
        city = host_data.get("city", "")
        if country or city:
            loc = f"{city}, {country}" if city else country
            findings.append(IntelligenceFinding(
                entity=f"Location: {loc}",
                type="Shodan Geolocation",
                source="Shodan",
                confidence="Medium",
                color="slate",
                status="Confirmed",
                resolution=ip,
                tags=["shodan", "geo"]
            ))

        org = host_data.get("org", "")
        isp = host_data.get("isp", "")
        if org or isp:
            findings.append(IntelligenceFinding(
                entity=f"Organization: {org or isp}",
                type="Shodan Organization",
                source="Shodan",
                confidence="High",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["shodan", "org"]
            ))

        vulns = host_data.get("vulns", [])
        if vulns:
            for vuln in list(vulns)[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Vulnerability: {vuln}",
                    type="Shodan Vulnerability",
                    source="Shodan",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Vulnerable",
                    resolution=ip,
                    tags=["shodan", "vulnerability", vuln.lower()]
                ))

        data = host_data.get("data", [])
        if data:
            for service in data[:5]:
                product = service.get("product", "")
                version = service.get("version", "")
                port = service.get("port", 0)
                transport = service.get("transport", "tcp")
                banner = service.get("data", "")[:200]

                if product:
                    findings.append(IntelligenceFinding(
                        entity=f"Port {port}/{transport}: {product} {version}".strip(),
                        type="Shodan Service Banner",
                        source="Shodan",
                        confidence="High",
                        color="slate",
                        status="Active",
                        resolution=ip,
                        raw_data=banner[:300],
                        tags=["shodan", "service", product.lower()]
                    ))

    else:
        findings.append(IntelligenceFinding(
            entity="No Shodan data available for this host",
            type="Shodan Check Complete",
            source="Shodan",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Not Found",
            resolution=ip,
            tags=["shodan", "empty"]
        ))

    return findings
