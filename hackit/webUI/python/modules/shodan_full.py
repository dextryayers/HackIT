import httpx
import asyncio
import json
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import List
from collections import defaultdict
from models import IntelligenceFinding

SHODAN_API = "https://api.shodan.io"
SHODAN_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

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
            params={"key": "", "query": query, "limit": 20},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_ports(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{SHODAN_API}/shodan/host/{ip}/ports",
            params={"key": ""},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_count(query: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{SHODAN_API}/shodan/host/count",
            params={"key": "", "query": query},
            headers={"User-Agent": SHODAN_UA, "Accept": "application/json"},
            timeout=15.0
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

    try:
        ip = socket.gethostbyname(t)
    except:
        ip = t

    host_data = await shodan_host(ip, client)
    search_data = await shodan_search(t, client)
    ports_data = await shodan_ports(ip, client)
    count_data = await shodan_count(t, client)

    if host_data:
        for key in ["ports", "hostnames", "os", "country_name", "city", "org", "isp", "vulns"]:
            pass

        open_ports = host_data.get("ports", ports_data.get("ports", []))
        if open_ports:
            port_counts = defaultdict(int)
            for p in open_ports:
                port_counts[p] += 1
            for port in sorted(open_ports)[:15]:
                findings.append(IntelligenceFinding(
                    entity=f"Port {port}/tcp open",
                    type="Shodan Port Discovery",
                    source="Shodan",
                    confidence="High",
                    color="slate",
                    status="Open",
                    resolution=ip,
                    tags=["shodan", "port", str(port)]
                ))

            service_breakdown = {}
            for entry in host_data.get("data", []):
                product = entry.get("product", entry.get("_product", ""))
                port = entry.get("port", 0)
                if product:
                    service_breakdown[port] = product
            for port, product in service_breakdown.items():
                findings.append(IntelligenceFinding(
                    entity=f"Port {port}: {product}",
                    type="Shodan Service Identification",
                    source="Shodan",
                    confidence="High",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["shodan", "service", product.lower().replace(" ", "-")]
                ))

        vulns = host_data.get("vulns", [])
        if vulns:
            findings.append(IntelligenceFinding(
                entity=f"{len(vulns)} CVEs associated with {ip}",
                type="Shodan Vulnerability Count",
                source="Shodan",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Vulnerable",
                resolution=ip,
                raw_data=", ".join(list(vulns)[:10]),
                tags=["shodan", "vulnerability", "cve"]
            ))
            for v in list(vulns)[:5]:
                findings.append(IntelligenceFinding(
                    entity=v,
                    type="Shodan CVE Details",
                    source="Shodan",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    status="Vulnerable",
                    resolution=ip,
                    tags=["shodan", "cve", v.lower()]
                ))

    if count_data:
        total = count_data.get("total", 0)
        if total > 0:
            findings.append(IntelligenceFinding(
                entity=f"{total} Shodan results for '{t}'",
                type="Shodan Search Count",
                source="Shodan",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status=f"{total} results",
                resolution=t,
                tags=["shodan", "search-count"]
            ))

    if search_data:
        matches = search_data.get("matches", [])
        if matches:
            for match in matches[:10]:
                match_ip = match.get("ip_str", "")
                match_port = match.get("port", 0)
                match_data = match.get("data", "")[:200]
                findings.append(IntelligenceFinding(
                    entity=f"Found: {match_ip}:{match_port}",
                    type="Shodan Search Match",
                    source="Shodan",
                    confidence="Medium",
                    color="slate",
                    status="Found",
                    resolution=t,
                    raw_data=match_data[:300],
                    tags=["shodan", "search"]
                ))

    if not host_data and not search_data:
        findings.append(IntelligenceFinding(
            entity="No Shodan data available",
            type="Shodan Full Check Complete",
            source="Shodan",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["shodan", "empty"]
        ))

    return findings
