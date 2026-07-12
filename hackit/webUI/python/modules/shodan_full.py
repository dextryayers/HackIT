import json
from datetime import datetime
from urllib.parse import urlparse
from typing import List
from collections import defaultdict
from settings_store import get_api_key
from ..module_common import safe_fetch, make_finding, resolve_ip

SHODAN_API = "https://api.shodan.io"
SHODAN_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def shodan_host(ip: str, client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/host/{ip}",
            params={"key": get_api_key("shodan")},
            headers={"Accept": "application/json"},
            timeout=15.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_search(query: str, client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/host/search",
            params={"key": get_api_key("shodan"), "query": query, "limit": 20},
            headers={"Accept": "application/json"},
            timeout=15.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_ports(ip: str, client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/host/{ip}/ports",
            params={"key": get_api_key("shodan")},
            headers={"Accept": "application/json"},
            timeout=15.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_count(query: str, client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/host/count",
            params={"key": get_api_key("shodan"), "query": query},
            headers={"Accept": "application/json"},
            timeout=15.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_protocols(client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/protocols",
            params={"key": get_api_key("shodan")},
            headers={"Accept": "application/json"},
            timeout=10.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def shodan_services(client) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{SHODAN_API}/shodan/services",
            params={"key": get_api_key("shodan")},
            headers={"Accept": "application/json"},
            timeout=10.0
        )
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def crawl(target: str, client: AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    ip = resolve_ip(t) or t

    host_data = await shodan_host(ip, client)
    search_data = await shodan_search(t, client)
    ports_data = await shodan_ports(ip, client)
    count_data = await shodan_count(t, client)
    proto_data = await shodan_protocols(client)
    svc_data = await shodan_services(client)

    if host_data:
        open_ports = host_data.get("ports", ports_data.get("ports", []))
        if open_ports:
            for port in sorted(open_ports)[:15]:
                findings.append(make_finding(
                    entity=f"Port {port}/tcp open",
                    ftype="Shodan Port Discovery",
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
                findings.append(make_finding(
                    entity=f"Port {port}: {product}",
                    ftype="Shodan Service Identification",
                    source="Shodan",
                    confidence="High",
                    color="slate",
                    status="Identified",
                    resolution=ip,
                    tags=["shodan", "service", product.lower().replace(" ", "-")]
                ))

        vulns = host_data.get("vulns", [])
        if vulns:
            findings.append(make_finding(
                entity=f"{len(vulns)} CVEs associated with {ip}",
                ftype="Shodan Vulnerability Count",
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
                findings.append(make_finding(
                    entity=v,
                    ftype="Shodan CVE Details",
                    source="Shodan",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    status="Vulnerable",
                    resolution=ip,
                    tags=["shodan", "cve", v.lower()]
                ))

        hostnames = host_data.get("hostnames", [])
        if hostnames:
            findings.append(make_finding(
                entity=f"Hostnames: {', '.join(hostnames[:5])}",
                ftype="Shodan Hostnames",
                source="Shodan",
                confidence="High",
                color="slate",
                status="Resolved",
                resolution=ip,
                tags=["shodan", "hostnames"]
            ))

        os = host_data.get("os", "")
        if os:
            findings.append(make_finding(
                entity=f"OS: {os}",
                ftype="Shodan OS Detection",
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
            findings.append(make_finding(
                entity=f"Location: {city}, {country}" if city else f"Country: {country}",
                ftype="Shodan Geolocation",
                source="Shodan",
                confidence="Medium",
                color="slate",
                status="Geolocated",
                resolution=ip,
                tags=["shodan", "geo"]
            ))

        org = host_data.get("org", "")
        isp = host_data.get("isp", "")
        if org or isp:
            findings.append(make_finding(
                entity=f"Org: {org or isp}",
                ftype="Shodan Organization",
                source="Shodan",
                confidence="High",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["shodan", "org"]
            ))

        domains = host_data.get("domains", [])
        if domains:
            findings.append(make_finding(
                entity=f"Domains: {', '.join(domains[:5])}",
                ftype="Shodan Domain Resolution",
                source="Shodan",
                confidence="Medium",
                color="slate",
                status="Resolved",
                resolution=ip,
                tags=["shodan", "domains"]
            ))

        asn = host_data.get("asn", "")
        if asn:
            findings.append(make_finding(
                entity=f"ASN: {asn}",
                ftype="Shodan ASN",
                source="Shodan",
                confidence="High",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["shodan", "asn"]
            ))

        data_entries = host_data.get("data", [])
        if data_entries:
            findings.append(make_finding(
                entity=f"{len(data_entries)} service banners collected",
                ftype="Shodan Service Data",
                source="Shodan",
                confidence="High",
                color="slate",
                status="Collected",
                resolution=ip,
                tags=["shodan", "banners"]
            ))

    if count_data:
        total = count_data.get("total", 0)
        if total > 0:
            findings.append(make_finding(
                entity=f"{total} Shodan results for '{t}'",
                ftype="Shodan Search Count",
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
                findings.append(make_finding(
                    entity=f"Found: {match_ip}:{match_port}",
                    ftype="Shodan Search Match",
                    source="Shodan",
                    confidence="Medium",
                    color="slate",
                    status="Found",
                    resolution=t,
                    raw_data=match_data[:300],
                    tags=["shodan", "search"]
                ))

    if proto_data:
        findings.append(make_finding(
            entity=f"Shodan protocols available: {len(proto_data)}",
            ftype="Shodan Protocol List",
            source="Shodan",
            confidence="Low",
            color="slate",
            status="Available",
            resolution=ip,
            tags=["shodan", "protocols"]
        ))

    if svc_data:
        findings.append(make_finding(
            entity=f"Shodan services database: {len(svc_data)} services",
            ftype="Shodan Services DB",
            source="Shodan",
            confidence="Low",
            color="slate",
            status="Available",
            resolution=ip,
            tags=["shodan", "services"]
        ))

    if not host_data and not search_data:
        findings.append(make_finding(
            entity="No Shodan data available",
            ftype="Shodan Full Check Complete",
            source="Shodan",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["shodan", "empty"]
        ))

    return findings
