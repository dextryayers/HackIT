import httpx
import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse
from typing import List
from collections import defaultdict
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip
from models import IntelligenceFinding

THREATMINER_API = "https://api.threatminer.org/v2"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

DOMAIN_ENDPOINTS = {
    "WHOIS": "5",
    "PDNS": "2",
    "Subdomains": "1",
    "Reports": "4",
    "Related Samples": "6",
}

IP_ENDPOINTS = {
    "PDNS": "2",
    "DNS Resolutions": "3",
    "Malware Samples": "4",
    "Reports": "5",
    "SSL Certs": "6",
}

async def query_domain(domain: str, endpoint: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/domain.php",
            params={"q": domain, "rt": endpoint},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_ip(ip: str, endpoint: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/host.php",
            params={"q": ip, "rt": endpoint},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_ssl(ssl_hash: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/ssl.php",
            params={"q": ssl_hash, "rt": "1"},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_report(query: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/report.php",
            params={"q": query, "rt": "1"},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_av(av_query: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/av.php",
            params={"q": av_query, "rt": "1"},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_imphash(imphash: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"{THREATMINER_API}/imphash.php",
            params={"q": imphash, "rt": "1"},
            headers={"User-Agent": UA, "Accept": "application/json"},
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

    is_ip_flag = is_ip(t)

    if is_ip_flag:
        for endpoint_name, rt in IP_ENDPOINTS.items():
            data = await query_ip(t, rt, client)
            results = data.get("results", [])
            if results:
                status_message = data.get("status_message", "Results found")
                findings.append(make_finding(
                    entity=f"{endpoint_name}: {len(results)} entries",
                    type=f"ThreatMiner: {endpoint_name}",
                    source="ThreatMiner",
                    confidence="Medium",
                    color="slate" if endpoint_name in ("WHOIS", "PDNS") else "orange",
                    threat_level="Elevated Risk" if endpoint_name in ("Malware Samples", "SSL Certs") else "Informational",
                    status=status_message,
                    resolution=t,
                    tags=["threatminer", endpoint_name.lower().replace(" ", "-")]
                ))
                for entry in results[:5]:
                    entry_str = str(entry)[:200]
                    findings.append(make_finding(
                        entity=f"{endpoint_name[:15]} entry: {entry_str}",
                        type=f"ThreatMiner: {endpoint_name} Detail",
                        source="ThreatMiner",
                        confidence="Low",
                        color="slate",
                        status="Found",
                        resolution=t,
                        tags=["threatminer", endpoint_name.lower().replace(" ", "-")]
                    ))

    else:
        for endpoint_name, rt in DOMAIN_ENDPOINTS.items():
            data = await query_domain(t, rt, client)
            results = data.get("results", [])
            if results:
                status_message = data.get("status_message", "Results found")
                findings.append(make_finding(
                    entity=f"{endpoint_name}: {len(results)} entries",
                    type=f"ThreatMiner: {endpoint_name}",
                    source="ThreatMiner",
                    confidence="Medium",
                    color="slate" if endpoint_name in ("WHOIS", "PDNS", "Subdomains") else "orange",
                    threat_level="Elevated Risk" if endpoint_name in ("Related Samples",) else "Informational",
                    status=status_message,
                    resolution=t,
                    tags=["threatminer", endpoint_name.lower().replace(" ", "-")]
                ))
                for entry in results[:5]:
                    entry_str = str(entry)[:200]
                    findings.append(make_finding(
                        entity=f"{endpoint_name[:15]} entry: {entry_str}",
                        type=f"ThreatMiner: {endpoint_name} Detail",
                        source="ThreatMiner",
                        confidence="Low",
                        color="slate",
                        status="Found",
                        resolution=t,
                        tags=["threatminer", endpoint_name.lower().replace(" ", "-")]
                    ))

    report_data = await query_report(t, client)
    results = report_data.get("results", [])
    if results:
        findings.append(make_finding(
            entity=f"Reports: {len(results)} APT/threat reports available",
            type="ThreatMiner: Reports",
            source="ThreatMiner",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Available",
            resolution=t,
            tags=["threatminer", "reports"]
        ))
        for r in results[:5]:
            findings.append(make_finding(
                entity=f"Report: {str(r)[:200]}",
                type="ThreatMiner Report Detail",
                source="ThreatMiner",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["threatminer", "report"]
            ))

    av_data = await query_av(t, client)
    av_results = av_data.get("results", [])
    if av_results:
        findings.append(make_finding(
            entity=f"AV detections: {len(av_results)} results",
            type="ThreatMiner: AV Detection",
            source="ThreatMiner",
            confidence="Medium",
            color="red",
            threat_level="High Risk",
            status="Detected",
            resolution=t,
            tags=["threatminer", "av"]
        ))

    if not findings:
        findings.append(make_finding(
            entity="No ThreatMiner data found",
            type="ThreatMiner Check Complete",
            source="ThreatMiner",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["threatminer", "empty"]
        ))

    return findings
