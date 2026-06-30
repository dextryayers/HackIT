import httpx
import asyncio
import json
import base64
import socket
from datetime import datetime
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

VT_API = "https://www.virustotal.com/api/v3"
VT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def vt_get(path: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{VT_API}/{path}",
            headers={"User-Agent": VT_UA, "Accept": "application/json", "x-apikey": ""},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def vt_ip_analysis(ip: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"ip_addresses/{ip}", client)

async def vt_domain_analysis(domain: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"domains/{domain}", client)

async def vt_url_analysis(url: str, client: httpx.AsyncClient) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return await vt_get(f"urls/{url_id}", client)

async def vt_file_analysis(file_hash: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"files/{file_hash}", client)

async def vt_ip_relationships(ip: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"ip_addresses/{ip}/relationships/resolutions?limit=10", client)

async def vt_domain_subdomains(domain: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"domains/{domain}/subdomains?limit=10", client)

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    is_ip = False
    try:
        socket.inet_aton(t)
        is_ip = True
    except:
        pass

    if is_ip:
        data = await vt_ip_analysis(t, client)
        rel_data = await vt_ip_relationships(t, client)
        endpoint = "IP"
    else:
        data = await vt_domain_analysis(t, client)
        sub_data = await vt_domain_subdomains(t, client)
        endpoint = "Domain"

    if data:
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        harmless = last_analysis.get("harmless", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if total > 0:
            findings.append(IntelligenceFinding(
                entity=f"VT Full: {malicious}/{total} engines detect as malicious",
                type=f"VirusTotal {endpoint} Full Analysis",
                source="VirusTotal",
                confidence="High",
                color="red" if malicious > 0 else "emerald",
                threat_level="High Risk" if malicious > 0 else ("Elevated Risk" if suspicious > 0 else "Informational"),
                status="Malicious" if malicious > 0 else "Clean",
                resolution=t,
                raw_data=json.dumps(last_analysis),
                tags=["virustotal", endpoint.lower(), "full-analysis"]
            ))

        if harmless > 0 or undetected > 0:
            findings.append(IntelligenceFinding(
                entity=f"Clean signal: {harmless} harmless, {undetected} undetected out of {total}",
                type="VirusTotal Clean Signal",
                source="VirusTotal",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                status="Clean Signal",
                resolution=t,
                tags=["virustotal", "clean-signal"]
            ))

        last_analysis_results = attributes.get("last_analysis_results", {})
        if last_analysis_results:
            engine_results = defaultdict(list)
            for engine, result in last_analysis_results.items():
                cat = result.get("category", "undetected")
                engine_results[cat].append(engine)

            for cat, engines in engine_results.items():
                if engines:
                    findings.append(IntelligenceFinding(
                        entity=f"{cat.title()}: {len(engines)} engine(s): {', '.join(engines[:5])}",
                        type="VirusTotal Engine Distribution",
                        source="VirusTotal",
                        confidence="Medium",
                        color="red" if cat == "malicious" else "slate",
                        threat_level="High Risk" if cat == "malicious" else "Informational",
                        status=cat.title(),
                        resolution=t,
                        tags=["virustotal", "engines", cat]
                    ))

        whois = attributes.get("whois", "")
        if whois:
            findings.append(IntelligenceFinding(
                entity="WHOIS data available for domain",
                type="VirusTotal WHOIS",
                source="VirusTotal",
                confidence="Medium",
                color="slate",
                status="Available",
                resolution=t,
                tags=["virustotal", "whois"]
            ))

        tags = attributes.get("tags", [])
        if tags:
            for tag in tags[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Tag: {tag}",
                    type="VirusTotal Tag",
                    source="VirusTotal",
                    confidence="Low",
                    color="slate",
                    status="Tagged",
                    resolution=t,
                    tags=["virustotal", "tag", tag.lower()]
                ))

        popularity = attributes.get("popularity_ranks", {})
        if popularity:
            for source, rank_data in list(popularity.items())[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"Rank #{rank_data.get('rank', 'N/A')} on {source}",
                    type="VirusTotal Popularity Rank",
                    source="VirusTotal",
                    confidence="Medium",
                    color="slate",
                    status="Ranked",
                    resolution=t,
                    tags=["virustotal", "popularity", source.lower()]
                ))

        last_https = attributes.get("last_https_response_content_length", 0)
        if last_https:
            findings.append(IntelligenceFinding(
                entity=f"Last HTTPS response: {last_https} bytes",
                type="VirusTotal HTTPS Metadata",
                source="VirusTotal",
                confidence="Low",
                color="slate",
                status="Metadata Available",
                resolution=t,
                tags=["virustotal", "https"]
            ))

    if is_ip and 'rel_data' in dir():
        resolutions = rel_data.get("data", [])
        if resolutions:
            findings.append(IntelligenceFinding(
                entity=f"{len(resolutions)} DNS resolutions for this IP",
                type="VirusTotal DNS Resolutions",
                source="VirusTotal",
                confidence="Medium",
                color="slate",
                status="Resolved",
                resolution=t,
                tags=["virustotal", "dns", "resolutions"]
            ))

    if not is_ip and 'sub_data' in dir():
        subdomains = sub_data.get("data", [])
        if subdomains:
            findings.append(IntelligenceFinding(
                entity=f"{len(subdomains)} subdomains found",
                type="VirusTotal Subdomain Discovery",
                source="VirusTotal",
                confidence="Medium",
                color="slate",
                status="Discovered",
                resolution=t,
                tags=["virustotal", "subdomains"]
            ))

    if not data:
        findings.append(IntelligenceFinding(
            entity="No VirusTotal full data available",
            type="VirusTotal Full Check Complete",
            source="VirusTotal",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["virustotal", "empty"]
        ))

    return findings
