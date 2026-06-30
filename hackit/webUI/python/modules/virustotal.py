import httpx
import asyncio
import json
from datetime import datetime
from typing import List
from models import IntelligenceFinding

VT_API = "https://www.virustotal.com/api/v3"
VT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def vt_ip_report(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{VT_API}/ip_addresses/{ip}",
            headers={"User-Agent": VT_UA, "Accept": "application/json", "x-apikey": ""},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def vt_domain_report(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{VT_API}/domains/{domain}",
            headers={"User-Agent": VT_UA, "Accept": "application/json", "x-apikey": ""},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def vt_url_report(url: str, client: httpx.AsyncClient) -> dict:
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = await client.get(
            f"{VT_API}/urls/{url_id}",
            headers={"User-Agent": VT_UA, "Accept": "application/json", "x-apikey": ""},
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

    is_ip = False
    try:
        import socket
        socket.inet_aton(t)
        is_ip = True
    except:
        pass

    if is_ip:
        data = await vt_ip_report(t, client)
        endpoint_type = "IP"
    else:
        data = await vt_domain_report(t, client)
        endpoint_type = "Domain"

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
                entity=f"VT Detection: {malicious}/{total} malicious ({suspicious} suspicious)",
                type=f"VirusTotal {endpoint_type} Report",
                source="VirusTotal",
                confidence="High",
                color="red" if malicious > 0 else "emerald",
                threat_level="High Risk" if malicious > 0 else ("Elevated Risk" if suspicious > 0 else "Informational"),
                status="Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean"),
                resolution=t,
                raw_data=json.dumps(last_analysis),
                tags=["virustotal", endpoint_type.lower(), "detection"]
            ))

            findings.append(IntelligenceFinding(
                entity=f"Detection ratio: {malicious}/{total} (harmless: {harmless}, undetected: {undetected})",
                type=f"VirusTotal Detection Breakdown",
                source="VirusTotal",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                resolution=t,
                tags=["virustotal", "detection-breakdown"]
            ))

        categories = attributes.get("categories", {})
        if categories:
            for engine, cat in list(categories.items())[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"{engine}: {cat}",
                    type="VirusTotal Category",
                    source="VirusTotal",
                    confidence="Medium",
                    color="slate",
                    status="Categorized",
                    resolution=t,
                    tags=["virustotal", "category"]
                ))

        reputation = attributes.get("reputation", 0)
        if reputation:
            findings.append(IntelligenceFinding(
                entity=f"VT Reputation: {reputation}",
                type="VirusTotal Reputation",
                source="VirusTotal",
                confidence="Medium",
                color="slate",
                status="Scored",
                resolution=t,
                tags=["virustotal", "reputation"]
            ))

        last_analysis_results = attributes.get("last_analysis_results", {})
        if last_analysis_results:
            malicious_engines = {k: v for k, v in last_analysis_results.items() if v.get("category") == "malicious"}
            if malicious_engines:
                for engine, result in list(malicious_engines.items())[:5]:
                    findings.append(IntelligenceFinding(
                        entity=f"{engine}: {result.get('result', 'malicious')}",
                        type="VirusTotal Engine Detection",
                        source="VirusTotal",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Detected",
                        resolution=t,
                        tags=["virustotal", "engine", engine.lower()]
                    ))

    else:
        findings.append(IntelligenceFinding(
            entity="No VirusTotal data available",
            type="VirusTotal Check Complete",
            source="VirusTotal",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["virustotal", "empty"]
        ))

    return findings
