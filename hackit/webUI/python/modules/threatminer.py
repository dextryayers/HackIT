import httpx
import asyncio
import json
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import List
from collections import defaultdict
from models import IntelligenceFinding

THREATMINER_API = "https://api.threatminer.org/v2"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def query_domain(domain: str, endpoint: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
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
        resp = await client.get(
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
        resp = await client.get(
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
        resp = await client.get(
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
        subdomains = await query_ip(t, "2", client)
        dns = await query_ip(t, "3", client)
        samples = await query_ip(t, "4", client)
        reports = await query_report(t, client)

        sub_data = subdomains.get("results", [])
        if sub_data:
            findings.append(IntelligenceFinding(
                entity=f"{len(sub_data)} subdomains/PDNS records for {t}",
                type="ThreatMiner PDNS Records",
                source="ThreatMiner",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["threatminer", "pdns"]
            ))

        dns_data = dns.get("results", [])
        if dns_data:
            for entry in dns_data[:10]:
                if isinstance(entry, dict):
                    findings.append(IntelligenceFinding(
                        entity=f"DNS: {entry.get('domain', entry.get('hostname', str(entry)))[:200]}",
                        type="ThreatMiner DNS Resolutions",
                        source="ThreatMiner",
                        confidence="Medium",
                        color="slate",
                        status="Resolved",
                        resolution=t,
                        tags=["threatminer", "dns"]
                    ))

        sample_data = samples.get("results", [])
        if sample_data:
            findings.append(IntelligenceFinding(
                entity=f"{len(sample_data)} malware samples associated",
                type="ThreatMiner Malware Samples",
                source="ThreatMiner",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status=f"{len(sample_data)} samples",
                resolution=t,
                tags=["threatminer", "malware"]
            ))

    else:
        whois = await query_domain(t, "5", client)
        pdns = await query_domain(t, "2", client)
        subdomains = await query_domain(t, "1", client)
        reports = await query_report(t, client)

        whois_data = whois.get("results", [])
        if whois_data:
            for entry in whois_data[:5]:
                if isinstance(entry, dict):
                    findings.append(IntelligenceFinding(
                        entity=f"WHOIS: {entry.get('whois', str(entry))[:200]}",
                        type="ThreatMiner WHOIS",
                        source="ThreatMiner",
                        confidence="Medium",
                        color="slate",
                        status="Found",
                        resolution=t,
                        tags=["threatminer", "whois"]
                    ))

        pdns_data = pdns.get("results", [])
        if pdns_data:
            for entry in pdns_data[:10]:
                if isinstance(entry, dict):
                    findings.append(IntelligenceFinding(
                        entity=f"PDNS: {entry.get('ip', entry.get('domain', str(entry)))[:200]}",
                        type="ThreatMiner Passive DNS",
                        source="ThreatMiner",
                        confidence="Medium",
                        color="slate",
                        status="Found",
                        resolution=t,
                        tags=["threatminer", "pdns"]
                    ))

        sub_data = subdomains.get("results", [])
        if sub_data:
            for sub in sub_data[:10]:
                if isinstance(sub, dict):
                    findings.append(IntelligenceFinding(
                        entity=f"Subdomain: {sub.get('subdomain', str(sub))[:200]}",
                        type="ThreatMiner Subdomain",
                        source="ThreatMiner",
                        confidence="Medium",
                        color="slate",
                        status="Found",
                        resolution=t,
                        tags=["threatminer", "subdomain"]
                    ))

    report_data = reports.get("results", [])
    if report_data:
        for r in report_data[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Report: {str(r)[:200]}",
                type="ThreatMiner Report",
                source="ThreatMiner",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["threatminer", "report"]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
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
