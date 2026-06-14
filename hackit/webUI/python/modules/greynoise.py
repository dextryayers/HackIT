import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

GREYNOISE_V3_BASE = "https://api.greynoise.io/v3"
GREYNOISE_V2_BASE = "https://api.greynoise.io/v2"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

RISK_LABELS = {
    "malicious": "Malicious",
    "benign": "Benign",
    "unknown": "Unknown",
    "suspicious": "Suspicious",
}

NOISE_CLASSIFICATIONS = {
    "known_scanner": "Known Scanner",
    "exploit_scanner": "Exploit Scanner",
    "botnet": "Botnet Node",
    "malware": "Malware C2",
    "phishing": "Phishing Host",
    "spam": "Spam Source",
    "proxy": "Proxy/VPN",
    "tor": "Tor Exit Node",
    "scanner": "Internet Scanner",
    "bruteforce": "Brute Force Source",
    "dnp3_scanner": "DNP3 Scanner",
    "http_scanner": "HTTP Scanner",
    "ssh_scanner": "SSH Scanner",
    "telnet_scanner": "Telnet Scanner",
    "web_spider": "Web Spider/Crawler",
}

CVE_PATTERNS = {
    "CVE-2017-": "JBOSS/Apache Struts2 (2017)",
    "CVE-2018-": "Various (2018)",
    "CVE-2019-": "Various (2019)",
    "CVE-2020-": "Various (2020)",
    "CVE-2021-": "Various (2021)",
    "CVE-2022-": "Various (2022)",
    "CVE-2023-": "Various (2023)",
    "CVE-2024-": "Various (2024)",
    "CVE-2025-": "Various (2025)",
    "CVE-2026-": "Various (2026)",
    "JBOSS": "JBOSS Exploitation",
    "Log4j": "Log4j Exploitation",
    "Log4Shell": "Log4Shell (CVE-2021-44228)",
    "Shellshock": "Shellshock (CVE-2014-6271)",
    "Heartbleed": "Heartbleed (CVE-2014-0160)",
    "EternalBlue": "EternalBlue (MS17-010)",
    "BlueKeep": "BlueKeep (CVE-2019-0708)",
    "ProxyLogon": "ProxyLogon (CVE-2021-26855)",
    "ProxyShell": "ProxyShell",
    "PrintNightmare": "PrintNightmare (CVE-2021-34527)",
    "ZeroLogon": "ZeroLogon (CVE-2020-1472)",
    "CitrixBleed": "CitrixBleed (CVE-2023-4966)",
    "Ivanti": "Ivanti CVE (2023-2024)",
}

def classify_ip_risk(data: dict) -> str:
    classification = str(data.get("classification", "")).lower()
    severity = str(data.get("severity", "")).lower()
    noise = data.get("noise", False)
    riot = data.get("riot", False)

    if classification == "malicious" or severity == "high":
        return "High Risk"
    elif classification == "suspicious" or severity == "medium":
        return "Elevated Risk"
    elif noise and not riot:
        return "Standard Target"
    elif riot:
        return "Low Risk (CDN/Cloud Provider)"
    return "Informational"

def score_noise_reputation(data: dict) -> int:
    score = 50
    classification = str(data.get("classification", "")).lower()
    severity = str(data.get("severity", "")).lower()
    confidence = str(data.get("confidence", "")).lower()
    noise = data.get("noise", False)
    riot = data.get("riot", False)

    if riot:
        score += 30
    if not noise:
        score += 20
    if classification == "benign":
        score += 15
    elif classification == "malicious":
        score -= 30
    elif classification == "suspicious":
        score -= 15
    if severity == "high":
        score -= 20
    elif severity == "medium":
        score -= 10
    if confidence == "high":
        score += 5
    return max(0, min(100, score))

def match_cve_tags(actor: str, tags: list) -> list:
    matched = []
    text = f"{actor or ''} {' '.join(tags or [])}"
    for pattern, label in CVE_PATTERNS.items():
        if pattern.lower() in text.lower():
            matched.append(label)
    return matched

async def resolve_domain_to_ips(domain: str) -> list:
    try:
        loop = asyncio.get_event_loop()
        addrinfo = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM))
        return list(set(a[4][0] for a in addrinfo[:10]))
    except:
        return []

async def query_greynoise_ip(ip: str, client: httpx.AsyncClient) -> dict:
    result = {"ip": ip, "error": None, "data": {}}
    try:
        resp = await client.get(f"{GREYNOISE_V3_BASE}/community/{ip}", timeout=15.0,
                                headers={"User-Agent": UA, "Accept": "application/json"})
        if resp.status_code == 200:
            result["data"] = resp.json()
        else:
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["error"] = str(e)[:100]

    if not result["data"].get("classification"):
        try:
            resp2 = await client.get(f"{GREYNOISE_V2_BASE}/noise/quick/{ip}", timeout=10.0,
                                     headers={"User-Agent": UA, "Accept": "application/json"})
            if resp2.status_code == 200:
                quick = resp2.json()
                result["data"]["quick_noise"] = quick.get("noise", False)
        except:
            pass

    return result

async def gnql_search(query: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.post(f"{GREYNOISE_V3_BASE}/experimental/gnql",
                                 json={"query": query, "size": 10},
                                 timeout=15.0,
                                 headers={"User-Agent": UA, "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            for hit in data.get("data", data.get("hits", [])):
                results.append(hit)
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    domain = raw_target

    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ips_to_check = []
    ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    if ip_re.match(domain):
        ips_to_check = [domain]
    else:
        resolved = await resolve_domain_to_ips(domain)
        if resolved:
            ips_to_check = resolved
            for ip in resolved:
                findings.append(IntelligenceFinding(
                    entity=ip, type="GreyNoise: Resolved IP", source="GreyNoise",
                    confidence="High", color="slate", threat_level="Informational",
                    status="DNS Resolution", resolution=f"Resolved from {domain}",
                    tags=["greynoise", "dns"]
                ))

    if not ips_to_check:
        findings.append(IntelligenceFinding(
            entity=f"Could not resolve {domain} to IPs", type="GreyNoise: Resolution Error",
            source="GreyNoise", confidence="Low", color="red", threat_level="Informational",
            status="Error", tags=["greynoise"]
        ))
        return findings

    for ip in ips_to_check[:5]:
        result = await query_greynoise_ip(ip, client)
        data = result["data"]
        if not data or result["error"]:
            findings.append(IntelligenceFinding(
                entity=f"{ip}: {result.get('error', 'No data')}",
                type="GreyNoise: API Error",
                source="GreyNoise", confidence="Low", color="red", threat_level="Informational",
                status="API Error", tags=["greynoise"]
            ))
            continue

        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        actor = data.get("actor", data.get("name", ""))
        tags = data.get("tags", [])
        last_seen = data.get("last_seen", "")
        first_seen = data.get("first_seen", "")
        severity = data.get("severity", "")
        confidence = data.get("confidence", "")
        cve_tags = match_cve_tags(actor, tags)

        risk = classify_ip_risk(data)
        rep_score = score_noise_reputation(data)
        risk_color = {"High Risk": "red", "Elevated Risk": "orange",
                      "Standard Target": "slate", "Low Risk (CDN/Cloud Provider)": "emerald",
                      "Informational": "blue"}.get(risk, "slate")
        noise_label = NOISE_CLASSIFICATIONS.get(classification, classification.title())

        findings.append(IntelligenceFinding(
            entity=f"{ip}: {noise_label}",
            type="GreyNoise: Noise Classification",
            source="GreyNoise",
            confidence=confidence.capitalize() if confidence else "Medium",
            color=risk_color,
            threat_level=risk,
            status=risk,
            resolution=f"Classification: {classification}, Severity: {severity}, Noise: {noise}, RIOT: {riot}",
            tags=["greynoise", f"classification-{classification}"]
        ))

        if actor:
            findings.append(IntelligenceFinding(
                entity=f"{actor}", type="GreyNoise: Actor",
                source="GreyNoise", confidence="Medium", color="orange",
                threat_level=risk, status="Actor Identified",
                resolution=f"Actor associated with {ip}",
                tags=["greynoise", "actor"]
            ))

        if tags:
            for tag in tags[:10]:
                findings.append(IntelligenceFinding(
                    entity=str(tag), type="GreyNoise: Tag",
                    source="GreyNoise", confidence="Medium", color="slate",
                    threat_level=risk, status="Tagged",
                    tags=["greynoise", "tag"]
                ))

        if last_seen:
            findings.append(IntelligenceFinding(
                entity=f"Last seen: {last_seen}", type="GreyNoise: Last Seen",
                source="GreyNoise", confidence="High", color="slate",
                threat_level="Informational", status="Timeline",
                tags=["greynoise"]
            ))
        if first_seen:
            findings.append(IntelligenceFinding(
                entity=f"First seen: {first_seen}", type="GreyNoise: First Seen",
                source="GreyNoise", confidence="High", color="slate",
                threat_level="Informational", status="Timeline",
                tags=["greynoise"]
            ))

        if severity:
            findings.append(IntelligenceFinding(
                entity=f"Severity: {severity}", type="GreyNoise: Severity",
                source="GreyNoise", confidence="High",
                color="red" if severity.lower() == "high" else ("orange" if severity.lower() == "medium" else "slate"),
                threat_level=risk, status=f"Severity {severity}",
                tags=["greynoise"]
            ))

        if noise:
            findings.append(IntelligenceFinding(
                entity=f"{ip} generates internet noise", type="GreyNoise: Noise Status",
                source="GreyNoise", confidence="High", color="orange",
                threat_level="Standard Target", status="Internet Noise",
                tags=["greynoise"]
            ))
        if riot:
            findings.append(IntelligenceFinding(
                entity=f"{ip} is a RIOT (CDN/SaaS provider)", type="GreyNoise: RIOT",
                source="GreyNoise", confidence="High", color="emerald",
                threat_level="Informational", status="Safe Provider",
                tags=["greynoise"]
            ))

        findings.append(IntelligenceFinding(
            entity=f"Reputation Score: {rep_score}/100",
            type="GreyNoise: IP Reputation",
            source="GreyNoise", confidence="High",
            color="emerald" if rep_score >= 70 else ("orange" if rep_score >= 40 else "red"),
            threat_level=risk, status="Scored",
            tags=["greynoise", "reputation"]
        ))

        for cve_tag in cve_tags:
            findings.append(IntelligenceFinding(
                entity=cve_tag, type="GreyNoise: CVE/Tag Pattern",
                source="GreyNoise", confidence="Medium", color="red",
                threat_level="Elevated Risk", status="CVE Pattern Match",
                tags=["greynoise", "cve", "threat"]
            ))

        if classification and classification not in ("unknown", "benign"):
            try:
                gnql_results = await gnql_search(f"ip:{ip}", client)
                for gnql_hit in gnql_results[:3]:
                    hit_ip = gnql_hit.get("ip", gnql_hit.get("address", ""))
                    hit_class = gnql_hit.get("classification", "")
                    hit_tags = gnql_hit.get("tags", [])
                    if hit_ip:
                        findings.append(IntelligenceFinding(
                            entity=f"GNQL: {hit_ip} ({hit_class})",
                            type="GreyNoise: GNQL Context",
                            source="GreyNoise", confidence="Medium", color="purple",
                            threat_level=risk, status="GNQL Result",
                            resolution=f"Tags: {', '.join(hit_tags[:5])}",
                            tags=["greynoise", "gnql"]
                        ))
            except:
                continue

    findings.append(IntelligenceFinding(
        entity=f"GreyNoise scan complete: {len(ips_to_check)} IPs checked, "
               f"{sum(1 for f in findings if 'High Risk' in (f.threat_level or ''))} high risk",
        type="GreyNoise Summary",
        source="GreyNoise",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["greynoise", "summary"]
    ))

    return findings
