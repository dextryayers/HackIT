import httpx
import asyncio
import json
from datetime import datetime
from typing import List
from models import IntelligenceFinding

GREYNOISE_API = "https://api.greynoise.io/v3"
GREYNOISE_RIOT = "https://api.greynoise.io/v3/riot"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

THREAT_SEVERITY = {
    "malicious": {"label": "Malicious", "color": "red", "level": "High Risk"},
    "suspicious": {"label": "Suspicious", "color": "orange", "level": "Elevated Risk"},
    "benign": {"label": "Benign", "color": "emerald", "level": "Informational"},
    "unknown": {"label": "Unknown", "color": "slate", "level": "Informational"},
}

CLASSIFICATION_WEIGHTS = {
    "spam": 10, "scanner": 15, "exploit": 30, "botnet": 35,
    "malware": 40, "phishing": 30, "ddos": 35, "c2": 45,
}

async def check_gnip(client: httpx.AsyncClient, ip: str) -> dict:
    result = {"raw": None, "noise": False, "classification": "", "tags": []}
    try:
        resp = await client.get(
            f"{GREYNOISE_API}/noise/context/{ip}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            result["raw"] = data
            result["noise"] = data.get("noise", False)
            result["classification"] = data.get("classification", "")
            result["tags"] = data.get("tags", [])
    except:
        pass
    return result

async def check_riot(client: httpx.AsyncClient, ip: str) -> dict:
    result = {"riot": False, "category": "", "name": "", "description": ""}
    try:
        resp = await client.get(
            f"{GREYNOISE_RIOT}/lookup/{ip}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            result["riot"] = data.get("riot", False)
            result["category"] = data.get("category", "")
            result["name"] = data.get("name", "")
            result["description"] = data.get("description", "")
    except:
        pass
    return result

async def check_gnql(client: httpx.AsyncClient, ip: str) -> dict:
    result = {"count": 0, "records": []}
    try:
        resp = await client.get(
            f"{GREYNOISE_API}/gnql?query=ip:{ip}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            result["count"] = data.get("count", 0)
            result["records"] = data.get("data", data.get("records", []))[:5]
    except:
        pass
    return result

async def check_gnql_multi(client: httpx.AsyncClient, ip: str) -> dict:
    result = {"records": []}
    queries = [f"ip:{ip}", f"destination_ip:{ip}", f"source_ip:{ip}"]
    for query in queries:
        try:
            resp = await client.get(
                f"{GREYNOISE_API}/gnql?query={query}",
                headers={"User-Agent": UA, "Accept": "application/json"},
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                result["records"].extend(data.get("data", data.get("records", []))[:3])
        except:
            pass
    return result

def calculate_threat_score(gnip_result: dict, riot_result: dict) -> int:
    score = 0
    if gnip_result.get("noise"):
        score += 40
    classification = gnip_result.get("classification", "")
    for cls, weight in CLASSIFICATION_WEIGHTS.items():
        if cls in classification.lower():
            score += weight
    if riot_result.get("riot"):
        score = 0
    return min(score, 100)

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    ip = target.strip().lower()
    if ip.startswith("http"):
        from urllib.parse import urlparse
        ip = urlparse(ip).netloc

    gnip_result = await check_gnip(client, ip)
    riot_result = await check_riot(client, ip)

    if gnip_result.get("raw"):
        data = gnip_result["raw"]
        noise = data.get("noise", False)
        classification = data.get("classification", "unknown")
        severity = THREAT_SEVERITY.get(classification, THREAT_SEVERITY["unknown"])

        findings.append(IntelligenceFinding(
            entity=f"GreyNoise classification: {classification}",
            type="GreyNoise IP Analysis",
            source="GreyNoise",
            confidence="High",
            color=severity["color"],
            threat_level=severity["level"],
            status="Noise" if noise else "Silent",
            resolution=ip,
            raw_data=json.dumps(data),
            tags=["greynoise", "ip-analysis", classification]
        ))

        if noise:
            findings.append(IntelligenceFinding(
                entity=f"Noise detected on internet scanners",
                type="GreyNoise Noise Status",
                source="GreyNoise",
                confidence="High",
                color=severity["color"],
                threat_level=severity["level"],
                status="Confirmed",
                resolution=ip,
                tags=["greynoise", "noise"]
            ))

        last_seen = data.get("last_seen", "")
        if last_seen:
            findings.append(IntelligenceFinding(
                entity=f"Last seen: {last_seen[:10]}",
                type="GreyNoise Last Seen",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Observed",
                resolution=ip,
                tags=["greynoise", "timeline"]
            ))

        first_seen = data.get("first_seen", "")
        if first_seen:
            findings.append(IntelligenceFinding(
                entity=f"First seen: {first_seen[:10]}",
                type="GreyNoise First Seen",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Observed",
                resolution=ip,
                tags=["greynoise", "timeline", "first-seen"]
            ))

        tags = data.get("tags", [])
        if tags:
            for tag in tags[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Tag: {tag}",
                    type="GreyNoise Tag",
                    source="GreyNoise",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Tagged",
                    resolution=ip,
                    tags=["greynoise", "tag", tag.lower().replace(" ", "-")]
                ))

        actor = data.get("actor", "")
        if actor:
            findings.append(IntelligenceFinding(
                entity=f"Actor: {actor}",
                type="GreyNoise Actor",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Identified",
                resolution=ip,
                tags=["greynoise", "actor", actor.lower().replace(" ", "-")]
            ))

        organization = data.get("organization", "")
        if organization:
            findings.append(IntelligenceFinding(
                entity=f"Organization: {organization}",
                type="GreyNoise Organization",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["greynoise", "organization"]
            ))

        cve_tags = [t for t in tags if "cve" in t.lower() or "CVE-" in t]
        if cve_tags:
            for cve_tag in cve_tags[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"CVE associated: {cve_tag}",
                    type="GreyNoise CVE Association",
                    source="GreyNoise",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Vulnerable",
                    resolution=ip,
                    tags=["greynoise", "cve", cve_tag.lower()]
                ))

        country = data.get("country", "")
        city = data.get("city", "")
        if country or city:
            loc = f"{city}, {country}" if city else country
            findings.append(IntelligenceFinding(
                entity=f"Location: {loc}",
                type="GreyNoise Geolocation",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["greynoise", "geo"]
            ))

        asn = data.get("asn", "")
        if asn:
            findings.append(IntelligenceFinding(
                entity=f"ASN: {asn}",
                type="GreyNoise ASN",
                source="GreyNoise",
                confidence="Medium",
                color="slate",
                status="Identified",
                resolution=ip,
                tags=["greynoise", "asn"]
            ))

    if riot_result.get("riot"):
        findings.append(IntelligenceFinding(
            entity=f"RIOT: {riot_result.get('name', 'Known service')}",
            type="GreyNoise RIOT",
            source="GreyNoise RIOT",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Trusted Service",
            resolution=ip,
            raw_data=json.dumps(riot_result),
            tags=["greynoise", "riot", "trusted"]
        ))

    threat_score = calculate_threat_score(gnip_result, riot_result)
    if threat_score > 0:
        score_level = "High Risk" if threat_score > 60 else ("Elevated Risk" if threat_score > 30 else "Informational")
        findings.append(IntelligenceFinding(
            entity=f"Threat score: {threat_score}/100",
            type="GreyNoise Threat Score",
            source="GreyNoise",
            confidence="Medium",
            color="red" if threat_score > 60 else "orange",
            threat_level=score_level,
            status=f"Score: {threat_score}",
            resolution=ip,
            tags=["greynoise", "threat-score"]
        ))

    gnql_result = await check_gnql(client, ip)
    if gnql_result.get("count", 0) > 0:
        findings.append(IntelligenceFinding(
            entity=f"{gnql_result['count']} GNQL records found",
            type="GreyNoise GNQL Query",
            source="GreyNoise",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Data Available",
            resolution=ip,
            tags=["greynoise", "gnql"]
        ))

    gnql_multi = await check_gnql_multi(client, ip)
    if gnql_multi.get("records"):
        findings.append(IntelligenceFinding(
            entity=f"{len(gnql_multi['records'])} multi-query GNQL records",
            type="GreyNoise Extended GNQL",
            source="GreyNoise",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Data Available",
            resolution=ip,
            tags=["greynoise", "gnql", "extended"]
        ))

    if not gnip_result.get("raw") and not riot_result.get("riot"):
        findings.append(IntelligenceFinding(
            entity="No GreyNoise data available",
            type="GreyNoise No Data",
            source="GreyNoise",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="No Data",
            resolution=ip,
            tags=["greynoise", "empty"]
        ))

    return findings
