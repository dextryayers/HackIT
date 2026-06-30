import httpx
import asyncio
import json
from datetime import datetime
from collections import defaultdict
from typing import List
from models import IntelligenceFinding

OTX_API = "https://otx.alienvault.com/api/v1"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def query_pulses(target: str, client: httpx.AsyncClient) -> dict:
    result = {"pulses": [], "indicators": [], "count": 0}
    try:
        resp = await client.get(
            f"{OTX_API}/indicators/IPv4/{target}/general",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            result["pulses"] = data.get("pulse_info", {}).get("pulses", [])
            result["indicators"] = data.get("indicator", [])
            result["count"] = data.get("pulse_info", {}).get("count", 0)
    except:
        pass
    return result

async def query_pulse_details(pulse_id: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{OTX_API}/pulses/{pulse_id}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_subscribed(client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"{OTX_API}/pulses/subscribed?limit=20",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json().get("results", [])
    except:
        pass
    return []

async def query_indicators_by_type(target: str, indicator_type: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{OTX_API}/indicators/{indicator_type}/{target}/general",
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
    query = target.strip().lower()

    result = await query_pulses(query, client)
    pulse_count = result.get("count", 0)
    pulses = result.get("pulses", [])
    indicators = result.get("indicators", [])

    if pulse_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"{pulse_count} associated OTX pulses",
            type="OTX Pulse Count",
            source="AlienVault OTX",
            confidence="High",
            color="red" if pulse_count > 5 else "orange",
            threat_level="High Risk" if pulse_count > 5 else "Elevated Risk",
            status=f"{pulse_count} pulses",
            resolution=query,
            tags=["otx", "pulse", "count"]
        ))

        for pulse in pulses[:10]:
            pulse_id = pulse.get("id", "")
            pulse_name = pulse.get("name", "Unnamed Pulse")
            pulse_desc = pulse.get("description", "")
            threat_type = pulse.get("threat_type", "unknown")
            tags = pulse.get("tags", [])
            created = pulse.get("created", "")
            author = pulse.get("author", {}).get("username", "Unknown")

            findings.append(IntelligenceFinding(
                entity=pulse_name[:200],
                type="OTX Pulse",
                source="AlienVault OTX",
                confidence="Medium",
                color="red" if threat_type != "unknown" else "orange",
                threat_level="High Risk" if threat_type != "unknown" else "Elevated Risk",
                status="Active" if pulse.get("is_active", True) else "Inactive",
                resolution=query,
                raw_data=f"Author: {author} | Type: {threat_type} | Created: {created} | Tags: {','.join(tags[:5])}",
                tags=["otx", "pulse", threat_type] + [t.lower() for t in tags[:3]]
            ))

            if pulse_desc:
                findings.append(IntelligenceFinding(
                    entity=f"Pulse description: {pulse_desc[:200]}",
                    type="OTX Pulse Detail",
                    source="AlienVault OTX",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Detail Available",
                    resolution=query,
                    tags=["otx", "detail"]
                ))

            if tags:
                for tag in tags[:3]:
                    findings.append(IntelligenceFinding(
                        entity=f"Tag: {tag}",
                        type="OTX Pulse Tag",
                        source="AlienVault OTX",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        status="Tagged",
                        resolution=query,
                        tags=["otx", "tag", tag.lower()]
                    ))

        pulse_types = defaultdict(int)
        for p in pulses:
            t = p.get("threat_type", "unknown")
            pulse_types[t] += 1
        if pulse_types:
            pt_summary = ", ".join(f"{k}: {v}" for k, v in sorted(pulse_types.items(), key=lambda x: -x[1]))
            findings.append(IntelligenceFinding(
                entity=f"Threat type distribution: {pt_summary}",
                type="OTX Threat Type Distribution",
                source="AlienVault OTX",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                resolution=query,
                tags=["otx", "distribution"]
            ))

    if indicators:
        findings.append(IntelligenceFinding(
            entity=f"{len(indicators)} indicators associated with {query}",
            type="OTX Indicator Count",
            source="AlienVault OTX",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status=f"{len(indicators)} indicators",
            resolution=query,
            tags=["otx", "indicator", "count"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No OTX data found for target",
            type="OTX Check Complete",
            source="AlienVault OTX",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["otx", "clean"]
        ))

    return findings
