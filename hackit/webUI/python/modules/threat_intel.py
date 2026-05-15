import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    # If target is a domain, we might need its IP for some intel checks
    # But many intel sources support domains too
    
    intel_sources = [
        {"name": "ThreatCrowd", "url": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"},
        {"name": "AlienVault OTX", "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"}
    ]
    
    for source in intel_sources:
        try:
            resp = await client.get(source["url"], timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                
                # Basic heuristics for threat detection
                is_malicious = False
                if source["name"] == "ThreatCrowd":
                    votes = data.get("votes", 0)
                    if votes < 0: is_malicious = True
                elif source["name"] == "AlienVault OTX":
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    if pulse_count > 0: is_malicious = True
                
                findings.append(IntelligenceFinding(
                    entity=target,
                    type="Threat Reputation",
                    source=source["name"],
                    confidence="High" if is_malicious else "Medium",
                    color="red" if is_malicious else "emerald",
                    category="Threat Intelligence",
                    threat_level="High Risk" if is_malicious else "Informational",
                    status="Malicious" if is_malicious else "Clean",
                    raw_data=str(data)[:1000]
                ))
        except: continue
        
    return findings
