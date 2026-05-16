import httpx
import asyncio
from models import IntelligenceFinding

async def check_source(client, target, source_name, url):
    try:
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            
            is_malicious = False
            status_msg = "Clean"
            color = "emerald"
            threat_lvl = "Informational"
            
            if source_name == "ThreatCrowd":
                votes = data.get("votes", 0)
                if votes < 0: is_malicious = True
            elif source_name == "AlienVault OTX":
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                if pulse_count > 0: is_malicious = True
            elif source_name == "GreyNoise":
                noise = data.get("noise", False)
                riot = data.get("riot", False)
                if noise and not riot:
                    is_malicious = True
                    status_msg = "Internet Background Noise (Scanner/Bot)"
            
            if is_malicious:
                color = "red"
                threat_lvl = "High Risk"
                status_msg = "Malicious / Blacklisted"
                
            return IntelligenceFinding(
                entity=target,
                type="Threat Reputation",
                source=source_name,
                confidence="High",
                color=color,
                category="Threat Intelligence",
                threat_level=threat_lvl,
                status=status_msg,
                raw_data=str(data)[:1000]
            )
    except:
        pass
    return None

async def crawl(target, client):
    findings = []
    
    # Check Domain or IP
    intel_sources = [
        ("ThreatCrowd", f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"),
        ("AlienVault OTX", f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"),
        ("GreyNoise", f"https://api.greynoise.io/v3/community/{target}") # Only works if target is IP, will fail gracefully
    ]
    
    tasks = [check_source(client, target, name, url) for name, url in intel_sources]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r: findings.append(r)
        
    return findings
