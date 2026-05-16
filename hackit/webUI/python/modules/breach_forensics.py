import httpx
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    
    # Logic inspired by sfp_leakix, sfp_haveibeenpwned
    # LeakIX is great for finding indexed leaks
    leakix_url = f"https://leakix.net/search?scope=leak&q={target}"
    headers = {"Accept": "application/json"}
    
    try:
        resp = await client.get(leakix_url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            for leak in data:
                event_type = leak.get("event_source", "Unknown Leak")
                leak_date = leak.get("time", "N/A")
                summary = leak.get("summary", "")
                
                findings.append(IntelligenceFinding(
                    entity=target,
                    type="Data Breach / Leak",
                    source="LeakIX Forensics",
                    confidence="High",
                    color="red",
                    category="Leak / Breach Analysis",
                    threat_level="High Risk",
                    status="Breached",
                    raw_data=f"Date: {leak_date} | Source: {event_type} | Summary: {summary}"
                ))
    except:
        pass
        
    # Simple check for Pastebin mentions (Concept from sfp_pastebin)
    try:
        paste_url = f"https://psbdmp.ws/api/search/{target}"
        resp = await client.get(paste_url, timeout=10.0)
        if resp.status_code == 200:
            pastes = resp.json()
            if pastes and isinstance(pastes, list):
                for p in pastes[:5]: # Limit to 5
                    findings.append(IntelligenceFinding(
                        entity=target,
                        type="Pastebin Mention",
                        source="PSBDMP.ws",
                        confidence="Medium",
                        color="orange",
                        category="Leak / Breach Analysis",
                        threat_level="Medium",
                        status="Exposed",
                        raw_data=f"Mention found in paste: https://pastebin.com/{p.get('id')}"
                    ))
    except:
        pass
        
    return findings
