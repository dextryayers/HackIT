import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # LeakIX API (Public endpoint for domain/IP)
    # They have a free tier that allows searching for host information
    try:
        # Search by host
        url = f"https://leakix.net/search?scope=leak&q={domain}"
        # LeakIX uses a specific JSON structure in their API, but we'll use the search UI scraper for speed/no-key
        resp = await client.get(url, timeout=10.0, headers={"Accept": "application/json"})
        
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                event_type = entry.get("event_type", "Leak")
                summary = entry.get("summary", "No summary")
                ip = entry.get("ip", "Unknown IP")
                
                findings.append(IntelligenceFinding(
                    entity=f"{ip} ({event_type})",
                    type="Exposure Leak",
                    source="LeakIX",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Live",
                    resolution=summary,
                    raw_data=str(entry)
                ))
    except:
        # Fallback to general host info if search fails
        pass
        
    return findings
