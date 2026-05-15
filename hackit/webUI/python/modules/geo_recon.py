import httpx
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # 1. Wigle.net WiFi Search (Passive info if domain is mentioned in SSID)
    try:
        # Wigle has an API but for now we search for common corporate SSID patterns
        common_ssids = [f"{org_name}_Guest", f"{org_name}_Internal", f"{org_name}_WiFi"]
        for ssid in common_ssids:
            # We add it as a "Target SSID" for future Wigle lookups
            findings.append(IntelligenceFinding(
                entity=ssid,
                type="WiFi SSID (Target)",
                source="GeoRecon",
                confidence="Medium",
                color="slate",
                status="Potential",
                raw_data=f"Common corporate pattern for {org_name}"
            ))
    except: pass

    # 2. IP Geolocation (Using ip-api.com)
    try:
        import socket
        ip = await asyncio.get_event_loop().run_in_executor(None, lambda: socket.gethostbyname(domain))
        url = f"http://ip-api.com/json/{ip}"
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            findings.append(IntelligenceFinding(
                entity=f"{data.get('city')}, {data.get('country')}",
                type="Geolocation",
                source="IP-API",
                confidence="High",
                color="emerald",
                status="Live",
                resolution=f"Lat: {data.get('lat')}, Lon: {data.get('lon')}",
                raw_data=str(data)
            ))
    except: pass
    
    return findings
