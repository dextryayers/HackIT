import httpx
import socket
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """GreyNoise — queries the free community API to check if an IP is a known scanner."""
    findings = []
    try:
        import asyncio
        ip = await asyncio.get_event_loop().run_in_executor(None, lambda: socket.gethostbyname(target))
        
        url = f"https://api.greynoise.io/v3/community/{ip}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            noise = data.get("noise", False)
            riot = data.get("riot", False)
            classification = data.get("classification", "unknown")
            name = data.get("name", "")
            
            findings.append(IntelligenceFinding(
                entity=ip,
                type="IP Reputation",
                source="GreyNoise",
                confidence="High",
                color="red" if noise else "emerald",
                threat_level="High Risk" if classification == "malicious" else "Informational",
                resolution=f"Noise: {noise}, RIOT: {riot}, Class: {classification}, Name: {name}"
            ))
    except Exception as e:
        print(f"[GreyNoise] Error: {e}")
    return findings
