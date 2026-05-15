import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """WiGLE — queries for wireless network info near target (needs API key for full data)."""
    findings = []
    try:
        url = f"https://api.wigle.net/api/v2/network/search?ssid={target}&first=0&resultsPerPage=10"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for net in data.get("results", []):
                ssid = net.get("ssid", "")
                mac = net.get("netid", "")
                encryption = net.get("encryption", "unknown")
                if ssid:
                    findings.append(IntelligenceFinding(
                        entity=f"{ssid} ({mac})",
                        type="Wireless Network",
                        source="WiGLE",
                        confidence="Medium",
                        color="slate",
                        resolution=f"Encryption: {encryption}"
                    ))
    except Exception as e:
        print(f"[WiGLE] Error: {e}")
    return findings
