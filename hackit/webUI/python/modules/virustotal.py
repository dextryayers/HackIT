import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """VirusTotal — queries domain relationships via the public v3 API."""
    findings = []
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=20"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", []):
                subdomain = item.get("id", "")
                if subdomain:
                    findings.append(IntelligenceFinding(
                        entity=subdomain,
                        type="Subdomain",
                        source="VirusTotal",
                        confidence="High",
                        color="blue"
                    ))
        # Also try the community resolutions endpoint
        url2 = f"https://www.virustotal.com/api/v3/domains/{target}/resolutions?limit=10"
        resp2 = await client.get(url2, headers={"User-Agent": "Mozilla/5.0"})
        if resp2.status_code == 200:
            data2 = resp2.json()
            for item in data2.get("data", []):
                attrs = item.get("attributes", {})
                ip = attrs.get("ip_address", "")
                if ip:
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="IP Address",
                        source="VirusTotal",
                        confidence="High",
                        color="blue",
                        resolution=f"Resolved from {target}"
                    ))
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")
    return findings
