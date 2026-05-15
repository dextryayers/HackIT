import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """SecurityTrails — uses their free community endpoint for subdomain enumeration."""
    findings = []
    try:
        # Free community API endpoint (limited)
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        headers = {"APIKEY": "guest", "Accept": "application/json"}
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                subdomain = f"{sub}.{target}"
                findings.append(IntelligenceFinding(
                    entity=subdomain,
                    type="Subdomain",
                    source="SecurityTrails",
                    confidence="High",
                    color="blue"
                ))
    except Exception as e:
        print(f"[SecurityTrails] Error: {e}")
    return findings
