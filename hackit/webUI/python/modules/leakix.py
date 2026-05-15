import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """LeakIX — queries the free subdomains API for exposed services."""
    findings = []
    try:
        url = f"https://leakix.net/api/subdomains/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    sub = item.get("subdomain", "") or item
                    if isinstance(sub, str) and sub:
                        findings.append(IntelligenceFinding(
                            entity=sub,
                            type="Subdomain",
                            source="LeakIX",
                            confidence="High",
                            color="blue"
                        ))
    except Exception as e:
        print(f"[LeakIX] Error: {e}")
    return findings
