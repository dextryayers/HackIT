import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """FullHunt — queries the attack surface API for subdomains and exposed services."""
    findings = []
    try:
        url = f"https://fullhunt.io/api/v1/domain/{target}/subdomains"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for host in data.get("hosts", []):
                findings.append(IntelligenceFinding(
                    entity=host,
                    type="Subdomain",
                    source="FullHunt",
                    confidence="High",
                    color="blue"
                ))
            # Domain metadata
            domain_info = data.get("metadata", {})
            if domain_info.get("organization"):
                findings.append(IntelligenceFinding(
                    entity=domain_info["organization"],
                    type="Organization",
                    source="FullHunt",
                    confidence="High",
                    color="emerald"
                ))
    except Exception as e:
        print(f"[FullHunt] Error: {e}")
    return findings
