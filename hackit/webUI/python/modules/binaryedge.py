import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """BinaryEdge — queries their free API for exposed services and vulnerabilities."""
    findings = []
    try:
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get("events", []):
                if isinstance(event, str):
                    findings.append(IntelligenceFinding(
                        entity=event,
                        type="Subdomain",
                        source="BinaryEdge",
                        confidence="High",
                        color="blue"
                    ))
    except Exception as e:
        print(f"[BinaryEdge] Error: {e}")
    return findings
