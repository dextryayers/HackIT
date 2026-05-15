import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """ONYPHE — queries their free search API for exposed assets and vulnerabilities."""
    findings = []
    try:
        url = f"https://www.onyphe.io/api/v2/simple/resolver/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get("results", []):
                ip = result.get("ip", "")
                forward = result.get("forward", "")
                if ip:
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="IP Address",
                        source="ONYPHE",
                        confidence="High",
                        color="blue",
                        resolution=forward
                    ))
    except Exception as e:
        print(f"[ONYPHE] Error: {e}")
    return findings
