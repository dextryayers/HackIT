import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Hunter.how — queries their search API for internet-connected assets."""
    findings = []
    try:
        url = f"https://hunter.how/api/web/search?query={target}&page=1&page_size=20"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", {}).get("list", []):
                ip = item.get("ip", "")
                port = item.get("port", "")
                domain = item.get("domain", "")
                if domain:
                    findings.append(IntelligenceFinding(
                        entity=domain,
                        type="Subdomain",
                        source="Hunter.how",
                        confidence="Medium",
                        color="blue",
                        resolution=ip
                    ))
                if ip and port:
                    findings.append(IntelligenceFinding(
                        entity=f"{ip}:{port}",
                        type="Open Port",
                        source="Hunter.how",
                        confidence="Medium",
                        color="red"
                    ))
    except Exception as e:
        print(f"[Hunter.how] Error: {e}")
    return findings
