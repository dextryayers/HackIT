import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """ZoomEye — queries their web search API for exposed hosts and services."""
    findings = []
    try:
        url = f"https://api.zoomeye.hk/web/search?query=site:{target}&page=1"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for match in data.get("matches", []):
                site = match.get("site", "")
                ip_list = match.get("ip", [])
                title = match.get("title", "")
                if site:
                    findings.append(IntelligenceFinding(
                        entity=site,
                        type="Web Asset",
                        source="ZoomEye",
                        confidence="High",
                        color="blue",
                        resolution=str(ip_list[0]) if ip_list else ""
                    ))
                if title:
                    findings.append(IntelligenceFinding(
                        entity=f"{site} — {title}",
                        type="Web Page",
                        source="ZoomEye",
                        confidence="Medium",
                        color="slate"
                    ))
    except Exception as e:
        print(f"[ZoomEye] Error: {e}")
    return findings
