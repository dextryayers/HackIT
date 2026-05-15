import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Censys — uses the free search.censys.io hosts search API."""
    findings = []
    try:
        url = f"https://search.censys.io/api/v2/hosts/search?q={target}&per_page=25"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip", "")
                services = hit.get("services", [])
                if ip:
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="IP Address",
                        source="Censys",
                        confidence="High",
                        color="blue"
                    ))
                for svc in services:
                    port = svc.get("port", "")
                    svc_name = svc.get("service_name", "unknown")
                    if port:
                        findings.append(IntelligenceFinding(
                            entity=f"{ip}:{port} ({svc_name})",
                            type="Open Port",
                            source="Censys",
                            confidence="High",
                            color="red",
                            threat_level="Elevated Risk"
                        ))
    except Exception as e:
        print(f"[Censys] Error: {e}")
    return findings
