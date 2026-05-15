import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Netlas.io — queries their search API for internet-facing assets."""
    findings = []
    try:
        url = f"https://app.netlas.io/api/domains/?q={target}&source_type=include&start=0&count=20"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                domain = item.get("data", {}).get("domain", "")
                a_records = item.get("data", {}).get("a", [])
                if domain:
                    findings.append(IntelligenceFinding(
                        entity=domain,
                        type="Subdomain",
                        source="Netlas.io",
                        confidence="High",
                        color="blue",
                        resolution=str(a_records[0]) if a_records else ""
                    ))
    except Exception as e:
        print(f"[Netlas] Error: {e}")
    return findings
