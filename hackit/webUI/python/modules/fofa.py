import httpx
import base64
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """FOFA — queries the FOFA search engine for internet-exposed assets."""
    findings = []
    try:
        # FOFA uses base64-encoded queries
        query = base64.b64encode(f'domain="{target}"'.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?qbase64={query}&size=20"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get("results", []):
                if isinstance(result, list) and len(result) >= 2:
                    host = result[0]
                    ip = result[1] if len(result) > 1 else ""
                    findings.append(IntelligenceFinding(
                        entity=host,
                        type="Network Asset",
                        source="FOFA",
                        confidence="High",
                        color="red",
                        resolution=ip
                    ))
    except Exception as e:
        print(f"[FOFA] Error: {e}")
    return findings
