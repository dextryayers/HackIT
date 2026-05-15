import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Robtex free passive DNS API — returns real forward DNS data."""
    findings = []
    try:
        url = f"https://freeapi.robtex.com/pdns/forward/{target}"
        resp = await client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for record in data:
                    rtype = record.get("rrtype", "")
                    rdata = record.get("rrdata", "")
                    rrname = record.get("rrname", target)
                    findings.append(IntelligenceFinding(
                        entity=rrname,
                        type=f"DNS {rtype} Record",
                        source="Robtex",
                        confidence="High",
                        color="blue",
                        resolution=rdata
                    ))
    except Exception as e:
        print(f"[Robtex] Error: {e}")
    return findings
