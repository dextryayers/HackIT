import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey"
        resp = await client.get(url)
        if resp.status_code == 200:
            for item in resp.json()[1:]:
                findings.append(IntelligenceFinding(
                    entity=item[2], 
                    type="Archived URL", 
                    source="Wayback Machine", 
                    confidence="Medium", 
                    color="slate"
                ))
    except: pass
    return findings
