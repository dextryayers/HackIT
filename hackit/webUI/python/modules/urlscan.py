import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
        resp = await client.get(url)
        if resp.status_code == 200:
            for item in resp.json().get('results', []):
                task = item.get('task', {})
                findings.append(IntelligenceFinding(
                    entity=task.get('url'), 
                    type="Web Page", 
                    source="URLScan", 
                    confidence="Medium", 
                    color="slate"
                ))
    except: pass
    return findings
