import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        resp = await client.get(url)
        if resp.status_code == 200:
            for item in resp.json():
                findings.append(IntelligenceFinding(
                    entity=item['common_name'], 
                    type="Subdomain", 
                    source="CRT.sh", 
                    confidence="High", 
                    color="blue"
                ))
    except: pass
    return findings
