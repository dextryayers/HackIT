import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        resp = await client.get(url)
        if resp.status_code == 200:
            for item in resp.json().get('passive_dns', []):
                findings.append(IntelligenceFinding(
                    entity=item['hostname'], 
                    type="Subdomain", 
                    source="AlienVault OTX", 
                    confidence="High", 
                    color="blue", 
                    resolution=item['address']
                ))
    except: pass
    return findings
