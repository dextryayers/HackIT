import httpx
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        resp = await client.get(url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if ',' in line:
                    host, ip = line.split(',')
                    findings.append(IntelligenceFinding(
                        entity=host, 
                        type="Subdomain", 
                        source="HackerTarget", 
                        confidence="High", 
                        color="blue",
                        resolution=ip
                    ))
    except: pass
    return findings
