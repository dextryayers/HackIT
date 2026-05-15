import httpx
import re
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """ViewDNS reverse IP lookup — scrapes shared hosting neighbors."""
    findings = []
    try:
        url = f"https://viewdns.info/reverseip/?host={target}&t=1"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            # Parse table rows for domain names
            domains = re.findall(r'<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>', resp.text)
            seen = set()
            for domain in domains:
                if domain not in seen and domain != target:
                    seen.add(domain)
                    findings.append(IntelligenceFinding(
                        entity=domain,
                        type="Shared Hosting",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate"
                    ))
    except Exception as e:
        print(f"[ViewDNS] Error: {e}")
    return findings
