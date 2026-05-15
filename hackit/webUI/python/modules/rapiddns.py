import httpx
import re
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        url = f"https://rapiddns.io/subdomain/{target}?full=1"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            # Parse HTML table rows for subdomains
            matches = re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(target) + r')</td>', resp.text)
            seen = set()
            for subdomain in matches:
                if subdomain not in seen:
                    seen.add(subdomain)
                    findings.append(IntelligenceFinding(
                        entity=subdomain,
                        type="Subdomain",
                        source="RapidDNS",
                        confidence="High",
                        color="blue"
                    ))
    except Exception as e:
        print(f"[RapidDNS] Error: {e}")
    return findings
