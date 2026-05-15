import httpx
import re
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """PublicWWW — queries for source code snippets and tracking IDs on public websites."""
    findings = []
    try:
        url = f"https://publicwww.com/websites/{target}/"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            # Extract domain results from the HTML
            domains = re.findall(r'href="https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"', resp.text)
            seen = set()
            for domain in domains:
                if domain not in seen and target in domain:
                    seen.add(domain)
                    findings.append(IntelligenceFinding(
                        entity=domain,
                        type="Linked Domain",
                        source="PublicWWW",
                        confidence="Medium",
                        color="orange"
                    ))
    except Exception as e:
        print(f"[PublicWWW] Error: {e}")
    return findings
