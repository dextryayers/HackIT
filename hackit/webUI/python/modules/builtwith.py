import httpx
import re
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """BuiltWith — scrapes technology stack detection from the public page."""
    findings = []
    try:
        url = f"https://builtwith.com/{target}"
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            # Extract technology names from the page
            tech_matches = re.findall(r'<h2[^>]*>([^<]+)</h2>', resp.text)
            detail_matches = re.findall(r'class="techItem"[^>]*>.*?<a[^>]*>([^<]+)</a>', resp.text, re.DOTALL)
            
            seen = set()
            for tech in detail_matches[:30]:
                tech = tech.strip()
                if tech and tech not in seen and len(tech) > 2:
                    seen.add(tech)
                    findings.append(IntelligenceFinding(
                        entity=tech,
                        type="Tech Stack",
                        source="BuiltWith",
                        confidence="High",
                        color="orange"
                    ))
            # Category headers
            for cat in tech_matches[:10]:
                cat = cat.strip()
                if cat and "BuiltWith" not in cat and len(cat) > 3:
                    findings.append(IntelligenceFinding(
                        entity=cat,
                        type="Tech Category",
                        source="BuiltWith",
                        confidence="Medium",
                        color="orange"
                    ))
    except Exception as e:
        print(f"[BuiltWith] Error: {e}")
    return findings
