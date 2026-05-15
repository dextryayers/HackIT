import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    # 1. robots.txt
    try:
        resp = await client.get(f"{base_url}/robots.txt", timeout=5.0)
        if resp.status_code == 200:
            findings.append(IntelligenceFinding(
                entity=f"{base_url}/robots.txt",
                type="Crawl Policy",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Detected",
                raw_data=resp.text[:1000]
            ))
            
            # Find Disallow paths
            disallowed = re.findall(r"Disallow: (.+)", resp.text)
            for path in disallowed[:10]: # Limit to 10
                findings.append(IntelligenceFinding(
                    entity=path.strip(),
                    type="Hidden Path (Disallowed)",
                    source="CrawlerCore",
                    confidence="High",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    raw_data=f"Found in robots.txt"
                ))
    except: pass

    # 2. sitemap.xml
    try:
        resp = await client.get(f"{base_url}/sitemap.xml", timeout=5.0)
        if resp.status_code == 200:
            findings.append(IntelligenceFinding(
                entity=f"{base_url}/sitemap.xml",
                type="Sitemap",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Detected",
                raw_data=resp.text[:1000]
            ))
    except: pass
    
    return findings
