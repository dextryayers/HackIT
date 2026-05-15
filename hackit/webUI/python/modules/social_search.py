import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # Dorking patterns for social media
    dorks = [
        f"site:linkedin.com \"{org_name}\"",
        f"site:twitter.com \"{org_name}\"",
        f"site:facebook.com \"{org_name}\"",
        f"site:github.com \"{org_name}\""
    ]
    
    # Using DuckDuckGo HTML for dorking (no API key needed)
    for dork in dorks:
        try:
            url = f"https://duckduckgo.com/html/?q={dork}"
            resp = await client.get(url, timeout=10.0, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            })
            
            # Simple regex to find links that look like social profiles
            social_links = re.findall(r"https?://(?:www\.)?(?:linkedin|twitter|facebook|github)\.com/[a-zA-Z0-9._%+-/]+", resp.text)
            
            for link in set(social_links):
                if org_name.lower() in link.lower():
                    findings.append(IntelligenceFinding(
                        entity=link,
                        type="Social Media Profile",
                        source="SocialSearch",
                        confidence="High",
                        color="purple",
                        category="Username & Social OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Found via dork: {dork}"
                    ))
        except: continue
        
    return findings
