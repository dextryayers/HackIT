import httpx
import re
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Search engine scrapers for email discovery (Bing & DuckDuckGo)
    # Using dorks like "@domain.com"
    engines = [
        {"name": "Bing", "url": f"https://www.bing.com/search?q=%22@{domain}%22"},
        {"name": "DuckDuckGo", "url": f"https://duckduckgo.com/html/?q=%22@{domain}%22"}
    ]
    
    email_regex = r"[a-zA-Z0-9._%+-]+@" + re.escape(domain)
    
    for engine in engines:
        try:
            resp = await client.get(engine["url"], timeout=10.0, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            })
            
            matches = re.findall(email_regex, resp.text, re.IGNORECASE)
            for email in set(matches):
                findings.append(IntelligenceFinding(
                    entity=email.lower(),
                    type="Email Address",
                    source=f"EmailHarvester ({engine['name']})",
                    confidence="High",
                    color="cyan",
                    category="Person Name", # Categorize under Person for SpiderFoot grouping
                    threat_level="Informational",
                    raw_data=f"Found via {engine['name']} dork"
                ))
        except: continue
        
    return findings
