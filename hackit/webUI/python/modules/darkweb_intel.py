import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # 1. Ahmia.fi (Clearnet interface for Onion search)
    try:
        url = f"https://ahmia.fi/search/?q={domain}"
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            onion_links = re.findall(r"([a-z2-7]{16,56}\.onion)", resp.text)
            for onion in list(set(onion_links))[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"http://{onion}",
                    type="Dark Web Mention",
                    source="Ahmia",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Live",
                    raw_data=f"Domain found in Tor search results"
                ))
    except: pass

    # 2. Ransomware Leak Site Mentions (Simulated via search dorks)
    try:
        dork = f"\"{domain}\" site:onion.ly | site:onion.pet"
        url = f"https://duckduckgo.com/html/?q={dork}"
        resp = await client.get(url, timeout=10.0)
        if domain in resp.text:
             findings.append(IntelligenceFinding(
                entity=target,
                type="Threat Actor Mention",
                source="DarkWebIntel",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Detected",
                raw_data="Mentions found on Tor proxy sites"
            ))
    except: pass
    
    return findings
