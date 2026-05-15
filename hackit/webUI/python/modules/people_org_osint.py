import httpx
from models import IntelligenceFinding
import re
from urllib.parse import quote

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # 1. LinkedIn Employee Mapping (via DuckDuckGo)
    try:
        query = f"site:linkedin.com/in/ \"{org_name}\""
        url = f"https://duckduckgo.com/html/?q={quote(query)}"
        
        # Simple fetch
        resp = await client.get(f"https://duckduckgo.com/html/?q={org_name}+linkedin+employees", timeout=10.0)
        
        # Look for names in result titles
        names = re.findall(r"([A-Z][a-z]+ [A-Z][a-z]+) - [^<]+LinkedIn", resp.text)
        for name in list(set(names))[:10]:
            findings.append(IntelligenceFinding(
                entity=name,
                type="Employee Profile",
                source="LinkedIn Scraper",
                confidence="Medium",
                color="purple",
                status="Active",
                raw_data=f"Mentioned as employee of {org_name}"
            ))
    except: pass

    # 2. WhoisXML style Org info
    try:
        # Check for subsidiaries/branch mentions
        dork = f"\"{org_name}\" subsidiaries | branches | office locations"
        resp = await client.get(f"https://duckduckgo.com/html/?q={org_name}+locations", timeout=10.0)
        if "office" in resp.text.lower():
             findings.append(IntelligenceFinding(
                entity=f"{org_name} Global Presence",
                type="Organization Relationship",
                source="OrgRecon",
                confidence="Medium",
                color="slate",
                status="Detected",
                raw_data="Mentions of branches/offices found"
            ))
    except: pass
    
    return findings
