import httpx
import re
from models import IntelligenceFinding
from urllib.parse import quote

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Advanced Dork List for Titan-Class Recon
    dorks = [
        {"type": "Directory Listing", "query": f"site:{domain} intitle:\"index of\""},
        {"type": "Exposed Config", "query": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini"},
        {"type": "Exposed Database", "query": f"site:{domain} ext:sql | ext:dbf | ext:mdb"},
        {"type": "Exposed Log Files", "query": f"site:{domain} ext:log"},
        {"type": "Backup Files", "query": f"site:{domain} ext:bkp | ext:bak | ext:old | ext:backup"},
        {"type": "Login/Admin Pages", "query": f"site:{domain} inurl:login | inurl:admin | inurl:manage"},
        {"type": "Exposed Documents", "query": f"site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx"}
    ]
    
    # Using DuckDuckGo HTML (No API Key required, high reliability for automated scraping)
    for dork in dorks:
        try:
            query_url = f"https://duckduckgo.com/html/?q={quote(dork['query'])}"
            resp = await client.get(query_url, timeout=10.0, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            })
            
            if resp.status_code == 200:
                # Extract links from DDG results
                links = re.findall(r"href=\"(https?://[^\"]+)\"", resp.text)
                found_links = set()
                
                for link in links:
                    if domain in link and "duckduckgo.com" not in link:
                        found_links.add(link)
                
                for link in list(found_links)[:5]: # Limit to top 5 results per dork for performance
                    findings.append(IntelligenceFinding(
                        entity=link,
                        type=f"Dork Result ({dork['type']})",
                        source="DorkEngine",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk" if "Config" in dork['type'] or "Database" in dork['type'] else "Informational",
                        status="Live",
                        raw_data=f"Query: {dork['query']}"
                    ))
        except Exception as e:
            continue
            
    return findings
