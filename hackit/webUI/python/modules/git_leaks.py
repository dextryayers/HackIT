import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # 1. Grep.app Search (Public API/Web interface)
    try:
        # grep.app uses a direct search URL
        url = f"https://grep.app/search?q={domain}"
        resp = await client.get(url, timeout=10.0)
        
        if resp.status_code == 200:
            # Look for repository links
            repos = re.findall(r"href=\"/repository/([^\"]+)\"", resp.text)
            for repo in list(set(repos))[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"https://github.com/{repo}",
                    type="Git Repository",
                    source="GrepApp",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Public",
                    raw_data=f"Mentioned in code search for {domain}"
                ))
    except: pass

    # 2. Search for Git Configs via dorks (Handled by DorkEngine, but we add more specific here)
    try:
        dork = f"site:github.com \"{domain}\""
        url = f"https://duckduckgo.com/html/?q={dork}"
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            code_links = re.findall(r"https://github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/blob/[^\s\"]+", resp.text)
            for link in list(set(code_links))[:5]:
                findings.append(IntelligenceFinding(
                    entity=link,
                    type="Source Code Leak",
                    source="GitLeaks",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Live",
                    raw_data=f"Domain mention found in file content"
                ))
    except: pass
    
    return findings
