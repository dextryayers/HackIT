import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    handle = domain.split(".")[0]
    
    # List of high-impact social platforms
    platforms = [
        {"name": "GitHub", "url": f"https://github.com/{handle}"},
        {"name": "Twitter", "url": f"https://twitter.com/{handle}"},
        {"name": "LinkedIn", "url": f"https://www.linkedin.com/company/{handle}"},
        {"name": "Facebook", "url": f"https://www.facebook.com/{handle}"},
        {"name": "Instagram", "url": f"https://www.instagram.com/{handle}/"},
        {"name": "YouTube", "url": f"https://www.youtube.com/@{handle}"},
        {"name": "Pinterest", "url": f"https://www.pinterest.com/{handle}/"},
        {"name": "Medium", "url": f"https://medium.com/@{handle}"}
    ]
    
    async def check_platform(p):
        try:
            resp = await client.get(p["url"], timeout=5.0, follow_redirects=True)
            # Basic check: 200 OK often means profile exists. 
            # Some sites return 200 for "Not Found" but we'll try to detect it.
            if resp.status_code == 200:
                text = resp.text.lower()
                is_valid = True
                if "page not found" in text or "404" in text or "doesn't exist" in text:
                    is_valid = False
                
                if is_valid:
                    return IntelligenceFinding(
                        entity=p["url"],
                        type="Social Profile",
                        source="WhatsMyName",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Profile detected on {p['name']}"
                    )
        except: pass
        return None

    import asyncio
    results = await asyncio.gather(*[check_platform(p) for p in platforms])
    findings.extend([r for r in results if r])
    
    return findings
