import httpx
import re
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    
    # Logic from sfp_webanalytics, sfp_google_tag_manager, etc.
    patterns = {
        "Google Analytics UA": r"UA-\d+-\d+",
        "Google Analytics 4": r"G-[\w\d]+",
        "Google Tag Manager": r"GTM-[\w\d]+",
        "Google AdSense": r"ca-pub-\d+",
        "AddThis": r"ra-[\w\d]+",
        "Facebook Pixel": r"fbq\('init',\s*'(\d+)'\)",
        "Mailchimp": r"mc-[\w\d]+",
        "HubSpot": r"hs-[\w\d]+",
    }
    
    try:
        # Fetch the homepage content
        url = f"https://{target}" if not target.startswith("http") else target
        resp = await client.get(url, timeout=10.0, follow_redirects=True)
        
        if resp.status_code == 200:
            content = resp.text
            
            for tracker_name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    unique_matches = set(matches)
                    for match in unique_matches:
                        # For Facebook Pixel, the regex captures the ID in group 1
                        if isinstance(match, tuple):
                            match = match[0]
                            
                        findings.append(IntelligenceFinding(
                            entity=match,
                            type="Web Tracker ID",
                            source="Tracker Identity Mapper",
                            confidence="Certain",
                            color="cyan",
                            category="Identity Mapping",
                            threat_level="Informational",
                            status="Detected",
                            raw_data=f"Found {tracker_name} ID: {match}. This ID can be used to find related websites owned by the same organization."
                        ))
                        
            # Safe Browsing check (Simulated concept from sfp_googlesafebrowsing)
            # In a real scenario, you'd call the Safe Browsing API.
            # We'll just look for malware warning patterns in headers or body if any.
            
    except Exception as e:
        pass
        
    return findings
