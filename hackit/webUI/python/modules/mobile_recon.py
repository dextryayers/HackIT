import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    
    # 1. Google Play Store Search
    try:
        url = f"https://play.google.com/store/search?q={org_name}&c=apps"
        resp = await client.get(url, timeout=10.0)
        # Find package names (com.org.app)
        packages = re.findall(r"details\?id=([a-zA-Z0-9\._]+)", resp.text)
        for pkg in list(set(packages))[:5]:
            findings.append(IntelligenceFinding(
                entity=pkg,
                type="Mobile App (Android)",
                source="Google Play",
                confidence="High",
                color="indigo",
                status="Published",
                raw_data=f"Package ID: {pkg}"
            ))
    except: pass

    # 2. Firebase Config Exposure
    try:
        # Common firebase URLs
        fb_url = f"https://{org_name}.firebaseio.com/.json"
        resp = await client.get(fb_url, timeout=5.0)
        if resp.status_code == 200:
            findings.append(IntelligenceFinding(
                entity=fb_url,
                type="Mobile/Cloud Backend (Firebase)",
                source="MobileRecon",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Open",
                raw_data=resp.text[:500]
            ))
    except: pass
    
    return findings
