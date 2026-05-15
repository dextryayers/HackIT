import httpx
from models import IntelligenceFinding
import re

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # 1. crt.sh (Certificate Transparency Logs)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await client.get(url, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    if sub.endswith(domain) and "*" not in sub:
                        subs.add(sub.strip().lower())
            
            for sub in subs:
                findings.append(IntelligenceFinding(
                    entity=sub,
                    type="Subdomain (Passive)",
                    source="crt.sh",
                    confidence="High",
                    color="emerald",
                    category="Domain & DNS Enumeration",
                    threat_level="Standard Target",
                    status="Existing",
                    raw_data=f"Found in Certificate Logs"
                ))
    except: pass

    # 2. Hackertarget (Passive DNS)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = await client.get(url, timeout=10.0)
        if resp.status_code == 200:
            lines = resp.text.split("\n")
            for line in lines:
                if "," in line:
                    sub, ip = line.split(",")
                    findings.append(IntelligenceFinding(
                        entity=sub,
                        type="Subdomain (Passive)",
                        source="Hackertarget",
                        confidence="High",
                        color="emerald",
                        category="Domain & DNS Enumeration",
                        threat_level="Standard Target",
                        status="Existing",
                        resolution=ip,
                        raw_data=f"Resolved to {ip} via passive DNS"
                    ))
    except: pass
    
    return findings
