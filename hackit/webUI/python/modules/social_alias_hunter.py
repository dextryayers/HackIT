import httpx
import asyncio
import hashlib
from models import IntelligenceFinding

async def check_platform(client, name, url, username):
    try:
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200 and "404" not in resp.text:
            return IntelligenceFinding(
                entity=username,
                type="Social Alias Profile",
                source=name,
                confidence="High",
                color="pink",
                category="Social Engineering",
                threat_level="Informational",
                status="Profile Found",
                raw_data=f"Potential alias match at: {url}"
            )
    except:
        pass
    return None

async def crawl(target, client):
    findings = []
    
    # 1. Gravatar Email Hash Check
    # If target resembles an email, check Gravatar. If domain, check common admin emails.
    emails_to_check = []
    if "@" in target:
        emails_to_check.append(target)
    else:
        emails_to_check.extend([f"admin@{target}", f"contact@{target}", f"info@{target}"])
        
    for email in emails_to_check:
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://en.gravatar.com/{email_hash}.json"
        
        try:
            resp = await client.get(gravatar_url, timeout=7.0)
            if resp.status_code == 200:
                data = resp.json()
                if "entry" in data and len(data["entry"]) > 0:
                    entry = data["entry"][0]
                    display_name = entry.get("displayName", "")
                    profile_url = entry.get("profileUrl", "")
                    photos = entry.get("photos", [])
                    photo_url = photos[0].get("value", "") if photos else ""
                    
                    details = f"Name: {display_name}\nProfile: {profile_url}\nAvatar: {photo_url}"
                    findings.append(IntelligenceFinding(
                        entity=email,
                        type="Gravatar Identity",
                        source="Gravatar OSINT",
                        confidence="Certain",
                        color="purple",
                        category="Social Engineering",
                        threat_level="High Risk" if display_name else "Informational",
                        status="Identity Leak",
                        raw_data=details
                    ))
        except:
            pass

    # 2. Social Alias Username Check
    # Extract the base word from the domain to use as a username alias
    base_name = target.split('.')[0] if '.' in target else target
    
    platforms = [
        ("GitHub", f"https://api.github.com/users/{base_name}"),
        ("HackerOne", f"https://hackerone.com/{base_name}"),
        ("Keybase", f"https://keybase.io/{base_name}/key.asc")
    ]
    
    tasks = [check_platform(client, p[0], p[1], base_name) for p in platforms]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r:
            findings.append(r)
            
    return findings
