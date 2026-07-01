import httpx
import re
import json
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    identifier = target.strip()

    page = None
    page_url = None

    if identifier.startswith("https://www.facebook.com/") or identifier.startswith("https://facebook.com/"):
        page_url = identifier.rstrip("/")
    elif identifier.startswith("fb.com/"):
        page_url = "https://www.facebook.com/" + identifier.split("fb.com/")[-1].rstrip("/")
    elif identifier.startswith("page:"):
        page_url = f"https://www.facebook.com/{identifier[5:].strip()}"
    elif "/" not in identifier and "." not in identifier:
        page_url = f"https://www.facebook.com/{identifier}"
    else:
        page_url = f"https://www.facebook.com/{identifier.split('/')[-1]}" if identifier.count("/") <= 2 else identifier

    if not page_url:
        findings.append(IntelligenceFinding(
            entity="Could not parse Facebook target", type="Facebook Error",
            source="SocialFacebookIntel", confidence="High", color="red",
            category="General OSINT", threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    try:
        resp = await client.get(page_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
            follow_redirects=True)
        if resp.status_code == 200:
            page = resp.text
    except Exception:
        pass

    if not page:
        try:
            resp = await client.get(f"https://mbasic.facebook.com/{page_url.split('/')[-1]}", timeout=15.0,
                headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
                follow_redirects=True)
            if resp.status_code == 200:
                page = resp.text
        except Exception:
            pass

    if not page:
        findings.append(IntelligenceFinding(
            entity=f"Could not access Facebook page: {page_url}",
            type="Facebook: Page Not Accessible",
            source="SocialFacebookIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["facebook", "unreachable"]
        ))
        return findings

    page_name = ""
    title_m = re.search(r'<title>([^<]+)</title>', page, re.IGNORECASE)
    if title_m:
        page_name = title_m.group(1).strip()

    findings.append(IntelligenceFinding(
        entity=f"Facebook page: {page_name or identifier}",
        type="Facebook: Page Profile",
        source="SocialFacebookIntel",
        confidence="Medium",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=page_url,
        tags=["facebook", "page-profile"]
    ))

    category_m = re.search(r'(?:Category|Type)[:\s]*([^<]{5,50})', page, re.IGNORECASE)
    if category_m:
        findings.append(IntelligenceFinding(
            entity=f"Category: {category_m.group(1).strip()}",
            type="Facebook: Page Category",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "category"]
        ))

    likes_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:like|Likes|like this)', page)
    if not likes_m:
        likes_m = re.search(r'(?:likes|Likes|like this)[:\s]*(\d[\d,.]*[KkMmBb]?)', page)
    if likes_m:
        findings.append(IntelligenceFinding(
            entity=f"Likes/Followers: {likes_m.group(1)}",
            type="Facebook: Page Likes",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "likes"]
        ))

    followers_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:follower|Follower|Followers)', page)
    if followers_m:
        findings.append(IntelligenceFinding(
            entity=f"Followers: {followers_m.group(1)}",
            type="Facebook: Page Followers",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "followers"]
        ))

    description_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', page, re.IGNORECASE)
    if description_m:
        findings.append(IntelligenceFinding(
            entity=f"Description: {description_m.group(1)[:200]}",
            type="Facebook: Page Description",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            raw_data=description_m.group(1)[:1000],
            tags=["facebook", "description"]
        ))

    phone_m = re.search(r'(?:Phone|phone)[:\s]*([^<]{7,20})', page)
    if phone_m:
        findings.append(IntelligenceFinding(
            entity=f"Phone: {phone_m.group(1).strip()}",
            type="Facebook: Phone Number",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="orange",
            category="Contact Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["facebook", "phone", "pii"]
        ))

    website_m = re.search(r'(?:Website|website)[:\s]*<a[^>]*href="([^"]+)"', page)
    if not website_m:
        website_m = re.search(r'(?:Website|website)[:\s]*([^<]{5,100})', page)
    if website_m:
        val = website_m.group(1).strip() if website_m.groups() else ""
        findings.append(IntelligenceFinding(
            entity=f"Website: {val[:100]}",
            type="Facebook: Website URL",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "website"]
        ))

    email_m = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', page)
    if email_m:
        findings.append(IntelligenceFinding(
            entity=f"Email found: {email_m.group(0)}",
            type="Facebook: Contact Email",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="orange",
            category="Contact Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["facebook", "email", "pii"]
        ))

    address_m = re.search(r'(?:Address|address|Location|location)[:\s]*([^<]{10,100})', page)
    if address_m:
        addr = address_m.group(1).strip()
        findings.append(IntelligenceFinding(
            entity=f"Address: {addr[:100]}",
            type="Facebook: Location/Address",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="orange",
            category="Contact Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["facebook", "address", "pii"]
        ))

    about_links = re.findall(r'href="(https?://[^"]+)"', page)
    external_links = [l for l in about_links if "facebook.com" not in l.lower() and "fb.com" not in l.lower()]
    if external_links:
        for link in external_links[:5]:
            findings.append(IntelligenceFinding(
                entity=f"External link: {link[:100]}",
                type="Facebook: External Link",
                source="SocialFacebookIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["facebook", "external-link"]
            ))

    og_image = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', page, re.IGNORECASE)
    if og_image:
        findings.append(IntelligenceFinding(
            entity=f"Profile image: {og_image.group(1)[:100]}",
            type="Facebook: Profile Image",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "profile-image"]
        ))

    page_id_m = re.search(r'page_id[":\s]+(\d+)', page)
    if page_id_m:
        findings.append(IntelligenceFinding(
            entity=f"Page ID: {page_id_m.group(1)}",
            type="Facebook: Page ID",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "page-id"]
        ))

    created_m = re.search(r'(?:Created|created|Page Creation)[:\s]*([^<]{5,30})', page)
    if created_m:
        findings.append(IntelligenceFinding(
            entity=f"Page created: {created_m.group(1).strip()}",
            type="Facebook: Page Creation Date",
            source="SocialFacebookIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "creation"]
        ))

    posts = re.findall(r'(?:class="[^"]*userContent[^"]*"|data-testid="post_message")[^>]*>([^<]{20,300})', page)
    if posts:
        for i, post in enumerate(posts[:5]):
            findings.append(IntelligenceFinding(
                entity=f"Post {i+1}: {post.strip()[:150]}",
                type="Facebook: Page Post",
                source="SocialFacebookIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["facebook", "post"]
            ))

    photos_m = re.findall(r'href="(/[^"]*photos/[^"]*)"', page)
    if photos_m:
        findings.append(IntelligenceFinding(
            entity=f"Photos section found ({len(photos_m)} photo links)",
            type="Facebook: Photos",
            source="SocialFacebookIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["facebook", "photos"]
        ))

    verified_m = re.search(r'(?:Verified|verified|VERIFIED)', page)
    if verified_m:
        findings.append(IntelligenceFinding(
            entity="Page is verified",
            type="Facebook: Verification Status",
            source="SocialFacebookIntel",
            confidence="Medium",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["facebook", "verified"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Facebook intelligence gathering complete for {identifier}",
        type="Facebook: Intel Summary",
        source="SocialFacebookIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status=f"Analyzed",
        raw_data=f"URL: {page_url} | Title: {page_name} | Posts found: {len(posts) if 'posts' in dir() else 0}",
        tags=["facebook", "summary"]
    ))

    return findings
