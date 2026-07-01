import httpx
import re
import json
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        username = parts[-1] if parts[-1] else parts[-2]
    if username.startswith("@"):
        username = username[1:]

    profile_url = f"https://www.instagram.com/{username}/"
    api_url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"

    html = None
    try:
        resp = await client.get(profile_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
            follow_redirects=True)
        if resp.status_code == 200:
            html = resp.text
    except Exception:
        pass

    if not html:
        findings.append(IntelligenceFinding(
            entity=f"Could not access Instagram profile: {username}",
            type="Instagram: Profile Not Accessible",
            source="SocialInstagramIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["instagram", "unreachable"]
        ))
        return findings

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else username

    findings.append(IntelligenceFinding(
        entity=f"Instagram profile: {title}",
        type="Instagram: Profile Found",
        source="SocialInstagramIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=profile_url,
        tags=["instagram", "profile", username]
    ))

    json_data = None
    json_m = re.search(r'<script[^>]*type="application\/ld\+json"[^>]*>([^<]+)</script>', html, re.IGNORECASE)
    if json_m:
        try:
            json_data = json.loads(json_m.group(1))
        except Exception:
            pass

    window_data = None
    window_m = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.*?});\s*</script>', html, re.DOTALL)
    if window_m:
        try:
            window_data = json.loads(window_m.group(1))
        except Exception:
            pass

    shared_data = None
    shared_m = re.search(r'window\.__sharedData__\s*=\s*({.*?});\s*</script>', html, re.DOTALL)
    if shared_m:
        try:
            shared_data = json.loads(shared_m.group(1))
        except Exception:
            pass

    bio_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if bio_m:
        bio_text = bio_m.group(1)
        findings.append(IntelligenceFinding(
            entity=f"Bio: {bio_text[:200]}",
            type="Instagram: Bio",
            source="SocialInstagramIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            raw_data=bio_text[:1000],
            tags=["instagram", "bio"]
        ))

    follower_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Follower|follower|Followers)', html)
    if not follower_count_m:
        follower_count_m = re.search(r'"edge_followed_by"\s*:\s*{\s*"count"\s*:\s*(\d+)', html)
    if not follower_count_m:
        follower_count_m = re.search(r'(?:followers|followed_by)\s*[:\s]*(\d[\d,.]*[KkMmBb]?)', html, re.IGNORECASE)
    if follower_count_m:
        findings.append(IntelligenceFinding(
            entity=f"Followers: {follower_count_m.group(1)}",
            type="Instagram: Follower Count",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "followers"]
        ))

    following_count_m = re.search(r'"edge_follow"\s*:\s*{\s*"count"\s*:\s*(\d+)', html)
    if not following_count_m:
        following_count_m = re.search(r'(?:following|follows)\s*[:\s]*(\d[\d,.]*[KkMmBb]?)', html, re.IGNORECASE)
    if following_count_m:
        findings.append(IntelligenceFinding(
            entity=f"Following: {following_count_m.group(1)}",
            type="Instagram: Following Count",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "following"]
        ))

    post_count_m = re.search(r'"edge_owner_to_timeline_media"\s*:\s*{\s*"count"\s*:\s*(\d+)', html)
    if not post_count_m:
        post_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:post|Post|Posts)', html)
    if post_count_m:
        findings.append(IntelligenceFinding(
            entity=f"Posts: {post_count_m.group(1)}",
            type="Instagram: Post Count",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "posts"]
        ))

    full_name_m = re.search(r'"full_name"\s*:\s*"([^"]+)"', html)
    if not full_name_m:
        full_name_m = re.search(r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if full_name_m:
        findings.append(IntelligenceFinding(
            entity=f"Full Name: {full_name_m.group(1)[:100]}",
            type="Instagram: Full Name",
            source="SocialInstagramIntel",
            confidence="High",
            color="slate",
            category="Personal Information",
            threat_level="Informational",
            tags=["instagram", "name"]
        ))

    external_url_m = re.search(r'"external_url"\s*:\s*"([^"]+)"', html)
    if external_url_m:
        url_val = external_url_m.group(1).replace('\\/', '/')
        findings.append(IntelligenceFinding(
            entity=f"Website/URL: {url_val[:100]}",
            type="Instagram: External URL",
            source="SocialInstagramIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "url"]
        ))

    category_m = re.search(r'"category_name"\s*:\s*"([^"]+)"', html)
    if category_m:
        findings.append(IntelligenceFinding(
            entity=f"Business category: {category_m.group(1)}",
            type="Instagram: Business Category",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "category"]
        ))

    is_business_m = re.search(r'"is_business_account"\s*:\s*true', html)
    if is_business_m:
        findings.append(IntelligenceFinding(
            entity="Business/creator account detected",
            type="Instagram: Account Type",
            source="SocialInstagramIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Business Account",
            tags=["instagram", "business"]
        ))

    is_verified_m = re.search(r'"is_verified"\s*:\s*true', html)
    if is_verified_m:
        findings.append(IntelligenceFinding(
            entity="Account is verified",
            type="Instagram: Verification Status",
            source="SocialInstagramIntel",
            confidence="High",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["instagram", "verified"]
        ))

    is_private_m = re.search(r'"is_private"\s*:\s*true', html)
    if is_private_m:
        findings.append(IntelligenceFinding(
            entity="Account is private",
            type="Instagram: Privacy Status",
            source="SocialInstagramIntel",
            confidence="High",
            color="orange",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Private",
            tags=["instagram", "private"]
        ))

    profile_pic_m = re.search(r'"profile_pic_url_hd"\s*:\s*"([^"]+)"', html)
    if not profile_pic_m:
        profile_pic_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if profile_pic_m:
        findings.append(IntelligenceFinding(
            entity=f"Profile picture URL: {profile_pic_m.group(1).replace('\\/', '/')[:100]}",
            type="Instagram: Profile Image",
            source="SocialInstagramIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "profile-image"]
        ))

    hashtags = re.findall(r'#(\w+)', html)
    if hashtags:
        unique_hashtags = list(set(hashtags))[:15]
        findings.append(IntelligenceFinding(
            entity=f"Hashtags used: {', '.join(unique_hashtags[:10])}",
            type="Instagram: Hashtag Analysis",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "hashtags"]
        ))

    location_m = re.search(r'"location_name"\s*:\s*"([^"]+)"', html)
    if location_m:
        findings.append(IntelligenceFinding(
            entity=f"Location: {location_m.group(1)}",
            type="Instagram: Location Tag",
            source="SocialInstagramIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "location"]
        ))

    contact_phone = re.search(r'"contact_phone_number"\s*:\s*"([^"]+)"', html)
    if contact_phone:
        findings.append(IntelligenceFinding(
            entity=f"Contact phone: {contact_phone.group(1)}",
            type="Instagram: Contact Phone",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="orange",
            category="Contact Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["instagram", "phone", "pii"]
        ))

    contact_email = re.search(r'"public_email"\s*:\s*"([^"]+)"', html)
    if contact_email:
        findings.append(IntelligenceFinding(
            entity=f"Contact email: {contact_email.group(1)}",
            type="Instagram: Contact Email",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="orange",
            category="Contact Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            tags=["instagram", "email", "pii"]
        ))

    biography_links = re.findall(r'(https?://[^\s"<]+)', html)
    if biography_links:
        unique_links = list(set(biography_links))[:5]
        for link in unique_links:
            if "instagram.com" not in link:
                findings.append(IntelligenceFinding(
                    entity=f"Bio link: {link[:100]}",
                    type="Instagram: Bio Link",
                    source="SocialInstagramIntel",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["instagram", "bio-link"]
                ))

    story_m = re.search(r'"has_highlight_reels"\s*:\s*true', html)
    if story_m:
        findings.append(IntelligenceFinding(
            entity="Profile has story highlights",
            type="Instagram: Story Highlights",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "highlights"]
        ))

    business_contact_method = re.search(r'"business_contact_method"\s*:\s*"([^"]+)"', html)
    if business_contact_method:
        findings.append(IntelligenceFinding(
            entity=f"Business contact method: {business_contact_method.group(1)}",
            type="Instagram: Contact Method",
            source="SocialInstagramIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["instagram", "contact-method"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Instagram intelligence gathering complete for @{username}",
        type="Instagram: Intel Summary",
        source="SocialInstagramIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Username: {username} | Title: {title} | Bio: {'found' if bio_m else 'none'}",
        tags=["instagram", "summary"]
    ))

    return findings
