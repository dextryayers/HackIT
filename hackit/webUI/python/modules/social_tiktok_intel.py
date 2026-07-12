import re
import json
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        for part in parts:
            if part.startswith("@"):
                username = part[1:]
                break
        else:
            username = parts[-1] if parts[-1] else parts[-2]
    if username.startswith("@"):
        username = username[1:]

    profile_url = f"https://www.tiktok.com/@{username}"
    html = None
    try:
        resp = await safe_fetch(client,profile_url, timeout=15.0,
            headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
            follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 500:
            html = resp.text
    except Exception:
        pass

    if not html:
        findings.append(make_finding(
            entity=f"Could not access TikTok profile: @{username}",
            ftype="TikTok: Profile Not Accessible",
            source="SocialTikTokIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["tiktok", "unreachable"]
        ))
        return findings

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else f"@{username}"

    findings.append(make_finding(
        entity=f"TikTok profile: {title}",
        ftype="TikTok: Profile Found",
        source="SocialTikTokIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=profile_url,
        tags=["tiktok", "profile", username]
    ))

    desc_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if desc_m:
        bio = desc_m.group(1).strip()[:200]
        bio_clean = re.sub(r'\s+', ' ', bio)
        findings.append(make_finding(
            entity=f"Bio: {bio_clean}",
            ftype="TikTok: Bio",
            source="SocialTikTokIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            raw_data=bio_clean[:1000],
            tags=["tiktok", "bio"]
        ))

    nickname_m = re.search(r'"nickname"\s*:\s*"([^"]+)"', html)
    if nickname_m:
        findings.append(make_finding(
            entity=f"Nickname: {nickname_m.group(1)[:100]}",
            ftype="TikTok: Display Name",
            source="SocialTikTokIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "nickname"]
        ))

    followers_m = re.search(r'"followerCount"\s*:\s*(\d+)', html)
    if not followers_m:
        followers_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Follower|follower|Followers)', html)
    if followers_m:
        findings.append(make_finding(
            entity=f"Followers: {followers_m.group(1)}",
            ftype="TikTok: Follower Count",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "followers"]
        ))

    following_m = re.search(r'"followingCount"\s*:\s*(\d+)', html)
    if not following_m:
        following_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Following|following)', html)
    if following_m:
        findings.append(make_finding(
            entity=f"Following: {following_m.group(1)}",
            ftype="TikTok: Following Count",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "following"]
        ))

    likes_m = re.search(r'"heartCount"\s*:\s*(\d+)', html)
    if not likes_m:
        likes_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Like|like|Likes|likes)', html)
    if likes_m:
        findings.append(make_finding(
            entity=f"Total likes: {likes_m.group(1)}",
            ftype="TikTok: Total Likes",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "likes"]
        ))

    videos_m = re.search(r'"videoCount"\s*:\s*(\d+)', html)
    if not videos_m:
        videos_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Video|video|Videos|videos)', html)
    if videos_m:
        findings.append(make_finding(
            entity=f"Videos: {videos_m.group(1)}",
            ftype="TikTok: Video Count",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "videos"]
        ))

    verified_m = re.search(r'(?:verified|isVerified)\s*:\s*true', html, re.IGNORECASE)
    if verified_m:
        findings.append(make_finding(
            entity="Account is verified",
            ftype="TikTok: Verification Status",
            source="SocialTikTokIntel",
            confidence="High",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["tiktok", "verified"]
        ))

    private_m = re.search(r'(?:privateAccount|isPrivate)\s*:\s*true', html, re.IGNORECASE)
    if private_m:
        findings.append(make_finding(
            entity="Account is private",
            ftype="TikTok: Privacy Status",
            source="SocialTikTokIntel",
            confidence="High",
            color="orange",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Private",
            tags=["tiktok", "private"]
        ))

    avatar_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if avatar_m:
        findings.append(make_finding(
            entity=f"Avatar: {avatar_m.group(1)[:100]}",
            ftype="TikTok: Profile Image",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "avatar"]
        ))

    signature_m = re.search(r'"signature"\s*:\s*"([^"]+)"', html)
    if signature_m:
        findings.append(make_finding(
            entity=f"Signature: {signature_m.group(1)[:100]}",
            ftype="TikTok: Signature",
            source="SocialTikTokIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "signature"]
        ))

    region_m = re.search(r'"region"\s*:\s*"([^"]+)"', html)
    if region_m:
        findings.append(make_finding(
            entity=f"Region: {region_m.group(1)}",
            ftype="TikTok: Region",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "region"]
        ))

    bio_link_m = re.search(r'"bioLink"\s*:\s*{[^}]*"link"\s*:\s*"([^"]+)"', html)
    if bio_link_m:
        link_val = bio_link_m.group(1).replace('\\/', '/')
        findings.append(make_finding(
            entity=f"Bio link: {link_val[:100]}",
            ftype="TikTok: Bio Link",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "bio-link"]
        ))

    hashtags = re.findall(r'#(\w+)', html)
    if hashtags:
        unique_hashtags = list(set(hashtags))[:15]
        findings.append(make_finding(
            entity=f"Hashtags used: {', '.join(unique_hashtags[:10])}",
            ftype="TikTok: Hashtag Analysis",
            source="SocialTikTokIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "hashtags"]
        ))

    sounds_m = re.findall(r'"music"\s*:\s*{[^}]*"title"\s*:\s*"([^"]+)"', html)
    if sounds_m:
        unique_sounds = list(set(sounds_m))[:5]
        findings.append(make_finding(
            entity=f"Sounds used: {', '.join(unique_sounds)}",
            ftype="TikTok: Sound Analysis",
            source="SocialTikTokIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["tiktok", "sounds"]
        ))

    video_descs = re.findall(r'"desc"\s*:\s*"([^"]+)"', html)
    if video_descs:
        unique_descs = list(set(video_descs))[:5]
        for i, vd in enumerate(unique_descs[:3]):
            findings.append(make_finding(
                entity=f"Video {i+1}: {vd[:100]}",
                ftype="TikTok: Video Description",
                source="SocialTikTokIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["tiktok", "video-desc"]
            ))

    findings.append(make_finding(
        entity=f"TikTok intelligence gathering complete for @{username}",
        ftype="TikTok: Intel Summary",
        source="SocialTikTokIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        tags=["tiktok", "summary"]
    ))

    return findings
