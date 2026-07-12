import re
import json
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

INVIDIOUS_INSTANCES = [
    "https://invidious.private.coffee",
    "https://invidious.slipfox.xyz",
    "https://invidious.projectsegfau.lt",
]

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    identifier = target.strip()

    channel_id = None
    channel_handle = identifier
    if identifier.startswith("http"):
        parts = identifier.rstrip("/").split("/")
        channel_handle = parts[-1] if parts[-1] else parts[-2]
    if channel_handle.startswith("@"):
        channel_handle = channel_handle[1:]

    channel_urls = [
        f"https://www.youtube.com/@{channel_handle}",
        f"https://www.youtube.com/channel/{channel_handle}",
        f"https://www.youtube.com/user/{channel_handle}",
        f"https://www.youtube.com/c/{channel_handle}",
    ]

    html = None
    used_url = ""
    for url in channel_urls:
        try:
            resp = await safe_fetch(client,url, timeout=15.0,
                headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
                follow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 1000:
                html = resp.text
                used_url = resp.url
                break
        except Exception:
            pass

    for instance in INVIDIOUS_INSTANCES:
        if html:
            break
        try:
            resp = await safe_fetch(client,f"{instance}/channel/{channel_handle}", timeout=15.0,
                headers={"User-Agent": UA})
            if resp.status_code == 200:
                html = resp.text
                used_url = resp.url
        except Exception:
            pass

    if not html:
        findings.append(make_finding(
            entity=f"Could not access YouTube channel: {channel_handle}",
            ftype="YouTube: Profile Not Accessible",
            source="SocialYouTubeIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["youtube", "unreachable"]
        ))
        return findings

    initial_data = None
    yt_m = re.search(r'var ytInitialData = ({.*?});', html, re.DOTALL)
    if not yt_m:
        yt_m = re.search(r'window\.ytInitialData\s*=\s*({.*?});', html, re.DOTALL)
    if yt_m:
        try:
            initial_data = json.loads(yt_m.group(1))
        except Exception:
            pass

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else channel_handle

    findings.append(make_finding(
        entity=f"YouTube channel: {title}",
        ftype="YouTube: Channel Found",
        source="SocialYouTubeIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=used_url or f"https://www.youtube.com/@{channel_handle}",
        tags=["youtube", "channel", channel_handle]
    ))

    desc_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if desc_m:
        desc = desc_m.group(1).strip()[:200]
        findings.append(make_finding(
            entity=f"Description: {desc}",
            ftype="YouTube: Channel Description",
            source="SocialYouTubeIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            raw_data=desc[:1000],
            tags=["youtube", "description"]
        ))

    subs_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:subscriber|Subscriber|Subscribers)', html)
    if not subs_m:
        subs_m = re.search(r'"subscriberCountText"\s*:\s*{[^}]*"simpleText"\s*:\s*"([^"]+)"', html)
    if subs_m:
        findings.append(make_finding(
            entity=f"Subscribers: {subs_m.group(1) if hasattr(subs_m, 'groups') and subs_m.groups() else subs_m}",
            ftype="YouTube: Subscriber Count",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "subscribers"]
        ))

    views_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:view|View|Views)', html)
    if not views_m:
        views_m = re.search(r'"viewCount"\s*:\s*"(\d+)"', html)
        if views_m:
            views_m = type('obj', (object,), {'group': lambda self, x: views_m.group(1)})()
    if views_m:
        findings.append(make_finding(
            entity=f"Total views: {views_m.group(1) if hasattr(views_m, 'groups') and views_m.groups() else views_m}",
            ftype="YouTube: Total Views",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "views"]
        ))

    video_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:video|Video|Videos)', html)
    if not video_count_m:
        video_count_m = re.search(r'"videosCount"\s*:\s*"(\d+)"', html)
        if video_count_m:
            video_count_m = type('obj', (object,), {'group': lambda self, x: video_count_m.group(1)})()
    if video_count_m:
        findings.append(make_finding(
            entity=f"Videos: {video_count_m.group(1)}",
            ftype="YouTube: Video Count",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "videos"]
        ))

    avatar_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if avatar_m:
        findings.append(make_finding(
            entity=f"Avatar: {avatar_m.group(1)[:100]}",
            ftype="YouTube: Channel Avatar",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "avatar"]
        ))

    join_date_m = re.search(r'(?:Joined|joined)[:\s]*([^<]{5,30})', html)
    if not join_date_m:
        join_date_m = re.search(r'"publishedAt"\s*:\s*"([^"]+)"', html)
    if join_date_m:
        findings.append(make_finding(
            entity=f"Joined: {join_date_m.group(1)[:30]}",
            ftype="YouTube: Join Date",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "join-date"]
        ))

    location_m = re.search(r'(?:Location|location)[:\s]*([^<]{3,50})', html)
    if location_m:
        findings.append(make_finding(
            entity=f"Location: {location_m.group(1).strip()}",
            ftype="YouTube: Location",
            source="SocialYouTubeIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "location"]
        ))

    links = re.findall(r'href="(https?://(?:www\.)?(?!youtube\.com|youtu\.be)[^"]+)"', html)
    if links:
        unique_links = list(set(links))[:5]
        for link in unique_links:
            findings.append(make_finding(
                entity=f"Link: {link[:100]}",
                ftype="YouTube: External Link",
                source="SocialYouTubeIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["youtube", "link"]
            ))

    video_titles = re.findall(r'"title"\s*:\s*{[^}]*"runs"\s*:\s*\[{[^}]*"text"\s*:\s*"([^"]+)"', html)
    if not video_titles:
        video_titles = re.findall(r'class="[^"]*(?:video-title|yt-simple-endpoint)[^"]*"[^>]*>([^<]{20,100})', html)
    if video_titles:
        unique_titles = list(set(video_titles))[:10]
        for i, vt in enumerate(unique_titles[:6]):
            findings.append(make_finding(
                entity=f"Video {i+1}: {vt.strip()[:100]}",
                ftype="YouTube: Video Title",
                source="SocialYouTubeIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["youtube", "video"]
            ))

        video_hashtags = []
        for vt in unique_titles:
            tags = re.findall(r'#(\w+)', vt)
            video_hashtags.extend(tags)
        if video_hashtags:
            unique_tags = list(set(video_hashtags))[:10]
            findings.append(make_finding(
                entity=f"Video hashtags: {', '.join(unique_tags)}",
                ftype="YouTube: Hashtag Analysis",
                source="SocialYouTubeIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["youtube", "hashtags"]
            ))

    verified_m = re.search(r'(?:badgeStyleType.*?VERIFIED|"verified"\s*:\s*true)', html)
    if verified_m:
        findings.append(make_finding(
            entity="Channel is verified",
            ftype="YouTube: Verification Status",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["youtube", "verified"]
        ))

    is_brand_m = re.search(r'(?:brand|branding|brand account)', html, re.IGNORECASE)
    if is_brand_m:
        findings.append(make_finding(
            entity="Brand account detected",
            ftype="YouTube: Account Type",
            source="SocialYouTubeIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "brand"]
        ))

    playlist_section = re.search(r'href="(/playlist\?list=[^"]+)"', html)
    if playlist_section:
        findings.append(make_finding(
            entity="Channel has public playlists",
            ftype="YouTube: Playlists",
            source="SocialYouTubeIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["youtube", "playlists"]
        ))

    findings.append(make_finding(
        entity=f"YouTube intelligence gathering complete for {channel_handle}",
        ftype="YouTube: Intel Summary",
        source="SocialYouTubeIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        tags=["youtube", "summary"]
    ))

    return findings
