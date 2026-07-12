import re
import json
from datetime import datetime
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

TWITTER_PROFILE_PATTERNS = {
    "bio": r'<meta[^>]+name="description"[^>]+content="([^"]+)"',
    "followers": r'(\d[\d,.]*[KkMmBb]?)\s*(?:Follower|follower|Followers)',
    "following": r'(\d[\d,.]*[KkMmBb]?)\s*(?:Following|following)',
    "tweets": r'(\d[\d,.]*[KkMmBb]?)\s*(?:Tweet|tweet|Tweets|tweets)',
    "likes": r'(\d[\d,.]*[KkMmBb]?)\s*(?:Like|like|Likes|likes)',
    "joined": r'(?:Joined|joined)\s*(?:\()?([A-Za-z]+\s+\d{4})',
    "location": r'(?:Location|location)[:\s]*([^<]{2,40})',
    "website": r'(?:Website|website)[:\s]*<a[^>]*href="([^"]+)"',
}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        username = parts[-1] if parts[-1] else parts[-2]
    if username.startswith("@"):
        username = username[1:]

    profile_url = f"https://twitter.com/{username}"
    nitter_url = f"https://nitter.net/{username}"

    html = None
    source = ""
    for url, name in [(profile_url, "Twitter"), (nitter_url, "Nitter")]:
        try:
            resp = await safe_fetch(client,url, timeout=15.0,
                headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
                follow_redirects=True)
            if resp.status_code == 200:
                html = resp.text
                source = name
                break
        except Exception:
            pass

    if not html:
        findings.append(make_finding(
            entity=f"Could not access Twitter/X profile: {username}",
            ftype="Twitter: Profile Not Accessible",
            source="SocialTwitterIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["twitter", "unreachable"]
        ))
        return findings

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else username

    findings.append(make_finding(
        entity=f"Twitter/X profile: {title}",
        ftype="Twitter: Profile Found",
        source="SocialTwitterIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=profile_url,
        raw_data=f"Source: {source} | URL: {profile_url}",
        tags=["twitter", "profile", username]
    ))

    display_name_m = re.search(r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if display_name_m:
        findings.append(make_finding(
            entity=f"Display name: {display_name_m.group(1).strip()[:100]}",
            ftype="Twitter: Display Name",
            source="SocialTwitterIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "display-name"]
        ))

    bio_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if bio_m:
        bio_text = bio_m.group(1)
        bio_text = re.sub(r'\s+', ' ', bio_text).strip()
        findings.append(make_finding(
            entity=f"Bio: {bio_text[:200]}",
            ftype="Twitter: Bio",
            source="SocialTwitterIntel",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            raw_data=bio_text[:1000],
            tags=["twitter", "bio"]
        ))

    avatar_url_m = re.search(r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"', html, re.IGNORECASE)
    if avatar_url_m:
        findings.append(make_finding(
            entity=f"Avatar URL: {avatar_url_m.group(1)[:100]}",
            ftype="Twitter: Profile Image",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "avatar"]
        ))

    followers_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Follower|follower|Followers)', html)
    if followers_count_m:
        findings.append(make_finding(
            entity=f"Followers: {followers_count_m.group(1)}",
            ftype="Twitter: Follower Count",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "followers"]
        ))

    following_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Following|following)', html)
    if following_count_m:
        findings.append(make_finding(
            entity=f"Following: {following_count_m.group(1)}",
            ftype="Twitter: Following Count",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "following"]
        ))

    tweet_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Tweets|tweets|Posts|posts)', html)
    if tweet_count_m:
        findings.append(make_finding(
            entity=f"Tweets: {tweet_count_m.group(1)}",
            ftype="Twitter: Tweet Count",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "tweets"]
        ))

    likes_count_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:Likes|likes)', html)
    if likes_count_m:
        findings.append(make_finding(
            entity=f"Likes: {likes_count_m.group(1)}",
            ftype="Twitter: Like Count",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "likes"]
        ))

    join_date_m = re.search(r'(?:Joined|joined)\s*(?:\(\))?\s*([A-Za-z]+\s+\d{4})', html)
    if join_date_m:
        join_str = join_date_m.group(1).strip()
        findings.append(make_finding(
            entity=f"Joined: {join_str}",
            ftype="Twitter: Join Date",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "join-date"]
        ))
        try:
            join_dt = datetime.strptime(join_str, "%B %Y")
            account_age_days = (datetime.now() - join_dt).days
            age_color = "emerald" if account_age_days > 365 else "orange"
            findings.append(make_finding(
                entity=f"Account age: {account_age_days} days ({account_age_days // 365} years)",
                ftype="Twitter: Account Age",
                source="SocialTwitterIntel",
                confidence="Medium",
                color=age_color,
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["twitter", "account-age"]
            ))
        except Exception:
            pass

    location_m = re.search(r'(?:Location|location)[:\s]*([^<]{2,40})', html)
    if location_m:
        loc = location_m.group(1).strip()
        findings.append(make_finding(
            entity=f"Location: {loc}",
            ftype="Twitter: Location",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "location"]
        ))

    website_m = re.search(r'(?:Website|website)[:\s]*<a[^>]*href="([^"]+)"', html)
    if website_m:
        findings.append(make_finding(
            entity=f"Website: {website_m.group(1)[:100]}",
            ftype="Twitter: Website",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "website"]
        ))

    verified_m = re.search(r'(?:Verified|verified|is_verified["\']:\s*true)', html)
    if verified_m:
        findings.append(make_finding(
            entity="Account is verified",
            ftype="Twitter: Verification Status",
            source="SocialTwitterIntel",
            confidence="High",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["twitter", "verified"]
        ))

    protected_m = re.search(r'(?:Protected|protected|is_protected["\']:\s*true)', html)
    if protected_m:
        findings.append(make_finding(
            entity="Account is protected (private tweets)",
            ftype="Twitter: Privacy Status",
            source="SocialTwitterIntel",
            confidence="High",
            color="orange",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Protected",
            tags=["twitter", "protected"]
        ))

    tweets = re.findall(r'(?:data-testid="tweetText"|class="[^"]*tweet-content[^"]*")[^>]*>([^<]{20,300})', html)
    if not tweets:
        tweets = re.findall(r'>([^<]{30,280})</(?:p|span|div)', html)
        tweets = [t for t in tweets if len(t) > 30 and not t.startswith("http")][:10]

    if tweets:
        for i, tweet in enumerate(tweets[:8]):
            tweet_clean = re.sub(r'\s+', ' ', tweet).strip()[:150]
            findings.append(make_finding(
                entity=f"Tweet {i+1}: {tweet_clean}",
                ftype="Twitter: Recent Tweet",
                source="SocialTwitterIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["twitter", "tweet"]
            ))

    hashtags = re.findall(r'#(\w+)', html)
    if hashtags:
        unique_tags = list(set(hashtags))[:10]
        findings.append(make_finding(
            entity=f"Hashtags used: {', '.join(unique_tags)}",
            ftype="Twitter: Hashtag Usage",
            source="SocialTwitterIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["twitter", "hashtags"]
        ))

    mentions = re.findall(r'@(\w+)', html)
    if mentions:
        unique_mentions = list(set(mentions))
        if username in unique_mentions:
            unique_mentions.remove(username)
        if unique_mentions:
            findings.append(make_finding(
                entity=f"Accounts mentioned/replied: @{', @'.join(unique_mentions[:10])}",
                ftype="Twitter: Mention Analysis",
                source="SocialTwitterIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["twitter", "mentions"]
            ))

    if source == "Nitter":
        nitter_pic = re.search(r'<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"', html)
        if nitter_pic:
            findings.append(make_finding(
                entity=f"Avatar (Nitter): {nitter_pic.group(1)[:100]}",
                ftype="Twitter: Profile Image (Nitter)",
                source="SocialTwitterIntel",
                confidence="Medium",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["twitter", "avatar", "nitter"]
            ))

        nitter_bio = re.search(r'<div[^>]+class="[^"]*profile-bio[^"]*"[^>]*>([^<]+)', html)
        if nitter_bio:
            bio_text = nitter_bio.group(1).strip()
            if bio_text:
                findings.append(make_finding(
                    entity=f"Bio (Nitter): {bio_text[:200]}",
                    ftype="Twitter: Bio (Nitter)",
                    source="SocialTwitterIntel",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    tags=["twitter", "bio", "nitter"]
                ))

        nitter_stats = re.findall(r'<tr[^>]*class="[^"]*stat[^"]*"[^>]*>.*?<td[^>]*class="[^"]*num[^"]*"[^>]*>([^<]+)</td>', html, re.DOTALL)
        if nitter_stats:
            labels = ["Tweets", "Following", "Followers", "Likes"]
            for i, stat in enumerate(nitter_stats[:4]):
                if i < len(labels):
                    findings.append(make_finding(
                        entity=f"{labels[i]} (Nitter): {stat.strip()}",
                        ftype=f"Twitter: {labels[i]} (Nitter)",
                        source="SocialTwitterIntel",
                        confidence="High",
                        color="slate",
                        category="Social Media Intelligence",
                        threat_level="Informational",
                        tags=["twitter", labels[i].lower(), "nitter"]
                    ))

    findings.append(make_finding(
        entity=f"Twitter/X intelligence gathering complete for @{username}",
        ftype="Twitter: Intel Summary",
        source="SocialTwitterIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Username: {username} | Tweets found: {len(tweets) if 'tweets' in dir() else 0} | Source: {source}",
        tags=["twitter", "summary"]
    ))

    return findings
