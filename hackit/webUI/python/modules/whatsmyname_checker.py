import httpx
import asyncio
import re
from models import IntelligenceFinding

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

PLATFORMS = [
    ("GitHub", "https://github.com/{username}", "dev", "High"),
    ("GitLab", "https://gitlab.com/{username}", "dev", "High"),
    ("Bitbucket", "https://bitbucket.org/{username}", "dev", "Medium"),
    ("Twitter/X", "https://x.com/{username}", "social", "High"),
    ("Instagram", "https://www.instagram.com/{username}/", "social", "High"),
    ("LinkedIn", "https://www.linkedin.com/in/{username}/", "professional", "High"),
    ("Facebook", "https://www.facebook.com/{username}/", "social", "High"),
    ("Reddit", "https://www.reddit.com/user/{username}/", "forum", "High"),
    ("YouTube", "https://www.youtube.com/@{username}", "social", "High"),
    ("Medium", "https://medium.com/@{username}", "creative", "Medium"),
    ("Dev.to", "https://dev.to/{username}", "dev", "Medium"),
    ("Keybase", "https://keybase.io/{username}", "professional", "Medium"),
    ("Telegram", "https://t.me/{username}", "social", "High"),
    ("Pinterest", "https://www.pinterest.com/{username}/", "social", "Medium"),
    ("TikTok", "https://www.tiktok.com/@{username}", "social", "High"),
    ("Twitch", "https://www.twitch.tv/{username}", "gaming", "High"),
    ("Snapchat", "https://www.snapchat.com/add/{username}", "social", "Medium"),
    ("Discord", "https://discord.com/users/{username}", "gaming", "Medium"),
    ("HackerNews", "https://news.ycombinator.com/user?id={username}", "forum", "Medium"),
    ("StackOverflow", "https://stackoverflow.com/users/{username}", "dev", "Medium"),
    ("ProductHunt", "https://www.producthunt.com/@{username}", "creative", "Medium"),
    ("Behance", "https://www.behance.net/{username}", "creative", "Medium"),
    ("Dribbble", "https://dribbble.com/{username}", "creative", "Medium"),
    ("Flickr", "https://www.flickr.com/people/{username}/", "creative", "Medium"),
    ("Vimeo", "https://vimeo.com/{username}", "creative", "Medium"),
    ("SoundCloud", "https://soundcloud.com/{username}", "creative", "Medium"),
    ("Spotify", "https://open.spotify.com/user/{username}", "creative", "Medium"),
    ("AngelList", "https://angel.co/u/{username}", "professional", "Medium"),
    ("Crunchbase", "https://www.crunchbase.com/person/{username}", "professional", "Medium"),
    ("About.me", "https://about.me/{username}", "professional", "Medium"),
    ("Upwork", "https://www.upwork.com/freelancers/~{username}", "professional", "Medium"),
    ("Fiverr", "https://www.fiverr.com/{username}", "professional", "Medium"),
    ("Freelancer", "https://www.freelancer.com/u/{username}", "professional", "Medium"),
    ("HackerOne", "https://hackerone.com/{username}", "dev", "Medium"),
    ("Bugcrowd", "https://bugcrowd.com/{username}", "dev", "Medium"),
    ("Steam", "https://steamcommunity.com/id/{username}", "gaming", "Medium"),
    ("Chess.com", "https://www.chess.com/member/{username}", "gaming", "Medium"),
    ("Patreon", "https://www.patreon.com/{username}", "creative", "Medium"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", "creative", "Medium"),
    ("Ko-fi", "https://ko-fi.com/{username}", "creative", "Medium"),
    ("TryHackMe", "https://tryhackme.com/p/{username}", "dev", "Medium"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{username}", "dev", "Medium"),
    ("Mastodon.social", "https://mastodon.social/@{username}", "social", "Medium"),
    ("Telegram Group", "https://t.me/{username}", "social", "Medium"),
    ("WhatsApp", "https://wa.me/{username}", "social", "Low"),
    ("Signal", "https://signal.me/#p/{username}", "social", "Low"),
    ("Replit", "https://replit.com/@{username}", "dev", "Medium"),
    ("CodePen", "https://codepen.io/{username}", "dev", "Medium"),
    ("Docker Hub", "https://hub.docker.com/u/{username}", "dev", "Medium"),
]

CATEGORY_MAP = {
    "social": "Social Media",
    "dev": "Developer / Tech",
    "forum": "Forums / Communities",
    "dating": "Dating",
    "crypto": "Cryptocurrency",
    "professional": "Professional / Business",
    "creative": "Creative / Content",
    "gaming": "Gaming",
}

async def check_platform(client: httpx.AsyncClient, username: str, platform: str, url_template: str):
    url = url_template.replace("{username}", username)
    try:
        resp = await client.get(
            url,
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT}
        )
        status_code = resp.status_code
        final_url = str(resp.url)
        content_len = len(resp.text)

        if status_code == 200:
            if "not found" in resp.text[:500].lower() or "page not found" in resp.text[:500].lower() or "doesn't exist" in resp.text[:500].lower() or "user not found" in resp.text[:500].lower():
                return None
            if content_len < 100 and "redirect" in resp.text.lower():
                return None
            return ("found", 200, url, final_url, content_len)
        elif status_code in (301, 302, 303, 307, 308):
            if "profile" in final_url.lower() or f"/{username.lower()}" in final_url.lower():
                return ("found", status_code, url, final_url, content_len)
            return None
        elif status_code == 403:
            return ("maybe", 403, url, final_url, content_len)
        elif status_code == 429:
            return ("rate-limited", 429, url, final_url, content_len)
        return None
    except (httpx.TimeoutException, httpx.ConnectError):
        return None
    except Exception:
        return None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    username = target.strip().lower()
    if username.startswith("http"):
        from urllib.parse import urlparse
        username = urlparse(username).netloc.split(".")[0]
    username = re.sub(r'[^a-zA-Z0-9_.-]', '', username.split("@")[0].split("/")[0]) if username else username

    if not username:
        findings.append(IntelligenceFinding(
            entity="Could not extract username from target",
            type="Username Error",
            source="WhatsMyName",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))
        return findings

    tasks = [check_platform(client, username, p[0], p[1]) for p in PLATFORMS]
    results = await asyncio.gather(*tasks)

    found_count = 0
    maybe_count = 0
    rate_limited_count = 0
    category_found = {}
    total_checked = len(PLATFORMS)

    for (platform, url_template, category, _), result in zip(PLATFORMS, results):
        if result is None:
            continue

        status_type, status_code, profile_url, final_url, content_len = result

        if status_type == "found":
            found_count += 1
            category_found.setdefault(category, 0)
            category_found[category] += 1

            activity_hint = ""
            if "last seen" in profile_url.lower() or "joined" in profile_url.lower():
                activity_hint = " (recent activity indicator available)"
            elif content_len > 5000:
                activity_hint = " (profile has content)"
            elif content_len < 500:
                activity_hint = " (minimal profile)"

            findings.append(IntelligenceFinding(
                entity=f"@{username} on {platform}{activity_hint}",
                type=f"Username Found: {platform}",
                source="WhatsMyName",
                confidence="High" if status_code == 200 else "Medium",
                color="emerald",
                threat_level="Informational",
                status="Found",
                resolution="",
                raw_data=f"Status: {status_code} | URL: {profile_url} | Size: {content_len}b",
                tags=["username", "found", category, platform.lower().replace(" ", "-")]
            ))

        elif status_type == "maybe":
            maybe_count += 1
            findings.append(IntelligenceFinding(
                entity=f"@{username} possibly on {platform} (HTTP {status_code})",
                type=f"Username Possibly: {platform}",
                source="WhatsMyName",
                confidence="Low",
                color="orange",
                threat_level="Informational",
                status="Maybe",
                raw_data=f"Status: {status_code} | URL: {profile_url}",
                tags=["username", "maybe", category, platform.lower().replace(" ", "-")]
            ))

        elif status_type == "rate-limited":
            rate_limited_count += 1
            findings.append(IntelligenceFinding(
                entity=f"Rate-limited checking {platform}",
                type="Rate Limited",
                source="WhatsMyName",
                confidence="Low",
                color="red",
                threat_level="Informational",
                status="RateLimited",
                raw_data=f"HTTP 429 from {url_template.replace('{username}', username)}",
                tags=["rate-limit", platform.lower()]
            ))

    for cat, cat_count in sorted(category_found.items(), key=lambda x: -x[1]):
        cat_label = CATEGORY_MAP.get(cat, cat)
        findings.append(IntelligenceFinding(
            entity=f"{cat_label}: {cat_count} profiles found",
            type=f"Username Category: {cat_label}",
            source="WhatsMyName",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Found",
            tags=["category", cat, "breakdown"]
        ))

    score = 0
    if found_count > 0:
        score = min(100, int((found_count / total_checked) * 100))
    score_level = "High" if score > 30 else ("Medium" if score > 10 else "Low")
    score_color = "red" if score > 30 else ("orange" if score > 10 else "emerald")

    findings.append(IntelligenceFinding(
        entity=f"Username '{username}' availability score: {score}% ({found_count} found / {maybe_count} maybe / {total_checked} checked)",
        type="Username Availability Score",
        source="WhatsMyName",
        confidence="High",
        color=score_color,
        threat_level="Informational",
        status="Complete",
        raw_data=f"Score: {score}% | Found: {found_count} | Maybe: {maybe_count} | Rate-limited: {rate_limited_count} | Checked: {total_checked}",
        tags=["username", "score", "summary"]
    ))

    categories_with_results = set()
    for (platform, _, cat, _), result in zip(PLATFORMS, results):
        if result and result[0] == "found":
            categories_with_results.add(cat)

    if categories_with_results:
        found_categories = [CATEGORY_MAP.get(c, c) for c in sorted(categories_with_results)]
        findings.append(IntelligenceFinding(
            entity=f"Platform categories with presence: {', '.join(found_categories)}",
            type="Username Platform Categories",
            source="WhatsMyName",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Complete",
            tags=["categories", "platforms", "summary"]
        ))

    social_count = category_found.get("social", 0)
    dev_count = category_found.get("dev", 0)
    prof_count = category_found.get("professional", 0)
    creative_count = category_found.get("creative", 0)
    gaming_count = category_found.get("gaming", 0)
    forum_count = category_found.get("forum", 0)

    breakdown_parts = []
    if social_count:
        breakdown_parts.append(f"Social: {social_count}")
    if dev_count:
        breakdown_parts.append(f"Dev: {dev_count}")
    if prof_count:
        breakdown_parts.append(f"Professional: {prof_count}")
    if creative_count:
        breakdown_parts.append(f"Creative: {creative_count}")
    if gaming_count:
        breakdown_parts.append(f"Gaming: {gaming_count}")
    if forum_count:
        breakdown_parts.append(f"Forum: {forum_count}")

    if breakdown_parts:
        findings.append(IntelligenceFinding(
            entity=f"Type breakdown: {' | '.join(breakdown_parts)}",
            type="Username Type Breakdown",
            source="WhatsMyName",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Complete",
            tags=["breakdown", "statistics"]
        ))

    return findings
