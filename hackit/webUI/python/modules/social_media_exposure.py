import re
import asyncio
from ..module_common import safe_fetch, make_finding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

SENSITIVITY_WEIGHTS = {
    "social-media": 8,
    "professional": 6,
    "development": 4,
    "gaming": 3,
    "security": 5,
    "blogging": 3,
    "messaging": 7,
    "creative": 3,
    "video": 4,
    "photo": 3,
    "music": 2,
    "shopping": 5,
    "reference": 2,
    "funding": 6,
    "dating": 9,
    "education": 3,
    "dating-app": 9,
    "crypto": 6,
    "forum": 4,
}

HIGH_RISK_PLATFORMS = [
    "Facebook", "Instagram", "LinkedIn", "Twitter/X", "TikTok",
    "Snapchat", "Telegram", "WhatsApp", "Discord", "OnlyFans",
    "Tinder", "Bumble", "Grindr", "OkCupid", "Hinge",
    "Patreon", "Venmo", "CashApp", "PayPal",
]

SENSITIVE_INFO_PATTERNS = {
    "email": r'[\w.+-]+@[\w-]+\.[\w.-]+',
    "phone": r'\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "address": r'\b\d{1,5}\s+[A-Za-z]+\s+(Street|St|Ave|Avenue|Road|Rd|Blvd|Boulevard|Lane|Ln|Drive|Dr|Way|Court|Ct)\b',
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "creditcard": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    "dob": r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
    "password": r'password[:\s]+[^\s,;\]]+',
    "api_key": r'(?:api[_-]?key|apikey)[:\s]+[a-zA-Z0-9_\-]{16,}',
}

PLATFORM_CHECK_URLS = {
    "Facebook": "https://www.facebook.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Twitter/X": "https://twitter.com/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Snapchat": "https://www.snapchat.com/add/{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Telegram": "https://t.me/{u}",
    "Discord": "https://discord.com/users/{u}",
    "Snapchat": "https://www.snapchat.com/add/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "ProductHunt": "https://www.producthunt.com/@{u}",
    "Behance": "https://www.behance.net/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Bandcamp": "https://{u}.bandcamp.com",
    "Spotify": "https://open.spotify.com/user/{u}",
    "Patreon": "https://www.patreon.com/{u}",
    "BuyMeACoffee": "https://www.buymeacoffee.com/{u}",
    "Ko-fi": "https://ko-fi.com/{u}",
    "Etsy": "https://www.etsy.com/shop/{u}",
    "eBay": "https://www.ebay.com/usr/{u}",
    "Fiverr": "https://www.fiverr.com/{u}",
    "Upwork": "https://www.upwork.com/freelancers/~{u}",
    "VK": "https://vk.com/{u}",
    "Ok.ru": "https://ok.ru/{u}",
    "Weibo": "https://www.weibo.com/{u}",
    "Bilibili": "https://space.bilibili.com/{u}",
    "Mastodon": "https://mastodon.social/@{u}",
    "Bluesky": "https://bsky.app/profile/{u}",
    "Threads": "https://www.threads.net/@{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Chess.com": "https://www.chess.com/member/{u}",
    "Lichess": "https://lichess.org/@/{u}",
    "Strava": "https://www.strava.com/athletes/{u}",
    "Keybase": "https://keybase.io/{u}",
    "HackerOne": "https://hackerone.com/{u}",
    "Bugcrowd": "https://bugcrowd.com/{u}",
    "TryHackMe": "https://tryhackme.com/p/{u}",
    "HackTheBox": "https://app.hackthebox.com/profile/{u}",
    "AngelList": "https://angel.co/u/{u}",
    "Crunchbase": "https://www.crunchbase.com/person/{u}",
    "Goodreads": "https://www.goodreads.com/{u}",
    "Letterboxd": "https://letterboxd.com/{u}/",
    "MyAnimeList": "https://myanimelist.net/profile/{u}",
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{u}",
    "About.me": "https://about.me/{u}",
    "Linktree": "https://linktr.ee/{u}",
    "Calendly": "https://calendly.com/{u}",
    "Substack": "https://{u}.substack.com",
    "WordPress": "https://{u}.wordpress.com",
    "Blogger": "https://{u}.blogspot.com",
    "Pastebin": "https://pastebin.com/u/{u}",
    "StackOverflow": "https://stackoverflow.com/users/{u}",
    "Kaggle": "https://www.kaggle.com/{u}",
    "Hugging Face": "https://huggingface.co/{u}",
    "Docker Hub": "https://hub.docker.com/u/{u}",
    "NPM": "https://www.npmjs.com/~{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "CodePen": "https://codepen.io/{u}",
    "Replit": "https://replit.com/@{u}",
    "LeetCode": "https://leetcode.com/{u}/",
    "HackerRank": "https://www.hackerrank.com/{u}",
    "Codewars": "https://www.codewars.com/users/{u}",
    "Wattpad": "https://www.wattpad.com/user/{u}",
    "Tinder": "https://tinder.com/@/{u}",
    "Bumble": "https://bumble.com/profile/{u}",
    "Last.fm": "https://www.last.fm/user/{u}",
    "Untappd": "https://untappd.com/user/{u}",
    "VSCO": "https://vsco.co/{u}",
    "Imgur": "https://imgur.com/user/{u}",
    "Flickr": "https://www.flickr.com/people/{u}/",
    "500px": "https://500px.com/{u}",
    "Unsplash": "https://unsplash.com/@{u}",
    "SlideShare": "https://www.slideshare.net/{u}",
    "Scribd": "https://www.scribd.com/{u}",
    "Issuu": "https://issuu.com/{u}",
    "Couchsurfing": "https://www.couchsurfing.com/people/{u}",
    "Meetup": "https://www.meetup.com/members/{u}/",
    "Eventbrite": "https://www.eventbrite.com/o/{u}",
    "ResearchGate": "https://www.researchgate.net/profile/{u}",
    "Academia.edu": "https://independent.academia.edu/{u}",
    "ORCID": "https://orcid.org/{u}",
    "Google Scholar": "https://scholar.google.com/citations?user={u}",
    "Quora": "https://www.quora.com/profile/{u}",
    "Parler": "https://parler.com/profile/{u}",
    "Gab": "https://gab.com/{u}",
    "Minds": "https://www.minds.com/{u}",
    "Rumble": "https://rumble.com/user/{u}",
    "Odysee": "https://odysee.com/@{u}",
    "Bitchute": "https://www.bitchute.com/channel/{u}",
    "DTube": "https://d.tube/#!/c/{u}",
    "Dailymotion": "https://www.dailymotion.com/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "Poshmark": "https://poshmark.com/closet/{u}",
    "Depop": "https://www.depop.com/{u}/",
    "Mercari": "https://www.mercari.com/u/{u}",
    "Grailed": "https://www.grailed.com/{u}",
    "StockX": "https://stockx.com/{u}",
    "OpenSea": "https://opensea.io/{u}",
    "Rarible": "https://rarible.com/{u}",
    "Zillow": "https://www.zillow.com/profile/{u}",
}

CATEGORY_CLASSIFICATION = {
    "Facebook": "social-media", "Instagram": "social-media", "Twitter/X": "social-media",
    "TikTok": "social-media", "Snapchat": "messaging", "LinkedIn": "professional",
    "GitHub": "development", "GitLab": "development", "Reddit": "social-media",
    "YouTube": "video", "Twitch": "gaming", "Telegram": "messaging",
    "Discord": "gaming", "Pinterest": "social-media", "Medium": "blogging",
    "Dev.to": "development", "HackerNews": "social-media", "ProductHunt": "professional",
    "Behance": "creative", "Dribbble": "creative", "SoundCloud": "music",
    "Bandcamp": "music", "Spotify": "music", "Patreon": "funding",
    "BuyMeACoffee": "funding", "Ko-fi": "funding", "Etsy": "shopping",
    "eBay": "shopping", "Fiverr": "professional", "Upwork": "professional",
    "VK": "social-media", "Ok.ru": "social-media", "Weibo": "social-media",
    "Bilibili": "social-media", "Mastodon": "social-media", "Bluesky": "social-media",
    "Threads": "social-media", "Steam": "gaming", "Chess.com": "gaming",
    "Lichess": "gaming", "Strava": "social-media", "Keybase": "security",
    "HackerOne": "security", "Bugcrowd": "security", "TryHackMe": "security",
    "HackTheBox": "security", "AngelList": "professional", "Crunchbase": "professional",
    "Goodreads": "social-media", "Letterboxd": "social-media", "MyAnimeList": "social-media",
    "Wikipedia": "reference", "About.me": "social-media", "Linktree": "social-media",
    "Calendly": "professional", "Substack": "blogging", "WordPress": "blogging",
    "Blogger": "blogging", "Pastebin": "development", "StackOverflow": "development",
    "Kaggle": "development", "Hugging Face": "development", "Docker Hub": "development",
    "NPM": "development", "PyPI": "development", "CodePen": "development",
    "Replit": "development", "LeetCode": "development", "HackerRank": "development",
    "Codewars": "development", "Wattpad": "social-media", "Tinder": "dating",
    "Bumble": "dating", "Last.fm": "music", "VSCO": "creative", "Imgur": "creative",
    "Flickr": "photo", "500px": "photo", "Unsplash": "photo", "SlideShare": "professional",
    "ResearchGate": "professional", "Academia.edu": "professional", "ORCID": "professional",
    "Google Scholar": "professional", "Quora": "social-media", "Parler": "social-media",
    "Gab": "social-media", "Minds": "social-media", "Rumble": "video",
    "Odysee": "video", "Bitchute": "video", "Vimeo": "video",
    "Poshmark": "shopping", "Depop": "shopping", "Mercari": "shopping",
    "Grailed": "shopping", "StockX": "shopping", "OpenSea": "crypto",
    "Rarible": "crypto", "Zillow": "reference",
}

async def check_platform(username: str, platform_name: str, url_template: str, client: AsyncClient) -> tuple:
    url = url_template.format(u=username)
    try:
        resp = await safe_fetch(client, url, timeout=10.0)
        if resp.status_code == 200:
            text_lower = resp.text.lower()
            not_found = ["page not found", "doesn't exist", "not found", "user not found",
                         "profile not found", "no user found", "could not find", "404"]
            if any(nf in text_lower for nf in not_found) and resp.status_code == 404:
                return (platform_name, False, None)
            if any(nf in text_lower for nf in not_found) and len(resp.text) < 500:
                return (platform_name, False, None)
            return (platform_name, True, resp.text[:5000])
        return (platform_name, False, None)
    except Exception:
        return (platform_name, False, None)

def calculate_exposure_score(found_platforms: list, sensitive_findings: list) -> dict:
    score = 0
    details = []

    for platform in found_platforms:
        cat = CATEGORY_CLASSIFICATION.get(platform, "social-media")
        weight = SENSITIVITY_WEIGHTS.get(cat, 3)
        score += weight
        if platform in HIGH_RISK_PLATFORMS:
            score += 5
            details.append(f"{platform}: high-risk (+{weight + 5})")
        else:
            details.append(f"{platform}: {cat} (+{weight})")

    if len(found_platforms) > 10:
        score += 15
        details.append(f"10+ platforms (+15)")
    elif len(found_platforms) > 5:
        score += 8
        details.append(f"5+ platforms (+8)")

    for sf in sensitive_findings:
        stype = sf.type
        if "Email" in stype:
            score += 8
            details.append("Email exposed (+8)")
        elif "Phone" in stype:
            score += 10
            details.append("Phone exposed (+10)")
        elif "Address" in stype:
            score += 8
            details.append("Address exposed (+8)")
        elif "DOB" in stype or "Birth" in stype:
            score += 6
            details.append("DOB exposed (+6)")

    score = min(100, max(0, score))
    level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    return {"score": score, "level": level, "details": details}

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    identifier = target.strip().lower()

    usernames = [identifier]
    if "@" in identifier:
        usernames.append(identifier.split("@")[0])
        usernames.append(identifier.split("@")[1].split(".")[0])

    found_platforms = []
    platform_pages = {}

    for username in usernames[:2]:
        tasks = []
        plat_items = list(PLATFORM_CHECK_URLS.items())
        for i in range(0, len(plat_items), 20):
            batch = plat_items[i:i+20]
            batch_tasks = []
            for pname, purl in batch:
                batch_tasks.append(check_platform(username, pname, purl, client))
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, tuple) and r[1]:
                    pname, _, page_content = r
                    if pname not in found_platforms:
                        found_platforms.append(pname)
                        platform_pages[pname] = page_content

    if not found_platforms:
        findings.append(make_finding(
            entity=f"No social media accounts found for '{identifier}'",
            ftype="Exposure: No Accounts Found",
            source="SocialMediaExposure",
            confidence="Medium",
            color="emerald",
            category="General OSINT",
            threat_level="Informational",
            status="Clean",
            tags=["exposure", "no-accounts"]
        ))
        return findings

    for platform in found_platforms:
        cat = CATEGORY_CLASSIFICATION.get(platform, "unknown")
        risk = "High" if platform in HIGH_RISK_PLATFORMS else "Medium" if cat in ("professional", "dating") else "Low"
        findings.append(make_finding(
            entity=f"{platform} account active",
            ftype=f"Exposure: {platform}",
            source="SocialMediaExposure",
            confidence="High",
            color="red" if risk == "High" else "orange" if risk == "Medium" else "slate",
            category=f"Platform: {cat.title()}",
            threat_level="Elevated Risk" if risk == "High" else "Standard Target" if risk == "Medium" else "Informational",
            status="Active",
            resolution=PLATFORM_CHECK_URLS.get(platform, "").format(u=usernames[0]),
            tags=["exposure", "social-media", cat, platform.lower().replace("/", "-").replace(" ", "-")]
        ))

    sensitive_findings = []
    all_text = " ".join(platform_pages.values())
    for stype, pattern in SENSITIVE_INFO_PATTERNS.items():
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        if matches:
            for m in matches[:3]:
                val = m if isinstance(m, str) else m[0]
                sfind = make_finding(
                    entity=f"{stype.upper()}: {val[:50]}",
                    ftype=f"Exposure: {stype.upper()} Leaked",
                    source="SocialMediaExposure",
                    confidence="Low",
                    color="red" if stype in ("ssn", "creditcard", "password", "api_key") else "orange",
                    category="Personal Information",
                    threat_level="Critical" if stype in ("ssn", "creditcard", "password") else "Elevated Risk",
                    status="Detected",
                    tags=["exposure", "pii", stype]
                )
                sensitive_findings.append(sfind)
                findings.append(sfind)

    score_data = calculate_exposure_score(found_platforms, sensitive_findings)
    s_color = "red" if score_data["level"] == "Critical" else "orange" if score_data["level"] == "High" else "yellow" if score_data["level"] == "Medium" else "emerald"

    findings.append(make_finding(
        entity=f"Social Media Exposure Score: {score_data['score']}/100 ({score_data['level']})",
        ftype="Exposure: Composite Score",
        source="SocialMediaExposure",
        confidence="Medium",
        color=s_color,
        category="Risk Assessment",
        threat_level=score_data["level"],
        status=f"{score_data['score']}/100",
        raw_data=f"Score: {score_data['score']}/100 | Level: {score_data['level']} | Platforms: {len(found_platforms)} | Breakdown: {'; '.join(score_data['details'][:15])}",
        tags=["exposure", "composite-score", score_data['level'].lower()]
    ))

    for platform in found_platforms:
        if platform in HIGH_RISK_PLATFORMS:
            findings.append(make_finding(
                entity=f"High-risk platform: {platform} - review privacy settings",
                ftype="Exposure: Privacy Recommendation",
                source="SocialMediaExposure",
                confidence="Medium",
                color="orange",
                category="Security Recommendation",
                threat_level="Informational",
                tags=["exposure", "recommendation", "privacy"]
            ))

    categories_found = {}
    for p in found_platforms:
        cat = CATEGORY_CLASSIFICATION.get(p, "unknown")
        categories_found[cat] = categories_found.get(cat, 0) + 1

    for cat, count in sorted(categories_found.items(), key=lambda x: -x[1]):
        findings.append(make_finding(
            entity=f"{cat.title()} platforms: {count}",
            ftype="Exposure: Category Breakdown",
            source="SocialMediaExposure",
            confidence="High",
            color="slate",
            category="General OSINT",
            threat_level="Informational",
            tags=["exposure", "category", cat]
        ))

    findings.append(make_finding(
        entity=f"Total platforms with accounts: {len(found_platforms)}",
        ftype="Exposure: Account Count",
        source="SocialMediaExposure",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        tags=["exposure", "total-accounts"]
    ))

    if score_data["score"] >= 50:
        recs = [
            "Review and tighten privacy settings on all platforms",
            "Remove personal information from public profiles",
            "Consider deleting unused or duplicate accounts",
            "Enable two-factor authentication on high-risk platforms",
            "Limit cross-platform data sharing",
        ]
        for i, rec in enumerate(recs):
            findings.append(make_finding(
                entity=f"Recommendation {i+1}: {rec}",
                ftype="Exposure: Privacy Improvement",
                source="SocialMediaExposure",
                confidence="Medium",
                color="orange",
                category="Security Recommendation",
                threat_level="Informational",
                tags=["exposure", "recommendation", "privacy"]
            ))

    if score_data["score"] >= 75:
        findings.append(make_finding(
            entity="CRITICAL: Extensive digital footprint detected - oversharing personal information",
            ftype="Exposure: Critical Alert",
            source="SocialMediaExposure",
            confidence="High",
            color="red",
            category="Risk Assessment",
            threat_level="Critical",
            status="Critical Exposure",
            tags=["exposure", "critical", "oversharing"]
        ))

    findings.append(make_finding(
        entity=f"Social media exposure assessment complete for '{identifier}'",
        ftype="Exposure: Assessment Summary",
        source="SocialMediaExposure",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level=score_data["level"],
        status="Complete",
        raw_data=f"Target: {identifier} | Platforms found: {len(found_platforms)} | Score: {score_data['score']}/100 | Level: {score_data['level']} | PII leaks: {len(sensitive_findings)}",
        tags=["exposure", "assessment-summary"]
    ))

    return findings
