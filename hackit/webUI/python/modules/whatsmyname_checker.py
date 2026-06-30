import httpx
import asyncio
import re
import unicodedata
import json
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse, urljoin
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
    ("Keybase", "https://keybase.io/{username}", "messaging", "Medium"),
    ("Telegram", "https://t.me/{username}", "messaging", "High"),
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
    ("SoundCloud", "https://soundcloud.com/{username}", "music", "Medium"),
    ("Spotify", "https://open.spotify.com/user/{username}", "music", "Medium"),
    ("Bandcamp", "https://bandcamp.com/{username}", "music", "Medium"),
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
    ("Mastodon", "https://{username}.mastodon.social", "social", "Medium"),
    ("WhatsApp", "https://wa.me/{username}", "messaging", "Low"),
    ("Signal", "https://signal.me/#p/{username}", "messaging", "Low"),
    ("Replit", "https://replit.com/@{username}", "dev", "Medium"),
    ("CodePen", "https://codepen.io/{username}", "dev", "Medium"),
    ("Docker Hub", "https://hub.docker.com/u/{username}", "dev", "Medium"),
    ("Threads", "https://www.threads.net/@{username}", "social", "High"),
    ("Bluesky", "https://bsky.app/profile/{username}", "social", "High"),
    ("Parler", "https://parler.com/profile/{username}", "social", "Medium"),
    ("Gab", "https://gab.com/{username}", "social", "Medium"),
    ("TruthSocial", "https://truthsocial.com/@{username}", "social", "Medium"),
    ("Weibo", "https://weibo.com/{username}", "social", "Medium"),
    ("VK", "https://vk.com/{username}", "social", "High"),
    ("Glitch", "https://glitch.com/@{username}", "dev", "Medium"),
    ("Codewars", "https://www.codewars.com/users/{username}", "dev", "Medium"),
    ("Exercism", "https://exercism.org/profiles/{username}", "dev", "Medium"),
    ("Topcoder", "https://www.topcoder.com/members/{username}", "dev", "Medium"),
    ("Kaggle", "https://www.kaggle.com/{username}", "dev", "Medium"),
    ("Hugging Face", "https://huggingface.co/{username}", "dev", "Medium"),
    ("NuGet", "https://www.nuget.org/profiles/{username}", "dev", "Medium"),
    ("Packagist", "https://packagist.org/packages/{username}", "dev", "Low"),
    ("RubyGems", "https://rubygems.org/profiles/{username}", "dev", "Medium"),
    ("Indeed", "https://www.indeed.com/r/{username}", "professional", "Medium"),
    ("Google Scholar", "https://scholar.google.com/citations?user={username}", "professional", "High"),
    ("ResearchGate", "https://www.researchgate.net/profile/{username}", "professional", "High"),
    ("Academia.edu", "https://independent.academia.edu/{username}", "professional", "Medium"),
    ("ORCID", "https://orcid.org/{username}", "professional", "High"),
    ("Calendly", "https://calendly.com/{username}", "professional", "Medium"),
    ("Imgur", "https://imgur.com/user/{username}", "creative", "Medium"),
    ("GIPHY", "https://giphy.com/{username}", "creative", "Medium"),
    ("VSCO", "https://vsco.co/{username}/gallery", "creative", "Medium"),
    ("Adobe Portfolio", "https://{username}.myportfolio.com", "creative", "Medium"),
    ("Carbonmade", "https://{username}.carbonmade.com", "creative", "Medium"),
    ("Wix", "https://{username}.wixsite.com", "creative", "Medium"),
    ("Squarespace", "https://{username}.squarespace.com", "creative", "Medium"),
    ("Epic Games", "https://www.epicgames.com/account/personal?displayName={username}", "gaming", "Medium"),
    ("Riot Games", "https://www.leagueoflegends.com/en-us/summoner/by-name/{username}", "gaming", "Medium"),
    ("Battle.net", "https://battle.net/{username}", "gaming", "Medium"),
    ("Origin", "https://www.origin.com/{username}", "gaming", "Medium"),
    ("Uplay", "https://uplay.ubisoft.com/en-GB/profile/{username}", "gaming", "Medium"),
    ("Minecraft", "https://namemc.com/profile/{username}", "gaming", "Medium"),
    ("Roblox", "https://www.roblox.com/user.aspx?username={username}", "gaming", "Medium"),
    ("Etherscan", "https://etherscan.io/address/{username}", "crypto", "Medium"),
    ("Solscan", "https://solscan.io/account/{username}", "crypto", "Medium"),
    ("BscScan", "https://bscscan.com/address/{username}", "crypto", "Medium"),
    ("Shazam", "https://www.shazam.com/artist/{username}", "music", "Medium"),
    ("Genius", "https://genius.com/{username}", "music", "Medium"),
    ("Last.fm", "https://www.last.fm/user/{username}", "music", "Medium"),
    ("Discogs", "https://www.discogs.com/user/{username}", "music", "Medium"),
    ("Mercari", "https://www.mercari.com/u/{username}", "shopping", "Medium"),
    ("Poshmark", "https://poshmark.com/closet/{username}", "shopping", "Medium"),
    ("Depop", "https://www.depop.com/{username}", "shopping", "Medium"),
    ("Etsy", "https://www.etsy.com/shop/{username}", "shopping", "Medium"),
    ("StockX", "https://stockx.com/{username}", "shopping", "Medium"),
    ("Slack", "https://{username}.slack.com", "messaging", "Low"),
    ("Tinder", "https://tinder.com/@{username}", "dating", "Low"),
    ("Bumble", "https://bumble.com/profile/{username}", "dating", "Low"),
    ("OkCupid", "https://www.okcupid.com/profile/{username}", "dating", "Low"),
    ("Hinge", "https://hinge.co/profile/{username}", "dating", "Low"),
    ("Grindr", "https://grindr.com/profile/{username}", "dating", "Low"),
    ("Badoo", "https://badoo.com/en/{username}", "dating", "Medium"),
    ("Nextdoor", "https://nextdoor.com/profile/{username}", "social", "Medium"),
    ("OK.ru", "https://ok.ru/{username}", "social", "High"),
    ("Zhihu", "https://www.zhihu.com/people/{username}", "social", "High"),
    ("Bilibili", "https://space.bilibili.com/{username}", "creative", "High"),
    ("Douban", "https://www.douban.com/people/{username}/", "creative", "Medium"),
    ("Rumble", "https://rumble.com/user/{username}", "creative", "Medium"),
    ("Odysee", "https://odysee.com/@{username}", "creative", "Medium"),
    ("Bitchute", "https://www.bitchute.com/channel/{username}", "creative", "Medium"),
    ("Dailymotion", "https://www.dailymotion.com/{username}", "creative", "Medium"),
    ("Youku", "https://youku.com/{username}", "creative", "Medium"),
    ("MyAnimeList", "https://myanimelist.net/profile/{username}", "creative", "Medium"),
    ("AniList", "https://anilist.co/user/{username}", "creative", "Medium"),
    ("Kitsu", "https://kitsu.io/users/{username}", "creative", "Medium"),
    ("Letterboxd", "https://letterboxd.com/{username}/", "creative", "Medium"),
    ("Trakt", "https://trakt.tv/users/{username}", "creative", "Medium"),
    ("IMDb", "https://www.imdb.com/user/ur{username}", "creative", "Medium"),
    ("Wattpad", "https://www.wattpad.com/user/{username}", "creative", "Medium"),
    ("Archive of Our Own", "https://archiveofourown.org/users/{username}", "creative", "Medium"),
    ("FanFiction.net", "https://www.fanfiction.net/u/{username}", "creative", "Medium"),
    ("Goodreads", "https://www.goodreads.com/{username}", "creative", "Medium"),
    ("LibraryThing", "https://www.librarything.com/profile/{username}", "creative", "Medium"),
    ("Strava", "https://www.strava.com/athletes/{username}", "creative", "Medium"),
    ("Runkeeper", "https://runkeeper.com/user/{username}", "creative", "Medium"),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{username}", "creative", "Medium"),
    ("AllTrails", "https://www.alltrails.com/members/{username}", "creative", "Medium"),
    ("Fitbit", "https://www.fitbit.com/user/{username}", "creative", "Medium"),
    ("Duolingo", "https://www.duolingo.com/profile/{username}", "creative", "Medium"),
    ("Memrise", "https://www.memrise.com/user/{username}", "creative", "Medium"),
    ("Coursera", "https://www.coursera.org/user/{username}", "professional", "Medium"),
    ("edX", "https://www.edx.org/user/{username}", "professional", "Medium"),
    ("Udemy", "https://www.udemy.com/user/{username}", "professional", "Medium"),
    ("Skillshare", "https://www.skillshare.com/profile/{username}", "professional", "Medium"),
    ("Pluralsight", "https://app.pluralsight.com/profile/{username}", "professional", "Medium"),
    ("DataCamp", "https://www.datacamp.com/portfolio/{username}", "professional", "Medium"),
    ("LeetCode", "https://leetcode.com/{username}/", "dev", "Medium"),
    ("HackerRank", "https://www.hackerrank.com/{username}", "dev", "Medium"),
    ("Codecademy", "https://www.codecademy.com/profiles/{username}", "dev", "Medium"),
    ("FreeCodeCamp", "https://www.freecodecamp.org/{username}", "dev", "Medium"),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{username}", "dev", "Medium"),
    ("Codementor", "https://www.codementor.io/@{username}", "dev", "Medium"),
    ("Kongregate", "https://www.kongregate.com/accounts/{username}", "gaming", "Medium"),
    ("Newgrounds", "https://{username}.newgrounds.com", "gaming", "Medium"),
    ("Speedrun.com", "https://www.speedrun.com/users/{username}", "gaming", "Medium"),
    ("Itch.io", "https://{username}.itch.io", "gaming", "Medium"),
    ("GameJolt", "https://gamejolt.com/@{username}", "gaming", "Medium"),
    ("PsnProfiles", "https://psnprofiles.com/{username}", "gaming", "Medium"),
    ("Xbox Live", "https://xbox.com/@{username}", "gaming", "Medium"),
    ("FiveM", "https://fivem.net/profile/{username}", "gaming", "Medium"),
    ("Roll20", "https://app.roll20.net/users/{username}", "gaming", "Medium"),
    ("Tabletopia", "https://tabletopia.com/users/{username}", "gaming", "Medium"),
    ("BoardGameGeek", "https://boardgamegeek.com/user/{username}", "gaming", "Medium"),
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
    "music": "Music / Audio",
    "shopping": "Shopping / Marketplace",
    "messaging": "Messaging / Chat",
}

CATEGORY_WEIGHTS = {
    "dev": 3.0,
    "professional": 3.0,
    "social": 2.5,
    "messaging": 2.0,
    "forum": 1.8,
    "gaming": 1.5,
    "creative": 1.2,
    "music": 1.2,
    "crypto": 1.5,
    "shopping": 1.0,
    "dating": 0.8,
}

def normalize_username(raw: str) -> str:
    raw = unicodedata.normalize("NFKC", raw).strip()
    raw = re.sub(r'[\u2000-\u206F\uFE00-\uFE0F\uFEFF]', '', raw)
    return raw

def extract_usernames_from_target(target: str) -> List[str]:
    candidates = set()
    cleaned = target.strip().lower()

    if "@" in cleaned:
        parts = cleaned.split("@")
        if len(parts) >= 2:
            local = parts[0].strip()
            domain = parts[1].strip("/ ").split("?")[0]
            if local:
                candidates.add(local)
            if "." in domain:
                sub = domain.split(".")[0]
                if sub and sub not in ("gmail", "yahoo", "hotmail", "outlook", "proton", "pm", "mail", "email"):
                    candidates.add(sub)

    if cleaned.startswith("http"):
        parsed = urlparse(cleaned)
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if path_parts:
            candidates.add(path_parts[-1].split("?")[0])
        host = parsed.netloc.split(":")
        hostname = host[0]
        host_parts = hostname.split(".")
        if len(host_parts) >= 3:
            candidates.add(host_parts[-3])
        elif len(host_parts) == 2:
            candidates.add(host_parts[0])

    if cleaned.startswith("u/") or cleaned.startswith("u\\"):
        candidates.add(cleaned[2:])
    if cleaned.startswith("@"):
        candidates.add(cleaned[1:])

    candidates.add(cleaned.split("/")[0].split("@")[0].split("?")[0])

    result = []
    for c in candidates:
        c = normalize_username(c)
        c = re.sub(r'[^a-zA-Z0-9_.\-\p{L}]', '', c)
        if c and len(c) >= 1:
            result.append(c)

    return list(set(result))

def extract_profile_details(html: str, final_url: str) -> Dict[str, Any]:
    details = {}

    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = re.sub(r'\s+', ' ', title_match.group(1)).strip()
        if title and title != "403 Forbidden":
            details["display_name"] = title[:200]

    meta_desc = re.search(r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if not meta_desc:
        meta_desc = re.search(r'<meta\s+property=["\']og:description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if meta_desc:
        desc = meta_desc.group(1).strip()[:300]
        if desc:
            details["bio"] = desc

    og_image = re.search(r'<meta\s+property=["\']og:image["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if og_image:
        img_url = og_image.group(1).strip()
        if img_url and not img_url.endswith("default-avatar.png") and "no-avatar" not in img_url.lower():
            details["avatar_url"] = img_url

    og_site = re.search(r'<meta\s+property=["\']og:url["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    if og_site:
        details["profile_url"] = og_site.group(1).strip()

    follower_patterns = [
        r'(\d[\d,.]*)\s*(?:follower|subscriber|member)',
        r'(\d[\d,.]*)\s*(?:abonnés|abonnees)',
        r'follower[^:]*:\s*(\d[\d,.]*)',
        r'"followerCount"\s*:\s*(\d+)',
        r'"followers"\s*:\s*(\d+)',
        r'(\d+)\s*followers?',
    ]
    for pat in follower_patterns:
        fm = re.search(pat, html[:5000], re.IGNORECASE)
        if fm:
            try:
                count = int(re.sub(r'[^\d]', '', fm.group(1)))
                if count >= 0:
                    details["followers"] = count
                    break
            except ValueError:
                pass

    join_patterns = [
        r'(?:joined|member since|registered)\s*[:\s]*(\w+\s+\d{4}|\d{4})',
        r'"createdAt"\s*:\s*"(\d{4}-\d{2}-\d{2})',
        r'"joinDate"\s*:\s*"([^"]+)"',
    ]
    for pat in join_patterns:
        jm = re.search(pat, html[:3000], re.IGNORECASE)
        if jm:
            details["join_date"] = jm.group(1).strip()
            break

    website_matches = re.findall(
        r'href=["\'](https?://(?:www\.)?(?!facebook\.com|twitter\.com|x\.com|instagram\.com|linkedin\.com|github\.com)[^"\'\\]+)["\']',
        html[:8000],
        re.IGNORECASE
    )
    external_sites = []
    for w in website_matches[:3]:
        domain = urlparse(w).netloc
        if domain and domain not in external_sites:
            external_sites.append(w)
    if external_sites:
        details["website"] = external_sites[0]
        if len(external_sites) > 1:
            details["websites"] = external_sites

    return details

def detect_verification(html: str) -> Dict[str, Any]:
    indicators = {}

    badge_patterns = [
        r'class=["\'][^"\']*verified[^"\']*badge[^"\']*["\']',
        r'class=["\'][^"\']*verified[^"\']*["\']',
        r'aria-label=["\']Verified[^"\']*["\']',
        r'aria-label=["\']verified[^"\']*["\']',
        r'>\s*✓\s*</',
        r'class=["\'][^"\']*checkmark[^"\']*["\']',
        r'alt=["\']Verified[^"\']*["\']',
        r'title=["\']Verified[^"\']*Account["\']',
        r'is-verified',
        r'"verified"\s*:\s*true',
        r'"verified"\s*:\s*True',
        r'"isVerified"\s*:\s*true',
        r'"is_verified"\s*:\s*true',
        r'verification.*badge',
        r'verified.*check',
    ]
    for pat in badge_patterns:
        if re.search(pat, html[:10000], re.IGNORECASE):
            indicators["has_verified_badge"] = True
            indicators["verification_method"] = "badge_html"
            break

    count_matches = re.findall(r'verified\s*(?:count|number)[^d]*?(\d+)', html[:5000], re.IGNORECASE)
    if count_matches:
        indicators["verification_count"] = int(count_matches[0])

    if "verification" in details_key:
        pass

    return indicators

def compute_profile_completeness(html: str, details: Dict[str, Any]) -> int:
    score = 0
    content_len = len(html)

    if content_len > 1000:
        score += 10
    if content_len > 5000:
        score += 10
    if content_len > 20000:
        score += 10

    if details.get("display_name"):
        score += 15
    if details.get("bio"):
        bio_len = len(details["bio"])
        if bio_len > 50:
            score += 15
        elif bio_len > 10:
            score += 8
    if details.get("avatar_url"):
        score += 15
    if details.get("followers") is not None:
        score += 10
    if details.get("website"):
        score += 10
    if details.get("join_date"):
        score += 5

    if "about" in html[:2000].lower():
        score += 5
    if "location" in html[:3000].lower() or "country" in html[:3000].lower():
        score += 5

    return min(100, score)

def compute_similarity_variants(base_username: str) -> List[str]:
    variants = []
    if "_" not in base_username and "-" not in base_username and "." not in base_username:
        variants.append(base_username + "_")
        variants.append(base_username + "_official")
        variants.append(base_username + "_real")
        variants.append("_" + base_username)
        variants.append(base_username + "1")
        variants.append(base_username + "123")
    else:
        stripped = re.sub(r'[^a-zA-Z0-9]', '', base_username)
        if stripped != base_username:
            variants.append(stripped)
        variants.append(base_username.replace("_", "").replace("-", "").replace(".", ""))
    return list(set(variants))

def compute_category_weighted_score(category_found: Dict[str, int]) -> Dict[str, Any]:
    weighted = 0.0
    max_possible = sum(CATEGORY_WEIGHTS.get(c, 1.0) * 20 for c in CATEGORY_WEIGHTS)
    breakdown = {}
    for cat, count in category_found.items():
        w = CATEGORY_WEIGHTS.get(cat, 1.0)
        weighted += w * count
        breakdown[cat] = {"count": count, "weight": w, "weighted_score": round(w * count, 1)}
    pct = min(100, round((weighted / max_possible) * 100, 1)) if max_possible > 0 else 0
    return {
        "weighted_score": round(weighted, 1),
        "max_possible": round(max_possible, 1),
        "percentage": pct,
        "breakdown": breakdown,
    }

async def enrich_profile(client: httpx.AsyncClient, platform: str, username: str, final_url: str, html: str) -> Dict[str, Any]:
    enrichment = {}

    if platform == "GitHub":
        api_url = f"https://api.github.com/users/{username}"
        try:
            resp = await client.get(api_url, timeout=8.0, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                enrichment["api_data"] = {
                    "name": data.get("name"),
                    "bio": data.get("bio"),
                    "public_repos": data.get("public_repos"),
                    "followers": data.get("followers"),
                    "following": data.get("following"),
                    "location": data.get("location"),
                    "company": data.get("company"),
                    "blog": data.get("blog"),
                    "twitter_username": data.get("twitter_username"),
                    "created_at": data.get("created_at"),
                    "hireable": data.get("hireable"),
                    "public_gists": data.get("public_gists"),
                    "type": data.get("type"),
                }
                enrichment["source"] = "GitHub API"
        except Exception:
            pass

    elif platform == "Reddit":
        about_url = f"https://www.reddit.com/user/{username}/about.json"
        try:
            resp = await client.get(about_url, timeout=8.0, headers={"User-Agent": f"{USER_AGENT} (by /u/{username})"})
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                enrichment["api_data"] = {
                    "name": data.get("name"),
                    "subreddit": data.get("subreddit", {}),
                    "created_utc": data.get("created_utc"),
                    "comment_karma": data.get("comment_karma"),
                    "link_karma": data.get("link_karma"),
                    "total_karma": data.get("total_karma"),
                    "is_employee": data.get("is_employee"),
                    "is_verified": data.get("is_verified"),
                    "has_verified_email": data.get("has_verified_email"),
                    "is_gold": data.get("is_gold"),
                    "is_mod": data.get("is_mod"),
                    "icon_img": data.get("icon_img"),
                }
                enrichment["source"] = "Reddit API"
        except Exception:
            pass

    elif platform == "HackerNews":
        api_url = f"https://hacker-news.firebaseio.com/v0/user/{username}.json"
        try:
            resp = await client.get(api_url, timeout=8.0)
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    enrichment["api_data"] = {
                        "id": data.get("id"),
                        "created": data.get("created"),
                        "karma": data.get("karma"),
                        "about": data.get("about"),
                    }
                    enrichment["source"] = "HackerNews API"
        except Exception:
            pass

    elif platform == "YouTube":
        try:
            channel_match = re.search(r'(?:channel/)([a-zA-Z0-9_-]+)', html, re.IGNORECASE)
            if channel_match:
                channel_id = channel_match.group(1)
                oembed_url = f"https://www.youtube.com/oembed?url=https://www.youtube.com/channel/{channel_id}&format=json"
                resp = await client.get(oembed_url, timeout=8.0)
                if resp.status_code == 200:
                    data = resp.json()
                    enrichment["api_data"] = {
                        "title": data.get("title"),
                        "author_name": data.get("author_name"),
                        "author_url": data.get("author_url"),
                        "thumbnail_url": data.get("thumbnail_url"),
                    }
                    enrichment["source"] = "YouTube oEmbed"
        except Exception:
            pass

    elif platform == "StackOverflow":
        api_url = f"https://api.stackexchange.com/2.3/users?inname={username}&order=desc&sort=reputation&site=stackoverflow"
        try:
            resp = await client.get(api_url, timeout=8.0, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                data = resp.json().get("items", [])
                if data:
                    enrichment["api_data"] = {
                        "reputation": data[0].get("reputation"),
                        "badge_counts": data[0].get("badge_counts"),
                        "location": data[0].get("location"),
                        "website_url": data[0].get("website_url"),
                        "account_id": data[0].get("account_id"),
                        "creation_date": data[0].get("creation_date"),
                        "profile_image": data[0].get("profile_image"),
                    }
                    enrichment["source"] = "StackExchange API"
        except Exception:
            pass

    elif platform == "HackerOne":
        try:
            hacktivity_url = f"https://hackerone.com/{username}/hacktivity"
            h1_match = re.search(r'href="https://hackerone\.com/([^"/]+)"', html, re.IGNORECASE)
            if h1_match and h1_match.group(1) == username:
                h1_profile = re.search(r'"signal"[^:]*:\s*(\d+)', html, re.IGNORECASE)
                h1_reputation = re.search(r'"reputation"[^:]*:\s*(\d+)', html, re.IGNORECASE)
                api = {}
                if h1_profile:
                    api["signal"] = int(h1_profile.group(1))
                if h1_reputation:
                    api["reputation"] = int(h1_reputation.group(1))
                if api:
                    enrichment["api_data"] = api
                    enrichment["source"] = "HackerOne parsing"
        except Exception:
            pass

    elif platform in ("Etherscan", "BscScan", "Solscan"):
        try:
            addr_match = re.search(r'0x[a-fA-F0-9]{40}', html)
            if addr_match:
                enrichment["api_data"] = {"address": addr_match.group(0)}
                enrichment["source"] = f"{platform} parsing"
        except Exception:
            pass

    return enrichment

async def check_platform(client: httpx.AsyncClient, username: str, platform: str, url_template: str, do_extract: bool = True):
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
            if "not found" in resp.text[:500].lower() or "page not found" in resp.text[:500].lower() or "doesn't exist" in resp.text[:500].lower() or "user not found" in resp.text[:500].lower() or "404" in resp.text[:200].lower():
                return None
            if content_len < 100 and "redirect" in resp.text.lower():
                return None

            result = ("found", 200, url, final_url, content_len, resp.text)
            return result

        elif status_code in (301, 302, 303, 307, 308):
            if "profile" in final_url.lower() or f"/{username.lower()}" in final_url.lower():
                return ("found", status_code, url, final_url, content_len, resp.text)
            return None

        elif status_code == 403:
            return ("maybe", 403, url, final_url, content_len, resp.text)
        elif status_code == 429:
            return ("rate-limited", 429, url, final_url, content_len, "")
        return None

    except (httpx.TimeoutException, httpx.ConnectError):
        return None
    except Exception:
        return None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []

    raw_username = target.strip()

    extracted_usernames = extract_usernames_from_target(raw_username)
    primary_username = None

    if extracted_usernames:
        primary_username = extracted_usernames[0]
    else:
        primary_username = raw_username.lower()

    primary_username = normalize_username(primary_username)
    primary_username = re.sub(r'[^a-zA-Z0-9_.\-\p{L}]', '', primary_username.split("@")[0].split("/")[0]) if primary_username else primary_username

    if not primary_username or len(primary_username) < 1:
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

    username = primary_username
    used_alias = False
    if len(extracted_usernames) > 1:
        used_alias = True
        findings.append(IntelligenceFinding(
            entity=f"Extracted {len(extracted_usernames)} username candidates: {', '.join(extracted_usernames)} — using '{username}' as primary",
            type="Username Extraction",
            source="WhatsMyName",
            confidence="Medium",
            color="blue",
            threat_level="Informational",
            status="Info",
            tags=["username", "extraction", "normalization"]
        ))

    tasks = [check_platform(client, username, p[0], p[1]) for p in PLATFORMS]
    results = await asyncio.gather(*tasks)

    found_count = 0
    maybe_count = 0
    rate_limited_count = 0
    category_found = {}
    total_checked = len(PLATFORMS)
    profile_details_map = {}
    enrichment_map = {}
    verification_map = {}
    completeness_map = {}
    found_platforms_info = []

    for (platform, url_template, category, _), result in zip(PLATFORMS, results):
        if result is None:
            continue

        status_type, status_code, profile_url, final_url, content_len, html = result

        if status_type == "found":
            found_count += 1
            category_found.setdefault(category, 0)
            category_found[category] += 1

            details = {}
            if html:
                details = extract_profile_details(html, final_url)
                if details:
                    profile_details_map[platform] = details

                ver = detect_verification(html)
                if ver:
                    verification_map[platform] = ver

                completeness = compute_profile_completeness(html, details)
                completeness_map[platform] = completeness

                enrichment = await enrich_profile(client, platform, username, final_url, html)
                if enrichment and enrichment.get("api_data"):
                    enrichment_map[platform] = enrichment

            activity_hint = ""
            if details.get("join_date"):
                activity_hint = f" (joined {details['join_date']})"
            elif content_len > 5000:
                activity_hint = " (profile has content)"
            elif content_len < 500:
                activity_hint = " (minimal profile)"

            display_name_str = ""
            if details.get("display_name"):
                display_name_str = f" — \"{details['display_name']}\""

            bio_str = ""
            if details.get("bio"):
                bio_short = details["bio"][:80].replace("\n", " ")
                bio_str = f" | bio: {bio_short}"

            followers_str = ""
            if details.get("followers") is not None:
                followers_str = f" | {details['followers']:,} followers"

            completeness_str = ""
            if platform in completeness_map:
                completeness_str = f" | completeness: {completeness_map[platform]}%"

            ver_str = ""
            if platform in verification_map:
                ver_str = " | ✅ verified"

            found_platforms_info.append({
                "platform": platform,
                "category": category,
                "url": final_url,
                "details": details,
                "completeness": completeness_map.get(platform, 0),
                "verified": platform in verification_map,
                "enrichment": enrichment_map.get(platform, {}).get("api_data"),
            })

            raw_data_parts = [f"Status: {status_code}", f"URL: {profile_url}", f"Size: {content_len}b"]
            if details.get("display_name"):
                raw_data_parts.append(f"Display Name: {details['display_name']}")
            if details.get("bio"):
                raw_data_parts.append(f"Bio: {details['bio'][:100]}")
            if details.get("followers") is not None:
                raw_data_parts.append(f"Followers: {details['followers']}")
            if details.get("avatar_url"):
                raw_data_parts.append(f"Avatar: {details['avatar_url']}")
            if details.get("website"):
                raw_data_parts.append(f"Website: {details['website']}")
            if details.get("join_date"):
                raw_data_parts.append(f"Joined: {details['join_date']}")
            if platform in verification_map:
                raw_data_parts.append("Verified: Yes")
            if platform in completeness_map:
                raw_data_parts.append(f"Completeness: {completeness_map[platform]}%")
            if platform in enrichment_map:
                em = enrichment_map[platform]
                raw_data_parts.append(f"Enriched via: {em.get('source', 'API')}")
                api = em.get("api_data", {})
                for k, v in list(api.items())[:6]:
                    if v is not None:
                        raw_data_parts.append(f"  {k}: {v}")

            tags = ["username", "found", category, platform.lower().replace(" ", "-")]
            if platform in verification_map:
                tags.append("verified")
            if completeness_map.get(platform, 0) >= 70:
                tags.append("complete-profile")
            elif completeness_map.get(platform, 0) >= 30:
                tags.append("partial-profile")
            else:
                tags.append("minimal-profile")
            if enrichment_map.get(platform):
                tags.append("enriched")

            findings.append(IntelligenceFinding(
                entity=f"@{username} on {platform}{display_name_str}{bio_str}{followers_str}{completeness_str}{ver_str}{activity_hint}",
                type=f"Username Found: {platform}",
                source="WhatsMyName",
                confidence="High" if status_code == 200 else "Medium",
                color="emerald",
                threat_level="Informational",
                status="Found",
                resolution="",
                raw_data=" | ".join(raw_data_parts),
                tags=tags,
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
    music_count = category_found.get("music", 0)
    shopping_count = category_found.get("shopping", 0)
    messaging_count = category_found.get("messaging", 0)
    dating_count = category_found.get("dating", 0)
    crypto_count = category_found.get("crypto", 0)

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
    if music_count:
        breakdown_parts.append(f"Music: {music_count}")
    if shopping_count:
        breakdown_parts.append(f"Shopping: {shopping_count}")
    if messaging_count:
        breakdown_parts.append(f"Messaging: {messaging_count}")
    if dating_count:
        breakdown_parts.append(f"Dating: {dating_count}")
    if crypto_count:
        breakdown_parts.append(f"Crypto: {crypto_count}")

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

    weighted = compute_category_weighted_score(category_found)
    weighted_pct = weighted["percentage"]
    w_color = "red" if weighted_pct > 50 else ("orange" if weighted_pct > 20 else "emerald")
    findings.append(IntelligenceFinding(
        entity=f"Category weighted presence: {weighted_pct}% (raw: {weighted['weighted_score']} / max: {weighted['max_possible']})",
        type="Category Weighted Analysis",
        source="WhatsMyName",
        confidence="Medium",
        color=w_color,
        threat_level="Informational",
        status="Complete",
        raw_data=json.dumps(weighted),
        tags=["weighted", "analysis", "category-weights"]
    ))

    if found_platforms_info:
        enriched_count = len(enrichment_map)
        verified_count = len(verification_map)
        avg_completeness = 0
        if completeness_map:
            avg_completeness = sum(completeness_map.values()) // len(completeness_map)

        high_value_cats = [p["platform"] for p in found_platforms_info if p["category"] in ("dev", "professional", "social") and p["completeness"] >= 50]

        findings.append(IntelligenceFinding(
            entity=f"Profile enrichment: {enriched_count} platforms enriched via API | {verified_count} verified badges | avg completeness {avg_completeness}% | {len(high_value_cats)} high-value profiles",
            type="Profile Enrichment Summary",
            source="WhatsMyName",
            confidence="Medium",
            color="blue",
            threat_level="Informational",
            status="Complete",
            tags=["enrichment", "verification", "completeness", "summary"]
        ))

        identity_report_parts = [
            f"Username '{username}' has accounts on {found_count}/{total_checked} platforms across {len(categories_with_results)} categories.",
            f"Dev footprint: {dev_count} platforms | Professional: {prof_count} | Social: {social_count} | Creative: {creative_count} | Gaming: {gaming_count} | Music: {music_count} | Shopping: {shopping_count} | Messaging: {messaging_count} | Dating: {dating_count} | Crypto: {crypto_count} | Forum: {forum_count}",
            f"Raw availability: {score}% | Weighted presence: {weighted_pct}%",
            f"Verified accounts: {verified_count} | Enriched via API: {enriched_count} | Avg profile completeness: {avg_completeness}%",
        ]

        if high_value_cats:
            identity_report_parts.append(f"High-value profiles (dev/prof/social with ≥50% completeness): {', '.join(high_value_cats[:8])}")

        all_followers = []
        for info in found_platforms_info:
            det = info.get("details", {})
            if det.get("followers") is not None:
                all_followers.append((info["platform"], det["followers"]))

        if all_followers:
            sorted_f = sorted(all_followers, key=lambda x: -x[1])[:5]
            follower_strs = [f"{p}: {c:,}" for p, c in sorted_f]
            identity_report_parts.append(f"Top platforms by followers: {' | '.join(follower_strs)}")

        total_followers = sum(c for _, c in all_followers)
        if total_followers > 0:
            identity_report_parts.append(f"Total estimated audience reach: {total_followers:,} followers")

        findings.append(IntelligenceFinding(
            entity="Identity Footprint Analysis Report",
            type="Identity Footprint Report",
            source="WhatsMyName",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Complete",
            raw_data="\n".join(identity_report_parts),
            tags=["identity", "footprint", "report", "comprehensive", "analysis"]
        ))

    verified_platforms = [info["platform"] for info in found_platforms_info if info.get("verified")]
    if verified_platforms:
        findings.append(IntelligenceFinding(
            entity=f"Verified accounts detected on: {', '.join(verified_platforms)}",
            type="Account Verification Detection",
            source="WhatsMyName",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            status="Found",
            tags=["verified", "badge", "accounts"]
        ))

    similarity_variants = compute_similarity_variants(username)

    if extracted_usernames:
        all_from_extraction = set(extracted_usernames)
        all_from_extraction.discard(username)
        if all_from_extraction:
            findings.append(IntelligenceFinding(
                entity=f"Extracted alias variants from target: {', '.join(sorted(all_from_extraction))}",
                type="Username Extraction Variants",
                source="WhatsMyName",
                confidence="Medium",
                color="teal",
                threat_level="Informational",
                status="Info",
                tags=["username", "variants", "extracted-aliases"]
            ))

    if similarity_variants:
        variant_tasks = []
        variant_map = []
        for v in similarity_variants[:5]:
            for p_name, p_url, p_cat, _ in PLATFORMS:
                variant_tasks.append(check_platform(client, v, p_name, p_url, do_extract=False))
                variant_map.append((v, p_name, p_url, p_cat))

        variant_results = await asyncio.gather(*variant_tasks) if variant_tasks else []

        similar_found = {}
        for (variant, p_name, p_url, p_cat), v_result in zip(variant_map, variant_results):
            if v_result is not None and v_result[0] == "found":
                similar_found.setdefault(variant, [])
                similar_found[variant].append(p_name)

        if similar_found:
            sim_parts = []
            for sim_username, sim_platforms in similar_found.items():
                sim_parts.append(f"'{sim_username}' → {', '.join(sim_platforms[:5])}")
            findings.append(IntelligenceFinding(
                entity=f"Similar username variants with existing profiles: {'; '.join(sim_parts)}",
                type="Username Similarity Detection",
                source="WhatsMyName",
                confidence="Low",
                color="teal",
                threat_level="Informational",
                status="Info",
                raw_data=f"Base username: {username} | Variants checked: {', '.join(similarity_variants)} | Similar found: {json.dumps(similar_found)}",
                tags=["similarity", "username-variants", "typosquat"]
            ))

    return findings
