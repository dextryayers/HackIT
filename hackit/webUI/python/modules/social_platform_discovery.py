import re
import asyncio
from ..module_common import safe_fetch, make_finding

PLATFORMS = [
    ("Facebook", "https://www.facebook.com/{u}", "social", "social-media"),
    ("Instagram", "https://www.instagram.com/{u}/", "social", "social-media"),
    ("Twitter/X", "https://twitter.com/{u}", "social", "social-media"),
    ("TikTok", "https://www.tiktok.com/@{u}", "social", "social-media"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "social", "messaging"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "professional", "professional"),
    ("GitHub", "https://github.com/{u}", "dev", "development"),
    ("GitLab", "https://gitlab.com/{u}", "dev", "development"),
    ("Bitbucket", "https://bitbucket.org/{u}", "dev", "development"),
    ("Reddit", "https://www.reddit.com/user/{u}/", "social", "social-media"),
    ("YouTube", "https://www.youtube.com/@{u}", "video", "video"),
    ("Twitch", "https://www.twitch.tv/{u}", "gaming", "gaming"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "social", "social-media"),
    ("Tumblr", "https://{u}.tumblr.com", "blog", "blogging"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "photo", "photo"),
    ("Telegram", "https://t.me/{u}", "messaging", "messaging"),
    ("WhatsApp", "https://wa.me/{u}", "messaging", "messaging"),
    ("Discord", "https://discord.com/users/{u}", "gaming", "gaming"),
    ("Steam", "https://steamcommunity.com/id/{u}", "gaming", "gaming"),
    ("Epic Games", "https://www.epicgames.com/id/{u}", "gaming", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{u}", "gaming", "gaming"),
    ("Lichess", "https://lichess.org/@/{u}", "gaming", "gaming"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "social", "social-media"),
    ("ProductHunt", "https://www.producthunt.com/@{u}", "product", "professional"),
    ("Behance", "https://www.behance.net/{u}", "portfolio", "creative"),
    ("Dribbble", "https://dribbble.com/{u}", "portfolio", "creative"),
    ("ArtStation", "https://www.artstation.com/{u}", "portfolio", "creative"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "portfolio", "creative"),
    ("SoundCloud", "https://soundcloud.com/{u}", "music", "creative"),
    ("Bandcamp", "https://{u}.bandcamp.com", "music", "creative"),
    ("Spotify", "https://open.spotify.com/user/{u}", "music", "creative"),
    ("Vimeo", "https://vimeo.com/{u}", "video", "video"),
    ("Medium", "https://medium.com/@{u}", "blog", "blogging"),
    ("Dev.to", "https://dev.to/{u}", "blog", "development"),
    ("Hashnode", "https://hashnode.com/@{u}", "blog", "blogging"),
    ("CodePen", "https://codepen.io/{u}", "dev", "development"),
    ("Replit", "https://replit.com/@{u}", "dev", "development"),
    ("StackOverflow", "https://stackoverflow.com/users/{u}", "dev", "development"),
    ("Kaggle", "https://www.kaggle.com/{u}", "dev", "development"),
    ("Hugging Face", "https://huggingface.co/{u}", "dev", "development"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "dev", "development"),
    ("NPM", "https://www.npmjs.com/~{u}", "dev", "development"),
    ("PyPI", "https://pypi.org/user/{u}/", "dev", "development"),
    ("RubyGems", "https://rubygems.org/profiles/{u}", "dev", "development"),
    ("Crates.io", "https://crates.io/users/{u}", "dev", "development"),
    ("NuGet", "https://www.nuget.org/profiles/{u}", "dev", "development"),
    ("Keybase", "https://keybase.io/{u}", "security", "security"),
    ("HackerOne", "https://hackerone.com/{u}", "security", "security"),
    ("Bugcrowd", "https://bugcrowd.com/{u}", "security", "security"),
    ("TryHackMe", "https://tryhackme.com/p/{u}", "security", "security"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{u}", "security", "security"),
    ("CTFtime", "https://ctftime.org/user/{u}", "security", "security"),
    ("AngelList", "https://angel.co/u/{u}", "professional", "professional"),
    ("Fiverr", "https://www.fiverr.com/{u}", "professional", "professional"),
    ("Upwork", "https://www.upwork.com/freelancers/~{u}", "professional", "professional"),
    ("Patreon", "https://www.patreon.com/{u}", "funding", "professional"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{u}", "funding", "professional"),
    ("Ko-fi", "https://ko-fi.com/{u}", "funding", "professional"),
    ("Etsy", "https://www.etsy.com/shop/{u}", "shop", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{u}", "shop", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{u}", "shop", "shopping"),
    ("Goodreads", "https://www.goodreads.com/{u}", "social", "social-media"),
    ("Letterboxd", "https://letterboxd.com/{u}/", "social", "social-media"),
    ("MyAnimeList", "https://myanimelist.net/profile/{u}", "social", "social-media"),
    ("IMDb", "https://www.imdb.com/user/ur{u}", "social", "social-media"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{u}", "reference", "reference"),
    ("About.me", "https://about.me/{u}", "social", "social-media"),
    ("Linktree", "https://linktr.ee/{u}", "social", "social-media"),
    ("Calendly", "https://calendly.com/{u}", "professional", "professional"),
    ("WordPress", "https://{u}.wordpress.com", "blog", "blogging"),
    ("Blogger", "https://{u}.blogspot.com", "blog", "blogging"),
    ("Substack", "https://{u}.substack.com", "blog", "blogging"),
    ("Pastebin", "https://pastebin.com/u/{u}", "dev", "development"),
    ("VK", "https://vk.com/{u}", "social", "social-media"),
    ("Ok.ru", "https://ok.ru/{u}", "social", "social-media"),
    ("Weibo", "https://www.weibo.com/{u}", "social", "social-media"),
    ("QQ", "https://user.qzone.qq.com/{u}", "social", "social-media"),
    ("Bilibili", "https://space.bilibili.com/{u}", "social", "social-media"),
    ("Mastodon", "https://mastodon.social/@{u}", "social", "social-media"),
    ("Bluesky", "https://bsky.app/profile/{u}", "social", "social-media"),
    ("Threads", "https://www.threads.net/@{u}", "social", "social-media"),
    ("Last.fm", "https://www.last.fm/user/{u}", "music", "creative"),
    ("Poshmark", "https://poshmark.com/closet/{u}", "shop", "shopping"),
    ("Depop", "https://www.depop.com/{u}/", "shop", "shopping"),
    ("Mercari", "https://www.mercari.com/u/{u}", "shop", "shopping"),
    ("Strava", "https://www.strava.com/athletes/{u}", "social", "social-media"),
    ("Meetup", "https://www.meetup.com/members/{u}/", "social", "social-media"),
    ("Signal", "https://signal.me/#p/{u}", "messaging", "messaging"),
    ("Keybase", "https://keybase.io/{u}", "security", "security"),
    ("LeetCode", "https://leetcode.com/{u}/", "dev", "development"),
    ("HackerRank", "https://www.hackerrank.com/{u}", "dev", "development"),
    ("Codewars", "https://www.codewars.com/users/{u}", "dev", "development"),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{u}", "dev", "development"),
    ("TopCoder", "https://www.topcoder.com/members/{u}", "dev", "development"),
    ("Exercism", "https://exercism.org/profiles/{u}", "dev", "development"),
    ("Frontend Mentor", "https://www.frontendmentor.io/profile/{u}", "dev", "development"),
    ("Codementor", "https://www.codementor.io/@{u}", "dev", "development"),
    ("Hackaday", "https://hackaday.io/{u}", "dev", "development"),
    ("Instructables", "https://www.instructables.com/member/{u}", "dev", "development"),
    ("Thingiverse", "https://www.thingiverse.com/{u}", "dev", "development"),
    ("Observable", "https://observablehq.com/@{u}", "dev", "development"),
    ("Glitch", "https://glitch.com/@{u}", "dev", "development"),
    ("CodeSandbox", "https://codesandbox.io/u/{u}", "dev", "development"),
    ("StackBlitz", "https://stackblitz.com/@{u}", "dev", "development"),
    ("Gitpod", "https://gitpod.io/{u}", "dev", "development"),
    ("ResearchGate", "https://www.researchgate.net/profile/{u}", "professional", "professional"),
    ("Academia.edu", "https://independent.academia.edu/{u}", "professional", "professional"),
    ("ORCID", "https://orcid.org/{u}", "professional", "professional"),
    ("Google Scholar", "https://scholar.google.com/citations?user={u}", "professional", "professional"),
    ("SlideShare", "https://www.slideshare.net/{u}", "professional", "professional"),
    ("Crunchbase", "https://www.crunchbase.com/person/{u}", "professional", "professional"),
    ("Glassdoor", "https://www.glassdoor.com/Profile/{u}", "professional", "professional"),
    ("Trustpilot", "https://www.trustpilot.com/review/{u}", "professional", "professional"),
    ("IndieHackers", "https://www.indiehackers.com/{u}", "professional", "professional"),
    ("Open Collective", "https://opencollective.com/{u}", "funding", "professional"),
    ("Liberapay", "https://liberapay.com/{u}", "funding", "professional"),
    ("Kickstarter", "https://www.kickstarter.com/profile/{u}", "funding", "professional"),
    ("GoFundMe", "https://www.gofundme.com/{u}", "funding", "professional"),
    ("Bumble", "https://bumble.com/profile/{u}", "dating", "dating"),
    ("Plurk", "https://www.plurk.com/{u}", "social", "social-media"),
    ("Gab", "https://gab.com/{u}", "social", "social-media"),
    ("Parler", "https://parler.com/profile/{u}", "social", "social-media"),
    ("Minds", "https://www.minds.com/{u}", "social", "social-media"),
    ("Gettr", "https://gettr.com/user/{u}", "social", "social-media"),
    ("Rumble", "https://rumble.com/user/{u}", "video", "video"),
    ("Odysee", "https://odysee.com/@{u}", "video", "video"),
    ("Bitchute", "https://www.bitchute.com/channel/{u}", "video", "video"),
    ("DTube", "https://d.tube/#!/c/{u}", "video", "video"),
    ("Dailymotion", "https://www.dailymotion.com/{u}", "video", "video"),
    ("Youku", "https://youku.com/{u}", "video", "video"),
    ("Unsplash", "https://unsplash.com/@{u}", "photo", "creative"),
    ("500px", "https://500px.com/{u}", "photo", "creative"),
    ("Pexels", "https://www.pexels.com/@{u}", "photo", "creative"),
    ("Pixabay", "https://pixabay.com/users/{u}/", "photo", "creative"),
    ("Freepik", "https://www.freepik.com/author/{u}", "design", "creative"),
    ("Shutterstock", "https://www.shutterstock.com/g/{u}", "design", "creative"),
    ("Coursera", "https://www.coursera.org/user/{u}", "education", "professional"),
    ("edX", "https://www.edx.org/user/{u}", "education", "professional"),
    ("Udemy", "https://www.udemy.com/user/{u}", "education", "professional"),
    ("Skillshare", "https://www.skillshare.com/profile/{u}", "education", "professional"),
    ("Duolingo", "https://www.duolingo.com/profile/{u}", "education", "social-media"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

CATEGORY_MAP = {}
for _, _, _, cat in PLATFORMS:
    if cat not in CATEGORY_MAP:
        CATEGORY_MAP[cat] = len(CATEGORY_MAP)

async def check_platform(username: str, platform_name: str, url: str, ptype: str, category: str, client: AsyncClient) -> IntelligenceFinding | None:
    try:
        resp = await safe_fetch(client, url.format(u=username), timeout=10.0)
        if resp.status_code == 200:
            text_lower = resp.text.lower()
            not_found = ["page not found", "doesn't exist", "not found", "user not found",
                         "profile not found", "no user found", "could not find", "404"]
            if any(nf in text_lower for nf in not_found) and resp.status_code == 404:
                return None
            if any(nf in text_lower for nf in not_found) and len(resp.text) < 500:
                return None

            title_m = re.search(r'<title>([^<]+)</title>', resp.text, re.IGNORECASE)
            title = title_m.group(1).strip()[:100] if title_m else ""

            return make_finding(
                entity=f"{platform_name}: {title or username}",
                ftype=f"Platform Discovery: {platform_name}",
                source="SocialPlatformDiscovery",
                confidence="High",
                color="purple",
                category=f"Platform: {category.title()}",
                threat_level="Informational",
                status="Active Profile",
                resolution=url.format(u=username),
                raw_data=f"URL: {url.format(u=username)} | Title: {title} | HTTP: {resp.status_code} | Category: {category}",
                tags=["platform-discovery", category, ptype, platform_name.lower().replace(" ", "-").replace("/", "-"), "active"]
            )
    except Exception:
        pass
    return None

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        username = parts[-1] if parts[-1] else parts[-2]
    if username.startswith("@"):
        username = username[1:]

    found_count = 0
    category_counts = {}

    for i in range(0, len(PLATFORMS), 15):
        batch = PLATFORMS[i:i+15]
        tasks = []
        for platform_name, url, ptype, category in batch:
            tasks.append(check_platform(username, platform_name, url, ptype, category, client))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, IntelligenceFinding):
                findings.append(r)
                found_count += 1
                for tag in r.tags:
                    if tag in ["social-media", "development", "professional", "gaming", "security",
                               "blogging", "messaging", "creative", "video", "photo", "music",
                               "shopping", "reference", "funding", "dating", "education"]:
                        category_counts[tag] = category_counts.get(tag, 0) + 1

    findings.append(make_finding(
        entity=f"Username '{username}' discovered on {found_count}/{len(PLATFORMS)} platforms",
        ftype="Platform Discovery: Summary",
        source="SocialPlatformDiscovery",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status=f"{found_count} platforms",
        raw_data=f"Username: {username} | Found: {found_count}/{len(PLATFORMS)} | Categories: {', '.join(f'{k}:{v}' for k, v in sorted(category_counts.items(), key=lambda x: -x[1]))}",
        tags=["platform-discovery", "summary", username]
    ))

    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        findings.append(make_finding(
            entity=f"{cat.title()}: {count} platform(s)",
            ftype=f"Platform Discovery: {cat.title()} Coverage",
            source="SocialPlatformDiscovery",
            confidence="Medium",
            color="slate",
            category="General OSINT",
            threat_level="Informational",
            tags=["platform-discovery", cat, "coverage"]
        ))

    if found_count > 0:
        coverage_pct = round(found_count / len(PLATFORMS) * 100, 1)
        level = "Extensive" if coverage_pct > 20 else "Significant" if coverage_pct > 10 else "Moderate" if coverage_pct > 5 else "Limited"
        findings.append(make_finding(
            entity=f"Cross-platform presence: {level} ({coverage_pct}% coverage)",
            ftype="Platform Discovery: Presence Score",
            source="SocialPlatformDiscovery",
            confidence="Medium",
            color="orange" if coverage_pct > 10 else "slate",
            category="General OSINT",
            threat_level="Elevated Risk" if coverage_pct > 15 else "Informational",
            status=level,
            tags=["platform-discovery", "presence", level.lower()]
        ))

    return findings
