import httpx
import re
import asyncio
from models import IntelligenceFinding

SOCIAL_PLATFORMS = [
    ("Twitter/X", "https://x.com/{u}", "profile", "social"),
    ("Instagram", "https://www.instagram.com/{u}/", "profile", "social"),
    ("Facebook", "https://www.facebook.com/{u}", "profile", "social"),
    ("TikTok", "https://www.tiktok.com/@{u}", "profile", "social"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "profile", "social"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "profile", "social"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "profile", "professional"),
    ("YouTube", "https://www.youtube.com/@{u}", "channel", "social"),
    ("Twitch", "https://www.twitch.tv/{u}", "channel", "gaming"),
    ("Reddit", "https://www.reddit.com/user/{u}/", "profile", "social"),
    ("Tumblr", "https://{u}.tumblr.com", "blog", "social"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "profile", "social"),
    ("Mastodon.social", "https://mastodon.social/@{u}", "profile", "social"),
    ("Bluesky", "https://bsky.app/profile/{u}", "profile", "social"),
    ("Threads", "https://www.threads.net/@{u}", "profile", "social"),
    ("WhatsApp", "https://wa.me/{u}", "contact", "social"),
    ("Telegram", "https://t.me/{u}", "profile", "social"),
    ("Discord", "https://discord.com/users/{u}", "profile", "gaming"),
    ("Signal", "https://signal.me/#p/{u}", "contact", "social"),
    ("WeChat", "https://web.wechat.com/{u}", "profile", "social"),
    ("GitHub", "https://github.com/{u}", "profile", "dev"),
    ("GitLab", "https://gitlab.com/{u}", "profile", "dev"),
    ("Bitbucket", "https://bitbucket.org/{u}", "profile", "dev"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "profile", "dev"),
    ("NPM", "https://www.npmjs.com/~{u}", "profile", "dev"),
    ("PyPI", "https://pypi.org/user/{u}/", "profile", "dev"),
    ("RubyGems", "https://rubygems.org/profiles/{u}", "profile", "dev"),
    ("NuGet", "https://www.nuget.org/profiles/{u}", "profile", "dev"),
    ("Crates.io", "https://crates.io/users/{u}", "profile", "dev"),
    ("Packagist", "https://packagist.org/packages/{u}/", "profile", "dev"),
    ("Dev.to", "https://dev.to/{u}", "blog", "dev"),
    ("Medium", "https://medium.com/@{u}", "blog", "dev"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "profile", "dev"),
    ("Stack Overflow", "https://stackoverflow.com/users/{u}", "profile", "dev"),
    ("CodePen", "https://codepen.io/{u}", "profile", "dev"),
    ("Replit", "https://replit.com/@{u}", "profile", "dev"),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{u}", "profile", "dev"),
    ("SourceForge", "https://sourceforge.net/u/{u}", "profile", "dev"),
    ("HackerOne", "https://hackerone.com/{u}", "profile", "dev"),
    ("Bugcrowd", "https://bugcrowd.com/{u}", "profile", "dev"),
    ("HackerRank", "https://www.hackerrank.com/{u}", "profile", "dev"),
    ("LeetCode", "https://leetcode.com/{u}/", "profile", "dev"),
    ("Codeforces", "https://codeforces.com/profile/{u}", "profile", "dev"),
    ("TopCoder", "https://www.topcoder.com/members/{u}", "profile", "dev"),
    ("CTFtime", "https://ctftime.org/user/{u}", "profile", "dev"),
    ("TryHackMe", "https://tryhackme.com/p/{u}", "profile", "dev"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{u}", "profile", "dev"),
    ("Keybase", "https://keybase.io/{u}", "profile", "dev"),
    ("Behance", "https://www.behance.net/{u}", "portfolio", "creative"),
    ("Dribbble", "https://dribbble.com/{u}", "portfolio", "creative"),
    ("ArtStation", "https://www.artstation.com/{u}", "portfolio", "creative"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "portfolio", "creative"),
    ("Figma", "https://www.figma.com/@{u}", "profile", "creative"),
    ("SoundCloud", "https://soundcloud.com/{u}", "profile", "creative"),
    ("Bandcamp", "https://bandcamp.com/{u}", "profile", "creative"),
    ("Mixcloud", "https://www.mixcloud.com/{u}/", "profile", "creative"),
    ("Spotify", "https://open.spotify.com/user/{u}", "profile", "creative"),
    ("AngelList", "https://angel.co/u/{u}", "profile", "professional"),
    ("Crunchbase", "https://www.crunchbase.com/person/{u}", "profile", "professional"),
    ("About.me", "https://about.me/{u}", "profile", "professional"),
    ("Linktree", "https://linktr.ee/{u}", "profile", "professional"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{u}", "profile", "professional"),
    ("Patreon", "https://www.patreon.com/{u}", "profile", "professional"),
    ("Ko-fi", "https://ko-fi.com/{u}", "profile", "professional"),
    ("ProductHunt", "https://www.producthunt.com/@{u}", "profile", "professional"),
    ("IndieHackers", "https://www.indiehackers.com/{u}", "profile", "professional"),
    ("Calendly", "https://calendly.com/{u}", "profile", "professional"),
    ("Hashnode", "https://hashnode.com/@{u}", "blog", "dev"),
    ("Steam", "https://steamcommunity.com/id/{u}", "profile", "gaming"),
    ("Epic Games", "https://www.epicgames.com/id/{u}", "profile", "gaming"),
    ("Xbox Live", "https://www.xboxgamertag.com/search/{u}", "profile", "gaming"),
    ("PlayStation", "https://psnprofiles.com/{u}", "profile", "gaming"),
    ("Nintendo", "https://en-americas-support.nintendo.com/user/{u}", "profile", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{u}", "profile", "gaming"),
    ("Lichess", "https://lichess.org/@/{u}", "profile", "gaming"),
    ("Speedrun.com", "https://www.speedrun.com/users/{u}", "profile", "gaming"),
    ("CurseForge", "https://www.curseforge.com/members/{u}", "profile", "gaming"),
    ("Etsy", "https://www.etsy.com/shop/{u}", "shop", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{u}", "profile", "shopping"),
    ("Amazon Wishlist", "https://www.amazon.com/gp/profile/{u}", "profile", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{u}", "shop", "shopping"),
    ("Fiverr", "https://www.fiverr.com/{u}", "profile", "professional"),
    ("Upwork", "https://www.upwork.com/freelancers/~{u}", "profile", "professional"),
    ("Freelancer", "https://www.freelancer.com/u/{u}", "profile", "professional"),
    ("BitcoinTalk", "https://bitcointalk.org/index.php?action=profile;u={u}", "forum", "crypto"),
    ("Gitcoin", "https://gitcoin.co/{u}", "profile", "crypto"),
    ("Etherscan", "https://etherscan.io/address/{u}", "address", "crypto"),
    ("Keybase (crypto)", "https://keybase.io/{u}/sigchain", "profile", "crypto"),
    ("Tinder", "https://tinder.com/@/{u}", "profile", "dating"),
    ("Bumble", "https://bumble.com/profile/{u}", "profile", "dating"),
    ("OkCupid", "https://www.okcupid.com/profile/{u}", "profile", "dating"),
    ("Hinge", "https://hinge.co/profile/{u}", "profile", "dating"),
    ("Grindr", "https://grindr.com/profile/{u}", "profile", "dating"),
]

def normalize_username(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r'[^a-z0-9._-]', '', raw)
    return raw[:30]

def generate_permutations(base: str) -> list:
    perms = set()
    perms.add(base)
    perms.add(f"_{base}")
    perms.add(f"{base}_")
    perms.add(f"__{base}")
    perms.add(f"{base}__")
    perms.add(f".{base}")
    perms.add(f"{base}.")
    perms.add(f"-{base}")
    perms.add(f"{base}-")
    perms.add(f"{base}1")
    perms.add(f"{base}123")
    perms.add(f"real{base}")
    perms.add(f"{base}official")
    perms.add(f"official{base}")
    perms.add(f"{base}real")
    perms.add(f"the{base}")
    perms.add(f"{base}the")
    perms.add(f"iam{base}")
    perms.add(f"{base}io")
    perms.add(f"{base}app")
    perms.add(f"{base}hq")
    perms.add(f"my{base}")
    perms.add(f"{base}me")
    perms.add(f"just{base}")
    if "_" in base:
        perms.add(base.replace("_", ""))
        perms.add(base.replace("_", "."))
        perms.add(base.replace("_", "-"))
    if "." in base:
        perms.add(base.replace(".", ""))
        perms.add(base.replace(".", "_"))
        perms.add(base.replace(".", "-"))
    if "-" in base:
        perms.add(base.replace("-", ""))
        perms.add(base.replace("-", "_"))
        perms.add(base.replace("-", "."))
    return sorted(perms)

RATE_LIMIT_PATTERNS = [
    (r'429', "HTTP 429"),
    (r'rate.?limit', "Rate Limit Text"),
    (r'too many requests', "Too Many Requests"),
    (r'retry.?after', "Retry-After"),
    (r'captcha', "CAPTCHA"),
    (r'blocked', "Blocked"),
    (r'access.?denied', "Access Denied"),
    (r'please.?wait', "Please Wait"),
    (r'slow.?down', "Slow Down"),
]

async def check_platform(client: httpx.AsyncClient, name: str, url: str, ptype: str, category: str, username: str) -> IntelligenceFinding | None:
    try:
        resp = await client.get(url, timeout=8.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        if resp.status_code == 200:
            ext = extract_profile_details(resp.text, name)
            raw = f"URL: {url} | Status: {resp.status_code}"
            if ext:
                raw += " | " + ext
            return IntelligenceFinding(
                entity=f"@{username} on {name} ({url})",
                type=f"Social Alias: {name}",
                source="SocialAliasHunter",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Found",
                resolution=f"Category: {category}, Type: {ptype}",
                raw_data=raw,
                tags=[category, ptype, "social-alias", "found"],
            )
        if resp.status_code == 403 or resp.status_code == 401:
            return IntelligenceFinding(
                entity=f"@{username} on {name} ({url})",
                type=f"Social Alias: {name}",
                source="SocialAliasHunter",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Restricted",
                resolution=f"HTTP {resp.status_code} - account may exist but is private/restricted",
                raw_data=f"URL: {url} | Status: {resp.status_code}",
                tags=[category, ptype, "social-alias", "restricted"],
            )
        for rl_pat, rl_name in RATE_LIMIT_PATTERNS:
            if re.search(rl_pat, resp.text, re.IGNORECASE) or re.search(rl_pat, str(resp.status_code)):
                return IntelligenceFinding(
                    entity=f"Rate limiting detected on {name} for {username}",
                    type="Rate Limit Detection",
                    source="SocialAliasHunter",
                    confidence="Medium",
                    color="red",
                    threat_level="Informational",
                    status="Rate Limited",
                    resolution=rl_name,
                    raw_data=f"URL: {url} | Pattern: {rl_pat}",
                    tags=["rate-limit", name.lower().replace("/", "-")],
                )
    except httpx.TimeoutException:
        return IntelligenceFinding(
            entity=f"Timeout checking {name} for {username}",
            type="Social Alias Timeout",
            source="SocialAliasHunter",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Timeout",
            resolution=f"URL: {url}",
            tags=["timeout"],
        )
    except Exception:
        pass
    return None

def extract_profile_details(html: str, platform: str) -> str:
    details = []
    name_patterns = [
        (r'<title>([^<]+)</title>', 'title'),
        (r'"name"\s*:\s*"([^"]+)"', 'json-name'),
        (r'"full_name"\s*:\s*"([^"]+)"', 'json-fullname'),
        (r'<meta[^>]+name="description"[^>]+content="([^"]+)"', 'meta-desc'),
        (r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', 'og-title'),
        (r'"displayName"\s*:\s*"([^"]+)"', 'display-name'),
        (r'"username"\s*:\s*"([^"]+)"', 'json-username'),
        (r'"screen_name"\s*:\s*"([^"]+)"', 'screen-name'),
    ]
    for pat, label in name_patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            val = m.group(1)[:100]
            details.append(f"{label}={val}")
            break
    follower_pat = r'(?:followers?|subscribers?|fans?)\s*:?\s*([\d,.KkMmBb]+)'
    fm = re.search(follower_pat, html, re.IGNORECASE)
    if fm:
        details.append(f"followers={fm.group(1)}")
    joined_pat = r'(?:joined|member since|registered)\s*:?\s*(\w+\s+\d{4})'
    jm = re.search(joined_pat, html, re.IGNORECASE)
    if jm:
        details.append(f"joined={jm.group(1)}")
    bio_pat = r'<meta[^>]+name="description"[^>]+content="([^"]{30,200})"'
    bm = re.search(bio_pat, html, re.IGNORECASE)
    if bm:
        details.append(f"bio={bm.group(1)[:80]}")
    site_pat = r'(?:website|url|link)\s*:?\s*"?(https?://[^"\s<]+)'
    sm = re.search(site_pat, html, re.IGNORECASE)
    if sm:
        details.append(f"site={sm.group(1)[:60]}")
    return " | ".join(details) if details else ""

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    try:
        base_name = normalize_username(domain.split(".")[0])
        if not base_name:
            return findings

        permutations = generate_permutations(base_name)
        findings.append(IntelligenceFinding(
            entity=f"Username: {base_name} | {len(permutations)} permutations generated",
            type="Social Alias Username Normalization",
            source="SocialAliasHunter",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Analyzed",
            resolution=f"{len(permutations)} username variants",
            raw_data=f"Base: {base_name}, Permutations: {', '.join(permutations[:15])}",
            tags=["username", "permutations"],
        ))

        tasks = []
        for platform_name, url_tpl, ptype, category in SOCIAL_PLATFORMS:
            url = url_tpl.format(u=base_name)
            tasks.append(check_platform(client, platform_name, url, ptype, category, base_name))

        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            results = await asyncio.gather(*chunk, return_exceptions=True)
            for r in results:
                if isinstance(r, IntelligenceFinding):
                    findings.append(r)

        found_count = sum(1 for f in findings if f.status == "Found" and f.type.startswith("Social Alias:"))
        restricted_count = sum(1 for f in findings if f.status == "Restricted")
        rate_limited = sum(1 for f in findings if f.status == "Rate Limited")

        categories_found = {}
        for f in findings:
            for tag in f.tags:
                if tag in ("social", "dev", "professional", "creative", "gaming", "crypto", "dating", "forum", "shopping"):
                    categories_found[tag] = categories_found.get(tag, 0) + 1

        summary_parts = [f"Found on {found_count} platforms"]
        if restricted_count:
            summary_parts.append(f"{restricted_count} restricted")
        if rate_limited:
            summary_parts.append(f"{rate_limited} rate-limited")
        if categories_found:
            cats = ", ".join(f"{k}: {v}" for k, v in sorted(categories_found.items()))
            summary_parts.append(f"[{cats}]")

        findings.append(IntelligenceFinding(
            entity=f"Alias '{base_name}' checked on {len(SOCIAL_PLATFORMS)} platforms: {', '.join(summary_parts)}",
            type="Social Alias Summary",
            source="SocialAliasHunter",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{found_count} found, {restricted_count} restricted, {rate_limited} rate-limited",
            raw_data=f"Total platforms: {len(SOCIAL_PLATFORMS)}, Found: {found_count}, Restricted: {restricted_count}",
            tags=["summary"],
        ))

        if found_count == 0 and rate_limited == 0:
            for perm in permutations[1:6]:
                perm_tasks = []
                for platform_name, url_tpl, ptype, category in SOCIAL_PLATFORMS[:20]:
                    url = url_tpl.format(u=perm)
                    perm_tasks.append(check_platform(client, platform_name, url, ptype, category, perm))
                perm_results = await asyncio.gather(*perm_tasks, return_exceptions=True)
                for r in perm_results:
                    if isinstance(r, IntelligenceFinding) and r.status == "Found":
                        findings.append(r)
                        break
    except Exception:
        pass
    return findings
