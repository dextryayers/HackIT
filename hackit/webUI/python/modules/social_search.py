import httpx
import re
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

PLATFORMS = [
    ("Twitter/X", "https://twitter.com/{username}", "social-media"),
    ("LinkedIn", "https://www.linkedin.com/in/{username}", "professional"),
    ("GitHub", "https://github.com/{username}", "development"),
    ("Instagram", "https://www.instagram.com/{username}", "social-media"),
    ("Facebook", "https://www.facebook.com/{username}", "social-media"),
    ("TikTok", "https://www.tiktok.com/@{username}", "social-media"),
    ("YouTube", "https://www.youtube.com/@{username}", "video"),
    ("Reddit", "https://www.reddit.com/user/{username}", "social-media"),
    ("Pinterest", "https://www.pinterest.com/{username}", "social-media"),
    ("Tumblr", "https://{username}.tumblr.com", "blogging"),
    ("Snapchat", "https://www.snapchat.com/add/{username}", "social-media"),
    ("Telegram", "https://t.me/{username}", "messaging"),
    ("Discord", "https://discord.com/users/{username}", "gaming"),
    ("Medium", "https://medium.com/@{username}", "blogging"),
    ("Dev.to", "https://dev.to/{username}", "development"),
    ("StackOverflow", "https://stackoverflow.com/users/{username}", "development"),
    ("Keybase", "https://keybase.io/{username}", "security"),
    ("GitLab", "https://gitlab.com/{username}", "development"),
    ("Bitbucket", "https://bitbucket.org/{username}", "development"),
    ("Behance", "https://www.behance.net/{username}", "design"),
    ("Dribbble", "https://dribbble.com/{username}", "design"),
    ("AngelList", "https://angel.co/u/{username}", "professional"),
    ("ProductHunt", "https://www.producthunt.com/@{username}", "product"),
    ("HackerNews", "https://news.ycombinator.com/user?id={username}", "social-media"),
    ("Mastodon", "https://mastodon.social/@{username}", "social-media"),
    ("Bluesky", "https://bsky.app/profile/{username}", "social-media"),
    ("Threads", "https://www.threads.net/@{username}", "social-media"),
    ("CodePen", "https://codepen.io/{username}", "development"),
    ("Replit", "https://replit.com/@{username}", "development"),
    ("Hashnode", "https://hashnode.com/@{username}", "blogging"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "reference"),
    ("SlideShare", "https://www.slideshare.net/{username}", "professional"),
    ("Flickr", "https://www.flickr.com/people/{username}", "photography"),
    ("Vimeo", "https://vimeo.com/{username}", "video"),
    ("SoundCloud", "https://soundcloud.com/{username}", "music"),
]


async def check_platform(username: str, platform_name: str, url_template: str,
                         category: str, client: httpx.AsyncClient) -> list:
    findings = []
    url = url_template.replace("{username}", username)
    try:
        resp = await client.get(url, timeout=10.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
            follow_redirects=True
        )
        page_text = resp.text.lower() if hasattr(resp, 'text') else ""

        # Consider a profile found if:
        # 1. Status 200 (not 404)
        # 2. Page contains username or the platform's "not found" indicators are absent
        not_found_indicators = [
            "page not found", "doesn't exist", "no user found",
            "could not find", "this page doesn't exist", "sorry",
            "not found", "we couldn't find", "no one uses this",
            "user not found", "profile not found", "this account doesn",
            "404", "this page isn't available",
        ]
        is_not_found = any(ind in page_text for ind in not_found_indicators) and resp.status_code == 404
        is_not_found = is_not_found or resp.status_code == 404

        if resp.status_code == 200 and not any(
            ind in page_text for ind in ["page not found", "doesn't exist", "not found", "could not find"]
        ):
            profile_name = ""
            title_match = re.search(r'<title>([^<]+)</title>', resp.text or "", re.IGNORECASE)
            if title_match:
                profile_name = title_match.group(1).strip()[:100]

            findings.append(IntelligenceFinding(
                entity=f"{platform_name}: {profile_name or username}",
                type=f"Social Profile: {platform_name}",
                source="SocialSearch",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Profile found",
                resolution=url,
                raw_data=f"URL: {url}, Title: {profile_name}",
                tags=["social-profile", category, platform_name.lower().replace("/", "-").replace(" ", "-")]
            ))

            # If Twitter/X, try to extract follower count, bio
            if platform_name == "Twitter/X":
                followers_match = re.search(r'(\d[\d,]*)\s*(?:follower|Follower)', resp.text or "")
                if followers_match:
                    findings.append(IntelligenceFinding(
                        entity=f"Followers: {followers_match.group(1)}",
                        type="Twitter/X: Followers",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["twitter", "followers"]
                    ))
            elif platform_name == "LinkedIn":
                headline_match = re.search(r'<title>([^|]+)', resp.text or "")
                if headline_match:
                    findings.append(IntelligenceFinding(
                        entity=headline_match.group(1).strip()[:150],
                        type="LinkedIn Headline",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["linkedin", "headline"]
                    ))
            elif platform_name == "GitHub":
                bio_match = re.search(r'<div\s+class=["\']user-profile-bio["\'][^>]*>\s*<div[^>]*>([^<]+)',
                                      resp.text or "", re.DOTALL)
                if not bio_match:
                    bio_match = re.search(r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
                                          resp.text or "")
                if bio_match:
                    findings.append(IntelligenceFinding(
                        entity=bio_match.group(1).strip()[:200],
                        type="GitHub Bio",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["github", "bio"]
                    ))
                repos_match = re.search(r'(\d[\d,]*)\s*(?:repositories?|Repositories?)', resp.text or "")
                if repos_match:
                    findings.append(IntelligenceFinding(
                        entity=f"Repos: {repos_match.group(1)}",
                        type="GitHub: Repositories",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["github", "repositories"]
                    ))

        elif resp.status_code < 500:
            pass
    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass
    return findings


async def check_username_across_platforms(username: str, client: httpx.AsyncClient) -> list:
    findings = []
    tasks = []
    for platform_name, url_template, category in PLATFORMS:
        tasks.append(
            check_platform(username, platform_name, url_template, category, client)
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    found_count = len(findings)
    if found_count > 0:
        platforms_found = ", ".join(
            sorted(set(re.sub(r"Social Profile: ", "", f.type) for f in findings))
        )
        findings.append(IntelligenceFinding(
            entity=f"Username '{username}' found on {found_count} platform(s): {platforms_found[:200]}",
            type="Social Search: Profile Summary",
            source="SocialSearch",
            confidence="High",
            color="purple" if found_count > 3 else "slate",
            threat_level="Informational",
            status=f"{found_count} profiles found",
            tags=["social-search", "username-summary", username]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Username '{username}' not found on checked platforms",
            type="Social Search: No Results",
            source="SocialSearch",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="No profiles found",
            tags=["social-search", "no-results"]
        ))

    return findings


def extract_potential_usernames(target: str) -> list:
    candidates = set()
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    # Domain parts as username
    parts = domain.split(".")
    if len(parts) >= 2:
        candidates.add(parts[0])
    if len(parts) >= 3:
        candidates.add(parts[1])
    if "-" in parts[0]:
        candidates.add(parts[0].replace("-", ""))
        candidates.add(parts[0].replace("-", "_"))
    if parts[0].endswith("blog"):
        candidates.add(parts[0][:-4])
    # Add the full TLD-stripped name
    main_part = parts[0]
    candidates.add(main_part)
    candidates.add(main_part.capitalize())
    candidates.add(main_part.upper())

    # Company name from domain
    company_variations = [
        main_part,
        main_part + "hq",
        main_part + "labs",
        main_part + "app",
        main_part + "io",
        main_part + "corp",
        main_part + "inc",
        main_part.capitalize(),
    ]
    for var in company_variations:
        candidates.add(var)

    # Filter too-short or too-long
    return [c for c in candidates if 3 <= len(c) <= 30]


async def check_domain_on_profiles(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    # Check key platforms for the domain name as company
    company_username = target.split(".")[0] if "." in target else target

    # Social profiles listing the domain/company
    soc_tasks = []
    for platform_name, url_template, category in [
        ("LinkedIn", "https://www.linkedin.com/company/{username}", "professional"),
        ("Facebook", "https://www.facebook.com/{username}", "social-media"),
        ("Twitter/X", "https://twitter.com/{username}", "social-media"),
        ("GitHub", "https://github.com/{username}", "development"),
        ("Instagram", "https://www.instagram.com/{username}", "social-media"),
        ("YouTube", "https://www.youtube.com/@{username}", "video"),
        ("Crunchbase", "https://www.crunchbase.com/organization/{username}", "business"),
        ("AngelList", "https://angel.co/company/{username}", "business"),
    ]:
        soc_tasks.append(
            check_platform(company_username, f"{platform_name} (Company/Org)",
                          url_template, category, client)
        )

    results = await asyncio.gather(*soc_tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    potential_usernames = extract_potential_usernames(domain)

    tasks = []
    # Search top 3 most likely usernames
    for username in potential_usernames[:3]:
        tasks.append(check_username_across_platforms(username, client))

    # Also check domain as company profile
    tasks.append(check_domain_on_profiles(domain, client))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    profile_count = sum(1 for f in findings if f.type.startswith("Social Profile:"))
    username_count = sum(1 for f in findings if "Username" in f.entity and "platform" in f.entity)

    findings.append(IntelligenceFinding(
        entity=f"Social Search: {profile_count} profiles across social platforms",
        type="Social Search Summary",
        source="SocialSearch",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{profile_count} profiles, {username_count} username matches",
        raw_data=f"Usernames checked: {', '.join(potential_usernames[:5])}",
        tags=["social-search", "summary"]
    ))

    return findings
