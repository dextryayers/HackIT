import httpx
import re
import hashlib
import json
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

SOCIAL_SITES = [
    ("GitHub", "https://api.github.com/search/commits?q={email}",
     lambda d: [i["commit"]["author"]["name"] for i in d.get("items", [])[:10]]),
    ("GitLab", "https://gitlab.com/api/v4/search?scope=users&search={email}",
     lambda d: [i.get("username", "") for i in d if isinstance(i, dict)]),
    ("Gravatar", "https://www.gravatar.com/{hash}.json",
     lambda d: [d.get("entry", [{}])[0].get("displayName", "")] if d.get("entry") else []),
    ("Bugzilla", "https://bugzilla.mozilla.org/rest/user?email={email}",
     lambda d: [d.get("users", [{}])[0].get("real_name", "")] if d.get("users") else []),
    ("Disqus", "https://disqus.com/api/3/users/details.json?email={email}",
     lambda d: [d.get("response", {}).get("username", "")] if d.get("response") else []),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?email={email}",
     lambda d: [d.get("them", [{}])[0].get("username", "")] if d.get("them") else []),
    ("Bitbucket", "https://api.bitbucket.org/2.0/users/?email={email}",
     lambda d: [v.get("username", "") for v in d.get("values", [])]),
    ("HackerNews", "https://hn.algolia.com/api/v1/search?query={email}&tags=comment",
     lambda d: list(set(i.get("author", "") for i in d.get("hits", [])))),
    ("Twitter", "https://api.twitter.com/2/users/by/email/{email}",
     lambda d: [d.get("data", {}).get("username", "")] if d.get("data") else []),
]

COMMIT_SEARCH_URL = "https://api.github.com/search/commits?q={email}&per_page=5"

PASTE_PATTERNS = [
    ("Pastebin", "https://pastebin.com/search?q={email}"),
    ("Ghostbin", "https://ghostbin.com/search?q={email}"),
    ("Rentry", "https://rentry.co/search?q={email}"),
    ("Paste.ee", "https://paste.ee/search?q={email}"),
    ("Hastebin", "https://hastebin.skyra.pw/search?q={email}"),
]

FORUM_PATTERNS = [
    ("XDA Developers", "https://forum.xda-developers.com/search/{email}"),
    ("Stack Overflow", "https://stackoverflow.com/search?q={email}"),
    ("Reddit", "https://www.reddit.com/search?q={email}"),
    ("Quora", "https://www.quora.com/search?q={email}"),
    ("Medium", "https://medium.com/search?q={email}"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def search_github_commits(email: str, client: httpx.AsyncClient) -> dict:
    result = {"usernames": [], "repos": [], "found": False}
    try:
        resp = await safe_fetch(client, 
            f"https://api.github.com/search/commits?q={email}&per_page=5",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/vnd.github.cloak-preview"}
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            for item in items:
                author = item.get("commit", {}).get("author", {})
                if author.get("email", "").lower() == email:
                    result["found"] = True
                    if author.get("name"):
                        result["usernames"].append(author["name"])
                    repo = item.get("repository", {}).get("full_name", "")
                    if repo:
                        result["repos"].append(repo)
            result["usernames"] = list(set(result["usernames"]))
            result["repos"] = list(set(result["repos"]))
    except Exception:
        pass
    return result

async def search_paste_sites(email: str, client: httpx.AsyncClient) -> list:
    results = []
    for name, url in PASTE_PATTERNS:
        try:
            resp = await safe_fetch(client, url.format(email=email), timeout=10.0,
                headers={"User-Agent": UA}, follow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 200:
                if email.lower() in resp.text.lower():
                    results.append({"site": name, "url": url.format(email=email), "size": len(resp.text)})
        except Exception:
            pass
    return results

async def check_gravatar(email: str, client: httpx.AsyncClient) -> dict:
    result = {"found": False, "profile_url": "", "display_name": "", "avatar_url": ""}
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        resp = await safe_fetch(client, 
            f"https://www.gravatar.com/{email_hash}.json",
            timeout=10.0,
            headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            if entry:
                result["found"] = True
                result["display_name"] = entry.get("displayName", "")
                result["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}"
                result["profile_url"] = entry.get("profileUrl", "")
                urls = entry.get("urls", [])
                if urls:
                    result["urls"] = [u.get("value", "") for u in urls if u.get("value")]
    except Exception:
        pass
    return result

async def search_forum_profiles(email: str, client: httpx.AsyncClient) -> list:
    results = []
    for name, url in FORUM_PATTERNS:
        try:
            resp = await safe_fetch(client, url.format(email=email), timeout=10.0,
                headers={"User-Agent": UA})
            if resp.status_code == 200:
                text_lower = resp.text.lower()
                if email.lower() in text_lower and len(text_lower) > 300:
                    results.append({"forum": name, "url": url.format(email=email), "matched": True})
        except Exception:
            pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    if "@" not in email:
        findings.append(make_finding(
            entity="Not a valid email",
            ftype="Social Correlation Error",
            source="EmailSocialCorrelation",
            confidence="High", color="red", category="General OSINT",
            threat_level="Informational", status="Error",
            tags=["error"]
        ))
        return findings

    domain = email.split("@")[1]
    local_part = email.split("@")[0]

    gravatar = await check_gravatar(email, client)
    if gravatar["found"]:
        findings.append(make_finding(
            entity=f"Gravatar profile: {gravatar['display_name'] or 'Unknown'}",
            ftype="Social: Gravatar Profile",
            source="EmailSocialCorrelation",
            confidence="High",
            color="purple",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=gravatar.get("profile_url", ""),
            raw_data=f"Name: {gravatar['display_name']} | Avatar: {gravatar['avatar_url']} | Profile: {gravatar.get('profile_url', 'N/A')}",
            tags=["gravatar", "social-profile", "email-correlation"]
        ))
        if gravatar.get("urls"):
            for u in gravatar["urls"][:5]:
                findings.append(make_finding(
                    entity=f"Associated URL: {u}",
                    ftype="Social: Gravatar Associated URL",
                    source="EmailSocialCorrelation",
                    confidence="Medium",
                    color="slate",
                    category="Social Media Intelligence",
                    threat_level="Informational",
                    raw_data=f"URL found in Gravatar profile: {u}",
                    tags=["gravatar", "associated-url"]
                ))
    else:
        findings.append(make_finding(
            entity="No Gravatar profile found",
            ftype="Social: Gravatar Check",
            source="EmailSocialCorrelation",
            confidence="High",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Not Found",
            tags=["gravatar", "not-found"]
        ))

    github = await search_github_commits(email, client)
    if github["found"]:
        for username in github["usernames"]:
            findings.append(make_finding(
                entity=f"GitHub commit author: {username} (email: {email})",
                type="Social: GitHub Commit Association",
                source="EmailSocialCorrelation",
                confidence="High",
                color="purple",
                category="Social Media Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=f"https://github.com/search?q={email}&type=commits",
                tags=["github", "commit", "code-correlation"]
            ))
        for repo in github["repos"][:5]:
            findings.append(make_finding(
                entity=f"GitHub repository: {repo}",
                ftype="Social: GitHub Repository",
                source="EmailSocialCorrelation",
                confidence="High",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["github", "repository"]
            ))
    else:
        findings.append(make_finding(
            entity="No GitHub commits found for this email",
            ftype="Social: GitHub Commit Search",
            source="EmailSocialCorrelation",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Not Found",
            tags=["github", "commit-search"]
        ))

    paste_results = await search_paste_sites(email, client)
    for pr in paste_results:
        findings.append(make_finding(
            entity=f"Email found on {pr['site']}",
            ftype="Social: Paste Site Presence",
            source="EmailSocialCorrelation",
            confidence="Medium",
            color="orange",
            category="Breach Intelligence",
            threat_level="Elevated Risk",
            status="Exposed on Paste Site",
            resolution=pr["url"],
            raw_data=f"Site: {pr['site']} | Size: {pr['size']} bytes",
            tags=["paste-site", "exposure", pr['site'].lower().replace(" ", "-")]
        ))

    forum_results = await search_forum_profiles(email, client)
    for fr in forum_results:
        findings.append(make_finding(
            entity=f"Email {email} possibly associated with {fr['forum']}",
            ftype="Social: Forum Profile Correlation",
            source="EmailSocialCorrelation",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Possible Match",
            resolution=fr["url"],
            tags=["forum", "profile-correlation", fr['forum'].lower().replace(" ", "-")]
        ))

    findings.append(make_finding(
        entity=f"Email domain: {domain}",
        ftype="Social: Domain Extraction",
        source="EmailSocialCorrelation",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status="Info",
        tags=["domain", domain]
    ))

    associated_usernames = []
    if gravatar.get("display_name"):
        associated_usernames.append(gravatar["display_name"])
    if github["usernames"]:
        associated_usernames.extend(github["usernames"])

    if associated_usernames:
        findings.append(make_finding(
            entity=f"Cross-referenced usernames from email {email}: {', '.join(set(associated_usernames))}",
            type="Social: Username Cross-Reference",
            source="EmailSocialCorrelation",
            confidence="Medium",
            color="purple",
            category="Social Media Intelligence",
            threat_level="Informational",
            status=f"{len(set(associated_usernames))} usernames",
            tags=["username", "cross-reference", "identity-link"]
        ))

    social_count = sum(1 for f in findings if f.type.startswith("Social:"))
    findings.append(make_finding(
        entity=f"Social correlation scan complete for {email}: {social_count} social links found",
        ftype="Social: Correlation Summary",
        source="EmailSocialCorrelation",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Gravatar: {'FOUND' if gravatar['found'] else 'NA'} | GitHub: {'FOUND' if github['found'] else 'NA'} | Paste Sites: {len(paste_results)} | Forums: {len(forum_results)}",
        tags=["correlation", "summary", "social-summary"]
    ))

    return findings
