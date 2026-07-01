import httpx
import re
import json
from models import IntelligenceFinding
from datetime import datetime

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    username = target.strip().lower()
    if target.startswith("http"):
        parts = target.rstrip("/").split("/")
        if "user" in parts:
            idx = parts.index("user")
            username = parts[idx + 1] if idx + 1 < len(parts) else parts[-1]
        else:
            username = parts[-1] if parts[-1] else parts[-2]
    username = username.replace("/", "").replace("u/", "")

    profile_urls = [
        f"https://www.reddit.com/user/{username}/",
        f"https://old.reddit.com/user/{username}/",
        f"https://libreddit.net/u/{username}",
    ]

    html = None
    source_url = ""
    for url in profile_urls:
        try:
            resp = await client.get(url, timeout=15.0,
                headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
                follow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 500:
                html = resp.text
                source_url = url
                break
        except Exception:
            pass

    if not html:
        findings.append(IntelligenceFinding(
            entity=f"Could not access Reddit profile: u/{username}",
            type="Reddit: Profile Not Accessible",
            source="SocialRedditIntel",
            confidence="High", color="orange",
            category="Social Media Intelligence",
            threat_level="Informational", status="Unreachable",
            tags=["reddit", "unreachable"]
        ))
        return findings

    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    title = title_m.group(1).strip() if title_m else f"u/{username}"

    findings.append(IntelligenceFinding(
        entity=f"Reddit profile: {title}",
        type="Reddit: Profile Found",
        source="SocialRedditIntel",
        confidence="High",
        color="purple",
        category="Social Media Intelligence",
        threat_level="Informational",
        status="Found",
        resolution=f"https://www.reddit.com/user/{username}/",
        tags=["reddit", "profile", username]
    ))

    cake_day_m = re.search(r'(?:Cake Day|cake day|cake_day)[:\s]*([^<]{5,30})', html)
    if not cake_day_m:
        cake_day_m = re.search(r'"created_utc"\s*:\s*(\d+)', html)
        if cake_day_m:
            try:
                ts = int(cake_day_m.group(1))
                dt = datetime.fromtimestamp(ts)
                cake_day_m = type('obj', (object,), {'group': lambda self, x: dt.strftime('%B %d, %Y')})()
            except Exception:
                cake_day_m = None
    if cake_day_m:
        cd_val = cake_day_m.group(1) if hasattr(cake_day_m, 'groups') and cake_day_m.groups() else str(cake_day_m)
        findings.append(IntelligenceFinding(
            entity=f"Account created: {cd_val[:50]}",
            type="Reddit: Account Age",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "cake-day"]
        ))

    karma_m = re.search(r'(\d[\d,.]*[KkMmBb]?)\s*(?:karma|Karma)', html)
    if karma_m:
        findings.append(IntelligenceFinding(
            entity=f"Karma: {karma_m.group(1)}",
            type="Reddit: Karma Total",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "karma"]
        ))

    post_karma_m = re.search(r'(?:Post Karma|post karma)[:\s]*(\d[\d,.]*[KkMmBb]?)', html, re.IGNORECASE)
    if post_karma_m:
        findings.append(IntelligenceFinding(
            entity=f"Post karma: {post_karma_m.group(1)}",
            type="Reddit: Post Karma",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "post-karma"]
        ))

    comment_karma_m = re.search(r'(?:Comment Karma|comment karma)[:\s]*(\d[\d,.]*[KkMmBb]?)', html, re.IGNORECASE)
    if comment_karma_m:
        findings.append(IntelligenceFinding(
            entity=f"Comment karma: {comment_karma_m.group(1)}",
            type="Reddit: Comment Karma",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "comment-karma"]
        ))

    subreddits = re.findall(r'/r/(\w+)', html)
    if subreddits:
        unique_subs = list(set(subreddits))[:15]
        findings.append(IntelligenceFinding(
            entity=f"Subreddits ({len(unique_subs)}): r/{', r/'.join(unique_subs)}",
            type="Reddit: Subreddit Participation",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "subreddits"]
        ))

    posts_comments = re.findall(r'<div[^>]*class="[^"]*(?:usertext-body|entry)[^"]*"[^>]*>([^<]{30,400})', html)
    if not posts_comments:
        posts_comments = re.findall(r'>([^<]{50,400})</(?:p|div)>', html)
        posts_comments = [p for p in posts_comments if len(p) > 50 and 'reddit' not in p.lower()[:20]][:10]

    if posts_comments:
        for i, content in enumerate(posts_comments[:6]):
            content_clean = re.sub(r'\s+', ' ', content).strip()[:150]
            findings.append(IntelligenceFinding(
                entity=f"Content {i+1}: {content_clean}",
                type="Reddit: User Content",
                source="SocialRedditIntel",
                confidence="Low",
                color="slate",
                category="Social Media Intelligence",
                threat_level="Informational",
                tags=["reddit", "content"]
            ))

    awards_m = re.findall(r'(?:Award|award|trophy|Trophy)[:\s]*([^<]{5,30})', html)
    if awards_m:
        findings.append(IntelligenceFinding(
            entity=f"Awards: {', '.join(awards_m[:5])}",
            type="Reddit: Awards/Trophies",
            source="SocialRedditIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "awards"]
        ))

    gold_m = re.search(r'(?:Gold|gold)', html)
    platinum_m = re.search(r'(?:Platinum|platinum)', html)
    if gold_m or platinum_m:
        findings.append(IntelligenceFinding(
            entity=f"Premium awards: {'Gold' if gold_m else ''} {'Platinum' if platinum_m else ''}",
            type="Reddit: Premium Awards",
            source="SocialRedditIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "premium"]
        ))

    is_mod_m = re.search(r'(?:Moderator|moderator|is_mod["\']:\s*true)', html)
    if is_mod_m:
        findings.append(IntelligenceFinding(
            entity="User is a moderator",
            type="Reddit: Moderator Status",
            source="SocialRedditIntel",
            confidence="Medium",
            color="orange",
            category="Social Media Intelligence",
            threat_level="Standard Target",
            status="Moderator",
            tags=["reddit", "moderator"]
        ))

    is_employee_m = re.search(r'(?:is_employee["\']:\s*true)', html)
    if is_employee_m:
        findings.append(IntelligenceFinding(
            entity="User is a Reddit employee",
            type="Reddit: Employee Status",
            source="SocialRedditIntel",
            confidence="Medium",
            color="orange",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Employee",
            tags=["reddit", "employee"]
        ))

    verified_m = re.search(r'(?:Verified|verified|is_verified["\']:\s*true)', html)
    if verified_m:
        findings.append(IntelligenceFinding(
            entity="User is verified",
            type="Reddit: Verification",
            source="SocialRedditIntel",
            confidence="Medium",
            color="emerald",
            category="Social Media Intelligence",
            threat_level="Informational",
            status="Verified",
            tags=["reddit", "verified"]
        ))

    has_gold_m = re.search(r'(?:has_gold["\']:\s*true|is_gold["\']:\s*true)', html)
    if has_gold_m:
        findings.append(IntelligenceFinding(
            entity="User has Reddit Premium/Gold",
            type="Reddit: Premium Status",
            source="SocialRedditIntel",
            confidence="Medium",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "premium"]
        ))

    extracted_info = []
    email_matches = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', html)
    for em in email_matches[:3]:
        extracted_info.append(f"email: {em}")
    phone_matches = re.findall(r'\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', html)
    for pm in phone_matches[:2]:
        extracted_info.append(f"phone: {pm}")

    if extracted_info:
        findings.append(IntelligenceFinding(
            entity=f"Personal info extracted: {'; '.join(extracted_info)}",
            type="Reddit: Personal Information",
            source="SocialRedditIntel",
            confidence="Low",
            color="orange",
            category="Personal Information",
            threat_level="Elevated Risk",
            status="Extracted",
            tags=["reddit", "pii"]
        ))

    interests = re.findall(r'\b(hobby|interest|love|enjoy|favorite|passion)[:\s]*([^.]{5,50})', html, re.IGNORECASE)
    if interests:
        interest_texts = [f"{i[0]}: {i[1].strip()}" for i in interests[:5]]
        findings.append(IntelligenceFinding(
            entity=f"Interests: {'; '.join(interest_texts)}",
            type="Reddit: Interest Extraction",
            source="SocialRedditIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "interests"]
        ))

    op_m = re.search(r'(?:Original Poster|OP)', html)
    if op_m:
        findings.append(IntelligenceFinding(
            entity="User frequently posts as OP in subreddits",
            type="Reddit: Posting Pattern",
            source="SocialRedditIntel",
            confidence="Low",
            color="slate",
            category="Social Media Intelligence",
            threat_level="Informational",
            tags=["reddit", "posting-pattern"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Reddit intelligence gathering complete for u/{username}",
        type="Reddit: Intel Summary",
        source="SocialRedditIntel",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Username: {username} | Subreddits: {len(subreddits) if 'subreddits' in dir() else 0} | Content items: {len(posts_comments) if 'posts_comments' in dir() else 0}",
        tags=["reddit", "summary"]
    ))

    return findings
