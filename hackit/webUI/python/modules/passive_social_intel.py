import re
import json
from urllib.parse import urlparse, quote
from ..module_common import safe_fetch, make_finding

SOCIAL_USERNAME_PATTERNS = [
    (r'facebook\.com/([^/\s"?]+)', "Facebook"),
    (r'twitter\.com/([^/\s"?]+)', "Twitter"),
    (r'x\.com/([^/\s"?]+)', "X (Twitter)"),
    (r'instagram\.com/([^/\s"?]+)', "Instagram"),
    (r'linkedin\.com/in/([^/\s"?]+)', "LinkedIn"),
    (r'github\.com/([^/\s"?]+)', "GitHub"),
    (r'reddit\.com/r/([^/\s"?]+)', "Reddit"),
    (r'medium\.com/@?([^/\s"?]+)', "Medium"),
    (r'youtube\.com/@?([^/\s"?]+)', "YouTube"),
    (r'tiktok\.com/@?([^/\s"?]+)', "TikTok"),
    (r'twitch\.tv/([^/\s"?]+)', "Twitch"),
    (r'pinterest\.com/([^/\s"?]+)', "Pinterest"),
    (r'telegram\.org/([^/\s"?]+)', "Telegram"),
    (r'patreon\.com/([^/\s"?]+)', "Patreon"),
    (r'crunchbase\.com/organization/([^/\s"?]+)', "Crunchbase"),
    (r'producthunt\.com/@?([^/\s"?]+)', "Product Hunt"),
    (r'keybase\.io/([^/\s"?]+)', "Keybase"),
    (r'about\.me/([^/\s"?]+)', "About.me"),
]

SOCIAL_MEDIA_META = [
    "og:site_name", "og:title", "og:description",
    "twitter:site", "twitter:creator",
    "article:author", "fb:app_id", "fb:profile_id",
]

async def _search_google_social(domain: str, client: AsyncClient) -> list:
    findings = []
    platforms_to_check = [
        ("facebook.com", "Facebook"), ("twitter.com", "Twitter"), ("linkedin.com", "LinkedIn"),
        ("instagram.com", "Instagram"), ("youtube.com", "YouTube"), ("reddit.com", "Reddit"),
        ("github.com", "GitHub"), ("tiktok.com", "TikTok"), ("medium.com", "Medium"),
        ("crunchbase.com", "Crunchbase"), ("glassdoor.com", "Glassdoor"),
    ]
    for platform_url, platform_name in platforms_to_check:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q=site:{platform_url}+{domain}", timeout=15.0)
            if resp.status_code == 200:
                mentions = re.findall(rf'href="(https?://(?:www\.)?{re.escape(platform_url)}[^"]*)"', resp.text)
                unique_mentions = list(set(mentions))[:10]
                if unique_mentions:
                    findings.append(make_finding(
                        entity=f"{platform_name}: {len(unique_mentions)} mention(s) found",
                        ftype=f"Social Intel - {platform_name} Mentions",
                        source="Google Search",
                        confidence="Medium",
                        color="blue",
                        status="Found",
                        raw_data=f"Mentions: {', '.join(unique_mentions[:5])}",
                        tags=["social", platform_name.lower(), "search"]
                    ))
                    for url in unique_mentions[:3]:
                        findings.append(make_finding(
                            entity=url[:200],
                            ftype=f"Social Intel - {platform_name} URL",
                            source="Google Search",
                            confidence="Medium",
                            color="slate",
                            status="Discovered",
                            tags=["social", platform_name.lower(), "url"]
                        ))
        except Exception:
            pass
    return findings

async def _check_linkedin_preview(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q=site:linkedin.com+{domain}", timeout=15.0)
        if resp.status_code == 200:
            previews = re.findall(r'<span[^>]*class="[^"]*BNeawe[^"]*"[^>]*>([^<]*(?:company|employee|professional|profile|director|manager|engineer)[^<]*)</span>', resp.text, re.I)
            for preview in previews[:10]:
                findings.append(make_finding(
                    entity=preview.strip()[:200],
                    ftype="Social Intel - LinkedIn Preview",
                    source="Google Search",
                    confidence="Low",
                    color="slate",
                    status="Preview",
                    raw_data=f"LinkedIn snippet: {preview.strip()}",
                    tags=["social", "linkedin", "preview"]
                ))
    except Exception:
        pass
    return findings

async def _check_reddit_mentions(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q=site:reddit.com+{domain}", timeout=15.0)
        if resp.status_code == 200:
            snippets = re.findall(r'<span[^>]*class="[^"]*BNeawe[^"]*"[^>]*>([^<]*)</span>', resp.text)
            unique_snippets = list(set(snippets))[:10]
            for snippet in unique_snippets:
                if domain.lower() in snippet.lower():
                    findings.append(make_finding(
                        entity=f"Reddit mention: {snippet.strip()[:200]}",
                        ftype="Social Intel - Reddit Mention",
                        source="Google Search",
                        confidence="Low",
                        color="orange",
                        status="Mentioned",
                        raw_data=f"Reddit snippet: {snippet.strip()}",
                        tags=["social", "reddit", "mention"]
                    ))
    except Exception:
        pass
    return findings

async def _check_youtube_mentions(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q=site:youtube.com+{domain}", timeout=15.0)
        if resp.status_code == 200:
            video_titles = re.findall(r'<h3[^>]*class="[^"]*LC20lb[^"]*"[^>]*>(.*?)</h3>', resp.text)
            for title in video_titles[:10]:
                title_clean = re.sub(r'<[^>]+>', '', title).strip()
                if title_clean:
                    findings.append(make_finding(
                        entity=title_clean[:200],
                        ftype="Social Intel - YouTube Video Mention",
                        source="Google Search",
                        confidence="Low",
                        color="slate",
                        status="Mentioned",
                        raw_data=f"YouTube: {title_clean}",
                        tags=["social", "youtube", "mention"]
                    ))
    except Exception:
        pass
    return findings

async def _check_review_platforms(domain: str, client: AsyncClient) -> list:
    findings = []
    review_sites = [
        ("trustpilot.com", "Trustpilot"), ("g2.com", "G2"),
        ("yelp.com", "Yelp"), ("glassdoor.com", "Glassdoor"),
        ("bbb.org", "Better Business Bureau"), ("sitejabber.com", "Sitejabber"),
        ("indeed.com", "Indeed"), ("google.com/maps", "Google Maps"),
    ]
    for site_url, site_name in review_sites:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q=site:{site_url}+{domain}", timeout=15.0)
            if resp.status_code == 200:
                result_count = len(re.findall(rf'href="https?://(?:www\.)?{re.escape(site_url)}', resp.text))
                if result_count > 0:
                    findings.append(make_finding(
                        entity=f"{site_name}: {result_count} reference(s)",
                        ftype=f"Social Intel - {site_name} Review",
                        source="Google Search",
                        confidence="Low",
                        color="slate",
                        status="Referenced",
                        raw_data=f"{site_name} references: {result_count}",
                        tags=["social", "review", site_name.lower().replace(" ", "-")]
                    ))
        except Exception:
            pass
    return findings

async def _check_google_business(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q={domain}+reviews", timeout=15.0)
        if resp.status_code == 200:
            ratings = re.findall(r'(\d+\.?\d*)\s*out of\s*5\s*stars', resp.text, re.I)
            if ratings:
                avg_rating = ratings[0]
                findings.append(make_finding(
                    entity=f"Google rating: {avg_rating}/5 stars",
                    ftype="Social Intel - Google Business Rating",
                    source="Google Search",
                    confidence="Low",
                    color="emerald" if float(avg_rating) >= 4 else "orange",
                    status="Rating Found",
                    tags=["social", "google", "rating"]
                ))
            review_count_m = re.search(r'(\d[\d,]*)\s*reviews?', resp.text, re.I)
            if review_count_m:
                count = review_count_m.group(1)
                findings.append(make_finding(
                    entity=f"{count} reviews on Google",
                    ftype="Social Intel - Google Review Count",
                    source="Google Search",
                    confidence="Low",
                    color="slate",
                    status="Count Found",
                    tags=["social", "google", "reviews"]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    google_findings = await _search_google_social(domain, client)
    findings.extend(google_findings)

    linkedin_findings = await _check_linkedin_preview(domain, client)
    findings.extend(linkedin_findings)

    reddit_findings = await _check_reddit_mentions(domain, client)
    findings.extend(reddit_findings)

    youtube_findings = await _check_youtube_mentions(domain, client)
    findings.extend(youtube_findings)

    review_findings = await _check_review_platforms(domain, client)
    findings.extend(review_findings)

    biz_findings = await _check_google_business(domain, client)
    findings.extend(biz_findings)

    if findings:
        findings.append(make_finding(
            entity=f"Social Media Intelligence complete: {len(findings)} findings",
            ftype="Social Intel - Summary",
            source="Passive Social Intel",
            confidence="High", color="purple",
            status="Complete",
            tags=["social", "summary"]
        ))

    return findings
