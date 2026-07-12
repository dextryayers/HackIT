import re
import json
from urllib.parse import urlparse, quote
from typing import List
from module_common import safe_fetch, make_finding

FORUM_SOURCES = [
    ("Stack Overflow", "https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&intitle={}&site=stackoverflow&filter=withbody"),
    ("Server Fault", "https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&intitle={}&site=serverfault"),
    ("Super User", "https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&intitle={}&site=superuser"),
    ("Quora", "https://www.quora.com/search?q={}"),
    ("Reddit", "https://www.reddit.com/search.json?q={}&limit=10&sort=relevance"),
    ("Hacker News", "https://hn.algolia.com/api/v1/search?query={}&hitsPerPage=10"),
    ("LWN", "https://lwn.net/Search/DoSearch?q={}"),
    ("Lobsters", "https://lobste.rs/search?q={}"),
    ("Slashdot", "https://slashdot.org/search?q={}"),
    ("Ars Technica", "https://arstechnica.com/search/?q={}"),
    ("TechCrunch", "https://techcrunch.com/search/{}"),
    ("The Verge", "https://www.theverge.com/search?q={}"),
    ("Spiceworks", "https://community.spiceworks.com/search?q={}"),
    ("Dell Community", "https://www.dell.com/community/search?q={}"),
    ("Cisco Community", "https://community.cisco.com/search?q={}"),
    ("Microsoft Community", "https://answers.microsoft.com/search?q={}"),
    ("Apple Community", "https://discussions.apple.com/search?q={}"),
    ("Google Product Forums", "https://support.google.com/search?q={}"),
    ("CloudFlare Community", "https://community.cloudflare.com/search?q={}"),
    ("AWS Forum", "https://repost.aws/search?q={}"),
    ("XDA Developers", "https://forum.xda-developers.com/search?q={}"),
    ("Unity Forums", "https://forum.unity.com/search?q={}"),
    ("Unreal Engine Forums", "https://forums.unrealengine.com/search?q={}"),
    ("Godot Forums", "https://godotforums.org/search?q={}"),
    ("MetaFilter", "https://www.metafilter.com/search/?q={}"),
    ("Something Awful", "https://forums.somethingawful.com/search.php?q={}"),
    ("CNET", "https://www.cnet.com/search/?q={}"),
    ("ZDNet", "https://www.zdnet.com/search/?q={}"),
    ("Samsung Community", "https://r1.community.samsung.com/search?q={}"),
    ("VMware Communities", "https://communities.vmware.com/search?q={}"),
    ("Oracle Community", "https://community.oracle.com/search?q={}"),
    ("IBM Community", "https://community.ibm.com/search?q={}"),
    ("Intel Community", "https://community.intel.com/search?q={}"),
    ("AMD Community", "https://community.amd.com/search?q={}"),
    ("NVIDIA Developer", "https://developer.nvidia.com/search?q={}"),
]

SENTIMENT_TECHNICAL = {
    "complaint": ["bug", "issue", "problem", "broken", "error", "crash", "failed", "frustrat", "terrible", "worst", "slow", "unusable"],
    "praise": ["great", "amazing", "excellent", "love", "fantastic", "awesome", "brilliant", "best", "perfect", "recommend"],
    "support": ["help", "how to", "solution", "fix", "workaround", "tutorial", "guide", "tip", "advice"],
    "feature_request": ["wish", "suggestion", "feature request", "would be nice", "improve", "missing"],
    "discussion": ["anyone else", "thoughts", "opinion", "experience", "review", "compare"],
}

async def search_reddit(target: str, client) -> dict:
    resp = await safe_fetch(client,
        "https://www.reddit.com/search.json",
        params={"q": target, "limit": 10, "sort": "relevance"},
        headers={"User-Agent": "OSINT-Module/1.0"})
    if resp and resp.status_code == 200:
        data = resp.json()
        posts = []
        for child in data.get("data", {}).get("children", []):
            d = child.get("data", {})
            posts.append({
                "title": d.get("title", ""),
                "subreddit": d.get("subreddit", ""),
                "score": d.get("score", 0),
                "url": d.get("url", ""),
                "num_comments": d.get("num_comments", 0),
                "created": d.get("created_utc", 0),
            })
        return {
            "source": "Reddit",
            "posts": posts,
            "total": len(posts),
        }
    return None


async def search_hackernews(target: str, client) -> dict:
    resp = await safe_fetch(client,
        "https://hn.algolia.com/api/v1/search",
        params={"query": target, "hitsPerPage": 10},
        headers={"User-Agent": "OSINT-Module/1.0"})
    if resp and resp.status_code == 200:
        hits = resp.json().get("hits", [])
        return {
            "source": "Hacker News",
            "posts": [{"title": h.get("title", ""), "url": h.get("url", "") or h.get("story_url", ""), "points": h.get("points", 0), "author": h.get("author", "")} for h in hits],
            "total": len(hits),
        }
    return None


async def search_stackexchange(target: str, client) -> list:
    results = []
    sites = [
        ("Stack Overflow", "stackoverflow"),
        ("Server Fault", "serverfault"),
        ("Super User", "superuser"),
    ]
    for site_name, site_param in sites:
        resp = await safe_fetch(client,
            "https://api.stackexchange.com/2.3/search",
            params={"order": "desc", "sort": "relevance", "intitle": target, "site": site_param, "filter": "withbody"},
            headers={"User-Agent": "OSINT-Module/1.0"})
        if resp and resp.status_code == 200:
            items = resp.json().get("items", [])
            if items:
                results.append({
                    "source": site_name,
                    "questions": [{"title": i.get("title", ""), "score": i.get("score", 0), "view_count": i.get("view_count", 0), "answer_count": i.get("answer_count", 0)} for i in items[:5]],
                    "total": len(items),
                })
    return results


def classify_discussion(text: str) -> list:
    categories = []
    for category, keywords in SENTIMENT_TECHNICAL.items():
        if any(kw in text.lower() for kw in keywords):
            categories.append(category)
    return categories


async def crawl(target: str, client) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    reddit = await search_reddit(t, client)
    hn = await search_hackernews(t, client)
    se_results = await search_stackexchange(t, client)

    if reddit and reddit["posts"]:
        findings.append(make_finding(
            entity=f"Reddit: {reddit['total']} posts mentioning {t}",
            ftype="Forum: Reddit Mentions",
            source="ForumIntel",
            confidence="High",
            color="orange",
            category="Forum Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["forum", "reddit", "mention"],
        ))
        for post in reddit["posts"][:5]:
            categories = classify_discussion(post["title"])
            findings.append(make_finding(
                entity=f"Reddit r/{post['subreddit']}: {post['title'][:120]}",
                ftype="Forum: Reddit Post",
                source="ForumIntel",
                confidence="High",
                color="blue",
                category="Forum Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                raw_data=f"Score: {post['score']}, Comments: {post['num_comments']}",
                tags=["forum", "reddit", f"r-{post['subreddit']}"] + categories,
            ))

    if hn and hn["posts"]:
        findings.append(make_finding(
            entity=f"Hacker News: {hn['total']} posts mentioning {t}",
            ftype="Forum: HN Mentions",
            source="ForumIntel",
            confidence="High",
            color="orange",
            category="Forum Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["forum", "hacker-news", "mention"],
        ))
        for post in hn["posts"][:5]:
            findings.append(make_finding(
                entity=f"HN: {post['title'][:120]} by {post['author']} ({post['points']} pts)",
                ftype="Forum: HN Post",
                source="ForumIntel",
                confidence="High",
                color="blue",
                category="Forum Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["forum", "hacker-news", "post"],
            ))

    for se in se_results:
        findings.append(make_finding(
            entity=f"{se['source']}: {se['total']} questions mentioning {t}",
            ftype="Forum: StackExchange Mentions",
            source="ForumIntel",
            confidence="High",
            color="orange",
            category="Forum Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["forum", se['source'].lower().replace(" ", "-"), "question"],
        ))
        for q in se["questions"][:3]:
            findings.append(make_finding(
                entity=f"{se['source']}: {q['title'][:120]}",
                ftype="Forum: StackExchange Question",
                source="ForumIntel",
                confidence="High",
                color="blue",
                category="Forum Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["forum", "question", "technical"],
            ))

    for name, url_template in FORUM_SOURCES:
        if name in ["Reddit", "Hacker News"]:
            continue
        if "stackexchange" in name.lower() or "stackoverflow" in name.lower() or "serverfault" in name.lower() or "superuser" in name.lower():
            continue
        url = url_template.format(quote(t))
        resp = await safe_fetch(client, url, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp and resp.status_code == 200 and len(resp.text) > 300:
            mentions = resp.text.lower().count(t.lower())
            if mentions > 0:
                findings.append(make_finding(
                    entity=f"{name}: {mentions} mentions of {t}",
                    ftype="Forum: Source Mention",
                    source="ForumIntel",
                    confidence="Low",
                    color="sky",
                    category="Forum Intelligence",
                    threat_level="Informational",
                    status="Found",
                    resolution=t,
                    tags=["forum", name.lower().replace(" ", "-")],
                ))

    if not reddit and not hn and not se_results:
        findings.append(make_finding(
            entity="No forum discussions found for target",
            ftype="Forum: Scan Complete",
            source="ForumIntel",
            confidence="Low",
            color="emerald",
            category="Forum Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["forum", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Forum scan complete for {t}",
        ftype="Forum: Scan Summary",
        source="ForumIntel",
        confidence="Medium",
        color="slate",
        category="Forum Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["forum", "summary"],
    ))

    return findings
