import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

SEARCH_ENGINES = [
    ("DuckDuckGo", "https://lite.duckduckgo.com/lite/?q={}"),
    ("Brave", "https://search.brave.com/search?q={}"),
    ("Mojeek", "https://www.mojeek.com/search?q={}"),
    ("Swisscows", "https://swisscows.com/web?query={}"),
    ("Gibiru", "https://gibiru.com/results.html?q={}"),
    ("Qwant", "https://www.qwant.com/?q={}"),
    ("Ecosia", "https://www.ecosia.org/search?q={}"),
    ("Startpage", "https://www.startpage.com/do/dsearch?query={}"),
    ("Yandex", "https://yandex.com/search/?text={}"),
    ("Bing", "https://www.bing.com/search?q={}"),
    ("SearX", "https://searx.be/search?q={}"),
    ("YaCy", "https://yacy.net/search.html?query={}"),
    ("Mullvad Leta", "https://leta.mullvad.net/?q={}"),
    ("Metager", "https://metager.org/meta/meta.ger3?eingabe={}"),
]

TITLE_PATTERN = re.compile(r'<[^>]*?class=["\'][^"\']*?(?:title|heading|result__title|result-title|h3)[^"\']*["\'][^>]*>(.*?)</', re.IGNORECASE | re.DOTALL)
URL_PATTERN = re.compile(r'https?://[^\s\'\"<>]+(?=["\'<\s])')
SNIPPET_PATTERN = re.compile(r'<[^>]*?class=["\'][^"\']*?(?:snippet|result__snippet|desc|abstract|content)[^"\']*["\'][^>]*>(.*?)</', re.IGNORECASE | re.DOTALL)
RESULT_COUNT_PATTERN = re.compile(r'(?:about|approximately|around|found|of (?:about|approximately|around))?\s*([0-9,]+)\s*(?:results?|pages?|matches?)', re.IGNORECASE)

RESULT_TYPE_KEYWORDS = {
    "news": ["news", "article", "headline", "press release", "coverage"],
    "social": ["facebook", "twitter", "linkedin", "reddit", "instagram", "tiktok", "youtube"],
    "forum": ["forum", "discussion", "thread", "board", "community"],
    "blog": ["blog", "post", "article", "medium", "wordpress"],
    "video": ["youtube", "vimeo", "dailymotion", "twitch", "video"],
    "shopping": ["shop", "buy", "price", "store", "amazon", "ebay", "walmart"],
    "govt": [".gov", ".mil", "government", "official"],
    "edu": [".edu", "university", "college", "school", "academic"],
    "job": ["job", "career", "hiring", "position", "employment"],
    "review": ["review", "rating", "complaint", "testimonial"],
}

CENSORSHIP_INDICATORS = [
    "blocked", "restricted", "taken down", "removed", "censor",
    "not available in your country", "403", "forbidden",
]


async def search_engine_query(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await client.get(
            url,
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            follow_redirects=True,
        )
        if resp.status_code == 200 and len(resp.text) > 200:
            text = resp.text
            titles = TITLE_PATTERN.findall(text)
            snippets = SNIPPET_PATTERN.findall(text)
            urls_found = URL_PATTERN.findall(text)

            cleaned_titles = [re.sub(r'<[^>]+>', '', t).strip() for t in titles if t.strip()]
            cleaned_snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets if s.strip()]

            target_count = text.lower().count(target.lower())

            censored = any(indicator in text.lower() for indicator in CENSORSHIP_INDICATORS)

            result_types = []
            text_lower = text.lower()
            for rtype, keywords in RESULT_TYPE_KEYWORDS.items():
                if any(kw in text_lower for kw in keywords):
                    result_types.append(rtype)

            return {
                "name": name,
                "url": url,
                "status": resp.status_code,
                "titles": cleaned_titles[:5],
                "snippets": cleaned_snippets[:5],
                "urls_found": urls_found[:5],
                "target_mentions": target_count,
                "result_types": result_types,
                "censored": censored,
                "content_length": len(text),
            }
    except:
        pass
    return None


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    engines_working = 0

    for name, url_template in SEARCH_ENGINES:
        result = await search_engine_query(name, url_template, t, client)
        if result:
            all_results.append(result)
            engines_working += 1

    if all_results:
        findings.append(IntelligenceFinding(
            entity=f"Search engine scan: {engines_working}/{len(SEARCH_ENGINES)} engines returned results for {t}",
            type="Search: Coverage Report",
            source="SearchAggregator",
            confidence="High",
            color="slate",
            category="Search Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["search", "coverage", "engines"],
        ))

    for result in all_results:
        title_count = len(result["titles"])
        mention_count = result["target_mentions"]
        types_str = ", ".join(result["result_types"]) if result["result_types"] else "general"

        findings.append(IntelligenceFinding(
            entity=f"{result['name']}: {mention_count} mentions, {title_count} result titles for {t}",
            type="Search: Engine Result",
            source="SearchAggregator",
            confidence="Medium",
            color="sky",
            category="Search Intelligence",
            threat_level="Informational",
            status="Found" if mention_count > 0 else "No Results",
            resolution=t,
            tags=["search", result['name'].lower().replace(" ", "-"), "result"],
        ))

        if result["titles"]:
            for i, title in enumerate(result["titles"][:3]):
                findings.append(IntelligenceFinding(
                    entity=f"Result title: {title[:120]}",
                    type="Search: Title Extract",
                    source="SearchAggregator",
                    confidence="Medium",
                    color="slate",
                    category="Search Intelligence",
                    threat_level="Informational",
                    status="Extracted",
                    resolution=t,
                    tags=["search", "title", f"result-{i+1}"],
                ))

        if result["urls_found"]:
            for url in result["urls_found"][:3]:
                findings.append(IntelligenceFinding(
                    entity=f"URL: {url[:150]}",
                    type="Search: URL Discovery",
                    source="SearchAggregator",
                    confidence="Medium",
                    color="slate",
                    category="Search Intelligence",
                    threat_level="Informational",
                    status="Discovered",
                    resolution=t,
                    tags=["search", "url", "discovery"],
                ))

        if result["result_types"]:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']} result types: {types_str}",
                type="Search: Result Classification",
                source="SearchAggregator",
                confidence="Medium",
                color="slate",
                category="Search Intelligence",
                threat_level="Informational",
                status="Classified",
                resolution=t,
                tags=["search", "classification"] + result["result_types"],
            ))

        if result["censored"]:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']} results may be censored for {t}",
                type="Search: Censorship Detection",
                source="SearchAggregator",
                confidence="Medium",
                color="orange",
                category="Search Intelligence",
                threat_level="Medium Risk",
                status="Censorship Detected",
                resolution=t,
                tags=["search", "censorship", result['name'].lower().replace(" ", "-")],
            ))

    all_titles = []
    all_snippets = []
    for r in all_results:
        all_titles.extend(r.get("titles", []))
        all_snippets.extend(r.get("snippets", []))

    if all_titles:
        deduped_titles = list(set(all_titles))
        findings.append(IntelligenceFinding(
            entity=f"{len(deduped_titles)} unique result titles across all search engines",
            type="Search: Aggregated Titles",
            source="SearchAggregator",
            confidence="Medium",
            color="slate",
            category="Search Intelligence",
            threat_level="Informational",
            status="Aggregated",
            resolution=t,
            tags=["search", "aggregated", "titles"],
        ))

    total_mentions = sum(r.get("target_mentions", 0) for r in all_results)
    if total_mentions > 0:
        findings.append(IntelligenceFinding(
            entity=f"Total search mentions: {total_mentions} across {engines_working} engines",
            type="Search: Mention Count",
            source="SearchAggregator",
            confidence="Medium",
            color="slate",
            category="Search Intelligence",
            threat_level="Informational",
            status="Counted",
            resolution=t,
            tags=["search", "mentions", "count"],
        ))

    result_type_distribution = {}
    for r in all_results:
        for rt in r.get("result_types", []):
            result_type_distribution[rt] = result_type_distribution.get(rt, 0) + 1

    if result_type_distribution:
        top_types = sorted(result_type_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
        type_summary = ", ".join(f"{t}({c})" for t, c in top_types)
        findings.append(IntelligenceFinding(
            entity=f"Result type distribution: {type_summary}",
            type="Search: Type Distribution",
            source="SearchAggregator",
            confidence="Medium",
            color="slate",
            category="Search Intelligence",
            threat_level="Informational",
            status="Distributed",
            resolution=t,
            tags=["search", "distribution"] + [t for t, _ in top_types],
        ))

    if not all_results:
        findings.append(IntelligenceFinding(
            entity="No search engine results found for target",
            type="Search: Scan Complete",
            source="SearchAggregator",
            confidence="Low",
            color="emerald",
            category="Search Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["search", "clean"],
        ))

    return findings
