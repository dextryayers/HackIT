import httpx
import re
from urllib.parse import urlparse, urljoin
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap/sitemap.xml",
    "/sitemap.xml.gz",
    "/sitemap-index.xml",
    "/sitemapindex.xml",
    "/sitemap/",
]

async def parse_sitemap(content: str) -> list:
    urls = []
    locs = re.findall(r"<loc>(.*?)</loc>", content, re.I)
    for loc in locs:
        urls.append(loc.strip())
    sub_sitemaps = re.findall(r"<sitemap>\s*<loc>(.*?)</loc>", content, re.I)
    return urls, sub_sitemaps

async def fetch_and_parse_sitemap(client: httpx.AsyncClient, url: str) -> dict:
    result = {"url": url, "status": 0, "urls": [], "sub_sitemaps": [], "success": False}
    try:
        resp = await client.get(url, timeout=10.0, follow_redirects=False, headers={"User-Agent": UA})
        result["status"] = resp.status_code
        if resp.status_code == 200:
            urls, sub_sitemaps = await parse_sitemap(resp.text)
            result["urls"] = urls
            result["sub_sitemaps"] = sub_sitemaps
            result["success"] = True
    except Exception:
        pass
    return result

async def get_robots_sitemaps(client: httpx.AsyncClient, base_url: str) -> list:
    sitemaps = []
    try:
        resp = await client.get(f"{base_url}/robots.txt", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                m = re.search(r"^Sitemap:\s*(\S+)", line, re.I)
                if m:
                    sitemaps.append(m.group(1).strip())
    except Exception:
        pass
    return sitemaps

def categorize_url(url: str) -> str:
    path = urlparse(url).path.lower()
    if "/product/" in path or "/products/" in path or "/item/" in path or "/shop/" in path:
        return "Product"
    if "/post/" in path or "/blog/" in path or "/article/" in path or "/news/" in path or "/202" in path:
        return "Post/Article"
    if "/category/" in path or "/categories/" in path or "/section/" in path:
        return "Category"
    if "/tag/" in path or "/tags/" in path:
        return "Tag"
    if "/page/" in path or "/pages/" in path:
        return "Page"
    if "/author/" in path:
        return "Author"
    if "/api/" in path:
        return "API"
    if path == "/" or path == "":
        return "Homepage"
    return "Other"

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    for proto in ["https", "http"]:
        try:
            r = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            if r.status_code == 200:
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    robots_sitemaps = await get_robots_sitemaps(client, base_url)
    all_sitemap_urls = []

    if robots_sitemaps:
        all_sitemap_urls.extend(robots_sitemaps)
        findings.append(IntelligenceFinding(
            entity=f"Found {len(robots_sitemaps)} sitemap reference(s) in robots.txt",
            type="Sitemap: From Robots.txt",
            source="SitemapAnalyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data="\n".join(robots_sitemaps),
            tags=["sitemap", "robots-txt"]
        ))

    for sp in SITEMAP_PATHS:
        full_url = f"{base_url}{sp}"
        if full_url not in all_sitemap_urls:
            all_sitemap_urls.append(full_url)

    all_urls = []
    processed_sitemaps = set()
    sitemaps_to_process = list(all_sitemap_urls)

    while sitemaps_to_process and len(processed_sitemaps) < 15:
        sm_url = sitemaps_to_process.pop(0)
        if sm_url in processed_sitemaps:
            continue
        processed_sitemaps.add(sm_url)

        result = await fetch_and_parse_sitemap(client, sm_url)
        if result["success"]:
            findings.append(IntelligenceFinding(
                entity=f"Sitemap found: {sm_url} ({len(result['urls'])} URLs, {len(result['sub_sitemaps'])} sub-sitemaps)",
                type="Sitemap: Found",
                source="SitemapAnalyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                raw_data=f"sitemap={sm_url}, urls={len(result['urls'])}, sub_sitemaps={len(result['sub_sitemaps'])}",
                tags=["sitemap", "found"]
            ))
            all_urls.extend(result["urls"])
            for sub in result["sub_sitemaps"]:
                if sub not in processed_sitemaps and sub not in sitemaps_to_process:
                    sitemaps_to_process.append(sub)
        else:
            if result["status"]:
                pass

    if not all_urls:
        findings.append(IntelligenceFinding(
            entity=f"No sitemap found for {domain}",
            type="Sitemap: None Found",
            source="SitemapAnalyzer",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["sitemap", "none"]
        ))
        return findings

    unique_locs = list(set(all_urls))
    findings.append(IntelligenceFinding(
        entity=f"Total unique URLs in sitemaps: {len(unique_locs)}",
        type="Sitemap: URL Count",
        source="SitemapAnalyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"total_urls={len(all_urls)}, unique={len(unique_locs)}",
        tags=["sitemap", "url-count"]
    ))

    categories = {}
    for url in unique_locs:
        cat = categorize_url(url)
        categories[cat] = categories.get(cat, 0) + 1

    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        findings.append(IntelligenceFinding(
            entity=f"Sitemap URL type: {cat}: {count} URL(s)",
            type="Sitemap: URL Category",
            source="SitemapAnalyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"category={cat}, count={count}",
            tags=["sitemap", "categorization"]
        ))

    hidden_indicators = ["admin", "private", "backup", "internal", "secret", "test", "debug", "dev", "staging", "hidden", "confidential", "draft", "temp", "old", "archive"]
    hidden_urls = [u for u in unique_locs if any(ind in urlparse(u).path.lower() for ind in hidden_indicators)]

    if hidden_urls:
        findings.append(IntelligenceFinding(
            entity=f"Sensitive/hidden URLs in sitemap: {len(hidden_urls)} found",
            type="Sitemap: Hidden URLs",
            source="SitemapAnalyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            raw_data="\n".join(hidden_urls[:15]),
            tags=["sitemap", "hidden", "exposure"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Sitemap Analysis: {len(processed_sitemaps)} sitemap(s), {len(unique_locs)} unique URLs, {len(hidden_urls)} hidden",
        type="Sitemap: Summary",
        source="SitemapAnalyzer",
        confidence="High",
        color="red" if hidden_urls else "blue",
        threat_level="High Risk" if hidden_urls else "Informational",
        raw_data=f"sitemaps={len(processed_sitemaps)}, unique_urls={len(unique_locs)}, hidden={len(hidden_urls)}, categories={categories}",
        tags=["sitemap", "summary"]
    ))

    return findings
