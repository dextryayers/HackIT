import httpx
import asyncio
import re
import gzip
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

LINK_RE = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
SCRIPT_RE = re.compile(r'<script[^>]*src=["\'](.*?)["\']', re.IGNORECASE)
FORM_RE = re.compile(r'<form[^>]*action=["\'](.*?)["\']', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]*name=["\'](.*?)["\']', re.IGNORECASE)
TITLE_RE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
META_RE = re.compile(r'<meta[^>]+name=["\'](.*?)["\'][^>]*content=["\'](.*?)["\']', re.IGNORECASE)
SITEMAP_LINK_RE = re.compile(r'<loc[^>]*>(.*?)</loc>', re.IGNORECASE | re.DOTALL)
SITEMAP_ATTR_RE = re.compile(r'<(?:lastmod|changefreq|priority)[^>]*>(.*?)</\w+>', re.IGNORECASE | re.DOTALL)
ROBOTS_SITEMAP_RE = re.compile(r'Sitemap:\s*(.*)', re.IGNORECASE)
CRAWL_DELAY_RE = re.compile(r'Crawl-delay:\s*(\d+)', re.IGNORECASE)

HIDDEN_PARAM_NAMES = {"debug", "test", "dev", "admin", "mode", "source",
    "token", "api_key", "apikey", "key", "secret", "password", "passwd",
    "auth", "access", "bypass", "override", "config", "env", "environment"}

EXTENSION_PRIORITY = {
    ".php": "Dynamic PHP",
    ".asp": "Dynamic ASP",
    ".aspx": "Dynamic ASPX",
    ".jsp": "Dynamic JSP",
    ".js": "JavaScript",
    ".json": "JSON API",
    ".xml": "XML Data",
    ".csv": "Data Export",
    ".pdf": "Document",
    ".zip": "Archive",
    ".sql": "Database Dump",
    ".env": "Environment Config",
    ".git": "Git Exposure",
}

async def fetch_url_with_fallback(client, url, timeout=10.0):
    for scheme in ["https", "http"]:
        try:
            full = f"{scheme}://{url.lstrip('http://').lstrip('https://')}"
            full = full.replace("https://https://", "https://").replace("http://http://", "http://")
            resp = await client.get(full, timeout=timeout,
                headers={"User-Agent": UA}, follow_redirects=True)
            if resp.status_code < 500:
                return resp
        except:
            pass
    return None

async def parse_sitemap_xml(client, sitemap_url, visited_sitemaps):
    findings = []
    urls_found = []
    if sitemap_url in visited_sitemaps:
        return findings, urls_found
    visited_sitemaps.add(sitemap_url)

    try:
        resp = await client.get(sitemap_url, timeout=10.0,
            headers={"User-Agent": UA}, follow_redirects=True)
        if resp.status_code != 200:
            return findings, urls_found

        content = resp.text
        if sitemap_url.endswith(".gz"):
            try:
                content = gzip.decompress(resp.content).decode("utf-8")
            except:
                pass

        sub_sitemaps = SITEMAP_LINK_RE.findall(content)
        for sub in sub_sitemaps:
            sub = sub.strip()
            if sub not in visited_sitemaps and "sitemap" in sub.lower():
                sub_results, sub_urls = await parse_sitemap_xml(client, sub, visited_sitemaps)
                findings.extend(sub_results)
                urls_found.extend(sub_urls)

        try:
            root = ET.fromstring(content)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for url_elem in root.findall(".//sm:url", ns):
                loc = url_elem.find("sm:loc", ns)
                if loc is not None and loc.text:
                    u = loc.text.strip()
                    urls_found.append(u)
                    lastmod = url_elem.find("sm:lastmod", ns)
                    changefreq = url_elem.find("sm:changefreq", ns)
                    priority = url_elem.find("sm:priority", ns)
                    attrs = []
                    if lastmod is not None and lastmod.text:
                        attrs.append(f"lastmod={lastmod.text}")
                    if changefreq is not None and changefreq.text:
                        attrs.append(f"freq={changefreq.text}")
                    if priority is not None and priority.text:
                        attrs.append(f"pri={priority.text}")
                    if attrs:
                        findings.append(IntelligenceFinding(
                            entity=u[:200],
                            type="Sitemap URL (with attributes)",
                            source="CrawlerCore",
                            confidence="High",
                            color="blue",
                            category="Web Crawling & Content Discovery",
                            threat_level="Informational",
                            status="Sitemap Entry",
                            raw_data=f"Attributes: {', '.join(attrs)}",
                            tags=["sitemap"]
                        ))
        except ET.ParseError:
            for loc_match in SITEMAP_LINK_RE.finditer(content):
                u = loc_match.group(1).strip()
                urls_found.append(u)

    except:
        pass
    return findings, urls_found

async def analyze_robots_txt(client, base_url):
    findings = []
    sitemaps_found = []
    try:
        resp = await client.get(f"{base_url}/robots.txt", timeout=8.0,
            headers={"User-Agent": UA})
        if resp.status_code == 200:
            text = resp.text
            findings.append(IntelligenceFinding(
                entity=f"{base_url}/robots.txt",
                type="Robots.txt Detected",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Detected",
                raw_data=text[:2000],
                tags=["robots"]
            ))

            sitemaps = ROBOTS_SITEMAP_RE.findall(text)
            for sm in sitemaps:
                sitemaps_found.append(sm.strip())

            delays = CRAWL_DELAY_RE.findall(text)
            if delays:
                findings.append(IntelligenceFinding(
                    entity=f"Crawl-Delay: {delays[0]}s",
                    type="Robots.txt Crawl Delay",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Detected",
                    tags=["robots", "crawl-delay"]
                ))

            user_agents = re.findall(r"User-agent:\s*(.+)", text)
            if user_agents:
                findings.append(IntelligenceFinding(
                    entity=f"User-Agents targeted: {', '.join(set(user_agents))[:200]}",
                    type="Robots.txt User-Agents",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Analyzed",
                    tags=["robots"]
                ))

            disallowed = re.findall(r"Disallow:\s*(.*)", text)
            allowed = re.findall(r"Allow:\s*(.*)", text)
            for path in disallowed[:10]:
                if path.strip():
                    findings.append(IntelligenceFinding(
                        entity=path.strip()[:200],
                        type="Disallowed Path (robots.txt)",
                        source="CrawlerCore",
                        confidence="High",
                        color="orange" if not path.strip().startswith("/") else "slate",
                        category="Web Crawling & Content Discovery",
                        threat_level="Informational",
                        status="Disallowed",
                        tags=["robots", "disallowed"]
                    ))
            for path in allowed[:5]:
                if path.strip():
                    findings.append(IntelligenceFinding(
                        entity=path.strip()[:200],
                        type="Allowed Path (robots.txt)",
                        source="CrawlerCore",
                        confidence="High",
                        color="slate",
                        category="Web Crawling & Content Discovery",
                        threat_level="Informational",
                        status="Allowed",
                        tags=["robots", "allowed"]
                    ))
    except:
        pass
    return findings, sitemaps_found

async def analyze_page(client, url, domain):
    findings = []
    try:
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": UA}, follow_redirects=True)
        if resp.status_code != 200:
            return findings
        html = resp.text

        links = LINK_RE.findall(html)
        internal_links = set()
        external_links = set()
        for link in links:
            link = link.strip()
            if not link or link.startswith("#") or link.startswith("javascript:"):
                continue
            full = urljoin(url, link)
            parsed = urlparse(full)
            if domain in parsed.netloc or not parsed.netloc:
                internal_links.add(full.split("?")[0])
            elif parsed.netloc:
                external_links.add(full)

        if internal_links:
            findings.append(IntelligenceFinding(
                entity=f"{len(internal_links)} internal links found on {url[:80]}",
                type="Internal Link Discovery",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Links Found",
                raw_data="\n".join(list(internal_links)[:20]),
                tags=["links", "internal"]
            ))

        if external_links:
            ext_domains = set()
            for el in external_links:
                ext_domains.add(urlparse(el).netloc)
            findings.append(IntelligenceFinding(
                entity=f"{len(ext_domains)} external domains linked from {url[:80]}",
                type="External Link Discovery",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="External Links",
                raw_data="\n".join(list(ext_domains)[:10]),
                tags=["links", "external"]
            ))

        scripts = SCRIPT_RE.findall(html)
        if scripts:
            unique_scripts = set(scripts)
            findings.append(IntelligenceFinding(
                entity=f"{len(unique_scripts)} JavaScript files referenced",
                type="JavaScript Discovery",
                source="CrawlerCore",
                confidence="High",
                color="orange",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="JS Found",
                raw_data="\n".join(list(unique_scripts)[:10]),
                tags=["javascript"]
            ))

        forms = FORM_RE.findall(html)
        if forms:
            findings.append(IntelligenceFinding(
                entity=f"{len(forms)} forms detected",
                type="Form Discovery",
                source="CrawlerCore",
                confidence="High",
                color="orange",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Forms Found",
                raw_data="\n".join(forms[:5]),
                tags=["forms"]
            ))

            inputs = INPUT_RE.findall(html)
            hidden_inputs = [i for i in inputs if any(p in i.lower() for p in HIDDEN_PARAM_NAMES)]
            for hi in hidden_inputs[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Hidden/interesting param: {hi}",
                    type="Hidden Parameter Detection",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Hidden Param",
                    tags=["parameters", "hidden"]
                ))

        title_match = TITLE_RE.search(html)
        if title_match:
            findings.append(IntelligenceFinding(
                entity=f"Page Title: {title_match.group(1).strip()[:200]}",
                type="Page Title",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Title",
                tags=["metadata"]
            ))

        meta_tags = META_RE.findall(html)
        for name, content in meta_tags[:5]:
            if name.lower() in ("description", "keywords", "robots", "author"):
                findings.append(IntelligenceFinding(
                    entity=f"Meta {name}: {content[:200]}",
                    type="Meta Tag",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Meta",
                    tags=["metadata"]
                ))

        url_params = parse_qs(urlparse(url).query)
        for param in url_params:
            if param.lower() in HIDDEN_PARAM_NAMES:
                findings.append(IntelligenceFinding(
                    entity=f"URL parameter: {param}={url_params[param][0][:100]}",
                    type="Interesting URL Parameter",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Interesting",
                    tags=["parameters"]
                ))

    except:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    base_url = f"https://{domain}"

    robots_results, extra_sitemaps = await analyze_robots_txt(client, base_url)
    findings.extend(robots_results)

    sitemap_urls_to_check = [f"{base_url}/sitemap.xml"]
    sitemap_urls_to_check.extend(extra_sitemaps)
    sitemap_urls_to_check.extend([
        f"{base_url}/sitemap_index.xml",
        f"{base_url}/sitemap1.xml",
        f"{base_url}/sitemapindex.xml",
    ])

    visited = set()
    all_sitemap_findings = []
    all_sitemap_urls = []
    for sm_url in sitemap_urls_to_check:
        sm_findings, sm_urls = await parse_sitemap_xml(client, sm_url, visited)
        all_sitemap_findings.extend(sm_findings)
        all_sitemap_urls.extend(sm_urls)

    findings.extend(all_sitemap_findings)

    if all_sitemap_urls:
        findings.append(IntelligenceFinding(
            entity=f"{len(all_sitemap_urls)} URLs discovered in sitemaps",
            type="Sitemap URL Count",
            source="CrawlerCore",
            confidence="High",
            color="blue",
            category="Web Crawling & Content Discovery",
            threat_level="Informational",
            status="Sitemap Complete",
            tags=["sitemap", "count"]
        ))

        ext_count = defaultdict(int)
        for u in all_sitemap_urls:
            parsed = urlparse(u)
            path = parsed.path.lower()
            for ext, label in EXTENSION_PRIORITY.items():
                if path.endswith(ext):
                    ext_count[label] += 1
        if ext_count:
            ext_str = ", ".join(f"{k}:{v}" for k, v in sorted(ext_count.items(), key=lambda x: -x[1]))
            findings.append(IntelligenceFinding(
                entity=f"Sitemap content: {ext_str}",
                type="Sitemap Content Breakdown",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Analyzed",
                tags=["sitemap", "content"]
            ))

        sample_urls = all_sitemap_urls[:20]
        page_tasks = [analyze_page(client, u, domain) for u in sample_urls]
        page_results = await asyncio.gather(*page_tasks, return_exceptions=True)
        for pr in page_results:
            if isinstance(pr, list):
                findings.extend(pr)

    else:
        page_results_initial = await analyze_page(client, base_url, domain)
        findings.extend(page_results_initial)

    return findings
