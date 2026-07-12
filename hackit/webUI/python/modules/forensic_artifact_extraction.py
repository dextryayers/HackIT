import httpx
import re
import json
from urllib.parse import urlparse, urljoin
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

OG_TAGS = [
    "og:title", "og:type", "og:url", "og:image", "og:description",
    "og:site_name", "og:locale", "og:video", "og:audio",
    "article:published_time", "article:author", "article:section",
    "article:tag", "book:author", "profile:username",
]

TWITTER_TAGS = [
    "twitter:card", "twitter:site", "twitter:creator", "twitter:title",
    "twitter:description", "twitter:image", "twitter:url",
    "twitter:domain", "twitter:app:name:iphone", "twitter:app:id:iphone",
]

JSONLD_TYPES = [
    "Organization", "Person", "WebSite", "WebPage", "Article",
    "Product", "Event", "LocalBusiness", "Restaurant",
    "Hospital", "EducationalOrganization", "Corporation",
    "GovernmentOrganization", "NGO", "SportsTeam",
    "MusicGroup", "Movie", "Book", "SoftwareApplication",
    "MobileApplication", "JobPosting", "Recipe",
]

COMMENT_PATTERNS = [
    (r'<!--(.*?)-->', "HTML Comment"),
    (r'//\s*TODO[:\s]*(.*?)(?:\n|$)', "TODO Comment"),
    (r'//\s*FIXME[:\s]*(.*?)(?:\n|$)', "FIXME Comment"),
    (r'//\s*HACK[:\s]*(.*?)(?:\n|$)', "HACK Comment"),
    (r'//\s*XXX[:\s]*(.*?)(?:\n|$)', "XXX Comment"),
    (r'#\s*TODO[:\s]*(.*?)(?:\n|$)', "Shell/Config TODO"),
    (r'/\*\*?(.*?)\*/', "Block Comment"),
]

SENSITIVE_IN_COMMENTS = [
    r'[\w.+-]+@[\w.-]+\.\w{2,}', r'password\s*[:=]\s*\S+', r'secret\s*[:=]\s*\S+',
    r'api[_-]?key\s*[:=]\s*\S+', r'token\s*[:=]\s*\S+', r'access[_-]?key\s*[:=]\s*\S+',
    r'secret[_-]?key\s*[:=]\s*\S+', r'credentials?\s*[:=]\s*\S+', r'aws[_-]?secret\s*[:=]\s*\S+',
    r'db[_-]?password\s*[:=]\s*\S+', r'mysql[_-]?password\s*[:=]\s*\S+',
]

API_ENDPOINT_PATTERNS = [
    r'/api/v\d+/[\w/]+', r'/graphql', r'/rest/[\w/]+', r'/wp-json/[\w/]+',
    r'/v\d+/[\w/]+', r'/api/[\w/]+', r'/services/[\w/]+', r'/endpoint/[\w/]+',
    r'/ws/[\w/]+', r'/soap/[\w/]+', r'/odata/[\w/]+',
]

SOURCE_MAP_PATTERN = re.compile(r'//# sourceMappingURL=(\S+\.map)')
SOURCE_URL_PATTERN = re.compile(r'//# sourceURL=(\S+)')

META_NAMES = [
    "author", "description", "keywords", "robots", "viewport",
    "theme-color", "application-name", "msapplication-TileColor",
    "msapplication-config", "google-site-verification", "googlebot",
    "rating", "revisit-after", "expires", "copyright", "language",
    "classification", "distribution",
]

async def _extract_html_comments(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp&limit=10&filter=statuscode:200",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            comments_found = 0
            sensitive_found = 0
            for row in data[1:10]:
                if isinstance(row, list) and len(row) >= 2:
                    orig = row[0]
                    ts = row[1]
                    try:
                        snap = await safe_fetch(client, 
                            f"http://web.archive.org/web/{ts}if_/{orig}",
                            timeout=15.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if snap.status_code == 200:
                            html = snap.text[:100000]
                            for pattern, comment_type in COMMENT_PATTERNS:
                                for m in re.finditer(pattern, html, re.I | re.DOTALL):
                                    content = m.group(1).strip()[:200]
                                    if content and len(content) > 5:
                                        comments_found += 1
                                        findings.append(make_finding(
                                            entity=f"[{ts[:8]}] {comment_type}: {content[:200]}",
                                            ftype=f"Forensic Artifact - {comment_type}",
                                            source="Wayback Machine",
                                            confidence="High", color="slate",
                                            status="Extracted",
                                            raw_data=f"Comment from {ts[:8]}: {m.group(0)[:500]}",
                                            tags=["forensic", "artifact", "comment"]
                                        ))
                                        for sens_pat in SENSITIVE_IN_COMMENTS:
                                            if re.search(sens_pat, content, re.I):
                                                sensitive_found += 1
                                                findings.append(make_finding(
                                                    entity=f"Sensitive in comment: {content[:200]}",
                                                    ftype="Forensic Artifact - Sensitive Data in Comment",
                                                    source="Wayback Machine",
                                                    confidence="High", color="red",
                                                    threat_level="High Risk",
                                                    status="Leaked",
                                                    tags=["forensic", "artifact", "sensitive"]
                                                ))
                                                break
                    except Exception:
                        pass
            if comments_found > 0:
                findings.append(make_finding(
                    entity=f"Found {comments_found} comments ({sensitive_found} with sensitive data)",
                    type="Forensic Artifact - Comment Mining Summary",
                    source="Wayback Machine",
                    confidence="High", color="purple",
                    status="Mined",
                    tags=["forensic", "artifact", "comment-summary"]
                ))
    except Exception:
        pass
    return findings

async def _extract_js_sourcemaps(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp&limit=10&filter=statuscode:200&filter=mimetype:text/javascript&filter=mimetype:application/javascript",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            map_count = 0
            for row in data[1:10]:
                if isinstance(row, list) and len(row) >= 2:
                    js_url = row[0]
                    ts = row[1]
                    try:
                        js_resp = await safe_fetch(client, 
                            f"http://web.archive.org/web/{ts}if_/{js_url}",
                            timeout=15.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if js_resp.status_code == 200:
                            js = js_resp.text[:50000]
                            for m in SOURCE_MAP_PATTERN.finditer(js):
                                map_url = m.group(1)
                                if not map_url.startswith("http"):
                                    map_url = urljoin(js_url, map_url)
                                map_count += 1
                                findings.append(make_finding(
                                    entity=f"SourceMap: {map_url} [from {ts[:8]}]",
                                    ftype="Forensic Artifact - Source Map URL",
                                    source="Wayback Machine",
                                    confidence="High", color="orange",
                                    status="Discovered",
                                    raw_data=f"Source map at {map_url} from {js_url}",
                                    tags=["forensic", "artifact", "sourcemap"]
                                ))
                            for m in SOURCE_URL_PATTERN.finditer(js):
                                source_url = m.group(1)
                                findings.append(make_finding(
                                    entity=f"SourceURL: {source_url} [from {ts[:8]}]",
                                    ftype="Forensic Artifact - Source URL Reference",
                                    source="Wayback Machine",
                                    confidence="High", color="slate",
                                    tags=["forensic", "artifact", "sourceurl"]
                                ))
                    except Exception:
                        pass
            if map_count > 0:
                findings.append(make_finding(
                    entity=f"Found {map_count} source map references",
                    ftype="Forensic Artifact - Source Map Summary",
                    source="Wayback Machine",
                    confidence="High", color="purple",
                    tags=["forensic", "artifact", "sourcemap-summary"]
                ))
    except Exception:
        pass
    return findings

async def _extract_structured_data(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp&limit=5&filter=statuscode:200&collapse=urlkey",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:6]:
                if isinstance(row, list) and len(row) >= 2:
                    orig = row[0]
                    ts = row[1]
                    try:
                        snap = await safe_fetch(client, 
                            f"http://web.archive.org/web/{ts}if_/{orig}",
                            timeout=15.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if snap.status_code == 200:
                            html = snap.text[:100000]
                            jsonld_matches = re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', html, re.I | re.DOTALL)
                            for jm in jsonld_matches:
                                try:
                                    jd = json.loads(jm)
                                    jd_type = jd.get("@type", "Unknown")
                                    if jd_type in JSONLD_TYPES:
                                        name = jd.get("name", jd.get("legalName", ""))
                                        findings.append(make_finding(
                                            entity=f"JSON-LD: {jd_type} - {name[:200] if name else 'Unnamed'}",
                                            ftype=f"Forensic Artifact - JSON-LD ({jd_type})",
                                            source=f"Wayback Machine [{ts[:8]}]",
                                            confidence="High", color="blue",
                                            raw_data=json.dumps(jd, indent=2)[:2000],
                                            tags=["forensic", "artifact", "json-ld", jd_type.lower()]
                                        ))
                                except Exception:
                                    pass
                            for tag in OG_TAGS:
                                m = re.search(rf'<meta[^>]+(?:property|name)=["\']{re.escape(tag)}["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
                                if m:
                                    content = m.group(1).strip()[:200]
                                    findings.append(make_finding(
                                        entity=f"OG: {tag} = {content}",
                                        ftype="Forensic Artifact - Open Graph Tag",
                                        source=f"Wayback Machine [{ts[:8]}]",
                                        confidence="High", color="slate",
                                        tags=["forensic", "artifact", "opengraph", tag.replace(":", "-")]
                                    ))
                            for tag in TWITTER_TAGS:
                                m = re.search(rf'<meta[^>]+name=["\']{re.escape(tag)}["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
                                if m:
                                    content = m.group(1).strip()[:200]
                                    findings.append(make_finding(
                                        entity=f"Twitter: {tag} = {content}",
                                        ftype="Forensic Artifact - Twitter Card Tag",
                                        source=f"Wayback Machine [{ts[:8]}]",
                                        confidence="High", color="slate",
                                        tags=["forensic", "artifact", "twitter-card", tag.replace(":", "-")]
                                    ))
                            for meta_name in META_NAMES:
                                m = re.search(rf'<meta[^>]+name=["\']{re.escape(meta_name)}["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
                                if m:
                                    content = m.group(1).strip()[:200]
                                    findings.append(make_finding(
                                        entity=f"Meta {meta_name}: {content}",
                                        ftype="Forensic Artifact - Meta Tag",
                                        source=f"Wayback Machine [{ts[:8]}]",
                                        confidence="High", color="slate",
                                        tags=["forensic", "artifact", "meta", meta_name]
                                    ))
                            api_endpoints = set()
                            for ep_pat in API_ENDPOINT_PATTERNS:
                                for m in re.finditer(ep_pat, html, re.I):
                                    ep = m.group(0).strip()[:200]
                                    if ep:
                                        api_endpoints.add(ep)
                            for ep in list(api_endpoints)[:15]:
                                findings.append(make_finding(
                                    entity=f"API Endpoint: {ep}",
                                    ftype="Forensic Artifact - API Endpoint Discovery",
                                    source=f"Wayback Machine [{ts[:8]}]",
                                    confidence="Medium", color="orange",
                                    status="Discovered",
                                    tags=["forensic", "artifact", "api-endpoint"]
                                ))
                            rss_feeds = re.findall(r'<link[^>]+type="application/rss\+xml"[^>]+href=["\']([^"\']+)["\']', html, re.I)
                            atom_feeds = re.findall(r'<link[^>]+type="application/atom\+xml"[^>]+href=["\']([^"\']+)["\']', html, re.I)
                            for feed in rss_feeds + atom_feeds:
                                findings.append(make_finding(
                                    entity=f"RSS/Atom Feed: {feed}",
                                    ftype="Forensic Artifact - Feed Discovery",
                                    source=f"Wayback Machine [{ts[:8]}]",
                                    confidence="High", color="slate",
                                    tags=["forensic", "artifact", "feed"]
                                ))
                            favicon = re.search(r'<link[^>]+rel=["\']?(?:shortcut )?icon["\']?[^>]+href=["\']([^"\']+)["\']', html, re.I)
                            if favicon:
                                fav_url = favicon.group(1)
                                if not fav_url.startswith("http"):
                                    fav_url = urljoin(orig, fav_url)
                                findings.append(make_finding(
                                    entity=f"Favicon: {fav_url}",
                                    ftype="Forensic Artifact - Favicon URL",
                                    source=f"Wayback Machine [{ts[:8]}]",
                                    confidence="High", color="slate",
                                    tags=["forensic", "artifact", "favicon"]
                                ))
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def _extract_error_pages(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    error_patterns = {
        "404": ["Not Found", "404", "Page Not Found"],
        "500": ["Internal Server Error", "500", "Server Error"],
        "403": ["Forbidden", "403", "Access Denied"],
        "401": ["Unauthorized", "401", "Authentication Required"],
        "503": ["Service Unavailable", "503"],
    }
    try:
        resp = await safe_fetch(client, 
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=20",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            error_pages = {}
            for row in data[1:]:
                if isinstance(row, list) and len(row) >= 3:
                    orig = row[0]
                    ts = row[1]
                    sc = row[2]
                    if sc in error_patterns:
                        if sc not in error_pages:
                            error_pages[sc] = []
                        error_pages[sc].append((orig, ts))
            for sc, pages in error_pages.items():
                findings.append(make_finding(
                    entity=f"HTTP {sc} ({error_patterns[sc][1]}) on {len(pages)} pages",
                    type="Forensic Artifact - Error Page Signature",
                    source="Wayback Machine",
                    confidence="High", color="orange",
                    status="Error Pages Found",
                    raw_data=f"HTTP {sc} pages: {', '.join([p[0][:100] for p in pages[:5]])}",
                    tags=["forensic", "artifact", f"http-{sc}"]
                ))
                for page_url, page_ts in pages[:5]:
                    try:
                        snap = await safe_fetch(client, 
                            f"http://web.archive.org/web/{page_ts}if_/{page_url}",
                            timeout=10.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if snap.status_code == 200:
                            html = snap.text[:20000]
                            path_info = re.findall(r'(?:path|file|script|line)\s*[:=]\s*([^\s<]+)', html, re.I)
                            for p in path_info[:5]:
                                findings.append(make_finding(
                                    entity=f"Path disclosure in error page: {p}",
                                    ftype="Forensic Artifact - Path Disclosure",
                                    source="Wayback Machine",
                                    confidence="High", color="red",
                                    threat_level="Elevated Risk",
                                    status="Disclosed",
                                    tags=["forensic", "artifact", "path-disclosure"]
                                ))
                            versions = re.findall(r'(?:version|v)[\s:]*(\d+\.\d+(?:\.\d+)?)', html, re.I)
                            for v in versions[:3]:
                                findings.append(make_finding(
                                    entity=f"Version disclosure in error page: {v}",
                                    ftype="Forensic Artifact - Version Disclosure",
                                    source="Wayback Machine",
                                    confidence="High", color="orange",
                                    threat_level="Standard Target",
                                    tags=["forensic", "artifact", "version-disclosure"]
                                ))
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    comment_findings = await _extract_html_comments(domain, client)
    findings.extend(comment_findings)

    sourcemap_findings = await _extract_js_sourcemaps(domain, client)
    findings.extend(sourcemap_findings)

    structured_findings = await _extract_structured_data(domain, client)
    findings.extend(structured_findings)

    error_findings = await _extract_error_pages(domain, client)
    findings.extend(error_findings)

    if findings:
        findings.append(make_finding(
            entity=f"Forensic Artifact Extraction complete: {len(findings)} artifacts",
            type="Forensic Artifact - Summary",
            source="Forensic Artifact Extraction",
            confidence="High", color="purple",
            status="Complete",
            tags=["forensic", "artifact", "summary"]
        ))

    return findings
