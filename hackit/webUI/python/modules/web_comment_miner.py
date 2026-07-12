import re, asyncio
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, make_finding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

KEYWORD_PATTERNS = [
    (r"(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND|OPTIMIZE|REVIEW|NOTE|QUESTION|IMPORTANT|DEPRECATED|REMOVE|TEMP|IDEA|FIXIT|HACKAROUND)", "Development Note"),
    (r"(?:password|passwd|pwd|secret|credentials?|api[_-]?key|auth[_-]?key|token|access[_-]?key|private[_-]?key)", "Credential/Secret"),
    (r"(?:https?://[^\s<>\"']+)", "URL/Link"),
    (r"(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "Email Address"),
    (r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)", "IP Address"),
    (r"(?:/var/www/|/home/|/root/|/opt/|/usr/local/|C:\\|D:\\)", "File Path"),
    (r"(?:bug\s*#?\d+|issue\s*#?\d+|ticket\s*#?\d+|JIRA-\d+)", "Issue/Ticket Reference"),
    (r"(?:v?[\d]+\.[\d]+\.[\d]+)", "Version Number"),
    (r"(?:AWS_ACCESS_KEY|AKIA[0-9A-Z]{16})", "AWS Key"),
    (r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})", "GitHub Token"),
    (r"(?:sk_live_[0-9a-zA-Z]{24,})", "Stripe Key"),
    (r"(?:eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})", "JWT Token"),
    (r"(?:mysql://[^\s]+|postgres://[^\s]+|mongodb://[^\s]+|redis://[^\s]+)", "Database Connection String"),
    (r"(?:BEGIN (?:RSA |DSA )?PRIVATE KEY)", "Private Key"),
    (r"(?:ssh-rsa\s+[A-Za-z0-9+/=]+)", "SSH Public Key"),
]

SENSITIVE_URLS = [
    "/", "/robots.txt", "/sitemap.xml", "/.env", "/.env.bak", "/.env.local",
    "/.git/config", "/.git/HEAD", "/.htaccess", "/wp-config.php.bak",
    "/config.yml", "/config.json", "/config.php", "/configuration.php",
    "/web.config", "/crossdomain.xml", "/.DS_Store",
    "/wp-content/debug.log", "/wp-content/uploads/",
    "/vendor/composer/installed.json", "/package.json", "/composer.json",
    "/.well-known/", "/security.txt",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/_debug/", "/telescope/",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/wp-json/wp/v2/users", "/wp-json/",
    "/readme.html", "/LICENSE.txt",
    "/console/", "/_profiler/",
    "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/prometheus",
]

JS_FILE_PATTERNS = [
    r"src=\"([^\"]+\.js(?:\?[^\"]*)?)\"",
    r"src='([^']+\.js(?:\?[^']*)?)'",
    r"href=\"([^\"]+\.js(?:\?[^\"]*)?)\"",
]

async def extract_comments_from_url(client, url: str) -> dict:
    result = {"comments": [], "inline_comments": [], "url": url, "status": 0, "content_type": "", "links": []}
    try:
        resp = await safe_fetch(client, url, timeout=8.0)
        if not resp:
            return result
        result["status"] = resp.status_code
        result["content_type"] = dict(resp.headers).get("content-type", "")
        html = resp.text

        html_comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        for c in html_comments:
            stripped = c.strip()
            if stripped:
                result["comments"].append(stripped)

        js_comments = re.findall(r"//\s*(.*)", html)
        for c in js_comments:
            stripped = c.strip()
            if stripped and len(stripped) > 5:
                result["inline_comments"].append(stripped)

        css_comments = re.findall(r"/\*.*?\*/", html, re.DOTALL)
        for c in css_comments:
            stripped = c.strip()
            if stripped:
                result["comments"].append(stripped)

        conditional_comments = re.findall(r"<!--\[if[^>]*>(.*?)<!\[endif\]-->", html, re.DOTALL)
        for c in conditional_comments:
            stripped = c.strip()
            if stripped:
                result["comments"].append(stripped)

        block_comments = re.findall(r"/\*\*[\s\S]*?\*/", html)
        for c in block_comments:
            stripped = c.strip()
            if stripped:
                result["comments"].append(stripped)

        internal_links = set()
        for match in re.finditer(r'href=["\'](/[^"\'#?]+)', html):
            link = match.group(1)
            if link.startswith("/") and not link.startswith("//"):
                internal_links.add(link)
        result["links"] = list(internal_links)[:50]

    except Exception:
        pass
    return result

async def extract_js_comments(client, base_url: str, js_urls: list) -> list:
    results = []
    sem = asyncio.Semaphore(10)

    async def fetch_js(url):
        async with sem:
            full_url = f"{base_url}{url}" if url.startswith("/") else url
            try:
                resp = await safe_fetch(client, full_url, timeout=8.0)
                if resp and resp.status_code == 200:
                    content = resp.text
                    comments = []
                    for c in re.findall(r"//\s*(.*)", content):
                        s = c.strip()
                        if s and len(s) > 3:
                            comments.append(s)
                    for c in re.findall(r"/\*(.*?)\*/", content, re.DOTALL):
                        s = c.strip()
                        if s and len(s) > 3:
                            comments.append(s)
                    if comments:
                        results.append({"url": full_url, "comments": comments[:30]})
            except Exception:
                pass

    await asyncio.gather(*[fetch_js(u) for u in js_urls])
    return results

def analyze_comment(comment: str) -> list:
    findings = []
    for pattern, category in KEYWORD_PATTERNS:
        matches = re.findall(pattern, comment, re.I)
        for m in matches:
            findings.append({"match": m.strip(), "category": category})
    return findings

async def crawl(target: str, client) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    sem = asyncio.Semaphore(15)

    async def fetch_url(url):
        async with sem:
            return await extract_comments_from_url(client, url)

    tasks = [fetch_url(f"{base_url}{path}") for path in SENSITIVE_URLS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_comments = []
    js_files_found = []
    for r in results:
        if isinstance(r, Exception) or not isinstance(r, dict):
            continue
        if r.get("comments") or r.get("inline_comments"):
            all_comments.append(r)
        for link in r.get("links", []):
            if link.endswith(".js"):
                js_files_found.append(link)

    js_comments = await extract_js_comments(client, base_url, js_files_found[:20])

    for jsr in js_comments:
        all_comments.append({
            "url": jsr["url"],
            "comments": jsr["comments"],
            "inline": [],
            "status": 200,
            "source": "javascript"
        })

    if not all_comments:
        findings.append(make_finding(
            entity=f"No HTML/JS comments found on {domain}",
            ftype="Comment: None Found",
            source="CommentMiner",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["comments", "none"]
        ))
        return findings

    summary_counts = {}
    for entry in all_comments:
        all_texts = entry.get("comments", []) + entry.get("inline", [])
        for comment in all_texts[:80]:
            comment_findings = analyze_comment(comment)
            for cf in comment_findings:
                cat = cf["category"]
                summary_counts[cat] = summary_counts.get(cat, 0) + 1
                findings.append(make_finding(
                    entity=f"Comment contains {cat}: {cf['match'][:80]}",
                    ftype=f"Comment: {cat}",
                    source="CommentMiner",
                    confidence="Medium",
                    color="red" if cat in ("Credential/Secret", "File Path") else ("orange" if cat in ("IP Address", "Email Address", "AWS Key", "GitHub Token", "Stripe Key", "JWT Token", "Private Key", "SSH Public Key", "Database Connection String") else "yellow"),
                    threat_level="Critical" if cat in ("Credential/Secret", "AWS Key", "GitHub Token", "Stripe Key", "Private Key") else ("High Risk" if cat in ("IP Address", "File Path", "Email Address", "JWT Token", "Database Connection String") else "Informational"),
                    raw_data=f"comment_context={comment[:200]}, match={cf['match']}, category={cat}, url={entry.get('url','')}",
                    tags=["comments", cat.lower().replace(" ", "-").replace("/", "-")]
                ))

    total_secrets = sum(summary_counts.get(c, 0) for c in ("Credential/Secret", "File Path", "AWS Key", "GitHub Token", "Stripe Key", "Private Key"))

    if total_secrets > 0:
        findings.append(make_finding(
            entity=f"SECURITY ISSUE: {total_secrets} potential secret(s)/path(s) found in comments!",
            ftype="Comment: Security Alert",
            source="CommentMiner",
            confidence="High",
            color="red",
            threat_level="Critical",
            raw_data=f"secrets={total_secrets}, breakdown={summary_counts}",
            tags=["comments", "security", "secret-leak"]
        ))

    findings.append(make_finding(
        entity=f"Comment Mining Summary: {sum(len(e.get('comments',[])) + len(e.get('inline',[])) for e in all_comments)} comments scanned across {len(all_comments)} pages, {sum(summary_counts.values())} matches, {len(js_files_found)} JS files",
        ftype="Comment: Summary",
        source="CommentMiner",
        confidence="High",
        color="red" if total_secrets else "blue",
        threat_level="Critical" if total_secrets else "Informational",
        raw_data=f"pages={len(all_comments)}, js_files={len(js_files_found)}, matches={summary_counts}",
        tags=["comments", "summary"]
    ))

    return findings
