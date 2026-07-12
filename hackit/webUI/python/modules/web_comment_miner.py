import re
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, make_finding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

KEYWORD_PATTERNS = [
    (r"(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND|OPTIMIZE|REVIEW|NOTE|QUESTION|IMPORTANT|DEPRECATED|REMOVE|TEMP|IDEA|FIXIT|HACKAROUND)", "Development Note"),
    (r"(?:password|passwd|pwd|secret|credentials?|api[_-]?key|auth[_-]?key|token|access[_-]?key)", "Credential/Secret"),
    (r"(?:https?://[^\s<>\"']+)", "URL/Link"),
    (r"(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "Email Address"),
    (r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)", "IP Address"),
    (r"(?:/var/www/|/home/|/root/|/opt/|/usr/local/|C:\\|D:\\)", "File Path"),
    (r"(?:bug\s*#?\d+|issue\s*#?\d+|ticket\s*#?\d+|JIRA-\d+)", "Issue/Ticket Reference"),
    (r"(?:v?[\d]+\.[\d]+\.[\d]+)", "Version Number"),
    (r"(?:@\w+)", "Username/Mention"),
    (r"(?:\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b)", "IP Address"),
]

PAGE_CATEGORIES = [
    ("", "Main Page"),
    ("/wp-content/", "WordPress Content"),
    ("/wp-includes/", "WordPress Includes"),
    ("/wp-admin/", "WordPress Admin"),
    ("/sites/default/", "Drupal Default"),
    ("/sites/all/", "Drupal All"),
]

async def extract_comments_from_url(client, url: str) -> dict:
    result = {"comments": [], "inline_comments": [], "url": url, "status": 0, "content_type": ""}
    try:
        resp = await safe_fetch(client, url, timeout=10.0)
        if resp:
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

    except Exception:
        pass
    return result

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

    all_comments = []
    summary_counts = {"Development Note": 0, "Credential/Secret": 0, "URL/Link": 0, "Email Address": 0, "IP Address": 0, "File Path": 0, "Other": 0}

    for url_suffix, category_name in PAGE_CATEGORIES:
        for proto in ["https", "http"]:
            url = f"{proto}://{domain}{url_suffix}"
            result = await extract_comments_from_url(client, url)
            if result["comments"] or result["inline_comments"]:
                total_comments = len(result["comments"]) + len(result["inline_comments"])
                all_comments.append({"url": url, "comments": result["comments"], "inline": result["inline_comments"], "status": result["status"]})

                findings.append(make_finding(
                    entity=f"Found {total_comments} comment(s) in {url} (HTTP {result['status']})",
                    ftype="Comment: Page Comments",
                    source="CommentMiner",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"url={url}, html_comments={len(result['comments'])}, inline_comments={len(result['inline_comments'])}",
                    tags=["comments", category_name.lower().replace(" ", "-")]
                ))
                break

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

    for entry in all_comments:
        all_texts = entry["comments"] + entry["inline"]
        for comment in all_texts[:50]:
            comment_findings = analyze_comment(comment)
            for cf in comment_findings:
                cat = cf["category"]
                if cat not in summary_counts:
                    summary_counts[cat] = 0
                summary_counts[cat] += 1
                findings.append(make_finding(
                    entity=f"Comment contains {cat}: {cf['match'][:80]}",
                    ftype=f"Comment: {cat}",
                    source="CommentMiner",
                    confidence="Medium",
                    color="red" if cat in ("Credential/Secret", "File Path") else ("orange" if cat in ("IP Address", "Email Address") else "yellow"),
                    threat_level="Critical" if cat == "Credential/Secret" else ("High Risk" if cat in ("IP Address", "File Path", "Email Address") else "Informational"),
                    raw_data=f"comment_context={comment[:200]}, match={cf['match']}, category={cat}",
                    tags=["comments", cat.lower().replace(" ", "-").replace("/", "-")]
                ))

    total_secrets = 0
    for cat, cnt in summary_counts.items():
        if cat in ("Credential/Secret", "File Path"):
            total_secrets += cnt

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
        entity=f"Comment Mining Summary: {sum(len(e['comments']) + len(e['inline']) for e in all_comments)} comments, {sum(summary_counts.values())} interesting matches",
        ftype="Comment: Summary",
        source="CommentMiner",
        confidence="High",
        color="red" if total_secrets else "blue",
        threat_level="Critical" if total_secrets else "Informational",
        raw_data=f"total_comments={sum(len(e['comments']) + len(e['inline']) for e in all_comments)}, matches={dict(summary_counts)}",
        tags=["comments", "summary"]
    ))

    return findings
