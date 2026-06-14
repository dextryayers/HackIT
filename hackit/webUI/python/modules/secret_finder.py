import httpx
import re
import asyncio
import json
from urllib.parse import urljoin, urlparse
from models import IntelligenceFinding

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "Critical"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key", "Critical"),
    (r'(?i)AIza[0-9A-Za-z\-_]{35}', "Google API Key (AIza)", "Critical"),
    (r'(?i)sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key", "Critical"),
    (r'(?i)pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key", "High"),
    (r'(?i)sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Secret Key", "Medium"),
    (r'(?i)pk_test_[0-9a-zA-Z]{24,}', "Stripe Test Publishable Key", "Medium"),
    (r'(?i)ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token", "Critical"),
    (r'(?i)gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token", "Critical"),
    (r'(?i)ghu_[0-9a-zA-Z]{36}', "GitHub User Token", "Critical"),
    (r'(?i)ghs_[0-9a-zA-Z]{36}', "GitHub App Token", "Critical"),
    (r'(?i)ghr_[0-9a-zA-Z]{36}', "GitHub Refresh Token", "Critical"),
    (r'(?i)glpat-[0-9A-Za-z\-_]{20,}', "GitLab Personal Access Token", "Critical"),
    (r'(?i)xox[abposr]-[0-9a-zA-Z\-]{10,}', "Slack Token", "Critical"),
    (r'(?i)discord(?:_token|_webhook)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{24,})["\']?', "Discord Token", "Critical"),
    (r'(?:https?://)?discord(?:app)?\.com/api/webhooks/[^\s\'"]+', "Discord Webhook URL", "Critical"),
    (r'(?i)telegram_bot_token\s*[=:]\s*["\']?([0-9]+:[A-Za-z0-9_\-]+)["\']?', "Telegram Bot Token", "Critical"),
    (r'(?i)twilio_account_sid\s*[=:]\s*["\']?(AC[0-9a-f]{32})["\']?', "Twilio Account SID", "Critical"),
    (r'(?i)twilio_auth_token\s*[=:]\s*["\']?([0-9a-f]{32})["\']?', "Twilio Auth Token", "Critical"),
    (r'(?i)mailchimp_api_key\s*[=:]\s*["\']?([0-9a-f]{32}-us[0-9]+)["\']?', "Mailchimp API Key", "Critical"),
    (r'(?i)sendgrid_api_key\s*[=:]\s*["\']?(SG\.[A-Za-z0-9_\-]{20,})["\']?', "SendGrid API Key", "Critical"),
    (r'(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----', "Private Key Exposure", "Critical"),
    (r'(?i)-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----', "PGP Key Block", "Critical"),
    (r'(?i)ssh-(rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{20,}', "OpenSSH Public Key", "High"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token", "Critical"),
    (r'(?i)(?:jwt|jws)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']?', "JWT Token (named)", "Critical"),
    (r'(?i)firebase.*url\s*[=:]\s*["\']?(https://[a-zA-Z0-9_\-\.]+\.firebaseio\.com)["\']?', "Firebase URL", "High"),
    (r'(?i)firebase.*api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "Firebase API Key", "High"),
    (r'(?i)mongo(db)?(?:\+srv)?://[^\s\'"]+', "MongoDB Connection String", "Critical"),
    (r'(?i)postgres(ql)?://[^\s\'"]+', "PostgreSQL Connection String", "Critical"),
    (r'(?i)mysql://[^\s\'"]+', "MySQL Connection String", "Critical"),
    (r'(?i)redis://[^\s\'"]+', "Redis Connection String", "Critical"),
    (r'(?i)heroku.*api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,})["\']?', "Heroku API Key", "Critical"),
    (r'(?i)secret_key_base\s*[=:]\s*["\']?([A-Za-z0-9]{64,128})["\']?', "Rails Secret Key Base", "Critical"),
    (r'(?i)django.*secret[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*()_\-+=]{40,})["\']?', "Django Secret Key", "Critical"),
    (r'(?i)s3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+', "S3 Bucket Reference", "High"),
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', "Generic API Key", "High"),
    (r'(?i)(?:secret|token|password|passwd)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.!@#$%^&*]{8,})["\']?', "Generic Secret/Token/Password", "High"),
    (r'(?i)authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+', "Bearer Authorization Token", "Critical"),
    (r'(?i)client_secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "OAuth Client Secret", "Critical"),
    (r'(?i)consumer_secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "OAuth Consumer Secret", "Critical"),
    (r'(?i)access_token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Access Token", "Critical"),
    (r'(?i)refresh_token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Refresh Token", "Critical"),
    (r'(?i)(?:session|cookie)_secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "Session/Cookie Secret", "Critical"),
    (r'(?i)encryption_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{16,})["\']?', "Encryption Key", "Critical"),
    (r'(?i)hmac_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{16,})["\']?', "HMAC Key", "Critical"),
    (r'(?i)digitalocean.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "DigitalOcean Token", "Critical"),
    (r'(?i)azure.*key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{32,})["\']?', "Azure Subscription Key", "Critical"),
    (r'(?i)azure.*connection.*string\s*[=:]\s*["\']?([A-Za-z0-9;=]+)["\']?', "Azure Connection String", "Critical"),
    (r'(?i)cloudinary.*url\s*[=:]\s*["\']?(cloudinary://[^\s\'"]+)["\']?', "Cloudinary URL", "Critical"),
    (r'(?i)(?:JDBC|jdbc):[a-z]+://[^\s\'"]+', "JDBC Connection String", "High"),
    (r'(?i)(?:DB_CONNECTION|DB_HOST|DB_USERNAME|DB_PASSWORD|DB_DATABASE)\s*[=:]\s*["\']?([^\s\'"]{3,})["\']?', "Database Environment Variable", "High"),
    (r'(?i)(?:STRIPE|STRIPE_SECRET|STRIPE_KEY)\s*[=:]\s*["\']?(sk_[^\s\'"]+)["\']?', "Stripe Environment Variable", "Critical"),
    (r'(?i)(?:MAIL_USERNAME|MAIL_PASSWORD|MAIL_HOST|MAIL_PORT)\s*[=:]\s*["\']?([^\s\'"]{3,})["\']?', "Mail Credential", "High"),
    (r'(?i)(?:sqs|sns|ses)_secret\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS SQS/SNS/SES Secret", "Critical"),
    (r'(?i)cf[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{20,})["\']?', "CloudFront Access Key", "Critical"),
    (r'(?i)slack_bot_token\s*[=:]\s*["\']?(xoxb-[^\s\'"]+)["\']?', "Slack Bot Token", "Critical"),
    (r'(?i)(?:SQLITE|sqlite)_database\s*[=:]\s*["\']?([^\s\'"]+\.db)["\']?', "SQLite Database", "High"),
    (r'(?i)MONGO_URI\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "MongoDB URI Env Var", "Critical"),
    (r'(?i)ELASTICSEARCH.*password\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "Elasticsearch Password", "Critical"),
    (r'(?i)NEW_RELIC_LICENSE_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "New Relic License Key", "High"),
    (r'(?i)SENTRY_DSN\s*[=:]\s*["\']?(https://[^\s\'"]+)["\']?', "Sentry DSN", "High"),
    (r'(?i)DATADOG_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Datadog API Key", "Critical"),
    (r'(?i)ROLLBAR_ACCESS_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Rollbar Access Token", "Critical"),
    (r'(?i)BUGSNAG_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Bugsnag API Key", "High"),
    (r'(?i)JWT_SECRET\s*[=:]\s*["\']?([^\s\'"]{16,})["\']?', "JWT Signing Secret", "Critical"),
    (r'(?i)SECRET_KEY\s*[=:]\s*["\']?([^\s\'"]{16,})["\']?', "Generic Secret Key", "Critical"),
    (r'(?i)PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Password Config Variable", "High"),
]

CONTEXT_WINDOW = 40
SENSITIVITY_WEIGHTS = {
    "Critical": 100, "High": 70, "Medium": 40, "Low": 10,
}
SENSITIVE_INPUT_NAMES = [
    "password", "passwd", "pwd", "secret", "token", "api_key",
    "apikey", "access_key", "secret_key", "auth_token",
    "private_key", "ssh_key", "encryption_key",
]
HIDDEN_FIELD_PATTERNS = [
    r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\'][^>]*>',
    r'<input[^>]*value=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*>',
]
COMMENT_PATTERNS = [
    r'<!--([\s\S]*?)-->',
    r'/*!?([\s\S]*?)\*/',
    r'\/\/\s*(.*)',
    r'#\s*(.*)',
]
SSN_PATTERNS = [
    r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
    r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b',
]
CC_PATTERNS = [
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
]


def _score_severity(secret_type: str, severity: str) -> int:
    base = SENSITIVITY_WEIGHTS.get(severity, 30)
    if "Private Key" in secret_type or "Secret Key" in secret_type:
        base += 20
    if "Connection" in secret_type or "URI" in secret_type:
        base += 10
    if "Password" in secret_type:
        base += 15
    return min(base, 100)


def _extract_context(text: str, match_start: int, match_end: int) -> str:
    start = max(0, match_start - CONTEXT_WINDOW)
    end = min(len(text), match_end + CONTEXT_WINDOW)
    prefix = text[start:match_start]
    matched = text[match_start:match_end]
    suffix = text[match_end:end]
    return f"...{prefix}[{matched}]{suffix}..."


async def _crawl_page(url: str, client: httpx.AsyncClient, domain: str) -> tuple:
    try:
        resp = await client.get(
            url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if resp.status_code == 200:
            return url, resp.text, dict(resp.headers)
    except Exception:
        pass
    return url, "", {}


async def _fetch_and_scan_js(js_url: str, base_url: str, domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    if js_url.startswith("//"):
        js_url = "https:" + js_url
    elif js_url.startswith("/"):
        js_url = urljoin(base_url, js_url)
    elif not js_url.startswith("http"):
        js_url = urljoin(base_url, js_url)
    if domain not in js_url:
        return findings
    try:
        resp = await client.get(
            js_url, timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        if resp.status_code != 200:
            return findings
        js = resp.text
    except Exception:
        return findings
    for pattern, stype, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, js):
            matched = m.group(0)[:60]
            color_map = {"Critical": "red", "High": "orange", "Medium": "yellow"}
            threat_map = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Elevated Risk"}
            findings.append(IntelligenceFinding(
                entity=f"JS [{severity}] {stype}: {matched}...",
                type=f"Secret Found: {stype}",
                source="SecretFinder",
                confidence="High",
                color=color_map.get(severity, "red"),
                threat_level=threat_map.get(severity, "High Risk"),
                tags=["secret", "javascript", stype.lower().replace(" ", "_")],
                raw_data=f"JS URL: {js_url}\nMatch: {m.group(0)[:500]}",
            ))
    return findings


def _scan_html_comments(html: str, page_url: str) -> list:
    findings = []
    comment_keywords = [
        "password", "secret", "token", "key", "credential", "api", "todo",
        "fixme", "hack", "debug", "remove", "FIXME", "TODO", "HACK",
        "admin", "login", "test", "dummy", "vulnerable", "backdoor",
    ]
    for cpat in COMMENT_PATTERNS:
        for m in re.finditer(cpat, html):
            comment_text = m.group(1).strip()
            if not comment_text or len(comment_text) < 10:
                continue
            matched_keywords = [kw for kw in comment_keywords if kw.lower() in comment_text.lower()]
            if matched_keywords:
                seen_kw = ",".join(matched_keywords[:3])
                truncated = comment_text[:150]
                findings.append(IntelligenceFinding(
                    entity=f"Sensitive comment: [{seen_kw}] {truncated}...",
                    type="Secret: Sensitive Comment",
                    source="SecretFinder",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["comment", *matched_keywords[:3]],
                    raw_data=f"URL: {page_url}\nComment: {comment_text[:500]}",
                ))
    return findings


def _scan_hidden_fields(html: str, page_url: str) -> list:
    findings = []
    for hpat in HIDDEN_FIELD_PATTERNS:
        for m in re.finditer(hpat, html):
            value = m.group(1).strip()
            input_tag = m.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', input_tag)
            field_name = name_match.group(1) if name_match else "unknown"
            if value and len(value) > 4 and field_name.lower() not in ("_token", "csrf_token", "nonce", "_method"):
                findings.append(IntelligenceFinding(
                    entity=f"Hidden field '{field_name}': {value[:50]}...",
                    type="Secret: Hidden Input Field",
                    source="SecretFinder",
                    confidence="Low",
                    color="orange",
                    threat_level="Informational",
                    tags=["hidden-field", field_name.lower()],
                    raw_data=f"URL: {page_url}\nField: {field_name}={value[:200]}",
                ))
    return findings


def _scan_sensitive_inputs(html: str, page_url: str) -> list:
    findings = []
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|search)["\'][^>]*>',
        re.I,
    )
    for m in input_pattern.finditer(html):
        name = m.group(1).lower()
        if any(sn in name for sn in SENSITIVE_INPUT_NAMES):
            findings.append(IntelligenceFinding(
                entity=f"Plaintext input for sensitive field: {m.group(1)}",
                type="Secret: Plaintext Sensitive Input",
                source="SecretFinder",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["plaintext-input", name],
                raw_data=f"URL: {page_url}\nInput: {m.group(0)[:300]}",
            ))
    return findings


def _scan_pii(html: str, page_url: str) -> list:
    findings = []
    for spat in SSN_PATTERNS:
        for m in re.finditer(spat, html):
            ssn = m.group(0)
            findings.append(IntelligenceFinding(
                entity=f"SSN: {ssn[:5]}**-**{ssn[-4:]}",
                type="Secret: SSN Exposed",
                source="SecretFinder",
                confidence="High",
                color="red",
                threat_level="Critical Risk",
                tags=["pii", "ssn"],
                raw_data=f"URL: {page_url}\nSSN: {ssn}",
            ))
    for cpat in CC_PATTERNS:
        for m in re.finditer(cpat, html):
            cc = m.group(0)
            findings.append(IntelligenceFinding(
                entity=f"Credit Card: {cc[:4]}********{cc[-4:]}",
                type="Secret: Credit Card Exposed",
                source="SecretFinder",
                confidence="High",
                color="red",
                threat_level="Critical Risk",
                tags=["pii", "credit-card"],
                raw_data=f"URL: {page_url}\nCC: {cc}",
            ))
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    pages_to_crawl = [base_url]
    crawled_pages = []

    try:
        resp = await client.get(
            base_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            html = resp.text
            headers = dict(resp.headers)
            crawled_pages.append((base_url, html, headers))
            link_pattern = re.compile(r'href=["\']((?:https?:)?//[^"\']*)["\']', re.I)
            for m in link_pattern.finditer(html):
                link = m.group(1)
                if link.startswith("//"):
                    link = "https:" + link
                elif link.startswith("/"):
                    link = urljoin(base_url, link)
                elif not link.startswith("http"):
                    link = urljoin(base_url, link)
                if domain in link and link not in pages_to_crawl:
                    pages_to_crawl.append(link)
                if len(pages_to_crawl) >= 15:
                    break
    except Exception:
        return findings

    page_tasks = [_crawl_page(p, client, domain) for p in pages_to_crawl[1:11]]
    page_results = await asyncio.gather(*page_tasks, return_exceptions=True)
    for res in page_results:
        if isinstance(res, tuple) and isinstance(res[1], str) and res[1]:
            crawled_pages.append(res)

    for page_url, html, headers in crawled_pages:
        page_findings = []
        for pattern, secret_type, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, html):
                secret_text = m.group(0)[:60]
                context = _extract_context(html, m.start(), m.end())
                score = _score_severity(secret_type, severity)
                color_map = {"Critical": "red", "High": "orange", "Medium": "yellow"}
                threat_map = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Elevated Risk"}
                page_findings.append(IntelligenceFinding(
                    entity=f"[{score}] {secret_type}: {secret_text}...",
                    type=f"Secret Found: {secret_type}",
                    source="SecretFinder",
                    confidence="High",
                    color=color_map.get(severity, "red"),
                    threat_level=threat_map.get(severity, "High Risk"),
                    tags=["secret", secret_type.lower().replace(" ", "_"), severity.lower()],
                    raw_data=f"URL: {page_url}\nContext: {context[:600]}",
                ))
        if page_findings:
            findings.extend(page_findings)

        findings.extend(_scan_html_comments(html, page_url))
        findings.extend(_scan_hidden_fields(html, page_url))
        findings.extend(_scan_sensitive_inputs(html, page_url))
        findings.extend(_scan_pii(html, page_url))

    for page_url, html, headers in crawled_pages:
        pwd_like = re.findall(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^"\';\s]{6,})["\']?', html)
        for p in pwd_like:
            if not re.match(r'^[a-zA-Z0-9_\-\.!@#$%^&*]{6,}$', p):
                continue
            findings.append(IntelligenceFinding(
                entity=f"Potential Password: {p[:30]}...",
                type="Secret Found: Password Field",
                source="SecretFinder",
                confidence="Medium",
                color="orange",
                threat_level="High Risk",
                tags=["password", "secret"],
                raw_data=f"URL: {page_url}\nValue: {p[:200]}",
            ))

    emails = set()
    for page_url, html, _ in crawled_pages:
        for m in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html):
            emails.add(m.group(0))
    for email in list(emails)[:15]:
        findings.append(IntelligenceFinding(
            entity=email,
            type="Secret: Email Address Found",
            source="SecretFinder",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["email", "pii"],
        ))

    api_endpoints = set()
    for page_url, html, _ in crawled_pages:
        for m in re.finditer(r'["\']((?:https?:)?//[^"\']*/api/[^"\']*)["\']', html):
            api_endpoints.add(m.group(1))
    for ep in list(api_endpoints)[:10]:
        findings.append(IntelligenceFinding(
            entity=ep[:200],
            type="Secret: API Endpoint Found",
            source="SecretFinder",
            confidence="Low",
            color="blue",
            threat_level="Informational",
            tags=["api", "endpoint"],
        ))

    js_urls = set()
    for page_url, html, _ in crawled_pages:
        for m in re.finditer(r'(?:src)=["\']([^"\']*\.(?:js|mjs|cjs)(?:[?#][^"\']*)?)["\']', html, re.I):
            js_urls.add(m.group(1))
    if js_urls:
        js_tasks = [_fetch_and_scan_js(js, base_url, domain, client) for js in js_urls]
        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
        for res in js_results:
            if isinstance(res, list):
                findings.extend(res)

    inline_scripts = []
    for page_url, html, _ in crawled_pages:
        for m in re.finditer(r'<script[^>]*>([\s\S]*?)</script>', html, re.I):
            inline_scripts.append((page_url, m.group(1)))
    for page_url, script in inline_scripts:
        for pattern, stype, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, script):
                matched = m.group(0)[:60]
                color_map = {"Critical": "red", "High": "orange", "Medium": "yellow"}
                threat_map = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Elevated Risk"}
                findings.append(IntelligenceFinding(
                    entity=f"Inline JS [{severity}] {stype}: {matched}...",
                    type=f"Secret Found: {stype}",
                    source="SecretFinder",
                    confidence="High",
                    color=color_map.get(severity, "red"),
                    threat_level=threat_map.get(severity, "High Risk"),
                    tags=["secret", "inline-js", stype.lower().replace(" ", "_")],
                    raw_data=f"URL: {page_url}\nMatch: {m.group(0)[:500]}",
                ))

    if findings:
        by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            tl = f.threat_level
            if tl == "Critical Risk":
                by_severity["Critical"] += 1
            elif tl == "High Risk":
                by_severity["High"] += 1
            elif tl == "Elevated Risk":
                by_severity["Medium"] += 1
            else:
                by_severity["Low"] += 1
        severity_str = f"C:{by_severity['Critical']} H:{by_severity['High']} M:{by_severity['Medium']} L:{by_severity['Low']}"
        findings.append(IntelligenceFinding(
            entity=f"Secret scan complete: {len(findings)} findings across {len(crawled_pages)} pages on {domain} ({severity_str})",
            type="SecretFinder Summary",
            source="SecretFinder",
            confidence="High",
            color="purple",
            threat_level="Informational",
            tags=["summary"],
        ))

    return findings
