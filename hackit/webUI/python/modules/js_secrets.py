import httpx
import re
import json
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from models import IntelligenceFinding

JS_FILE_PATTERNS = [
    (r'["\']((?:https?:)?//[^"\']*\.js(?:[?#][^"\']*)?)["\']', "JavaScript File Reference"),
    (r'["\']((?:https?:)?//[^"\']*\.min\.js(?:[?#][^"\']*)?)["\']', "Minified JavaScript File"),
    (r'["\']((?:https?:)?//[^"\']*\.map(?:[?#][^"\']*)?)["\']', "Source Map Reference"),
    (r'sourceMappingURL=([^\s\'"]+)', "Inline Source Map"),
    (r'//# sourceMappingURL=([^\s\'"]+)', "Source Map Directive"),
]

API_ENDPOINT_PATTERNS = [
    (r'["\']((?:https?:)?//[^"\']*/api/[^"\']*)["\']', "API Endpoint"),
    (r'["\']((?:https?:)?//[^"\']*/graphql[^"\']*)["\']', "GraphQL Endpoint"),
    (r'["\']((?:https?:)?//[^"\']*/v[0-9]+/[^"\']*)["\']', "Versioned API Endpoint"),
    (r'["\']((?:https?:)?//[^"\']*/rest/[^"\']*)["\']', "REST API Endpoint"),
    (r'["\']((?:https?:)?//[^"\']*/swagger[^"\']*)["\']', "Swagger/OpenAPI"),
    (r'["\']((?:https?:)?//[^"\']*/docs(?:/[^"\']*)?)["\']', "API Docs"),
    (r'["\']((?:https?:)?//[^"\']*/redoc[^"\']*)["\']', "Redoc API Docs"),
    (r'["\']((?:https?:)?//[^"\']*/openapi[^"\']*)["\']', "OpenAPI Spec"),
    (r'["\']((?:https?:)?//[^"\']*/sockjs[^"\']*)["\']', "SockJS Endpoint"),
    (r'["\']((?:https?:)?//[^"\']*/socket\.io[^"\']*)["\']', "Socket.IO Endpoint"),
]

INTERNAL_HOST_PATTERNS = [
    (r'["\']((?:https?:)?//(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?(?:/[^"\']*)?)["\']', "Internal Host Reference"),
    (r'["\']((?:https?:)?//[^"\']*\.(?:internal|local|intranet|corp|private)[^"\']*)["\']', "Internal Domain Reference"),
    (r'["\']((?:https?:)?//[^"\']*:(?:3000|8080|8443|8000|9000|5000|4200|3001|9090)(?:/[^"\']*)?)["\']', "Dev Server Reference"),
]

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "Critical"),
    (r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key", "Critical"),
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
    (r'(?i)xapp-[0-9A-Za-z\-]{10,}', "Slack App Token", "Critical"),
    (r'(?i)discord_token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{24,})["\']?', "Discord Bot Token", "Critical"),
    (r'(?:https?://)?discord\.com/api/webhooks/[^\s\'"]+', "Discord Webhook URL", "Critical"),
    (r'(?i)telegram_bot_token\s*[=:]\s*["\']?([0-9]+:[A-Za-z0-9_\-]+)["\']?', "Telegram Bot Token", "Critical"),
    (r'(?i)twilio_account_sid\s*[=:]\s*["\']?(AC[0-9a-f]{32})["\']?', "Twilio Account SID", "Critical"),
    (r'(?i)twilio_auth_token\s*[=:]\s*["\']?([0-9a-f]{32})["\']?', "Twilio Auth Token", "Critical"),
    (r'(?i)mailchimp_api_key\s*[=:]\s*["\']?([0-9a-f]{32}-us[0-9]+)["\']?', "Mailchimp API Key", "Critical"),
    (r'(?i)sendgrid_api_key\s*[=:]\s*["\']?(SG\.[A-Za-z0-9_\-]{20,})["\']?', "SendGrid API Key", "Critical"),
    (r'(?i)facebook.*token\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?', "Facebook Access Token", "Critical"),
    (r'(?i)(?:twitter|twtr).*token\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?', "Twitter API Token", "Critical"),
    (r'(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----', "Private Key Exposure", "Critical"),
    (r'(?i)-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----', "PGP Key Exposure", "Critical"),
    (r'(?i)ssh-(rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{20,}', "OpenSSH Public Key", "High"),
    (r'(?i)(?:jwt|jws)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']?', "JWT Token", "Critical"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token (bare)", "Critical"),
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
    (r'(?i)\.s3\.amazonaws\.com', "S3 Bucket URL", "High"),
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
    (r'(?i)sqs.*secret.*key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS SQS Secret", "Critical"),
    (r'(?i)cloudinary.*api[_-]?secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Cloudinary API Secret", "Critical"),
    (r'(?i)digitalocean.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "DigitalOcean Token", "Critical"),
    (r'(?i)azure.*key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{32,})["\']?', "Azure Key", "Critical"),
    (r'(?i)azure.*connection.*string\s*[=:]\s*["\']?([A-Za-z0-9;=]+)["\']?', "Azure Connection String", "Critical"),
]

SENSITIVE_ROUTES = [
    r'["\'](/?admin[^"\']*)["\']',
    r'["\'](/?dashboard[^"\']*)["\']',
    r'["\'](/?login[^"\']*)["\']',
    r'["\'](/?signin[^"\']*)["\']',
    r'["\'](/?register[^"\']*)["\']',
    r'["\'](/?reset[^"\']*)["\']',
    r'["\'](/?forgot[^"\']*)["\']',
    r'["\'](/?logout[^"\']*)["\']',
    r'["\'](/?oauth[^"\']*)["\']',
    r'["\'](/?callback[^"\']*)["\']',
    r'["\'](/?webhook[^"\']*)["\']',
    r'["\'](/?upload[^"\']*)["\']',
    r'["\'](/?download[^"\']*)["\']',
    r'["\'](/?export[^"\']*)["\']',
    r'["\'](/?import[^"\']*)["\']',
    r'["\'](/?debug[^"\']*)["\']',
    r'["\'](/?health[^"\']*)["\']',
    r'["\'](/?metrics[^"\']*)["\']',
    r'["\'](/?monitor[^"\']*)["\']',
]


async def _extract_js_urls(html: str) -> list[str]:
    urls = []
    for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.(?:js|jsx|ts|tsx|mjs|cjs)(?:[?#][^"\']*)?)["\']', html, re.I):
        url = m.group(1).strip()
        if url and url not in urls:
            urls.append(url)
    for m in re.finditer(r'import\(?["\']([^"\']+\.(?:js|jsx|ts|tsx|mjs|cjs))["\']', html):
        url = m.group(1).strip()
        if url and url not in urls:
            urls.append(url)
    return urls


async def _fetch_and_scan_js(url: str, base_url: str, domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    if url.startswith("//"):
        url = "https:" + url
    elif url.startswith("/"):
        url = urljoin(base_url, url)
    elif not url.startswith("http"):
        url = urljoin(base_url, url)

    if domain not in url:
        return findings

    try:
        resp = await client.get(
            url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        if resp.status_code != 200:
            return findings
        js_content = resp.text
    except Exception:
        return findings

    if len(js_content) > 500000:
        findings.append(IntelligenceFinding(
            entity=f"Large JS file ({len(js_content)} bytes): {url}",
            type="JS: Large File",
            source="JSSecrets",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            tags=["javascript", "large-file"],
        ))
        js_content = js_content[:500000]

    for pattern, stype, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, js_content):
            matched = m.group(0)[:80]
            color_map = {"Critical": "red", "High": "orange", "Medium": "yellow"}
            threat_map = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Elevated Risk"}
            findings.append(IntelligenceFinding(
                entity=f"{stype}: {matched}...",
                type=f"JS Secret: {stype}",
                source="JSSecrets",
                confidence="High",
                color=color_map.get(severity, "red"),
                threat_level=threat_map.get(severity, "High Risk"),
                tags=["secret", "javascript", stype.lower().replace(" ", "_")],
                raw_data=m.group(0)[:500],
            ))

    for pattern, ftype in API_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, js_content):
            endpoint = m.group(1)[:200]
            findings.append(IntelligenceFinding(
                entity=endpoint,
                type=f"JS Endpoint: {ftype}",
                source="JSSecrets",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                tags=["endpoint", "api"],
                raw_data=endpoint,
            ))

    for pattern, ftype in INTERNAL_HOST_PATTERNS:
        for m in re.finditer(pattern, js_content):
            internal_ref = m.group(1)[:200]
            findings.append(IntelligenceFinding(
                entity=internal_ref,
                type=f"JS Internal: {ftype}",
                source="JSSecrets",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                tags=["internal", "network"],
                raw_data=internal_ref,
            ))

    for pattern in SENSITIVE_ROUTES:
        for m in re.finditer(pattern, js_content):
            route = m.group(1)[:200]
            findings.append(IntelligenceFinding(
                entity=route,
                type="JS: Sensitive Route Found",
                source="JSSecrets",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["route", "sensitive"],
            ))

    for m in re.finditer(r'["\'](/?[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)?)["\']', js_content):
        potential_route = m.group(1)
        if 5 < len(potential_route) < 100 and "/" in potential_route:
            findings.append(IntelligenceFinding(
                entity=potential_route,
                type="JS: Potential API Route",
                source="JSSecrets",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["route", "api"],
            ))

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    html = ""

    try:
        resp = await client.get(
            base_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        html = resp.text
    except Exception:
        return findings

    for pattern, ftype in JS_FILE_PATTERNS:
        for m in re.finditer(pattern, html):
            url = m.group(1)[:200]
            findings.append(IntelligenceFinding(
                entity=url,
                type=f"JS: {ftype}",
                source="JSSecrets",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["javascript", "reference"],
            ))

    for pattern, ftype in API_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, html):
            endpoint = m.group(1)[:200]
            findings.append(IntelligenceFinding(
                entity=endpoint,
                type=f"JS Endpoint: {ftype}",
                source="JSSecrets",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                tags=["endpoint", "api"],
            ))

    js_urls = await _extract_js_urls(html)
    if not js_urls:
        inline_js = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
        for script_block in inline_js:
            for pattern, ftype in JS_FILE_PATTERNS:
                for m in re.finditer(pattern, script_block):
                    url = m.group(1)[:200]
                    findings.append(IntelligenceFinding(
                        entity=url,
                        type=f"JS (inline): {ftype}",
                        source="JSSecrets",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["javascript", "inline"],
                    ))

    js_tasks = [_fetch_and_scan_js(js_url, base_url, domain, client) for js_url in js_urls]
    js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
    for res in js_results:
        if isinstance(res, list):
            findings.extend(res)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"JS secrets scan complete: {len(findings)} findings across {len(js_urls)} JS files",
            type="JSSecrets Summary",
            source="JSSecrets",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
        ))

    return findings
