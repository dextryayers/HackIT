import httpx
import re
import json
import math
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from module_common import safe_fetch, make_finding
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
    (r'["\']((?:https?:)?//[^"\']*:(?:3000|8080|8443|8000|9000|5000|4200|3001|9090|9200|5432|3306|6379|27017)(?:/[^"\']*)?)["\']', "Dev Server Reference"),
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
    (r'(?i)slack_bot_token\s*[=:]\s*["\']?(xoxb-[^\s\'"]+)["\']?', "Slack Bot Token", "Critical"),
    (r'(?i)slack_webhook_url\s*[=:]\s*["\']?(https://hooks\.slack\.com/[^\s\'"]+)["\']?', "Slack Webhook URL", "Critical"),
    (r'(?i)gitlab_token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "GitLab Token", "Critical"),
    (r'(?i)bitbucket.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Bitbucket Password", "Critical"),
    (r'(?i)bitbucket.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Bitbucket Token", "Critical"),
    (r'(?i)pypi.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "PyPI Password", "Critical"),
    (r'(?i)npm.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "NPM Token", "Critical"),
    (r'(?i)npm.*_auth\s*[=:]\s*["\']?([A-Za-z0-9+/=]{20,})["\']?', "NPM Auth Token", "Critical"),
    (r'(?i)docker.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Docker Password", "Critical"),
    (r'(?i)sonar.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "SonarQube Token", "Critical"),
    (r'(?i)jira.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "JIRA Token", "Critical"),
    (r'(?i)confluence.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Confluence Password", "Critical"),
    (r'(?i)circleci.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "CircleCI Token", "Critical"),
    (r'(?i)travis.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "TravisCI Token", "Critical"),
    (r'(?i)jenkins.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Jenkins Password", "Critical"),
    (r'(?i)jenkins.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "Jenkins Token", "Critical"),
    (r'(?i)ansible.*vault.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Ansible Vault Password", "Critical"),
    (r'(?i)vault.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Vault Token", "Critical"),
    (r'(?i)consul.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Consul Token", "Critical"),
    (r'(?i)k8s.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Kubernetes Token", "Critical"),
    (r'(?i)kubernetes.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Kubernetes Token", "Critical"),
    (r'(?i)kube.*config\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Kubeconfig Token", "Critical"),
    (r'(?i)google_application_credentials\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+\.json)["\']?', "GCP Service Account", "Critical"),
    (r'(?i)GOOGLE_CREDENTIALS\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+)["\']?', "GCP Credentials", "Critical"),
    (r'(?i)sentry_dsn\s*[=:]\s*["\']?(https://[^\s\'"]+)["\']?', "Sentry DSN", "High"),
    (r'(?i)datadog_api_key\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Datadog API Key", "Critical"),
    (r'(?i)new_relic_license_key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "New Relic License Key", "High"),
    (r'(?i)rollbar_access_token\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Rollbar Access Token", "Critical"),
    (r'(?i)bugsnag_api_key\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Bugsnag API Key", "High"),
    (r'(?i)loggly_token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Loggly Token", "High"),
    (r'(?i)papertrail.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Papertrail Token", "High"),
    (r'(?i)algolia.*api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Algolia API Key", "Critical"),
    (r'(?i)mapbox.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Mapbox Token", "High"),
    (r'(?i)humio.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Humio Token", "High"),
    (r'(?i)sumo.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Sumo Logic Token", "High"),
    (r'(?i)pagerduty.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "PagerDuty Token", "Critical"),
    (r'(?i)opsgenie.*api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Opsgenie API Key", "Critical"),
    (r'(?i)grafana.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Grafana Token", "Critical"),
    (r'(?i)kibana.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Kibana Password", "Critical"),
    (r'(?i)elastic.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', "Elasticsearch Password", "Critical"),
    (r'(?i)jdbc:[a-z]+://[^\s\'"]+', "JDBC Connection String", "High"),
    (r'(?i)redis://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "Redis Auth Connection", "Critical"),
    (r'(?i)amqp://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "AMQP Connection", "Critical"),
    (r'(?i)rabbitmq://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "RabbitMQ Connection", "Critical"),
    (r'(?i)mysql://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "MySQL Auth Connection", "Critical"),
    (r'(?i)postgresql://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "PostgreSQL Auth Connection", "Critical"),
    (r'(?i)mongodb://[^\s\'":]+:[^\s\'":]+@[^\s\'"]+', "MongoDB Auth Connection", "Critical"),
    (r'(?i)redshift://[^\s\'"]+', "Redshift Connection", "Critical"),
    (r'(?i)presto://[^\s\'"]+', "Presto Connection", "High"),
    (r'(?i)hive://[^\s\'"]+', "Hive Connection", "High"),
    (r'(?i)bigquery.*credential.*json\s*[=:]\s*["\']?({[^}]+})["\']?', "BigQuery Credential JSON", "Critical"),
    (r'(?i)snowflake.*password\s*[=:]\s*["\']?([A-Za-z0-9_\-!@#$%^&*]{6,})["\']?', "Snowflake Password", "Critical"),
    (r'(?i)databricks.*token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Databricks Token", "Critical"),
    (r'(?i)db_password\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Database Password", "Critical"),
    (r'(?i)db_username\s*[=:]\s*["\']?([^\s\'"]{3,})["\']?', "Database Username", "High"),
    (r'(?i)connection_string\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "Connection String", "Critical"),
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
    r'["\'](/?api[^"\']*)["\']',
    r'["\'](/?v[0-9]+[^"\']*)["\']',
    r'["\'](/?config[^"\']*)["\']',
    r'["\'](/?private[^"\']*)["\']',
    r'["\'](/?internal[^"\']*)["\']',
    r'["\'](/?secret[^"\']*)["\']',
    r'["\'](/?token[^"\']*)["\']',
    r'["\'](/?payment[^"\']*)["\']',
    r'["\'](/?checkout[^"\']*)["\']',
]

HIGH_ENTROPY_STRING_PATTERN = re.compile(r'["\'][A-Za-z0-9_\-\.!@#$%^&*()+/=]{20,}["\']')
ENTROPY_THRESHOLD = 4.0

SECRET_CLASSIFICATION = {
    "Critical": ["AWS", "Stripe Live", "Private Key", "JWT", "GitHub", "Discord", "Slack", "OAuth", "Connection String", "Database Password"],
    "High": ["API Key", "Access Token", "Encryption Key", "Firebase", "S3"],
    "Medium": ["Stripe Test", "Generic", "Test"],
    "Low": ["Example", "Sample", "Your "],
}

COMMON_PATTERNS_FP = [
    r"node_modules/", r"\.git/", r"package\.json", r"yarn\.lock",
    r"package-lock\.json", r"readme\.md", r"readme",
    r"example\.", r"sample\.", r"your-", r"your_",
    r"changeme", r"replaceme", r"your_key", r"your-secret",
    r"TODO", r"FIXME", r"XXX", r"HACK",
    r"documentation", r"docs/", r"README",
]

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for c in (chr(i) for i in range(128)):
        p = s.count(c) / len(s)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def _is_false_positive(match: str, context: str) -> bool:
    match_lower = match.lower()
    for fp in COMMON_PATTERNS_FP:
        if re.search(fp, match_lower) or re.search(fp, context.lower()):
            return True
    if len(match) < 8:
        return True
    if re.match(r'^[\d\s]+$', match):
        return True
    if re.match(r'^[a-zA-Z]+$', match):
        return True
    return False

def _classify_secret(stype: str, severity: str) -> str:
    for level, keywords in SECRET_CLASSIFICATION.items():
        for kw in keywords:
            if kw.lower() in stype.lower():
                return level
    return severity

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
    for m in re.finditer(r'require\(["\']([^"\']+\.(?:js|jsx|ts|tsx|mjs|cjs))["\']', html):
        url = m.group(1).strip()
        if url and url not in urls:
            urls.append(url)
    for m in re.finditer(r'import\s+["\']([^"\']+\.(?:js|jsx|ts|tsx|mjs|cjs))["\']', html):
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
        resp = await safe_fetch(client, 
            url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
        )
        if resp.status_code != 200:
            return findings
        js_content = resp.text
    except Exception:
        return findings

    if len(js_content) > 500000:
        findings.append(make_finding(
            entity=f"Large JS file ({len(js_content)} bytes): {url}",
            ftype="JS: Large File",
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
            context_start = max(0, m.start() - 100)
            context_end = min(len(js_content), m.end() + 100)
            context = js_content[context_start:context_end]

            if _is_false_positive(matched, context):
                continue

            actual_severity = _classify_secret(stype, severity)
            color_map = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "slate"}
            threat_map = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Elevated Risk", "Low": "Informational"}
            findings.append(make_finding(
                entity=f"{stype}: {matched}...",
                ftype=f"JS Secret: {stype}",
                source="JSSecrets",
                confidence="High",
                color=color_map.get(actual_severity, "red"),
                threat_level=threat_map.get(actual_severity, "High Risk"),
                tags=["secret", "javascript", stype.lower().replace(" ", "_"), actual_severity.lower()],
                raw_data=m.group(0)[:500],
            ))

    for m in HIGH_ENTROPY_STRING_PATTERN.finditer(js_content):
        s = m.group(0).strip("\"'")
        if len(s) >= 20 and _shannon_entropy(s) >= ENTROPY_THRESHOLD:
            is_secret = not _is_false_positive(s, m.group(0))
            if is_secret:
                findings.append(make_finding(
                    entity=f"High entropy string ({_shannon_entropy(s):.1f}): {s[:40]}...",
                    ftype="JS: High Entropy String (Potential Secret)",
                    source="JSSecrets",
                    confidence="Low",
                    color="yellow",
                    threat_level="Elevated Risk",
                    tags=["secret", "entropy", "potential-secret"],
                    raw_data=m.group(0)[:500],
                ))

    for pattern, ftype in API_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, js_content):
            endpoint = m.group(1)[:200]
            findings.append(make_finding(
                entity=endpoint,
                ftype=f"JS Endpoint: {ftype}",
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
            findings.append(make_finding(
                entity=internal_ref,
                ftype=f"JS Internal: {ftype}",
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
            findings.append(make_finding(
                entity=route,
                ftype="JS: Sensitive Route Found",
                source="JSSecrets",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["route", "sensitive"],
            ))

    for m in re.finditer(r'["\'](/?[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)?)["\']', js_content):
        potential_route = m.group(1)
        if 5 < len(potential_route) < 100 and "/" in potential_route:
            findings.append(make_finding(
                entity=potential_route,
                ftype="JS: Potential API Route",
                source="JSSecrets",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["route", "api"],
            ))

    try:
        import base64
        potential_b64 = re.findall(r'["\'][A-Za-z0-9+/=]{40,}["\']', js_content)
        for b64_str in potential_b64:
            b64_str = b64_str.strip("\"'")
            try:
                decoded = base64.b64decode(b64_str)
                decoded_str = decoded.decode("utf-8", errors="ignore")
                if re.search(r'(?:password|secret|key|token|api|credential)', decoded_str, re.I):
                    findings.append(make_finding(
                        entity=f"Base64 encoded secret: {b64_str[:40]}...",
                        ftype="JS: Base64 Encoded Secret",
                        source="JSSecrets",
                        confidence="Medium",
                        color="orange",
                        threat_level="High Risk",
                        raw_data=f"Decoded: {decoded_str[:200]}",
                        tags=["secret", "base64"],
                    ))
            except Exception:
                pass
    except Exception:
        pass

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
        resp = await safe_fetch(client, 
            base_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        html = resp.text
    except Exception:
        return findings

    for pattern, ftype in JS_FILE_PATTERNS:
        for m in re.finditer(pattern, html):
            url = m.group(1)[:200]
            findings.append(make_finding(
                entity=url,
                ftype=f"JS: {ftype}",
                source="JSSecrets",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["javascript", "reference"],
            ))

    for pattern, ftype in API_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, html):
            endpoint = m.group(1)[:200]
            findings.append(make_finding(
                entity=endpoint,
                ftype=f"JS Endpoint: {ftype}",
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
                    findings.append(make_finding(
                        entity=url,
                        ftype=f"JS (inline): {ftype}",
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
        findings.append(make_finding(
            entity=f"JS secrets scan complete: {len(findings)} findings across {len(js_urls)} JS files",
            ftype="JSSecrets Summary",
            source="JSSecrets",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
        ))

    return findings

CLOUD_SECRET_PATTERNS = [
    (r'(?i)google_application_credentials\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+\.json)["\']?', "GCP Service Account JSON", "Critical"),
    (r'(?i)GOOGLE_CREDENTIALS\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+)["\']?', "GCP Credentials Path", "Critical"),
    (r'(?i)SERVICE_ACCOUNT\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+)["\']?', "Service Account", "Critical"),
    (r'(?i)AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "AWS Access Key Env", "Critical"),
    (r'(?i)AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Key Env", "Critical"),
    (r'(?i)AWS_SESSION_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9/+=]+)["\']?', "AWS Session Token", "Critical"),
    (r'(?i)ARM_CLIENT_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?', "Azure Client ID", "Critical"),
    (r'(?i)ARM_CLIENT_SECRET\s*[=:]\s*["\']?([A-Za-z0-9_\-]{34})["\']?', "Azure Client Secret", "Critical"),
    (r'(?i)ARM_TENANT_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?', "Azure Tenant ID", "Critical"),
    (r'(?i)ARM_SUBSCRIPTION_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?', "Azure Subscription ID", "High"),
    (r'(?i)DO_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{64})["\']?', "DigitalOcean Token", "Critical"),
    (r'(?i)LINODE_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{64})["\']?', "Linode Token", "Critical"),
    (r'(?i)VULTR_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Vultr API Key", "Critical"),
    (r'(?i)HETZNER_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32})["\']?', "Hetzner API Key", "Critical"),
    (r'(?i)OCI_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]+)["\']?', "Oracle OCI Key", "Critical"),
    (r'(?i)ALIBABA_CLOUD_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{24})["\']?', "Alibaba Key", "Critical"),
    (r'(?i)YC_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]+)["\']?', "Yandex Cloud Token", "Critical"),
    (r'(?i)SCW_SECRET_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "Scaleway Secret", "Critical"),
    (r'(?i)CF_APITOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "Cloudflare API Token", "Critical"),
    (r'(?i)CF_APIKEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{37})["\']?', "Cloudflare API Key", "Critical"),
    (r'(?i)NETLIFY_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40,})["\']?', "Netlify Token", "Critical"),
    (r'(?i)VERCEL_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{24})["\']?', "Vercel Token", "Critical"),
    (r'(?i)HEROKU_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,})["\']?', "Heroku API Key", "Critical"),
    (r'(?i)RAILWAY_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]+)["\']?', "Railway Token", "Critical"),
    (r'(?i)RENDER_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "Render API Key", "Critical"),
    (r'(?i)MONGO_URI\s*[=:]\s*["\']?(mongodb(?:\+srv)?://[^\s\'"]+)["\']?', "MongoDB URI Env", "Critical"),
    (r'(?i)ELASTICSEARCH_URL\s*[=:]\s*["\']?(https?://[^\s\'"]+)["\']?', "Elasticsearch URL", "Critical"),
    (r'(?i)REDIS_URL\s*[=:]\s*["\']?(redis://[^\s\'"]+)["\']?', "Redis URL Env", "Critical"),
    (r'(?i)DATABASE_URL\s*[=:]\s*["\']?(postgres(?:ql)?://[^\s\'"]+)["\']?', "Database URL", "Critical"),
    (r'(?i)JAWSDB_URL\s*[=:]\s*["\']?(mysql://[^\s\'"]+)["\']?', "JAWSDB URL", "Critical"),
    (r'(?i)CLEARDB_DATABASE_URL\s*[=:]\s*["\']?(mysql://[^\s\'"]+)["\']?', "ClearDB URL", "Critical"),
    (r'(?i)SENDGRID_API_KEY\s*[=:]\s*["\']?(SG\.[A-Za-z0-9_\-]{20,})["\']?', "SendGrid API Key", "Critical"),
    (r'(?i)MAILGUN_API_KEY\s*[=:]\s*["\']?(key-[A-Za-z0-9]{32})["\']?', "Mailgun API Key", "Critical"),
    (r'(?i)MAILGUN_DOMAIN\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]+)["\']?', "Mailgun Domain", "High"),
    (r'(?i)STRIPE_API_KEY\s*[=:]\s*["\']?(sk_live_[^\s\'"]+)["\']?', "Stripe Live Key Env", "Critical"),
    (r'(?i)STRIPE_PUBLISHABLE_KEY\s*[=:]\s*["\']?(pk_live_[^\s\'"]+)["\']?', "Stripe Publishable Key", "High"),
    (r'(?i)TWILIO_ACCOUNT_SID\s*[=:]\s*["\']?(AC[0-9a-f]{32})["\']?', "Twilio SID Env", "Critical"),
    (r'(?i)TWILIO_AUTH_TOKEN\s*[=:]\s*["\']?([0-9a-f]{32})["\']?', "Twilio Auth Token Env", "Critical"),
    (r'(?i)JWT_SECRET\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32,})["\']?', "JWT Secret Env", "Critical"),
    (r'(?i)SECRET_KEY_BASE\s*[=:]\s*["\']?([A-Za-z0-9]{64,})["\']?', "Rails Secret Base Env", "Critical"),
    (r'(?i)DATADOG_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?', "Datadog API Key Env", "Critical"),
    (r'(?i)NEW_RELIC_LICENSE_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "New Relic Key Env", "Critical"),
    (r'(?i)SENTRY_DSN\s*[=:]\s*["\']?(https://[^\s\'"]+)["\']?', "Sentry DSN Env", "High"),
    (r'(?i)SLACK_TOKEN\s*[=:]\s*["\']?(xox[abposr]-[^\s\'"]+)["\']?', "Slack Token Env", "Critical"),
    (r'(?i)SLACK_WEBHOOK_URL\s*[=:]\s*["\']?(https://hooks\.slack\.com[^\s\'"]+)["\']?', "Slack Webhook Env", "Critical"),
    (r'(?i)GITHUB_TOKEN\s*[=:]\s*["\']?(gh[pousr]_[^\s\'"]+)["\']?', "GitHub Token Env", "Critical"),
    (r'(?i)GITLAB_TOKEN\s*[=:]\s*["\']?(glpat-[^\s\'"]+)["\']?', "GitLab Token Env", "Critical"),
    (r'(?i)DOCKER_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{8,})["\']?', "Docker Password Env", "Critical"),
    (r'(?i)NPM_TOKEN\s*[=:]\s*["\']?([^\s\'"]{20,})["\']?', "NPM Token Env", "Critical"),
    (r'(?i)FIREBASE_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "Firebase API Key Env", "Critical"),
    (r'(?i)FIREBASE_DATABASE_URL\s*[=:]\s*["\']?(https://[^\s\'"]+firebaseio\.com)["\']?', "Firebase DB URL", "High"),
    (r'(?i)MAPBOX_TOKEN\s*[=:]\s*["\']?(pk\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']?', "Mapbox Token", "High"),
    (r'(?i)ALGOLIA_API_KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32})["\']?', "Algolia API Key Env", "Critical"),
    (r'(?i)ALGOLIA_APP_ID\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10})["\']?', "Algolia App ID", "High"),
    (r'(?i)CLOUDINARY_URL\s*[=:]\s*["\']?(cloudinary://[^\s\'"]+)["\']?', "Cloudinary URL Env", "Critical"),
    (r'(?i)AZURE_STORAGE_KEY\s*[=:]\s*["\']?([A-Za-z0-9/+=]{88})["\']?', "Azure Storage Key", "Critical"),
    (r'(?i)AZURE_STORAGE_CONNECTION_STRING\s*[=:]\s*["\']?(DefaultEndpointsProtocol=[^\s\'"]+)["\']?', "Azure Storage Conn String", "Critical"),
    (r'(?i)CONFLUENCE_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Confluence Password Env", "Critical"),
    (r'(?i)JIRA_API_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "JIRA API Token Env", "Critical"),
    (r'(?i)CIRCLE_CI_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "CircleCI Token Env", "Critical"),
    (r'(?i)TRAVIS_CI_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{22})["\']?', "TravisCI Token Env", "Critical"),
    (r'(?i)JENKINS_API_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32})["\']?', "Jenkins Token Env", "Critical"),
    (r'(?i)SONAR_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "SonarQube Token Env", "Critical"),
    (r'(?i)ARTIFACTORY_KEY\s*[=:]\s*["\']?(AKC[A-Za-z0-9]{30,})["\']?', "Artifactory Key", "Critical"),
    (r'(?i)VAULT_TOKEN\s*[=:]\s*["\']?(s\.[A-Za-z0-9_\-]{20,})["\']?', "Vault Token", "Critical"),
    (r'(?i)CONSUL_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "Consul Token Env", "Critical"),
    (r'(?i)KUBERNETES_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', "K8s Token Env", "Critical"),
    (r'(?i)KUBECONFIG\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "Kubeconfig Path", "High"),
    (r'(?i)VAULT_ADDR\s*[=:]\s*["\']?(https?://[^\s\'"]+)["\']?', "Vault Address", "High"),
    (r'(?i)SSH_PRIVATE_KEY\s*[=:]\s*["\']?(-----BEGIN[^"]+)["\']?', "SSH Private Key Var", "Critical"),
    (r'(?i)PGPASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "PostgreSQL Password Env", "Critical"),
    (r'(?i)MYSQL_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "MySQL Password Env", "Critical"),
    (r'(?i)MONGO_INITDB_ROOT_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Mongo Root Password Env", "Critical"),
    (r'(?i)REDIS_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Redis Password Env", "Critical"),
    (r'(?i)POSTGRES_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Postgres Password Env", "Critical"),
    (r'(?i)RABBITMQ_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "RabbitMQ Password Env", "Critical"),
    (r'(?i)ELASTIC_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Elastic Password Env", "Critical"),
    (r'(?i)KEYCLOAK_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "Keycloak Password Env", "Critical"),
    (r'(?i)PGHOST\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "PostgreSQL Host", "Medium"),
    (r'(?i)PGDATABASE\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "PostgreSQL Database", "Medium"),
    (r'(?i)RDS_HOSTNAME\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "RDS Hostname", "High"),
    (r'(?i)RDS_DB_NAME\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "RDS Database Name", "Medium"),
    (r'(?i)RDS_USERNAME\s*[=:]\s*["\']?([^\s\'"]+)["\']?', "RDS Username", "High"),
    (r'(?i)RDS_PASSWORD\s*[=:]\s*["\']?([^\s\'"]{6,})["\']?', "RDS Password Env", "Critical"),
    (r'(?i)CIRCLECI_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "CircleCI Token Alt", "Critical"),
    (r'(?i)CODECOV_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "Codecov Token Env", "Critical"),
    (r'(?i)COVERALLS_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "Coveralls Token Env", "Critical"),
    (r'(?i)SONAR_LOGIN\s*[=:]\s*["\']?([A-Za-z0-9_\-]{40})["\']?', "SonarQube Login", "Critical"),
    (r'(?i)SSH_KEY\s*[=:]\s*["\']?(-----BEGIN[^"]+)["\']?', "SSH Key Var", "Critical"),
    (r'(?i)AWS_DEFAULT_REGION\s*[=:]\s*["\']?([A-Za-z0-9\-]{5,})["\']?', "AWS Region", "Low"),
    (r'(?i)AWS_ACCOUNT_ID\s*[=:]\s*["\']?(\d{12})["\']?', "AWS Account ID", "High"),
    (r'(?i)GCP_PROJECT_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{6,})["\']?', "GCP Project ID", "Medium"),
    (r'(?i)GCP_PROJECT_NUMBER\s*[=:]\s*["\']?(\d{12,})["\']?', "GCP Project Number", "Medium"),
    (r'(?i)AZURE_CLIENT_SECRET\s*[=:]\s*["\']?([A-Za-z0-9_\-]{34})["\']?', "Azure Client Secret", "Critical"),
    (r'(?i)AZURE_TENANT_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?', "Azure Tenant ID", "High"),
    (r'(?i)AZURE_CLIENT_ID\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?', "Azure Client ID", "High"),
]

async def _scan_cloud_secrets(js_content: str, findings: list):
    for pattern, stype, severity in CLOUD_SECRET_PATTERNS:
        for m in re.finditer(pattern, js_content):
            matched = m.group(0)[:80]
            context_start = max(0, m.start() - 100)
            context_end = min(len(js_content), m.end() + 100)
            context = js_content[context_start:context_end]
            if _is_false_positive(matched, context):
                continue
            color_map = {"Critical": "red", "High": "orange"}
            threat_map = {"Critical": "Critical Risk", "High": "High Risk"}
            findings.append(make_finding(
                entity=f"{stype}: {matched}...",
                ftype=f"JS Cloud Secret: {stype}",
                source="JSSecrets",
                confidence="High",
                color=color_map.get(severity, "red"),
                threat_level=threat_map.get(severity, "High Risk"),
                tags=["secret", "cloud", stype.lower().replace(" ", "_")],
                raw_data=m.group(0)[:500],
            ))
