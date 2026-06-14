import httpx
import re
import asyncio
import base64
from models import IntelligenceFinding

GITHUB_SEARCH_QUERIES = [
    "filename:.env",
    "filename:.gitignore",
    "filename:credentials",
    "filename:config",
    "filename:config.php",
    "filename:config.json",
    "filename:database.yml",
    "filename:secrets.yml",
    "filename:settings.py",
    "filename:password",
    "filename:secret",
    "filename:token",
    "filename:.npmrc",
    "filename:.dockercfg",
    "filename:.s3cfg",
    "filename:.netrc",
    "filename:id_rsa",
    "filename:id_dsa",
    "filename:deploy",
    "filename:Makefile",
    "extension:sql password",
    "extension:log password",
    "extension:pem PRIVATE KEY",
    "extension:key PRIVATE KEY",
    "extension:env DB_PASSWORD",
    "extension:yml DB_PASSWORD",
    "extension:yaml DB_PASSWORD",
    "extension:json DB_PASSWORD",
    "extension:xml password",
    "extension:cfg password",
    "extension:ini password",
    "extension:conf password",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "mongodb+srv://",
    "postgresql://",
    "mysql://",
    "redis://",
    "sk_live_",
    "pk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xoxp-",
    "xoxb-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "AKIA",
    "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "STRIPE_API_KEY",
    "MAILCHIMP_API_KEY",
    "SENDGRID_API_KEY",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "GOOGLE_API_KEY",
    "AIza",
    "-----BEGIN CERTIFICATE-----",
    "password=",
    "passwd=",
    "db_password=",
    "db_username=",
    "jdbc:",
    "spring.datasource.password",
    "app.secret",
    "session_secret",
    "cookie_secret",
    "encryption_key",
    "hmac_key",
    "api_secret",
    "client_secret",
    "consumer_secret",
    "auth_token",
    "access_token",
    "refresh_token",
    "secret_key",
    "private_key",
    "api_key",
    "admin_password",
    "root_password",
    "sa_password",
]

GITHUB_RAW_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key"),
    (r'(?i)google_api_key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})["\']?', "Google API Key"),
    (r'(?i)AIza[0-9A-Za-z\-_]{35}', "Google API Key (AIza)"),
    (r'(?i)sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'(?i)pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key"),
    (r'(?i)ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'(?i)gho_[0-9a-zA-Z]{36}', "GitHub OAuth Access Token"),
    (r'(?i)ghu_[0-9a-zA-Z]{36}', "GitHub User Token"),
    (r'(?i)ghs_[0-9a-zA-Z]{36}', "GitHub App Token"),
    (r'(?i)ghr_[0-9a-zA-Z]{36}', "GitHub Refresh Token"),
    (r'(?i)xox[abposr]-[0-9a-zA-Z\-]{10,}', "Slack Token"),
    (r'(?i)discord_token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{24,})["\']?', "Discord Token"),
    (r'(?i)telegram_bot_token\s*[=:]\s*["\']?([0-9]+:[A-Za-z0-9_\-]+)["\']?', "Telegram Bot Token"),
    (r'(?i)twilio_account_sid\s*[=:]\s*["\']?(AC[0-9a-f]{32})["\']?', "Twilio Account SID"),
    (r'(?i)twilio_auth_token\s*[=:]\s*["\']?([0-9a-f]{32})["\']?', "Twilio Auth Token"),
    (r'(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----', "Private Key Exposure"),
    (r'(?i)mongodb(?:\+srv)?://[^\s\'"]+', "MongoDB Connection String"),
    (r'(?i)postgresql?://[^\s\'"]+', "PostgreSQL Connection String"),
    (r'(?i)mysql://[^\s\'"]+', "MySQL Connection String"),
    (r'(?i)redis://[^\s\'"]+', "Redis Connection String"),
    (r'(?i)jdbc:[a-z]+://[^\s\'"]+', "JDBC Connection String"),
    (r'(?i)s3://[^\s\'"]+', "S3 Bucket URL"),
    (r'(?i)password\s*[=:]\s*["\']?([^"\';\s]{6,})["\']?', "Password"),
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', "API Key"),
    (r'(?i)(?:secret|token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.!@#$%^&*]{8,})["\']?', "Secret/Token"),
    (r'(?i)-----BEGIN CERTIFICATE-----', "Certificate Exposure"),
]

PLATFORMS = [
    {
        "name": "GitHub",
        "search_url": "https://api.github.com/search/code?q={query}+repo:{org}/{repo}",
        "org_search_url": "https://api.github.com/search/code?q={query}+org:{org}",
        "user_search_url": "https://api.github.com/search/code?q={query}+user:{user}",
        "gist_search_url": "https://api.github.com/search/code?q={query}",
        "commit_url": "https://api.github.com/search/commits?q={query}",
        "headers": {"Accept": "application/vnd.github.v3+json"},
    },
]

ALTERNATIVE_PLATFORMS = [
    {
        "name": "GitLab",
        "search_url": "https://gitlab.com/api/v4/projects?search={query}&per_page=20",
    },
    {
        "name": "Bitbucket",
        "search_url": "https://api.bitbucket.org/2.0/repositories?q=description~{query}",
    },
    {
        "name": "CodeBerg",
        "search_url": "https://codeberg.org/api/v1/repos/search?q={query}",
    },
]


async def _search_github(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    for query in GITHUB_SEARCH_QUERIES:
        q = f"{target}+{query}"
        try:
            resp = await client.get(
                f"https://api.github.com/search/code?q={q}&per_page=5",
                timeout=15.0,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("total_count", 0)
                if total > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"{total} GitHub results for: {query} on {target}",
                        type="GitHub Code Search Hit",
                        source="GitLeaks",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["github", "leak", "code-search"],
                        raw_data=f"Query: {query}, Total: {total}",
                    ))
                    for item in data.get("items", [])[:3]:
                        repo = item.get("repository", {}).get("full_name", "unknown")
                        file_url = item.get("html_url", "")
                        path = item.get("path", "")
                        findings.append(IntelligenceFinding(
                            entity=f"{repo}: {path}",
                            type="GitHub Leaked File Reference",
                            source="GitLeaks",
                            confidence="Medium",
                            color="red",
                            threat_level="High Risk",
                            tags=["github", "leak", "file"],
                            raw_data=file_url[:500],
                        ))
        except Exception:
            continue
    return findings


async def _search_github_gists(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.github.com/search/code?q={target}+gist&per_page=10",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{total} Gist results mentioning {target}",
                    type="GitHub Gist Leak",
                    source="GitLeaks",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    tags=["github", "gist", "leak"],
                    raw_data=f"Total gists: {total}",
                ))
                for item in data.get("items", [])[:5]:
                    repo = item.get("repository", {}).get("full_name", "")
                    html_url = item.get("html_url", "")
                    if html_url:
                        findings.append(IntelligenceFinding(
                            entity=html_url[:200],
                            type="Gist Reference",
                            source="GitLeaks",
                            confidence="Medium",
                            color="orange",
                            threat_level="Elevated Risk",
                            tags=["gist", "leak"],
                        ))
    except Exception:
        pass
    return findings


async def _search_github_commits(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.github.com/search/commits?q={target}+email&per_page=10",
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/vnd.github.cloak-preview+json",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{total} commits referencing {target}",
                    type="GitHub Commit History Leak",
                    source="GitLeaks",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["github", "commit", "leak"],
                ))
                for item in data.get("items", [])[:5]:
                    repo = item.get("repository", {}).get("full_name", "")
                    commit_url = item.get("html_url", "")
                    author = item.get("commit", {}).get("author", {}).get("name", "Unknown")
                    date = item.get("commit", {}).get("author", {}).get("date", "")
                    message = item.get("commit", {}).get("message", "")[:100]
                    findings.append(IntelligenceFinding(
                        entity=f"{repo}: {message}",
                        type="Commit Reference",
                        source="GitLeaks",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["github", "commit", author],
                        raw_data=f"Author: {author}, Date: {date}, URL: {commit_url}",
                    ))
    except Exception:
        pass
    return findings


async def _search_github_repos(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.github.com/search/repositories?q={target}+in:name,description,readme&per_page=10",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{total} repositories mentioning {target}",
                    type="GitHub Repository Hit",
                    source="GitLeaks",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["github", "repo"],
                ))
                for item in data.get("items", [])[:5]:
                    full_name = item.get("full_name", "")
                    description = item.get("description", "") or ""
                    stars = item.get("stargazers_count", 0)
                    forks = item.get("forks_count", 0)
                    updated = item.get("updated_at", "")
                    findings.append(IntelligenceFinding(
                        entity=f"{full_name} ({stars}★ {forks}⑂)",
                        type="Repository Metadata",
                        source="GitLeaks",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        tags=["github", "repo"],
                        raw_data=f"Description: {description}, Updated: {updated}",
                    ))
    except Exception:
        pass
    return findings


async def _search_alternative_platforms(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    for platform in ALTERNATIVE_PLATFORMS:
        try:
            url = platform["search_url"].format(query=target)
            resp = await client.get(url, timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                data = resp.json()
                count = 0
                if platform["name"] == "GitLab":
                    count = len(data) if isinstance(data, list) else 0
                elif platform["name"] == "Bitbucket":
                    count = len(data.get("values", [])) if isinstance(data, dict) else 0
                elif platform["name"] == "CodeBerg":
                    count = data.get("ok", False) if isinstance(data, dict) else 0
                if count > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"{count} results on {platform['name']} for {target}",
                        type=f"{platform['name']} Search Hit",
                        source="GitLeaks",
                        confidence="Low",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=[platform['name'].lower(), "leak"],
                    ))
        except Exception:
            continue
    return findings


async def _scan_raw_content(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://raw.githubusercontent.com/{target}/main/README.md",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            text = resp.text
            for pattern, stype in GITHUB_RAW_PATTERNS:
                for m in re.finditer(pattern, text):
                    matched = m.group(0)[:80]
                    findings.append(IntelligenceFinding(
                        entity=f"{stype}: {matched}...",
                        type=f"Git Leaked Secret: {stype}",
                        source="GitLeaks",
                        confidence="High",
                        color="red",
                        threat_level="Critical Risk",
                        tags=["secret", "leak", stype.lower().replace(" ", "_")],
                        raw_data=m.group(0)[:500],
                    ))
    except Exception:
        pass
    try:
        resp2 = await client.get(
            f"https://api.github.com/repos/{target}/contents/.env",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"},
        )
        if resp2.status_code == 200:
            content_data = resp2.json()
            if content_data.get("content"):
                try:
                    decoded = base64.b64decode(content_data["content"]).decode("utf-8", errors="replace")
                    for pattern, stype in GITHUB_RAW_PATTERNS:
                        for m in re.finditer(pattern, decoded):
                            findings.append(IntelligenceFinding(
                                entity=f"{stype}: {m.group(0)[:60]}...",
                                type=f"Git Leaked Secret: {stype}",
                                source="GitLeaks",
                                confidence="High",
                                color="red",
                                threat_level="Critical Risk",
                                tags=["secret", "env", stype.lower().replace(" ", "_")],
                                raw_data=m.group(0)[:500],
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

    results = await asyncio.gather(
        _search_github(domain, client),
        _search_github_gists(domain, client),
        _search_github_commits(domain, client),
        _search_github_repos(domain, client),
        _search_alternative_platforms(domain, client),
        _scan_raw_content(domain, client),
        return_exceptions=True,
    )

    for res in results:
        if isinstance(res, list):
            findings.extend(res)

    total_leaks = len(findings)
    if total_leaks > 0:
        findings.append(IntelligenceFinding(
            entity=f"Git leak scan complete: {total_leaks} total findings for {domain}",
            type="GitLeaks Summary",
            source="GitLeaks",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            tags=["summary"],
        ))

    return findings
