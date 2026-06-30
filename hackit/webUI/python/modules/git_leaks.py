import httpx
import asyncio
import re
import json
from urllib.parse import urljoin, urlparse, quote
from typing import List, Optional
from models import IntelligenceFinding

GIT_CONFIG_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/packed-refs",
    ".git/description",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
]

GITHUB_SEARCH_API = "https://api.github.com/search/code"
GITLAB_SEARCH_API = "https://gitlab.com/api/v4/search"

SENSITIVE_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*\S+', "Password"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*\S+', "API Key"),
    (r'(?:secret|secret[_-]?key)\s*[:=]\s*\S+', "Secret"),
    (r'(?:access[_-]?key|accesskey)\s*[:=]\s*\S+', "Access Key"),
    (r'(?:token|bearer|jwt)\s*[:=]\s*\S+', "Token"),
    (r'-----BEGIN.*PRIVATE KEY-----', "Private Key"),
    (r'(?:aws[_-]?key|aws_secret)', "AWS Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}', "GitHub Token"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Key"),
    (r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Key"),
    (r'xox[baprs]-[0-9a-zA-Z\-]{24,}', "Slack Token"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'sqlite:///[^\s]+', "SQLite Database"),
    (r'mongodb://[^\s]+', "MongoDB URI"),
    (r'postgresql://[^\s]+', "PostgreSQL URI"),
    (r'mysql://[^\s]+', "MySQL URI"),
    (r'rediss?://[^\s]+', "Redis URI"),
]

async def check_git_exposure(client: httpx.AsyncClient, domain: str) -> list:
    results = []
    for path in GIT_CONFIG_PATHS:
        try:
            url = f"https://{domain}/{path}"
            resp = await client.get(url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and len(resp.text) > 20:
                results.append({"path": path, "url": url, "content": resp.text[:1000]})
        except:
            pass
    return results

async def detect_sensitive_data(content: str) -> list:
    findings = []
    for pattern, label in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({"label": label, "count": len(matches), "samples": matches[:3]})
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    git_exposures = await check_git_exposure(client, t)

    if git_exposures:
        for exposure in git_exposures:
            findings.append(IntelligenceFinding(
                entity=f".git exposure: {exposure['path']} accessible",
                type="Git Leak: Exposure",
                source="GitLeaks",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Exposed",
                resolution=t,
                raw_data=f"URL: {exposure['url']}",
                tags=["git", "leak", "exposure", "critical"]
            ))

            sensitive = await detect_sensitive_data(exposure["content"])
            if sensitive:
                for s in sensitive:
                    findings.append(IntelligenceFinding(
                        entity=f"Sensitive data in .git: {s['label']} ({s['count']} occurrences)",
                        type=f"Git Leak: {s['label']}",
                        source="GitLeaks",
                        confidence="High",
                        color="red",
                        threat_level="Critical",
                        status="Secret Leaked",
                        resolution=t,
                        tags=["git", "secret", s["label"].lower().replace(" ", "-")]
                    ))

    if not git_exposures:
        findings.append(IntelligenceFinding(
            entity="No .git exposure detected",
            type="Git Leak: Check Complete",
            source="GitLeaks",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["git", "clean"]
        ))

    return findings
