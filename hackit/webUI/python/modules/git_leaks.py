import re
import json
from urllib.parse import urlparse
from module_common import safe_fetch, make_finding

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

async def check_git_exposure(client, domain: str) -> list:
    results = []
    for path in GIT_CONFIG_PATHS:
        url = f"https://{domain}/{path}"
        resp = await safe_fetch(client, url, headers={"User-Agent": "Mozilla/5.0"})
        if resp and resp.status_code == 200 and len(resp.text) > 20:
            results.append({"path": path, "url": url, "content": resp.text[:1000]})
    return results

async def detect_sensitive_data(content: str) -> list:
    findings = []
    for pattern, label in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({"label": label, "count": len(matches), "samples": matches[:3]})
    return findings

GIT_HUB_API = "https://api.github.com"
GIT_LAB_API = "https://gitlab.com/api/v4"

ADDITIONAL_GIT_PATHS = [
    ".git/ORIG_HEAD",
    ".git/FETCH_HEAD",
    ".git/MERGE_HEAD",
    ".git/CHERRY_PICK_HEAD",
    ".git/REBASE_HEAD",
    ".git/objects/info/packs",
    ".git/info/refs",
    ".git/info/exclude",
    ".git/config.bak",
    ".git/config.old",
    ".git-credentials",
    ".git-ftp-config",
    ".gitreview",
    ".git-blame-ignore-revs",
    ".git-pre-commit",
    ".git-commit-template",
    "backup/.git/config",
    "old/.git/config",
]

COMMIT_HASH_PATTERN = re.compile(r"\b[0-9a-f]{40}\b")
URL_REF_PATTERN = re.compile(r"(?:github|gitlab|bitbucket)[.:][^\s\"'<>]+")

async def check_git_dir_listing(domain: str, client) -> list:
    results = []
    base = f"https://{domain}"
    paths = [
        ".git/", ".git/objects/", ".git/refs/", ".git/logs/",
        ".git/hooks/", ".git/info/",
    ]
    for path in paths:
        url = f"{base}/{path}"
        resp = await safe_fetch(client, url, headers={"User-Agent": "Mozilla/5.0"})
        if resp and resp.status_code == 200 and ("index" in resp.text.lower() or "parent directory" in resp.text.lower()):
            results.append({"path": path, "url": url, "type": "directory_listing"})
    return results

async def check_github_search(domain: str, client) -> list:
    results = []
    resp = await safe_fetch(client,
        f"{GIT_HUB_API}/search/code",
        params={"q": domain, "per_page": 5},
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"})
    if resp and resp.status_code == 200:
        data = resp.json()
        total = data.get("total_count", 0)
        if total:
            items = data.get("items", [])
            for item in items[:5]:
                results.append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                })
    return results

async def check_gitlab_search(domain: str, client) -> list:
    results = []
    resp = await safe_fetch(client,
        f"{GIT_LAB_API}/search",
        params={"scope": "blobs", "search": domain, "per_page": 5},
        headers={"User-Agent": "Mozilla/5.0"})
    if resp and resp.status_code == 200:
        items = resp.json()
        if isinstance(items, list) and items:
            for item in items[:5]:
                results.append({
                    "project": item.get("project_id", ""),
                    "path": item.get("filename", item.get("path", "")),
                    "ref": item.get("ref", ""),
                })
    return results

async def crawl(target: str, client) -> list:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    git_exposures = await check_git_exposure(client, t)

    if git_exposures:
        for exposure in git_exposures:
            findings.append(make_finding(
                entity=f".git exposure: {exposure['path']} accessible",
                ftype="Git Leak: Exposure",
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
                    findings.append(make_finding(
                        entity=f"Sensitive data in .git: {s['label']} ({s['count']} occurrences)",
                        ftype=f"Git Leak: {s['label']}",
                        source="GitLeaks",
                        confidence="High",
                        color="red",
                        threat_level="Critical",
                        status="Secret Leaked",
                        resolution=t,
                        tags=["git", "secret", s["label"].lower().replace(" ", "-")]
                    ))

            all_git_content = " ".join(e["content"] for e in git_exposures)
            commits = COMMIT_HASH_PATTERN.findall(all_git_content)
            if commits:
                findings.append(make_finding(
                    entity=f"{len(set(commits))} commit hashes found in .git data",
                    ftype="Git Leak: Commit History",
                    source="GitLeaks",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Exposed",
                    resolution=t,
                    tags=["git", "commit", "history"]
                ))

    dir_listings = await check_git_dir_listing(t, client)
    if dir_listings:
        for dl in dir_listings:
            findings.append(make_finding(
                entity=f"Git directory listing: {dl['path']}",
                ftype="Git Leak: Directory Listing",
                source="GitLeaks",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Exposed",
                resolution=t,
                tags=["git", "directory-listing", "exposure"]
            ))

    gh_results = await check_github_search(t, client)
    if gh_results:
        findings.append(make_finding(
            entity=f"GitHub: {len(gh_results)} code results referencing {t}",
            ftype="Git Leak: GitHub Code Search",
            source="GitLeaks",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Found",
            resolution=t,
            tags=["git", "github", "code-search"]
        ))
        for r in gh_results[:3]:
            findings.append(make_finding(
                entity=f"GitHub reference: {r['repo']}/{r['path']}",
                ftype="Git Leak: GitHub Reference",
                source="GitLeaks",
                confidence="Medium",
                color="slate",
                status="Referenced",
                resolution=t,
                tags=["git", "github", r['repo'].replace("/", "-").lower()]
            ))

    gl_results = await check_gitlab_search(t, client)
    if gl_results:
        findings.append(make_finding(
            entity=f"GitLab: {len(gl_results)} code results referencing {t}",
            ftype="Git Leak: GitLab Code Search",
            source="GitLeaks",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Found",
            resolution=t,
            tags=["git", "gitlab", "code-search"]
        ))

    if not git_exposures:
        findings.append(make_finding(
            entity="No .git exposure detected",
            ftype="Git Leak: Check Complete",
            source="GitLeaks",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["git", "clean"]
        ))

    return findings
