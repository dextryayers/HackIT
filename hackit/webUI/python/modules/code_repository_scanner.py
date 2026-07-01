import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

CODE_PLATFORMS = [
    ("GitHub", "https://api.github.com/search/code?q={}&per_page=10"),
    ("GitHub Repos", "https://api.github.com/search/repositories?q={}&per_page=10"),
    ("GitLab", "https://gitlab.com/api/v4/search?scope=blobs&search={}&per_page=10"),
    ("GitLab Repos", "https://gitlab.com/api/v4/search?scope=projects&search={}&per_page=10"),
    ("Bitbucket", "https://api.bitbucket.org/2.0/repositories?q={}&pagelen=10"),
    ("SourceForge", "https://sourceforge.net/search/?q={}&limit=10"),
    ("Gitee", "https://search.gitee.com/?type=repository&q={}&page=1"),
    ("Codeberg", "https://codeberg.org/api/v1/repos/search?q={}&limit=10"),
    ("Gist GitHub", "https://api.github.com/search/gist?q={}&per_page=10"),
]

SENSITIVE_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "Critical"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Key", "Critical"),
    (r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Key", "High"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Token", "Critical"),
    (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token", "Critical"),
    (r'xox[baprs]-[0-9a-zA-Z\-]{24,}', "Slack Token", "Critical"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "Critical"),
    (r'-----BEGIN\s?(RSA\s)?PRIVATE KEY-----', "Private Key", "Critical"),
    (r'-----BEGIN CERTIFICATE-----', "Certificate", "High"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*\S+', "Password", "Critical"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*\S+', "API Key", "Critical"),
    (r'(?:secret|secret[_-]?key)\s*[:=]\s*\S+', "Secret Key", "Critical"),
    (r'mongodb(?:\+srv)?://[^\s\'\"<>]+', "MongoDB URI", "Critical"),
    (r'postgresql?://[^\s\'\"<>]+', "PostgreSQL URI", "Critical"),
    (r'mysql://[^\s\'\"<>]+', "MySQL URI", "Critical"),
    (r'redis://[^\s\'\"<>]+', "Redis URI", "Critical"),
    (r'https?://[^\s]+@[^\s]+', "URL with Credentials", "High"),
    (r'(?:jwt|bearer)\s+[A-Za-z0-9\-_.]{20,}', "JWT Token", "Critical"),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key", "Critical"),
    (r'(?:sk|pk)_[a-z]+_[0-9a-zA-Z]{20,}', "Stripe Key", "Critical"),
    (r'[0-9a-fA-F]{32,64}', "Potential Hash/SHA", "Medium"),
]

COMMIT_PATTERN = re.compile(r'\b[0-9a-f]{40}\b')
EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

async def search_github(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://api.github.com/search/code",
            params={"q": target, "per_page": 10},
            headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "source": "GitHub",
                "total": data.get("total_count", 0),
                "items": [
                    {"repo": i.get("repository", {}).get("full_name", ""), "path": i.get("path", ""), "url": i.get("html_url", "")}
                    for i in data.get("items", [])
                ]
            })
    except:
        pass

    try:
        resp = await client.get(
            f"https://api.github.com/search/repositories",
            params={"q": target, "per_page": 10},
            headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                results.append({
                    "source": "GitHub Repo",
                    "name": item.get("full_name", ""),
                    "desc": item.get("description", "") or "",
                    "url": item.get("html_url", ""),
                    "stars": item.get("stargazers_count", 0),
                    "topics": item.get("topics", []),
                    "lang": item.get("language", ""),
                })
    except:
        pass

    try:
        resp = await client.get(
            f"https://api.github.com/search/gist",
            params={"q": target, "per_page": 10},
            headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("total_count", 0) > 0:
                results.append({
                    "source": "GitHub Gist",
                    "total": data.get("total_count", 0),
                    "items": [
                        {"url": i.get("html_url", ""), "desc": i.get("description", "")}
                        for i in data.get("items", [])[:5]
                    ]
                })
    except:
        pass

    return results

async def search_gitlab(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            "https://gitlab.com/api/v4/search",
            params={"scope": "blobs", "search": target, "per_page": 10},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            items = resp.json()
            if isinstance(items, list) and items:
                results.append({
                    "source": "GitLab Blobs",
                    "total": len(items),
                    "items": [
                        {"project": i.get("project_id", ""), "path": i.get("filename", i.get("path", "")), "ref": i.get("ref", "")}
                        for i in items[:10]
                    ]
                })
    except:
        pass

    try:
        resp = await client.get(
            "https://gitlab.com/api/v4/search",
            params={"scope": "projects", "search": target, "per_page": 10},
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            items = resp.json()
            if isinstance(items, list):
                for item in items:
                    results.append({
                        "source": "GitLab Project",
                        "name": item.get("path_with_namespace", ""),
                        "desc": item.get("description", "") or "",
                        "url": item.get("web_url", ""),
                        "topics": item.get("topics", []),
                    })
    except:
        pass

    return results

async def search_other_platforms(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://api.bitbucket.org/2.0/repositories?q={quote(target)}&pagelen=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            values = data.get("values", [])
            if values:
                results.append({
                    "source": "Bitbucket",
                    "total": len(values),
                    "items": [
                        {"name": v.get("full_name", ""), "desc": v.get("description", ""), "url": v.get("links", {}).get("html", {}).get("href", "")}
                        for v in values[:5]
                    ]
                })
    except:
        pass

    try:
        resp = await client.get(
            f"https://codeberg.org/api/v1/repos/search?q={quote(target)}&limit=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            repos = data.get("data", [])
            if repos:
                results.append({
                    "source": "Codeberg",
                    "total": len(repos),
                    "names": [r.get("full_name", "") for r in repos[:5]]
                })
    except:
        pass

    try:
        resp = await client.get(
            f"https://search.gitee.com/?type=repository&q={quote(target)}",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            text = resp.text
            count = text.count('class="repository"')
            if count > 0:
                results.append({"source": "Gitee", "count": count})
    except:
        pass

    return results

async def scan_content_for_secrets(content: str, source: str) -> list:
    findings = []
    for pattern, label, severity in SENSITIVE_PATTERNS:
        try:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.append({
                    "label": label,
                    "severity": severity,
                    "count": len(matches),
                    "source": source,
                    "samples": [m[:50] for m in matches[:3]]
                })
        except:
            pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    await asyncio.sleep(0)

    gh_results = await search_github(t, client)
    for result in gh_results:
        if "total" in result:
            findings.append(IntelligenceFinding(
                entity=f"{result['source']}: {result['total']} code results for {t}",
                type="Code Repo: Search Results",
                source="CodeRepoScanner",
                confidence="Medium",
                color="orange" if result['total'] > 0 else "slate",
                category="Code Intelligence",
                threat_level="Elevated Risk" if result['total'] > 5 else "Informational",
                status="Found" if result['total'] > 0 else "Empty",
                resolution=t,
                tags=["code", result['source'].lower().replace(" ", "-"), "search"]
            ))
            for item in result.get("items", []):
                findings.append(IntelligenceFinding(
                    entity=f"File: {item.get('path', '')} in {item.get('repo', '')}",
                    type="Code Repo: File Reference",
                    source="CodeRepoScanner",
                    confidence="Medium",
                    color="slate",
                    category="Code Intelligence",
                    threat_level="Informational",
                    status="Referenced",
                    resolution=t,
                    tags=["code", "file", item.get('repo', '').replace("/", "-").lower()]
                ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"{result.get('source', '')}: {result.get('name', '')} - {result.get('desc', '')[:100]}",
                type="Code Repo: Repository Found",
                source="CodeRepoScanner",
                confidence="High",
                color="blue",
                category="Code Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                raw_data=f"Stars: {result.get('stars', 0)}, Language: {result.get('lang', '')}",
                tags=["code", "repository", result.get('lang', '').lower().replace(" ", "-")]
            ))

    gl_results = await search_gitlab(t, client)
    for result in gl_results:
        if "total" in result:
            findings.append(IntelligenceFinding(
                entity=f"{result['source']}: {result['total']} blob results for {t}",
                type="Code Repo: GitLab Blobs",
                source="CodeRepoScanner",
                confidence="Medium",
                color="orange" if result['total'] > 0 else "slate",
                category="Code Intelligence",
                threat_level="Elevated Risk" if result['total'] > 5 else "Informational",
                status="Found" if result['total'] > 0 else "Empty",
                resolution=t,
                tags=["code", "gitlab", "blob"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"GitLab Project: {result.get('name', '')}",
                type="Code Repo: GitLab Project",
                source="CodeRepoScanner",
                confidence="High",
                color="blue",
                category="Code Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["code", "gitlab", "project"]
            ))

    other_results = await search_other_platforms(t, client)
    for result in other_results:
        label = result.get("source", "Unknown")
        count = result.get("total", result.get("count", 0))
        findings.append(IntelligenceFinding(
            entity=f"{label}: {count} repositories referencing {t}",
            type="Code Repo: Platform Match",
            source="CodeRepoScanner",
            confidence="Medium",
            color="blue",
            category="Code Intelligence",
            threat_level="Informational",
            status="Found" if count else "Empty",
            resolution=t,
            tags=["code", label.lower().replace(" ", "-"), "platform"]
        ))

    all_content = ""
    for result in gh_results:
        for item in result.get("items", []):
            try:
                resp = await client.get(
                    f"https://raw.githubusercontent.com/{item.get('repo', '')}/main/{item.get('path', '')}",
                    headers={"User-Agent": "OSINT-Module/1.0"}, timeout=10.0
                )
                if resp.status_code == 200:
                    all_content += resp.text[:5000] + "\n"
            except:
                pass

    secrets_found = []
    if all_content:
        secrets_found = await scan_content_for_secrets(all_content, "GitHub")
        for s in secrets_found:
            findings.append(IntelligenceFinding(
                entity=f"Secret in code: {s['label']} ({s['count']} occurrences)",
                type=f"Code Repo: {s['severity']} Secret",
                source="CodeRepoScanner",
                confidence="High",
                color="red",
                category="Code Intelligence",
                threat_level=s['severity'],
                status="Secret Found",
                resolution=t,
                raw_data=f"Samples: {', '.join(s['samples'])}",
                tags=["secret", s['label'].lower().replace(" ", "-"), s['severity'].lower()]
            ))

    emails = EMAIL_PATTERN.findall(all_content)
    unique_emails = set(emails) - {t}
    if unique_emails:
        findings.append(IntelligenceFinding(
            entity=f"{len(unique_emails)} emails found in code: {', '.join(list(unique_emails)[:5])}",
            type="Code Repo: Email Disclosure",
            source="CodeRepoScanner",
            confidence="Medium",
            color="orange",
            category="Code Intelligence",
            threat_level="Medium Risk",
            status="Exposed",
            resolution=t,
            tags=["email", "exposure", "code"]
        ))

    domains = DOMAIN_PATTERN.findall(all_content)
    unique_domains = set(domains) - {t}
    if unique_domains:
        findings.append(IntelligenceFinding(
            entity=f"{len(unique_domains)} internal domains referenced in code",
            type="Code Repo: Domain Disclosure",
            source="CodeRepoScanner",
            confidence="Medium",
            color="orange",
            category="Code Intelligence",
            threat_level="Medium Risk",
            status="Exposed",
            resolution=t,
            tags=["domain", "internal", "code"]
        ))

    ips = IP_PATTERN.findall(all_content)
    private_ips = [ip for ip in ips if ip.startswith(("10.", "172.16.", "192.168."))]
    if private_ips:
        findings.append(IntelligenceFinding(
            entity=f"{len(set(private_ips))} internal IPs exposed in code: {', '.join(set(private_ips)[:5])}",
            type="Code Repo: Internal IP Leak",
            source="CodeRepoScanner",
            confidence="High",
            color="red",
            category="Code Intelligence",
            threat_level="Critical",
            status="Exposed",
            resolution=t,
            tags=["ip", "internal", "leak", "code"]
        ))

    commits = COMMIT_PATTERN.findall(all_content)
    if commits:
        findings.append(IntelligenceFinding(
            entity=f"{len(set(commits))} commit hashes referenced in code content",
            type="Code Repo: Commit References",
            source="CodeRepoScanner",
            confidence="Medium",
            color="slate",
            category="Code Intelligence",
            threat_level="Informational",
            status="Referenced",
            resolution=t,
            tags=["code", "commit", "hash"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Code repository scan complete for {t}",
        type="Code Repo: Scan Summary",
        source="CodeRepoScanner",
        confidence="High",
        color="slate",
        category="Code Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["code", "summary"]
    ))

    return findings
