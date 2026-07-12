import re, asyncio
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, make_finding
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

COMMON_DIRECTORIES = [
    "images", "css", "js", "uploads", "backup", "admin", "assets",
    "static", "downloads", "files", "media", "data", "logs", "tmp",
    "private", "secure", "config", "include", "inc", "lib", "src",
    "app", "dist", "build", "public", "cache", "temp", "archive",
    "docs", "documentation", "sql", "database", "db", "migrations",
    "vendor", "node_modules", "bower_components", "themes", "plugins",
    "modules", "components", "widgets", "api", "v1", "v2", "rest",
    "soap", "graphql", "swagger", "api-docs", "openapi",
    "backup", "backups", "old", "new", "test", "tests", "testing",
    "dev", "development", "staging", "stage", "beta", "alpha", "demo",
    "debug", "trace", "monitor", "status", "health", "metrics",
    "assets", "resource", "resources", "static", "public", "shared",
    "templates", "views", "layouts", "partials", "includes",
    "cgi-bin", "scripts", "bin", "sbin", "exec", "run",
    "content", "pages", "blog", "news", "forum", "community",
    "support", "help", "faq", "wiki", "kb", "knowledgebase",
    "portal", "dashboard", "panel", "control", "manager",
    "uploads", "upload", "file", "files", "document", "documents",
    "image", "images", "img", "pic", "pics", "photo", "photos",
    "video", "videos", "audio", "media", "download", "downloads",
    "software", "packages", "repo", "repository", "registry",
    "logs", "log", "audit", "event", "events", "error", "errors",
    "tmp", "temp", "cache", "caches", "session", "sessions",
    "data", "datas", "dataset", "datasets", "export", "imports",
    "config", "configuration", "conf", "cfg", "setting", "settings",
    "secret", "secrets", "credential", "credentials", "auth",
    "ssl", "cert", "certs", "certificate", "certificates", "keys",
    "key", "keys", "token", "tokens", "password", "passwords",
    "private", "priv", "restricted", "internal", "int", "intra",
    "secure", "security", "safe", "safety", "protection",
    "backup", "bak", "bkp", "bk", "orig", "original", "copy",
    "old", "new", "previous", "prev", "last", "current",
    "test", "testing", "tests", "spec", "specs", "experiment",
    "debug", "debugging", "trace", "tracing", "profile", "profiling",
    ".git", ".svn", ".hg", ".bzr", ".cvs",
    ".env", ".htaccess", ".htpasswd", "web.config",
]

SENSITIVE_IN_LISTING = [
    r"\.bak$", r"\.old$", r"\.swp$", r"\.swo$", r"~$",
    r"\.sql$", r"\.dump$", r"\.tar\.gz$", r"\.zip$", r"\.rar$",
    r"\.log$", r"\.txt$", r"config", r"password", r"secret",
    r"credential", r"\.key$", r"\.pem$", r"\.crt$", r"cert",
    r"\.env", r"\.git", r"\.svn", r"\.htaccess", r"\.htpasswd",
    r"database", r"backup", r"dump", r"export",
]

CONCURRENT_LIMIT = 30

async def check_directory_listing(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    result = {"path": path, "listing_enabled": False, "files": [], "status": 0, "sensitive_files": []}
    try:
        resp = await safe_fetch(client, f"{base_url}/{path}/", timeout=6.0, follow_redirects=False, headers={"User-Agent": UA})
        if not resp:
            return result
        result["status"] = resp.status_code
        content = resp.text

        if resp.status_code == 200:
            if re.search(r"<title>Index of /", content, re.I) or re.search(r"Parent Directory</a>", content, re.I):
                result["listing_enabled"] = True
                file_pattern = re.compile(r'<a\s+href\s*=\s*"([^"]+)"[^>]*>', re.I)
                files = file_pattern.findall(content)
                result["files"] = [f for f in files if f not in (".", "..", "../")]
                for f in result["files"]:
                    for sens_pat in SENSITIVE_IN_LISTING:
                        if re.search(sens_pat, f, re.I):
                            result["sensitive_files"].append(f)
                            break
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    base_accessible = False
    for proto in ["https", "http"]:
        try:
            r = await safe_fetch(client, f"{proto}://{domain}", timeout=8.0, follow_redirects=True, headers={"User-Agent": UA})
            if r and r.status_code < 500:
                base_accessible = True
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    if not base_accessible:
        findings.append(make_finding(
            entity=f"Site {domain} not accessible",
            ftype="DirListing: Unreachable",
            source="DirectoryListingCheck",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["directory-listing", "error"]
        ))
        return findings

    sem = asyncio.Semaphore(CONCURRENT_LIMIT)

    async def check_dir(d):
        async with sem:
            return await check_directory_listing(client, base_url, d)

    tasks = [check_dir(d) for d in COMMON_DIRECTORIES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    listing_dirs = []
    non_listing_accessible = []
    for r in results:
        if isinstance(r, Exception) or not isinstance(r, dict):
            continue
        if r["listing_enabled"]:
            listing_dirs.append(r)
        elif r["status"] in (200, 401, 403):
            non_listing_accessible.append({"path": r["path"], "status": r["status"]})

    for ld in listing_dirs:
        sensitive_files = ld.get("sensitive_files", [])
        findings.append(make_finding(
            entity=f"Directory listing ENABLED: /{ld['path']}/ ({len(ld['files'])} files)",
            ftype="DirListing: Enabled",
            source="DirectoryListingCheck",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Vulnerable",
            raw_data=f"path=/{ld['path']}/, files={len(ld['files'])}, sensitive={len(sensitive_files)}",
            tags=["directory-listing", "exposure", "vulnerability"]
        ))

        if ld["files"]:
            findings.append(make_finding(
                entity=f"Files in /{ld['path']}/: {', '.join(ld['files'][:15])}",
                ftype="DirListing: File List",
                source="DirectoryListingCheck",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(ld["files"]),
                tags=["directory-listing", "files"]
            ))

        if sensitive_files:
            findings.append(make_finding(
                entity=f"Sensitive files in /{ld['path']}/: {', '.join(sensitive_files[:10])}",
                ftype="DirListing: Sensitive Files Exposed",
                source="DirectoryListingCheck",
                confidence="High",
                color="red",
                threat_level="Critical",
                raw_data="\n".join(sensitive_files),
                tags=["directory-listing", "sensitive", "critical"]
            ))

    for nd in non_listing_accessible[:20]:
        findings.append(make_finding(
            entity=f"/{nd['path']}/ returns HTTP {nd['status']}",
            ftype="DirListing: Accessible",
            source="DirectoryListingCheck",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["directory-listing", "accessible"]
        ))

    if not listing_dirs:
        findings.append(make_finding(
            entity="No directory listings enabled on common paths (good security practice)",
            ftype="DirListing: All Secure",
            source="DirectoryListingCheck",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["directory-listing", "secure"]
        ))

    total_sensitive = sum(len(ld.get("sensitive_files", [])) for ld in listing_dirs)
    listing_score = min(len(listing_dirs) * 20, 100)
    findings.append(make_finding(
        entity=f"Directory Listing Score: {listing_score}/100 ({len(listing_dirs)} enabled, {total_sensitive} sensitive files, {len(COMMON_DIRECTORIES)} checked)",
        ftype="DirListing: Score",
        source="DirectoryListingCheck",
        confidence="High",
        color="red" if listing_score > 0 else "emerald",
        threat_level="High Risk" if listing_score > 0 else "Informational",
        status=f"Score: {listing_score}/100",
        raw_data=f"listing_dirs={len(listing_dirs)}, sensitive_files={total_sensitive}, accessible_no_listing={len(non_listing_accessible)}, dirs_checked={len(COMMON_DIRECTORIES)}",
        tags=["directory-listing", "score"]
    ))

    return findings
