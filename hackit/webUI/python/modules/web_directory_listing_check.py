import httpx
import re
from urllib.parse import urlparse
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
]

SENSITIVE_IN_LISTING = [
    r"\.bak$", r"\.old$", r"\.swp$", r"\.swo$", r"~$",
    r"\.sql$", r"\.dump$", r"\.tar\.gz$", r"\.zip$", r"\.rar$",
    r"\.log$", r"\.txt$", r"config", r"password", r"secret",
    r"credential", r"\.key$", r"\.pem$", r"\.crt$", r"cert",
]

async def check_directory_listing(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    result = {"path": path, "listing_enabled": False, "files": [], "status": 0, "sensitive_files": []}
    try:
        resp = await client.get(f"{base_url}/{path}/", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
        result["status"] = resp.status_code
        content = resp.text

        if resp.status_code == 200:
            if re.search(r"<title>Index of /", content, re.I) or re.search(r"Parent Directory</a>", content, re.I):
                result["listing_enabled"] = True
                file_pattern = re.compile(r"<a\s+href\s*=\s*\"([^\"]+)\"[^>]*>\s*\1\s*</a>", re.I)
                files = file_pattern.findall(content)
                result["files"] = [f for f in files if f not in (".", "..")]
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
            r = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            if r.status_code == 200:
                base_accessible = True
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    if not base_accessible:
        findings.append(IntelligenceFinding(
            entity=f"Site {domain} not accessible",
            type="DirListing: Unreachable",
            source="DirectoryListingCheck",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["directory-listing", "error"]
        ))
        return findings

    findings.append(IntelligenceFinding(
        entity=f"Checking {len(COMMON_DIRECTORIES)} common directories for listing enabled",
        type="DirListing: Scan Started",
        source="DirectoryListingCheck",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        tags=["directory-listing", "scan"]
    ))

    listing_dirs = []
    non_listing_accessible = []

    for d in COMMON_DIRECTORIES:
        result = await check_directory_listing(client, base_url, d)
        if result["listing_enabled"]:
            listing_dirs.append(result)
        elif result["status"] in (200, 401, 403):
            non_listing_accessible.append({"path": d, "status": result["status"]})

    for ld in listing_dirs:
        sensitive_files = ld.get("sensitive_files", [])
        findings.append(IntelligenceFinding(
            entity=f"Directory listing ENABLED: /{ld['path']}/ ({len(ld['files'])} file(s))",
            type="DirListing: Enabled",
            source="DirectoryListingCheck",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Vulnerable",
            raw_data=f"path=/{ld['path']}/, files={len(ld['files'])}, sensitive={len(sensitive_files)}",
            tags=["directory-listing", "exposure", "vulnerability"]
        ))

        if ld["files"]:
            findings.append(IntelligenceFinding(
                entity=f"Files in /{ld['path']}/: {', '.join(ld['files'][:10])}",
                type="DirListing: File List",
                source="DirectoryListingCheck",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(ld["files"]),
                tags=["directory-listing", "files"]
            ))

        if sensitive_files:
            findings.append(IntelligenceFinding(
                entity=f"Sensitive files in /{ld['path']}/: {', '.join(sensitive_files[:10])}",
                type="DirListing: Sensitive Files Exposed",
                source="DirectoryListingCheck",
                confidence="High",
                color="red",
                threat_level="Critical",
                raw_data="\n".join(sensitive_files),
                tags=["directory-listing", "sensitive", "critical"]
            ))

    for nd in non_listing_accessible:
        findings.append(IntelligenceFinding(
            entity=f"/{nd['path']}/ returns HTTP {nd['status']} (responds but listing disabled)",
            type="DirListing: No Listing",
            source="DirectoryListingCheck",
            confidence="Medium",
            color="yellow",
            threat_level="Informational",
            tags=["directory-listing", "accessible"]
        ))

    if not listing_dirs:
        findings.append(IntelligenceFinding(
            entity="No directory listings enabled on common paths (good security practice)",
            type="DirListing: All Secure",
            source="DirectoryListingCheck",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["directory-listing", "secure"]
        ))

    total_sensitive = sum(len(ld.get("sensitive_files", [])) for ld in listing_dirs)
    listing_score = min(len(listing_dirs) * 20, 100)
    findings.append(IntelligenceFinding(
        entity=f"Directory Listing Score: {listing_score}/100 ({len(listing_dirs)} listing(s) enabled, {total_sensitive} sensitive file(s))",
        type="DirListing: Score",
        source="DirectoryListingCheck",
        confidence="High",
        color="red" if listing_score > 0 else "emerald",
        threat_level="High Risk" if listing_score > 0 else "Informational",
        status=f"Score: {listing_score}/100",
        raw_data=f"listing_dirs={len(listing_dirs)}, sensitive_files={total_sensitive}, accessible_no_listing={len(non_listing_accessible)}",
        tags=["directory-listing", "score"]
    ))

    return findings
