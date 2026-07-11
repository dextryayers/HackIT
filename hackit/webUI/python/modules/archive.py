import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Optional
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

WAYBACK_API = "https://web.archive.org"
CDX_API = f"{WAYBACK_API}/cdx/search/cdx"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

SENSITIVE_EXTENSIONS = [
    ".sql", ".bak", ".old", ".backup", ".dump", ".tar.gz", ".zip",
    ".rar", ".7z", ".log", ".env", ".git", ".svn", ".htaccess",
    ".json", ".yaml", ".yml", ".xml", ".conf", ".ini", ".cfg",
    ".pem", ".key", ".crt", ".cert", ".p12",
    ".xls", ".xlsx", ".doc", ".docx", ".pdf",
]

SENSITIVE_PATHS = [
    r'/(?:admin|administrator|backup|config|configuration|db|database)',
    r'/(?:wp-admin|wp-content|wp-config|wp-includes)',
    r'/\.git(?:/config|/HEAD)?',
    r'/\.env(?:\.example)?',
    r'/(?:phpmyadmin|phpMyAdmin|mysql|pma)',
    r'/(?:api|v1|v2|graphql|swagger|docs)',
    r'/(?:login|signin|register|forgot|reset)',
]

async def query_cdx(domain: str, client: httpx.AsyncClient, limit: int = 200) -> list:
    results = []
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype,length",
        "limit": str(limit),
        "filter": "statuscode:200",
        "collapse": "urlkey",
    }
    resp = await safe_fetch(client, CDX_API, params=params, timeout=30.0)
    if resp and resp.status_code == 200:
        lines = resp.text.strip().splitlines()
        for line in lines[1:]:
            try:
                parts = json.loads(line) if line.startswith("[") else line.split(" ")
                if isinstance(parts, list) and len(parts) >= 4:
                    results.append({
                        "url": parts[0] if len(parts) > 0 else "",
                        "timestamp": parts[1] if len(parts) > 1 else "",
                        "status": parts[2] if len(parts) > 2 else "",
                        "mime": parts[3] if len(parts) > 3 else "",
                        "length": parts[4] if len(parts) > 4 else "0",
                    })
            except:
                continue
    return results

async def query_available(domain: str, client: httpx.AsyncClient) -> dict:
    resp = await safe_fetch(client, f"{WAYBACK_API}/available?url={domain}")
    if resp and resp.status_code == 200:
        return resp.json()
    return {}

async def query_cdx_raw(domain: str, client: httpx.AsyncClient, limit: int = 500) -> list:
    results = []
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original,timestamp,statuscode,mimetype,length",
        "limit": str(limit),
        "collapse": "urlkey",
    }
    resp = await safe_fetch(client, CDX_API, params=params, timeout=30.0)
    if resp and resp.status_code == 200:
        lines = resp.text.strip().splitlines()
        for line in lines:
            parts = line.strip().split(" ")
            if len(parts) >= 5:
                results.append({
                    "url": parts[0], "timestamp": parts[1],
                    "status": parts[2], "mime": parts[3], "length": parts[4],
                })
    return results

async def analyze_url_structure(urls: list) -> list:
    findings = []
    try:
        path_depths = {}
        query_count = 0
        for r in urls:
            url = r.get("url", "")
            if "?" in url: query_count += 1
            parsed = urlparse(url)
            depth = len([p for p in parsed.path.split("/") if p])
            path_depths[depth] = path_depths.get(depth, 0) + 1
        if path_depths:
            avg_depth = sum(k * v for k, v in path_depths.items()) / sum(path_depths.values())
            findings.append(make_finding(
                entity=f"Avg URL path depth: {avg_depth:.1f} (query URLs: {query_count})",
                ftype="Archive: URL Structure Analysis",
                source="Wayback Machine",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution="",
                tags=["archive", "structure"]
            ))
    except:
        pass
    return findings

async def detect_technology_archived(urls: list, client: httpx.AsyncClient) -> list:
    findings = []
    tech_patterns = {
        "WordPress": ["/wp-content/", "/wp-includes/", "/wp-json/"],
        "Drupal": ["/sites/default/", "/modules/", "/themes/"],
        "Joomla": ["/components/", "/modules/", "/templates/"],
        "Laravel": ["/vendor/", "/storage/", "/artisan"],
        "Django": ["/admin/", "/static/", "/media/"],
        "React": ["/static/js/", "/service-worker.js"],
        "Angular": ["/polyfills.", "/main.", "/runtime."],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
    }
    found_techs = set()
    for r in urls[:100]:
        url = r.get("url", "").lower()
        for tech, patterns in tech_patterns.items():
            for p in patterns:
                if p.lower() in url:
                    found_techs.add(tech)
    for tech in found_techs:
        findings.append(make_finding(
            entity=f"Technology detected: {tech}",
            ftype="Archive: Technology Detection",
            source="Wayback Machine",
            confidence="Medium",
            color="slate",
            status="Identified",
            resolution="",
            tags=["archive", "technology", tech.lower()]
        ))
    return findings

async def check_redirect_chain_archived(urls: list) -> list:
    findings = []
    statuses = {}
    for r in urls:
        s = r.get("status", "000")
        statuses[s] = statuses.get(s, 0) + 1
    redirect_count = sum(v for k, v in statuses.items() if k.startswith("3"))
    error_count = sum(v for k, v in statuses.items() if k.startswith(("4", "5")))
    if redirect_count:
        findings.append(make_finding(
            entity=f"{redirect_count} redirects (3xx) in archive",
            ftype="Archive: Redirect Analysis",
            source="Wayback Machine",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            status=f"{redirect_count} redirects",
            resolution="",
            tags=["archive", "redirect"]
        ))
    if error_count:
        findings.append(make_finding(
            entity=f"{error_count} error responses (4xx/5xx) in archive",
            ftype="Archive: Error Analysis",
            source="Wayback Machine",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status=f"{error_count} errors",
            resolution="",
            tags=["archive", "error"]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    available = await query_available(t, client)
    archived_snapshots = available.get("archived_snapshots", {})
    closest = archived_snapshots.get("closest", {})
    if closest:
        findings.append(make_finding(
            entity=f"Archived snapshot available: {closest.get('url', '')[:200]}",
            ftype="Archive: Snapshot Available",
            source="Wayback Machine",
            confidence="High",
            color="slate",
            status="Available",
            resolution=t,
            raw_data=json.dumps(closest),
            tags=["archive", "snapshot", "wayback"]
        ))

    cdx_results = await query_cdx(t, client)
    if cdx_results:
        cdx_raw = await query_cdx_raw(t, client)

        struct_results = await analyze_url_structure(cdx_results)
        findings.extend(struct_results)

        tech_results = await detect_technology_archived(cdx_results, client)
        findings.extend(tech_results)

        redirect_results = await check_redirect_chain_archived(cdx_results)
        findings.extend(redirect_results)
        findings.append(make_finding(
            entity=f"{len(cdx_results)} historical URLs archived",
            ftype="Archive: Historical URL Count",
            source="Wayback CDX",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"{len(cdx_results)} URLs",
            resolution=t,
            tags=["archive", "historical", "cdx"]
        ))

        mime_types = {}
        status_codes = {}
        for r in cdx_results:
            mime = r.get("mime", "unknown")
            mime_types[mime] = mime_types.get(mime, 0) + 1
            status = r.get("status", "000")
            status_codes[status] = status_codes.get(status, 0) + 1

        for mime, count in sorted(mime_types.items(), key=lambda x: -x[1])[:5]:
            findings.append(make_finding(
                entity=f"MIME type '{mime}': {count} URLs",
                ftype="Archive: MIME Type Distribution",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["archive", "mime", mime.replace("/", "-")]
            ))

        for status, count in sorted(status_codes.items(), key=lambda x: -x[1])[:5]:
            findings.append(make_finding(
                entity=f"Status {status}: {count} URLs",
                ftype="Archive: Status Code Distribution",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["archive", "status", status]
            ))

        sensitive_urls = []
        for r in cdx_results:
            url = r.get("url", "")
            ext = url.split("?")[0].lower()
            if any(ext.endswith(se) for se in SENSITIVE_EXTENSIONS):
                sensitive_urls.append(url)
            for sp in SENSITIVE_PATHS:
                if re.search(sp, url, re.IGNORECASE):
                    sensitive_urls.append(url)

        if sensitive_urls:
            for su in sensitive_urls[:10]:
                findings.append(make_finding(
                    entity=f"Sensitive URL archived: {su[:200]}",
                    ftype="Archive: Sensitive File Found",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Exposed",
                    resolution=t,
                    tags=["archive", "sensitive", "exposure"]
                ))

        years = {}
        for r in cdx_results:
            ts = r.get("timestamp", "")[:4]
            if ts:
                years[ts] = years.get(ts, 0) + 1
        if years:
            for year, count in sorted(years.items())[:10]:
                findings.append(make_finding(
                    entity=f"Year {year}: {count} snapshots",
                    ftype="Archive: Yearly Snapshot Distribution",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Analyzed",
                    resolution=t,
                    tags=["archive", "timeline", year]
                ))

    if not findings:
        findings.append(make_finding(
            entity="No archive data found for target",
            ftype="Archive: Check Complete",
            source="Wayback Machine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["archive", "empty"]
        ))

    return findings
