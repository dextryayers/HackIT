import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Optional
from models import IntelligenceFinding

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
    try:
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype,length",
            "limit": str(limit),
            "filter": "statuscode:200",
            "collapse": "urlkey",
        }
        resp = await client.get(CDX_API, params=params, timeout=30.0,
            headers={"User-Agent": UA})
        if resp.status_code == 200:
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
    except:
        pass
    return results

async def query_available(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{WAYBACK_API}/available?url={domain}",
            timeout=15.0,
            headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    available = await query_available(t, client)
    archived_snapshots = available.get("archived_snapshots", {})
    closest = archived_snapshots.get("closest", {})
    if closest:
        findings.append(IntelligenceFinding(
            entity=f"Archived snapshot available: {closest.get('url', '')[:200]}",
            type="Archive: Snapshot Available",
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
        findings.append(IntelligenceFinding(
            entity=f"{len(cdx_results)} historical URLs archived",
            type="Archive: Historical URL Count",
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
            findings.append(IntelligenceFinding(
                entity=f"MIME type '{mime}': {count} URLs",
                type="Archive: MIME Type Distribution",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["archive", "mime", mime.replace("/", "-")]
            ))

        for status, count in sorted(status_codes.items(), key=lambda x: -x[1])[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Status {status}: {count} URLs",
                type="Archive: Status Code Distribution",
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
                findings.append(IntelligenceFinding(
                    entity=f"Sensitive URL archived: {su[:200]}",
                    type="Archive: Sensitive File Found",
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
                findings.append(IntelligenceFinding(
                    entity=f"Year {year}: {count} snapshots",
                    type="Archive: Yearly Snapshot Distribution",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Analyzed",
                    resolution=t,
                    tags=["archive", "timeline", year]
                ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No archive data found for target",
            type="Archive: Check Complete",
            source="Wayback Machine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["archive", "empty"]
        ))

    return findings
