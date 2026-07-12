import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_API = "https://archive.org/wayback/available"

async def query_cdx(target: str, filters: dict = None) -> list:
    results = []
    try:
        params = {
            "url": f"{target}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype,length,digest",
            "limit": "500",
            "fastLatest": "true",
            "collapse": "urlkey",
        }
        if filters:
            params.update(filters)
        async with httpx.AsyncClient(timeout=30.0) as c:
            resp = await safe_fetch(c, CDX_API, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:
                    if len(row) >= 6:
                        results.append({
                            "url": row[0],
                            "timestamp": row[1],
                            "status": row[2],
                            "mimetype": row[3],
                            "length": row[4],
                            "digest": row[5],
                        })
    except Exception:
        pass
    return results

async def check_current_status(target: str, path: str, client: httpx.AsyncClient) -> int:
    try:
        full_url = f"https://{target}{path}" if target in path else f"https://{target}{path}"
        if path.startswith("http"):
            full_url = path
        else:
            full_url = f"https://{target}{path}"
        resp = await safe_fetch(client,full_url, timeout=10.0, follow_redirects=False)
        return resp.status_code
    except Exception:
        return 0

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    snapshots = await query_cdx(domain)
    if not snapshots:
        findings.append(make_finding(
            entity=f"No archive snapshots found for {domain}",
            ftype="Archive: No Data",
            source="ArchiveDeep",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["archive", "wayback", "cdx"]
        ))
        return findings

    findings.append(make_finding(
        entity=f"Found {len(snapshots)} archived snapshots for {domain}",
        ftype="Archive: Snapshot Count",
        source="ArchiveDeep",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"Total CDX entries: {len(snapshots)}",
        tags=["archive", "wayback", "cdx"]
    ))

    status_codes = {}
    mimetypes = {}
    for s in snapshots:
        status_codes[s["status"]] = status_codes.get(s["status"], 0) + 1
        mimetypes[s["mimetype"]] = mimetypes.get(s["mimetype"], 0) + 1

    for status, count in sorted(status_codes.items(), key=lambda x: -x[1])[:5]:
        findings.append(make_finding(
            entity=f"HTTP {status}: {count} snapshots",
            ftype="Archive: Status Code Distribution",
            source="ArchiveDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"status={status}, count={count}",
            tags=["archive", "status-codes"]
        ))

    for mt, count in sorted(mimetypes.items(), key=lambda x: -x[1])[:5]:
        findings.append(make_finding(
            entity=f"MIME {mt}: {count} snapshots",
            ftype="Archive: MIME Type Distribution",
            source="ArchiveDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"mimeftype={mt}, count={count}",
            tags=["archive", "mimetypes"]
        ))

    unique_paths = set()
    for s in snapshots:
        try:
            p = urlparse(s["url"]).path
            if p and p != "/":
                unique_paths.add(p)
        except Exception:
            pass

    if unique_paths:
        findings.append(make_finding(
            entity=f"Found {len(unique_paths)} unique paths in archive history",
            ftype="Archive: Unique Paths",
            source="ArchiveDeep",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data="\n".join(sorted(list(unique_paths))[:20]),
            tags=["archive", "paths", "discovery"]
        ))

    sensitive_paths = [p for p in unique_paths if any(x in p.lower() for x in ["admin", "api", "backup", "config", "db", "sql", "wp-", ".env", "secret", "private", "internal", ".git", "debug", "test", "dev"])]
    if sensitive_paths:
        findings.append(make_finding(
            entity=f"Found {len(sensitive_paths)} potentially sensitive paths in archive",
            ftype="Archive: Sensitive Paths",
            source="ArchiveDeep",
            confidence="Medium",
            color="red",
            threat_level="High Risk",
            raw_data="\n".join(sensitive_paths[:15]),
            tags=["archive", "sensitive", "exposure"]
        ))

    gone_pages = []
    for s in snapshots[:100]:
        if s["status"] in ("200", "201", "202") and s["mimetype"] == "text/html":
            current = await check_current_status(domain, s["url"], client)
            if current in (404, 410, 0):
                gone_pages.append({"url": s["url"], "last_seen": s["timestamp"], "current_status": current})

    if gone_pages:
        findings.append(make_finding(
            entity=f"Found {len(gone_pages)} removed pages (existed in archive, now {gone_pages[0]['current_status']})",
            ftype="Archive: Removed Pages",
            source="ArchiveDeep",
            confidence="Medium",
            color="red",
            threat_level="Elevated Risk",
            raw_data="\n".join([f"{g['url']} (last seen {g['last_seen']})" for g in gone_pages[:10]]),
            tags=["archive", "removed", "content-drift"]
        ))

    years = {}
    for s in snapshots:
        year = s["timestamp"][:4]
        years[year] = years.get(year, 0) + 1

    if len(years) > 1:
        sorted_years = sorted(years.items())
        findings.append(make_finding(
            entity=f"Archive history spans {len(years)} years ({sorted_years[0][0]}-{sorted_years[-1][0]})",
            ftype="Archive: Historical Span",
            source="ArchiveDeep",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"Years: {dict(sorted_years)}",
            tags=["archive", "timeline"]
        ))

    tech_changes = []
    for s in snapshots:
        if "wp-content" in s["url"] or "wp-includes" in s["url"]:
            tech_changes.append(("WordPress", s["timestamp"]))
        elif ".php" in s["url"]:
            tech_changes.append(("PHP", s["timestamp"]))
        elif ".asp" in s["url"] or ".aspx" in s["url"]:
            tech_changes.append(("ASP.NET", s["timestamp"]))
        elif "wp-json" in s["url"]:
            tech_changes.append(("WordPress REST API", s["timestamp"]))

    if tech_changes:
        seen_techs = set()
        for tech, ts in tech_changes:
            if tech not in seen_techs:
                seen_techs.add(tech)
                findings.append(make_finding(
                    entity=f"Technology detected in archive: {tech} (first seen {ts})",
                    ftype="Archive: Tech History",
                    source="ArchiveDeep",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"tech={tech}, first_seen={ts}",
                    tags=["archive", "technology"]
                ))

    first_snap = snapshots[0]
    last_snap = snapshots[-1]
    findings.append(make_finding(
        entity=f"First snapshot: {first_snap['timestamp']} | Latest: {last_snap['timestamp']}",
        ftype="Archive: Snapshot Timeline",
        source="ArchiveDeep",
        confidence="High",
        color="slate",
        threat_level="Informational",
        raw_data=f"first={first_snap['timestamp']}, latest={last_snap['timestamp']}",
        tags=["archive", "timeline"]
    ))

    findings.append(make_finding(
        entity=f"Archive Deep Analysis complete: {len(snapshots)} snapshots, {len(unique_paths)} paths, {len(gone_pages)} removed",
        ftype="Archive: Summary",
        source="ArchiveDeep",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"snapshots={len(snapshots)}, unique_paths={len(unique_paths)}, removed={len(gone_pages)}, years={len(years)}",
        tags=["archive", "summary"]
    ))

    return findings
