import re
import json
import httpx
from urllib.parse import urlparse
from typing import List
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

WAYBACK_API = "https://web.archive.org"
CDX_API = f"{WAYBACK_API}/cdx/search/cdx"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

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
        resp = await safe_fetch(client,CDX_API, params=params, timeout=30.0,
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

async def get_archived_content(url: str, ts: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await safe_fetch(client,
            f"{WAYBACK_API}/web/{ts}/{url}",
            timeout=20.0,
            headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            return resp.text[:10000]
    except:
        pass
    return ""

WAYBACK_CALENDAR_URL = "https://web.archive.org/web/"

async def query_cdx_timeline(domain: str, client: httpx.AsyncClient) -> dict:
    yearly_counts = {}
    try:
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "timestamp",
            "limit": "50000",
            "collapse": "timestamp:4",
        }
        resp = await safe_fetch(client,CDX_API, params=params, timeout=30.0,
            headers={"User-Agent": UA})
        if resp.status_code == 200:
            lines = resp.text.strip().splitlines()
            for line in lines[1:]:
                try:
                    ts = json.loads(line)[1][:4] if line.startswith("[") else line.split(" ")[1][:4]
                    yearly_counts[ts] = yearly_counts.get(ts, 0) + 1
                except:
                    continue
    except:
        pass
    return yearly_counts

async def analyze_snapshot_gaps(yearly_counts: dict) -> list:
    findings = []
    if not yearly_counts:
        return findings
    years = sorted(yearly_counts.keys())
    if len(years) > 1:
        gaps = []
        for i in range(len(years) - 1):
            yr1, yr2 = int(years[i]), int(years[i+1])
            if yr2 - yr1 > 1:
                gaps.append(f"{yr1+1}-{yr2-1}")
        if gaps:
            findings.append(make_finding(
                entity=f"Snapshot gaps: {', '.join(gaps[:5])}",
                ftype="Wayback: Archival Gaps",
                source="Wayback Machine",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status=f"{len(gaps)} gaps",
                tags=["wayback", "gaps", "timeline"]
            ))
    total = sum(yearly_counts.values())
    avg_per_year = total / max(len(yearly_counts), 1)
    findings.append(make_finding(
        entity=f"Snapshot frequency: avg {avg_per_year:.0f} per year over {len(yearly_counts)} years",
        ftype="Wayback: Archival Frequency",
        source="Wayback Machine",
        confidence="Medium",
        color="slate",
        status="Analyzed",
        tags=["wayback", "frequency"]
    ))
    return findings

async def query_specific_snapshots(domain: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client,
            f"{WAYBACK_API}/web/2010/{domain}",
            timeout=10.0, headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            first_year = "2010"
            results.append(first_year)
    except:
        pass
    try:
        resp = await safe_fetch(client,
            f"{WAYBACK_API}/web/2020/{domain}",
            timeout=10.0, headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            results.append("2020")
    except:
        pass
    try:
        resp = await safe_fetch(client,
            f"{WAYBACK_API}/web/2024/{domain}",
            timeout=10.0, headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            results.append("2024")
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    yearly_timeline = await query_cdx_timeline(t, client)
    gap_results = await analyze_snapshot_gaps(yearly_timeline)
    findings.extend(gap_results)

    snap_years = await query_specific_snapshots(t, client)
    for yr in snap_years:
        findings.append(make_finding(
            entity=f"Snapshot exists for year {yr}",
            ftype="Wayback: Yearly Snapshot Check",
            source="Wayback Machine",
            confidence="High",
            color="slate",
            status="Available",
            resolution=t,
            tags=["wayback", "year", yr]
        ))

    if cdx_results:
        url_count = len(cdx_results)
        findings.append(make_finding(
            entity=f"Total archived pages: {url_count}",
            ftype="Wayback: Page Count",
            source="Wayback Machine",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"{url_count} pages",
            resolution=t,
            tags=["wayback", "pages", "count"]
        ))

        page_sizes = [int(r.get("length", 0)) for r in cdx_results if r.get("length", "0").isdigit()]
        if page_sizes:
            avg_size = sum(page_sizes) // len(page_sizes)
            max_size = max(page_sizes)
            findings.append(make_finding(
                entity=f"Page size: avg {avg_size} bytes, max {max_size} bytes",
                ftype="Wayback: Page Size Analysis",
                source="Wayback Machine",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["wayback", "size"]
            ))

        for r in cdx_results[:15]:
            url = r.get("url", "")
            ts = r.get("timestamp", "")
            mime = r.get("mime", "")
            findings.append(make_finding(
                entity=f"Archived: {url[:200]} ({ts[:10]})",
                ftype="Wayback: Archived URL",
                source="Wayback Machine",
                confidence="High",
                color="slate",
                status="Archived",
                resolution=t,
                raw_data=f"MIME: {mime}, Date: {ts[:10]}",
                tags=["wayback", "archived", mime.split("/")[0] if mime else "unknown"]
            ))

        for r in cdx_results[:5]:
            url = r.get("url", "")
            ts = r.get("timestamp", "")
            content = await get_archived_content(url, ts, client)
            if content:
                title = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                if title:
                    ttl = title.group(1).strip()[:200]
                    findings.append(make_finding(
                        entity=f"Page title ({ts[:10]}): {ttl}",
                        ftype="Wayback: Archived Page Title",
                        source="Wayback Machine",
                        confidence="Medium",
                        color="slate",
                        status="Retrieved",
                        resolution=t,
                        tags=["wayback", "content", "title"]
                    ))

    if not findings:
        findings.append(make_finding(
            entity="No Wayback Machine data found",
            ftype="Wayback: Check Complete",
            source="Wayback Machine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["wayback", "empty"]
        ))

    return findings
