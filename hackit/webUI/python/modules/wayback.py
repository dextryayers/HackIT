import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Optional
from collections import defaultdict
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

async def get_archived_content(url: str, ts: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await client.get(
            f"{WAYBACK_API}/web/{ts}/{url}",
            timeout=20.0,
            headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            return resp.text[:10000]
    except:
        pass
    return ""

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
        url_count = len(cdx_results)
        findings.append(IntelligenceFinding(
            entity=f"Total archived pages: {url_count}",
            type="Wayback: Page Count",
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
            findings.append(IntelligenceFinding(
                entity=f"Page size: avg {avg_size} bytes, max {max_size} bytes",
                type="Wayback: Page Size Analysis",
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
            findings.append(IntelligenceFinding(
                entity=f"Archived: {url[:200]} ({ts[:10]})",
                type="Wayback: Archived URL",
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
                    findings.append(IntelligenceFinding(
                        entity=f"Page title ({ts[:10]}): {ttl}",
                        type="Wayback: Archived Page Title",
                        source="Wayback Machine",
                        confidence="Medium",
                        color="slate",
                        status="Retrieved",
                        resolution=t,
                        tags=["wayback", "content", "title"]
                    ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No Wayback Machine data found",
            type="Wayback: Check Complete",
            source="Wayback Machine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["wayback", "empty"]
        ))

    return findings
