import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

WAYBACK_API = "https://web.archive.org"
CDX_API = f"{WAYBACK_API}/cdx/search/cdx"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

async def query_cdx(domain: str, client: httpx.AsyncClient, limit: int = 500) -> list:
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

async def get_snapshot_content(url: str, ts: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await client.get(
            f"{WAYBACK_API}/web/{ts}/{url}",
            timeout=20.0,
            headers={"User-Agent": UA}
        )
        if resp.status_code == 200:
            return resp.text[:5000]
    except:
        pass
    return ""

async def get_page_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""

async def extract_links_from_content(html: str) -> list:
    links = []
    try:
        for m in re.finditer(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"', html, re.IGNORECASE):
            links.append(m.group(1))
        for m in re.finditer(r'<a\s+(?:[^>]*?\s+)?href=\'([^\']*)\'', html, re.IGNORECASE):
            links.append(m.group(1))
        for m in re.finditer(r'src="([^"]*)"', html, re.IGNORECASE):
            links.append(m.group(1))
        for m in re.finditer(r'src=\'([^\']*)\'', html, re.IGNORECASE):
            links.append(m.group(1))
    except:
        pass
    return links

async def analyze_archived_content(url: str, ts: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        content = await get_snapshot_content(url, ts, client)
        if not content:
            return findings
        links = await extract_links_from_content(content)
        if links:
            findings.append(IntelligenceFinding(
                entity=f"Content analysis: {len(links)} links extracted from archived page",
                type="Archive Forensics: Link Extraction",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=url[:200],
                tags=["forensics", "links", "content"]
            ))
            internal = [l for l in links if l.startswith("/") or urlparse(url).netloc in l]
            external = [l for l in links if l.startswith("http") and urlparse(url).netloc not in l]
            if internal:
                findings.append(IntelligenceFinding(
                    entity=f"{len(internal)} internal links found in archived page",
                    type="Archive Forensics: Internal Links",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Extracted",
                    resolution=url[:200],
                    tags=["forensics", "internal-links"]
                ))
            if external:
                findings.append(IntelligenceFinding(
                    entity=f"{len(external)} external links to {len(set(urlparse(l).netloc for l in external))} unique domains",
                    type="Archive Forensics: External Links",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Extracted",
                    resolution=url[:200],
                    tags=["forensics", "external-links"]
                ))
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()[:200]
            findings.append(IntelligenceFinding(
                entity=f"Archived page title: {title}",
                type="Archive Forensics: Page Title",
                source="Wayback CDX",
                confidence="High",
                color="slate",
                status="Retrieved",
                resolution=url[:200],
                tags=["forensics", "title", "content"]
            ))
        meta_desc = re.search(r'<meta\s+name="description"\s+content="([^"]*)"', content, re.IGNORECASE)
        if meta_desc:
            findings.append(IntelligenceFinding(
                entity=f"Meta description: {meta_desc.group(1)[:200]}",
                type="Archive Forensics: Meta Description",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Retrieved",
                resolution=url[:200],
                tags=["forensics", "meta", "description"]
            ))
        scripts = re.findall(r'<script[^>]*src="([^"]*)"', content, re.IGNORECASE)
        if scripts:
            findings.append(IntelligenceFinding(
                entity=f"{len(scripts)} JavaScript files referenced in archived page",
                type="Archive Forensics: JS References",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Counted",
                resolution=url[:200],
                tags=["forensics", "javascript", "scripts"]
            ))
    except:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
        findings.append(IntelligenceFinding(
            entity=f"{len(cdx_results)} archived pages for {t}",
            type="Archive Forensics: Historical Data",
            source="Wayback CDX",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"{len(cdx_results)} pages",
            resolution=t,
            tags=["forensics", "archive", "historical"]
        ))

        path_counts = defaultdict(int)
        for r in cdx_results:
            try:
                path = urlparse(r.get("url", "")).path
                if path:
                    top = "/" + path.split("/")[1] if "/" in path[1:] else "/"
                    path_counts[top[:50]] += 1
            except:
                path_counts["/unknown"] += 1

        for path, count in sorted(path_counts.items(), key=lambda x: -x[1])[:10]:
            findings.append(IntelligenceFinding(
                entity=f"Path '{path}': {count} archived URLs",
                type="Archive Forensics: Path Analysis",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["forensics", "path", path.lower().replace("/", "-").replace(" ", "")]
            ))

        subdomains = defaultdict(int)
        for r in cdx_results:
            host = urlparse(r.get("url", "")).netloc
            if host:
                parts = host.split(".")
                if len(parts) > 2:
                    sub = parts[0]
                    subdomains[sub] += 1

        if subdomains:
            for sub, count in sorted(subdomains.items(), key=lambda x: -x[1])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"Subdomain '{sub}.{t}': {count} archived pages",
                    type="Archive Forensics: Subdomain Discovery",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Discovered",
                    resolution=t,
                    tags=["forensics", "subdomain", sub]
                ))

        earliest = min(r.get("timestamp", "9999") for r in cdx_results if r.get("timestamp"))
        latest = max(r.get("timestamp", "0000") for r in cdx_results if r.get("timestamp"))
        for r in cdx_results[:5]:
            content_results = await analyze_archived_content(r.get("url", ""), r.get("timestamp", ""), client)
            findings.extend(content_results)

        if earliest and latest:
            findings.append(IntelligenceFinding(
                entity=f"Archive timeline: {earliest[:10]} to {latest[:10]}",
                type="Archive Forensics: Timeline",
                source="Wayback CDX",
                confidence="High",
                color="slate",
                status="Timeline Built",
                resolution=t,
                tags=["forensics", "timeline", "historical"]
            ))

            findings.append(IntelligenceFinding(
                entity=f"Archive span: {len(set(r.get('timestamp', '')[:4] for r in cdx_results if r.get('timestamp')))} years",
                type="Archive Forensics: Temporal Coverage",
                source="Wayback CDX",
                confidence="Medium",
                color="slate",
                status="Analyzed",
                resolution=t,
                tags=["forensics", "temporal", "coverage"]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No forensic archive data found",
            type="Archive Forensics: Complete",
            source="Wayback Machine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["forensics", "empty"]
        ))

    return findings
