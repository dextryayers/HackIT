import httpx
import re
import json
from datetime import datetime, timezone
from collections import defaultdict
from models import IntelligenceFinding

MIME_FILTER_MAP = {
    "HTML": "text/html",
    "PDF": "application/pdf",
    "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "JSON": "application/json",
    "XML": "application/xml",
    "CSS": "text/css",
    "JS": "application/javascript",
    "Images": "image/",
    "Plain": "text/plain",
}

SENSITIVE_EXTENSIONS = [
    ".env", ".git", ".gitignore", ".gitconfig", ".gitattributes",
    ".bak", ".backup", ".old", ".orig", ".swp", ".swo",
    ".sql", ".dump", ".dmp",
    ".conf", ".config", ".cfg", ".ini", ".yml", ".yaml", ".toml",
    ".json", ".xml", ".yaml",
    ".pem", ".key", ".crt", ".cert", ".p12", ".pfx", ".jks",
    ".htpasswd", ".htaccess",
    ".log", ".txt",
    ".zip", ".tar", ".tgz", ".gz", ".rar", ".7z",
    ".rdp", ".vnc",
    ".ovpn", ".vpn",
    ".tf", ".tfvars", ".tfstate",
    ".dockercfg", ".dockerconfigjson",
    ".npmrc", ".yarnrc", ".gemrc",
    ".bashrc", ".bash_history", ".profile", ".zshrc",
    ".ssh", ".id_rsa", ".id_dsa", ".authorized_keys",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "wp-config.php", "configuration.php", "config.php", ".env.production", ".env.development",
]

async def wayback_available(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://archive.org/wayback/available?url={target}",
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            snapshots = data.get("archived_snapshots", {})
            closest = snapshots.get("closest")
            if closest:
                findings.append(IntelligenceFinding(
                    entity=closest.get("url", ""),
                    type="Wayback Machine Snapshot",
                    source="Wayback Machine",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Archived",
                    resolution=f"Timestamp: {closest.get('timestamp', 'unknown')}, Status: {closest.get('status', '200')}",
                    raw_data=str(closest),
                    tags=["wayback", "snapshot"],
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"No snapshot found for {target}",
                    type="Wayback Availability",
                    source="Wayback Machine",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="No Archive",
                    tags=["wayback", "no-archive"],
                ))
    except Exception:
        pass
    return findings


async def wayback_cdx(target: str, client: httpx.AsyncClient, mime_filter: str = None, status_filter: str = None, from_ts: str = None, to_ts: str = None) -> list:
    findings = []
    params = [
        f"url={target}/*",
        "output=json",
        "limit=5000",
        "fl=timestamp,original,mimetype,statuscode,digest,length",
    ]
    if mime_filter:
        params.append(f"filter=mimetype:{mime_filter}")
    if status_filter:
        params.append(f"filter=statuscode:{status_filter}")
    if from_ts:
        params.append(f"from={from_ts}")
    if to_ts:
        params.append(f"to={to_ts}")

    cdx_url = f"http://web.archive.org/cdx/search/cdx?{'&'.join(params)}"
    try:
        resp = await client.get(cdx_url, timeout=45.0)
        if resp.status_code != 200:
            return findings
        try:
            history_data = resp.json()
        except Exception:
            return findings

        if len(history_data) <= 1:
            findings.append(IntelligenceFinding(
                entity=f"No archived URLs found for {target}",
                type="Wayback CDX",
                source="Wayback Machine",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Empty",
                tags=["wayback"],
            ))
            return findings

        total_urls = len(history_data) - 1
        mime_counts = defaultdict(int)
        status_counts = defaultdict(int)
        years = defaultdict(int)
        unique_originals = set()
        unique_digests = set()

        for row in history_data[1:]:
            if len(row) >= 2:
                unique_originals.add(row[1])
            if len(row) >= 5:
                unique_digests.add(row[4])
            if len(row) >= 1:
                ts = row[0][:4] if len(row[0]) >= 4 else "unknown"
                years[ts] += 1
            if len(row) >= 4:
                mime_counts[row[3]] += 1
            if len(row) >= 5:
                status_counts[row[4]] += 1

        url_count = len(unique_originals)
        unique_snapshots = len(unique_digests)

        findings.append(IntelligenceFinding(
            entity=f"Total: {total_urls} captures, {url_count} unique URLs, {unique_snapshots} unique content snapshots",
            type="Wayback Archive Summary",
            source="Wayback Machine",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Analyzed",
            resolution=f"{total_urls} captures across {len(years)} years",
            raw_data=f"Total captures: {total_urls}, URLs: {url_count}, Unique snapshots: {unique_snapshots}",
            tags=["wayback", "summary"],
        ))

        if years:
            oldest = min(years.keys())
            newest = max(years.keys())
            findings.append(IntelligenceFinding(
                entity=f"Archive range: {oldest} to {newest} ({len(years)} years)",
                type="Wayback History Range",
                source="Wayback Machine",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Ranged",
                resolution=f"Oldest: {oldest}, Newest: {newest}",
                raw_data=f"Year distribution: {', '.join(f'{y}: {c}' for y, c in sorted(years.items()))}",
                tags=["wayback", "timeline"],
            ))

        top_mimes = sorted(mime_counts.items(), key=lambda x: -x[1])[:5]
        if top_mimes:
            findings.append(IntelligenceFinding(
                entity=f"Top content types: {', '.join(f'{mt} ({c})' for mt, c in top_mimes)}",
                type="Wayback Content Analysis",
                source="Wayback Machine",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                tags=["wayback", "content"],
            ))

        top_statuses = sorted(status_counts.items(), key=lambda x: -x[1])[:5]
        if top_statuses:
            findings.append(IntelligenceFinding(
                entity=f"Status codes: {', '.join(f'{sc} ({c})' for sc, c in top_statuses)}",
                type="Wayback Status Analysis",
                source="Wayback Machine",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                tags=["wayback", "status"],
            ))

        sensitive_findings = []
        seen_sensitive = set()
        for row in history_data[1:]:
            if len(row) < 2:
                continue
            original = row[1].lower()
            for ext in SENSITIVE_EXTENSIONS:
                if original.endswith(ext) and original not in seen_sensitive:
                    seen_sensitive.add(original)
                    sensitive_findings.append((row[1], ext))
                    break

        if sensitive_findings:
            for surl, ext in sensitive_findings[:8]:
                findings.append(IntelligenceFinding(
                    entity=surl[:200],
                    type="Wayback Sensitive File",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Sensitive File",
                    resolution=f"Extension: {ext}",
                    raw_data=surl[:500],
                    tags=["wayback", "sensitive", ext.lstrip(".") if ext else "unknown"],
                ))
            if len(sensitive_findings) > 8:
                findings.append(IntelligenceFinding(
                    entity=f"... and {len(sensitive_findings) - 8} more sensitive files",
                    type="Wayback Sensitive Files Summary",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Summary",
                    raw_data=f"Total sensitive: {len(sensitive_findings)}",
                    tags=["wayback", "sensitive"],
                ))

        js_urls = set()
        for row in history_data[1:]:
            if len(row) >= 4 and ("javascript" in row[3] or "text/javascript" in row[3] or row[3].endswith("/javascript") or row[1].endswith(".js")):
                js_urls.add(row[1])
        if js_urls:
            findings.append(IntelligenceFinding(
                entity=f"JavaScript files: {len(js_urls)} unique JS archives",
                type="Wayback JS Analysis",
                source="Wayback Machine",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
                status="Analyzed",
                raw_data=f"JS URLs: {', '.join(list(js_urls)[:5])}",
                tags=["wayback", "javascript", "static"],
            ))

    except Exception:
        pass
    return findings


async def retrieve_snapshot_content(target: str, client: httpx.AsyncClient, timestamp: str = None) -> list:
    findings = []
    try:
        ts_path = f"{timestamp}/" if timestamp else ""
        url = f"https://web.archive.org/web/{ts_path}{target}"
        resp = await client.get(url, timeout=20.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        })
        if resp.status_code == 200:
            html = resp.text
            findings.append(IntelligenceFinding(
                entity=f"Retrieved snapshot of {target}" + (f" at {timestamp}" if timestamp else ""),
                type="Wayback Snapshot Content",
                source="Wayback Machine",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Retrieved",
                resolution=f"Content length: {len(html)} bytes",
                raw_data=html[:3000],
                tags=["wayback", "content"],
            ))

            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
            if emails:
                findings.append(IntelligenceFinding(
                    entity=f"Emails found: {', '.join(list(emails)[:8])}{'...' if len(emails) > 8 else ''}",
                    type="Wayback Email Extraction",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="orange",
                    threat_level="Informational",
                    status="Extracted",
                    resolution=f"{len(emails)} email addresses",
                    raw_data=", ".join(emails),
                    tags=["wayback", "emails", "pii"],
                ))

            links = set(re.findall(r'href=["\'](https?://[^"\'<>\s]+)["\']', html))
            internal = [l for l in links if target in l]
            external = [l for l in links if target not in l]
            if internal:
                findings.append(IntelligenceFinding(
                    entity=f"Internal links: {len(internal)}",
                    type="Wayback Link Extraction",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Extracted",
                    raw_data="\n".join(list(internal)[:10]),
                    tags=["wayback", "links"],
                ))
            if external:
                findings.append(IntelligenceFinding(
                    entity=f"External links: {len(external)} (first: {list(external)[:3]})",
                    type="Wayback External Links",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Extracted",
                    tags=["wayback", "external-links"],
                ))

            scripts = set(re.findall(r'<script[^>]*src=["\'](https?://[^"\'<>\s]+)["\']', html))
            if scripts:
                findings.append(IntelligenceFinding(
                    entity=f"Scripts: {len(scripts)} external scripts",
                    type="Wayback Script Analysis",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Extracted",
                    raw_data="\n".join(list(scripts)[:8]),
                    tags=["wayback", "scripts"],
                ))

    except Exception:
        pass
    return findings


async def diff_snapshots(target: str, client: httpx.AsyncClient, ts1: str, ts2: str) -> list:
    findings = []
    try:
        url1 = f"https://web.archive.org/web/{ts1}/{target}"
        url2 = f"https://web.archive.org/web/{ts2}/{target}"
        r1 = await client.get(url1, timeout=15.0, follow_redirects=True)
        r2 = await client.get(url2, timeout=15.0, follow_redirects=True)
        if r1.status_code == 200 and r2.status_code == 200:
            text1 = r1.text
            text2 = r2.text
            len1 = len(text1)
            len2 = len(text2)
            diff_ratio = abs(len1 - len2) / max(len1, len2) * 100 if max(len1, len2) > 0 else 0

            findings.append(IntelligenceFinding(
                entity=f"Diff: {ts1} vs {ts2} — size: {len1} → {len2} bytes ({diff_ratio:.1f}% change)",
                type="Wayback Snapshot Diff",
                source="Wayback Machine",
                confidence="High",
                color="orange" if diff_ratio > 10 else "slate",
                threat_level="Informational",
                status="Compared",
                resolution=f"Size change: {len2 - len1:+d} bytes ({diff_ratio:.1f}%)",
                raw_data=f"Timestamp 1: {ts1} ({len1} bytes)\nTimestamp 2: {ts2} ({len2} bytes)",
                tags=["wayback", "diff"],
            ))

            added_scripts = set(re.findall(r'<script[^>]*src=["\'](https?://[^"\'<>\s]+)["\']', text2)) - \
                           set(re.findall(r'<script[^>]*src=["\'](https?://[^"\'<>\s]+)["\']', text1))
            if added_scripts:
                findings.append(IntelligenceFinding(
                    entity=f"New scripts in {ts2}: {', '.join(list(added_scripts)[:5])}",
                    type="Wayback Diff Scripts",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="orange",
                    threat_level="Informational",
                    status="Changed",
                    tags=["wayback", "diff", "scripts"],
                ))

            removed_scripts = set(re.findall(r'<script[^>]*src=["\'](https?://[^"\'<>\s]+)["\']', text1)) - \
                             set(re.findall(r'<script[^>]*src=["\'](https?://[^"\'<>\s]+)["\']', text2))
            if removed_scripts:
                findings.append(IntelligenceFinding(
                    entity=f"Removed scripts in {ts2}: {', '.join(list(removed_scripts)[:5])}",
                    type="Wayback Diff Scripts Removed",
                    source="Wayback Machine",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    status="Changed",
                    tags=["wayback", "diff", "scripts"],
                ))

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        avail = await wayback_available(domain, client)
        findings.extend(avail)

        cdx = await wayback_cdx(domain, client)
        findings.extend(cdx)

        recent_ts = None
        for f in findings:
            if f.type == "Wayback Machine Snapshot":
                raw = f.raw_data or ""
                ts_match = re.search(r"timestamp['\"]?\s*:\s*['\"]?(\d{4,14})", raw)
                if ts_match:
                    recent_ts = ts_match.group(1)
                    break

        if recent_ts:
            content = await retrieve_snapshot_content(domain, client, timestamp=recent_ts)
            findings.extend(content)

            oldest_ts = None
            for f in findings:
                if f.type == "Wayback History Range":
                    raw = f.raw_data or ""
                    years_found = re.findall(r'(\d{4}):\s*\d+', raw)
                    if years_found:
                        oldest_ts = min(years_found)[2:]
                        break
            if oldest_ts and len(oldest_ts) >= 4:
                first = f"{oldest_ts}0101000000"
                diff_result = await diff_snapshots(domain, client, first, recent_ts)
                findings.extend(diff_result)

        if not findings:
            findings.append(IntelligenceFinding(
                entity=f"No Wayback Machine data for {domain}",
                type="Wayback No Data",
                source="Wayback Machine",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="No Data",
                tags=["wayback"],
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"Wayback Machine analysis complete: {len(findings)} findings",
                type="Wayback Summary",
                source="Wayback Machine",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Complete",
                tags=["wayback", "summary"],
            ))

    except Exception:
        pass
    return findings
