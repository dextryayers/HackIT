import httpx
import asyncio
import re
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs
from models import IntelligenceFinding

SENSITIVE_EXTS = {'.env', '.git', '.bak', '.sql', '.dump', '.conf', '.pem', '.key',
    '.log', '.csv', '.xls', '.xlsx', '.doc', '.docx', '.pdf', '.zip', '.tar.gz',
    '.7z', '.rar', '.gz', '.tgz', '.json', '.yml', '.yaml', '.xml', '.htaccess',
    '.htpasswd', '.rdp', '.ovpn', '.cer', '.crt', '.pfx', '.p12', '.jks',
    '.snap', '.swp', '.swo', '.svn', '.gitignore', '.dockerignore', '.idea'}

DOC_EXTS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.rtf', '.txt', '.csv', '.tsv'}

MEDIA_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    '.mp4', '.mp3', '.avi', '.mov', '.webm', '.ogg', '.wav'}

ARCHIVE_EXTS = {'.zip', '.tar', '.tar.gz', '.gz', '.bz2', '.xz', '.7z', '.rar'}

INTERESTING_DIRS = re.compile(
    r"(admin|backup|config|secret|credential|token|password|private|"
    r"internal|intranet|dev|staging|test|api|swagger|graphql|wp-admin|phpmyadmin|"
    r"manager|panel|dashboard|jenkins|jira|confluence|gitlab|prometheus|grafana|kibana)", re.IGNORECASE
)

async def fetch_cdx_data(client, target, limit=5000, filters=None):
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest,length",
        "limit": str(limit),
        "collapse": "urlkey"
    }
    if filters:
        params.update(filters)
    try:
        resp = await client.get(
            "http://web.archive.org/cdx/search/cdx",
            params=params, timeout=45.0
        )
        if resp.status_code == 200:
            return domain, resp.json()
    except:
        pass
    return domain, []

async def fetch_wayback_raw(client, target, specific_timestamp=None):
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    ts = specific_timestamp or "20060102150405"
    try:
        resp = await client.get(
            f"http://web.archive.org/web/{ts}id_/{domain}",
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            return resp.text, resp.headers
    except:
        pass
    return None, None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain, data = await fetch_cdx_data(client, target, limit=5000)

    if not data or len(data) <= 1:
        return findings

    findings.append(IntelligenceFinding(
        entity=f"Archive analysis for {domain}",
        type="Archive Analysis Summary",
        source="Archive.org Deep Analysis",
        confidence="High",
        color="slate",
        category="Web Archive Intelligence",
        threat_level="Informational",
        status="Analyzed",
        tags=["archive"]
    ))

    rows = data[1:]
    total = len(rows)

    url_index = {}
    mime_stats = defaultdict(int)
    status_stats = defaultdict(int)
    year_stats = defaultdict(int)
    filetype_ext_stats = defaultdict(int)
    param_urls = []
    path_structure = defaultdict(set)
    sitemap_urls = set()
    sensitive_files = []
    redirect_chain_map = defaultdict(list)
    digest_groups = defaultdict(list)

    for row in rows:
        if len(row) < 6:
            continue
        ts, original, mimetype, statuscode, digest, length = row[:6]
        year = ts[:4] if len(ts) >= 4 else "?"
        year_stats[year] += 1
        mime_stats[mimetype] += 1
        status_stats[statuscode] += 1
        url_index[original] = row
        lower = original.lower()
        parsed = urlparse(original)
        path = parsed.path.rstrip("/") or "/"
        dir_path = "/".join(path.split("/")[:-1]) if path != "/" else "/"
        path_structure[dir_path].add(path)

        if "?" in original and "=" in original:
            param_urls.append(original)

        for ext in SENSITIVE_EXTS:
            if lower.endswith(ext):
                sensitive_files.append((original, ext, mimetype, ts))
                break

        for ext in DOC_EXTS:
            if lower.endswith(ext):
                filetype_ext_stats["documents"] += 1
                break
        for ext in MEDIA_EXTS:
            if lower.endswith(ext):
                filetype_ext_stats["media"] += 1
                break
        for ext in ARCHIVE_EXTS:
            if lower.endswith(ext):
                filetype_ext_stats["archives"] += 1
                break

        digest_groups[digest].append(row)

        if statuscode in ("301", "302", "303", "307", "308"):
            redirect_chain_map[original].append((ts, statuscode))

    findings.append(IntelligenceFinding(
        entity=f"{total} total archived URLs",
        type="Archive Total URLs",
        source="Archive.org Deep Analysis",
        confidence="High",
        color="blue",
        category="Web Archive Intelligence",
        threat_level="Informational",
        status="Count",
        tags=["statistics"]
    ))

    years_sorted = sorted(year_stats.keys())
    if years_sorted:
        yr_min, yr_max = years_sorted[0], years_sorted[-1]
        peak_year = max(year_stats, key=year_stats.get)
        findings.append(IntelligenceFinding(
            entity=f"Timeline: {yr_min}-{yr_max} | Peak: {peak_year} ({year_stats[peak_year]} pages)",
            type="Archive Timeline Analysis",
            source="Archive.org Deep Analysis",
            confidence="High",
            color="purple",
            category="Web Archive Intelligence",
            threat_level="Informational",
            status="Timeline",
            tags=["timeline"]
        ))

    top_mimes = sorted(mime_stats.items(), key=lambda x: -x[1])[:6]
    mime_str = ", ".join(f"{m}({c})" for m, c in top_mimes)
    findings.append(IntelligenceFinding(
        entity=f"Content Types: {mime_str}",
        type="Content Type Distribution",
        source="Archive.org Deep Analysis",
        confidence="High",
        color="slate",
        category="Web Archive Intelligence",
        threat_level="Informational",
        status="Distribution",
        tags=["mime", "content"]
    ))

    if filetype_ext_stats:
        ft_str = ", ".join(f"{k}:{v}" for k, v in sorted(filetype_ext_stats.items(), key=lambda x: -x[1]))
        findings.append(IntelligenceFinding(
            entity=f"File Types: {ft_str}",
            type="Archive File Type Breakdown",
            source="Archive.org Deep Analysis",
            confidence="High",
            color="orange",
            category="Web Archive Intelligence",
            threat_level="Informational",
            status="Breakdown",
            tags=["filetypes"]
        ))

    top_statuses = sorted(status_stats.items(), key=lambda x: -x[1])[:7]
    status_str = ", ".join(f"{s}({c})" for s, c in top_statuses)
    findings.append(IntelligenceFinding(
        entity=f"Status Codes: {status_str}",
        type="HTTP Status Code Trends",
        source="Archive.org Deep Analysis",
        confidence="High",
        color="slate",
        category="Web Archive Intelligence",
        threat_level="Informational",
        status="Trends",
        tags=["status", "http"]
    ))

    bad_statuses = {s: c for s, c in status_stats.items() if s.startswith("4") or s.startswith("5")}
    if bad_statuses:
        total_bad = sum(bad_statuses.values())
        findings.append(IntelligenceFinding(
            entity=f"{total_bad} error responses (4xx/5xx) in archive history",
            type="Archive Error Responses",
            source="Archive.org Deep Analysis",
            confidence="High",
            color="red",
            category="Web Archive Intelligence",
            threat_level="Elevated Risk",
            status="Errors",
            raw_data=f"Error breakdown: {bad_statuses}",
            tags=["errors"]
        ))

    if redirect_chain_map:
        findings.append(IntelligenceFinding(
            entity=f"{len(redirect_chain_map)} URLs with redirect behavior in archive",
            type="Redirect Chain Analysis",
            source="Archive.org Deep Analysis",
            confidence="Medium",
            color="blue",
            category="Web Archive Intelligence",
            threat_level="Informational",
            status="Redirects",
            raw_data=f"Found {len(redirect_chain_map)} URLs that were redirected in archived snapshots",
            tags=["redirect"]
        ))

    for surl, sext, smime, sts in sensitive_files[:12]:
        findings.append(IntelligenceFinding(
            entity=surl[:200],
            type="Sensitive Archived File",
            source="Archive.org Deep Analysis",
            confidence="High",
            color="red",
            category="Web Archive Intelligence",
            threat_level="Elevated Risk",
            status="Exposed",
            resolution=f"Type: {sext}",
            raw_data=f"File archived {sts}: {surl}",
            tags=["sensitive", "exposed"]
        ))
    if sensitive_files:
        findings.append(IntelligenceFinding(
            entity=f"{len(sensitive_files)} sensitive files exposed in archive history",
            type="Sensitive Exposure Summary",
            source="Archive.org Deep Analysis",
            confidence="High",
            color="red",
            category="Web Archive Intelligence",
            threat_level="High Risk",
            status="Exposure Warning",
            tags=["sensitive", "warning"]
        ))

    if param_urls:
        param_hosts = defaultdict(int)
        for pu in param_urls:
            base_path = urlparse(pu).path
            param_hosts[base_path or "/"] += 1
        top_param_paths = sorted(param_hosts.items(), key=lambda x: -x[1])[:5]
        for path, count in top_param_paths:
            findings.append(IntelligenceFinding(
                entity=f"{path} ({count} param variations)",
                type="URL Parameter Analysis",
                source="Archive.org Deep Analysis",
                confidence="Medium",
                color="slate",
                category="Web Archive Intelligence",
                threat_level="Informational",
                status="Parameters",
                tags=["parameters"]
            ))

    dir_paths = sorted(path_structure.keys(), key=lambda d: -len(path_structure[d]))[:15]
    for dp in dir_paths[:6]:
        if INTERESTING_DIRS.search(dp):
            findings.append(IntelligenceFinding(
                entity=f"{dp} ({len(path_structure[dp])} pages)",
                type="Interesting Directory Structure",
                source="Archive.org Deep Analysis",
                confidence="Medium",
                color="orange",
                category="Web Archive Intelligence",
                threat_level="Informational",
                status="Interesting",
                tags=["directory", "interesting"]
            ))

    changed_urls = [urls for urls in digest_groups.values() if len(urls) > 1]
    if changed_urls:
        high_change = [u for u in changed_urls if len(u) > 5]
        findings.append(IntelligenceFinding(
            entity=f"{len(changed_urls)} URLs with content changes "
                   f"({len(high_change)} with 5+ revisions)",
            type="Content Change Frequency",
            source="Archive.org Deep Analysis",
            confidence="Medium",
            color="purple",
            category="Web Archive Intelligence",
            threat_level="Informational",
            status="Changes",
            tags=["changes", "diff"]
        ))

    for ext_list, label in [(DOC_EXTS, "Documents"), (ARCHIVE_EXTS, "Archives/Backups")]:
        ext_files = [r for r in rows if len(r) > 1 and
                     any(r[1].lower().endswith(e) for e in ext_list)]
        if ext_files:
            findings.append(IntelligenceFinding(
                entity=f"{len(ext_files)} {label} found in archives",
                type=f"Archive {label}",
                source="Archive.org Deep Analysis",
                confidence="High",
                color="blue",
                category="Web Archive Intelligence",
                threat_level="Informational",
                status="Found",
                tags=["extraction"]
            ))

    try:
        raw_html, raw_headers = await fetch_wayback_raw(client, target)
        if raw_html:
            title_match = re.search(r"<title>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
            if title_match:
                findings.append(IntelligenceFinding(
                    entity=f"Historical Page Title: {title_match.group(1).strip()[:200]}",
                    type="Archived Page Title",
                    source="Archive.org Deep Analysis",
                    confidence="Medium",
                    color="slate",
                    category="Web Archive Intelligence",
                    threat_level="Informational",
                    status="Title",
                    tags=["content"]
                ))
    except:
        pass

    return findings
