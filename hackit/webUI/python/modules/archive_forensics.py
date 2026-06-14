import httpx
import asyncio
import re
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse, urljoin
from models import IntelligenceFinding
from osint_common import extract_emails, extract_urls, extract_ips

SENSITIVE_PATTERNS = re.compile(
    r"(?:sk_live|sk_test|pk_live|pk_test|AKIA[0-9A-Z]{16}|"
    r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|"
    r"xox[baprs]-[0-9a-zA-Z\-]{24,}|"
    r"-----BEGIN\s?(RSA\s)?PRIVATE KEY-----)", re.IGNORECASE
)

SENSITIVE_EXTS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar.gz',
    '.sql', '.bak', '.env', '.conf', '.pem', '.key', '.log', '.dump',
    '.csv', '.json', '.yml', '.yaml', '.xml', '.git', '.svn', '.htaccess',
    '.htpasswd', '.rdp', '.ovpn', '.cer', '.crt', '.pfx', '.p12'}

INTERESTING_PATHS = re.compile(
    r"(admin|backup|config|secret|credential|token|password|private|"
    r"internal|dev|staging|test|api|swagger|graphql|wp-admin|phpmyadmin)", re.IGNORECASE
)

async def cdx_query(client, base_url, params, label="default"):
    results = []
    try:
        resp = await client.get(base_url, params=params, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                for row in data[1:]:
                    results.append(row)
    except:
        pass
    return results

async def fetch_archived_content(client, wayback_url):
    try:
        resp = await client.get(wayback_url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        base_cdx = "http://web.archive.org/cdx/search/cdx"
        cdx_params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode,digest,length",
            "limit": "5000",
            "collapse": "urlkey"
        }
        all_rows = await cdx_query(client, base_cdx, cdx_params)

        if all_rows:
            findings.append(IntelligenceFinding(
                entity=f"{len(all_rows)} archived snapshots for {domain}",
                type="Archive Forensics Summary",
                source="Wayback CDX Forensics",
                confidence="High",
                color="slate",
                category="Historical Intel",
                threat_level="Informational",
                status="Complete",
                tags=["archive", "wayback"]
            ))

            missing = []
            sensitive_files = []
            mime_dist = defaultdict(int)
            status_dist = defaultdict(int)
            year_dist = defaultdict(int)
            path_map = defaultdict(set)
            js_urls = []
            cdn_urls = []
            param_urls = []
            emails_found = set()
            ips_found = set()

            for row in all_rows:
                if len(row) < 6:
                    continue
                ts, original, mimetype, statuscode, digest, length = row[:6]
                year = ts[:4] if ts else "?"
                year_dist[year] += 1
                mime_dist[mimetype] += 1
                status_dist[statuscode] += 1
                parsed = urlparse(original)
                path = parsed.path.rstrip("/")
                if path:
                    path_map[path].add(year)
                if "?" in original and "=" in original:
                    param_urls.append(original)
                lower_url = original.lower()
                if any(lower_url.endswith(ext) for ext in SENSITIVE_EXTS):
                    sensitive_files.append((original, mimetype, ts))
                if mimetype.startswith("image/"):
                    missing.append(original)
                if mimetype == "text/javascript" or lower_url.endswith(".js"):
                    js_urls.append(original)
                for cdn_domain in ["cdn.", "fonts.googleapis", "ajax.googleapis",
                    "cdnjs.cloudflare", "stackpath.bootstrapcdn", "unpkg.com",
                    "jsdelivr.net", "cloudfront.net", "amazonaws.com"]:
                    if cdn_domain in lower_url:
                        cdn_urls.append(original)

            for (surl, smime, sts) in sensitive_files[:15]:
                findings.append(IntelligenceFinding(
                    entity=surl[:200],
                    type="Historical Sensitive File",
                    source="Wayback CDX Forensics",
                    confidence="Certain",
                    color="red",
                    category="Historical Intel",
                    threat_level="Elevated Risk",
                    status="Sensitive Archive",
                    resolution=f"Type: {smime}, Date: {sts}",
                    raw_data=f"Sensitive file archived at {sts}: {surl}",
                    tags=["sensitive", "archive"]
                ))
            if sensitive_files:
                findings.append(IntelligenceFinding(
                    entity=f"{len(sensitive_files)} total sensitive files archived",
                    type="Sensitive File Count",
                    source="Wayback CDX Forensics",
                    confidence="High",
                    color="orange",
                    category="Historical Intel",
                    threat_level="Elevated Risk",
                    status="Aggregated",
                    tags=["sensitive", "archive"]
                ))

            missing_by_status = [r for r in all_rows if len(r) > 4 and r[4] in ("404", "301", "302")]
            if missing_by_status:
                findings.append(IntelligenceFinding(
                    entity=f"{len(missing_by_status)} non-200 responses (redirects/missing pages)",
                    type="Deleted or Moved Pages",
                    source="Wayback CDX Forensics",
                    confidence="High",
                    color="orange",
                    category="Historical Intel",
                    threat_level="Informational",
                    status="Historical",
                    raw_data="Pages that returned non-200 status codes in archives",
                    tags=["deleted-pages"]
                ))

            mime_breakdown = sorted(mime_dist.items(), key=lambda x: -x[1])[:8]
            mime_str = ", ".join(f"{m}({c})" for m, c in mime_breakdown)
            findings.append(IntelligenceFinding(
                entity=f"Content: {mime_str}",
                type="Archive MIME Distribution",
                source="Wayback CDX Forensics",
                confidence="High",
                color="purple",
                category="Historical Intel",
                threat_level="Informational",
                status="Analyzed",
                tags=["mime", "statistics"]
            ))

            top_statuses = sorted(status_dist.items(), key=lambda x: -x[1])[:5]
            status_str = ", ".join(f"{s}({c})" for s, c in top_statuses)
            findings.append(IntelligenceFinding(
                entity=f"Status Codes: {status_str}",
                type="HTTP Status Trend",
                source="Wayback CDX Forensics",
                confidence="High",
                color="slate",
                category="Historical Intel",
                threat_level="Informational",
                status="Analyzed",
                tags=["status-codes"]
            ))

            years_sorted = sorted(year_dist.keys())
            if years_sorted:
                yr_range = f"{years_sorted[0]}-{years_sorted[-1]} ({len(years_sorted)} years)"
                findings.append(IntelligenceFinding(
                    entity=f"Archive Range: {yr_range}",
                    type="Archive Timeline",
                    source="Wayback CDX Forensics",
                    confidence="High",
                    color="blue",
                    category="Historical Intel",
                    threat_level="Informational",
                    status="Timeline",
                    tags=["timeline"]
                ))

            if js_urls:
                for js in js_urls[:8]:
                    findings.append(IntelligenceFinding(
                        entity=js[:200],
                        type="Historical JavaScript File",
                        source="Wayback CDX Forensics",
                        confidence="Medium",
                        color="slate",
                        category="Historical Intel",
                        threat_level="Informational",
                        status="Found",
                        raw_data=f"JS file found in archive: {js}",
                        tags=["javascript"]
                    ))

            if cdn_urls:
                old_cdns = set()
                for cu in cdn_urls:
                    parsed = urlparse(cu)
                    old_cdns.add(parsed.netloc)
                for oc in list(old_cdns)[:5]:
                    findings.append(IntelligenceFinding(
                        entity=oc,
                        type="Historical CDN Reference",
                        source="Wayback CDX Forensics",
                        confidence="Medium",
                        color="purple",
                        category="Historical Intel",
                        threat_level="Informational",
                        status="CDN Reference",
                        tags=["cdn", "deprecated"]
                    ))

            for param_url in param_urls[:10]:
                findings.append(IntelligenceFinding(
                    entity=param_url[:200],
                    type="URL with Parameters (Historical)",
                    source="Wayback CDX Forensics",
                    confidence="Low",
                    color="slate",
                    category="Historical Intel",
                    threat_level="Informational",
                    status="Param URL",
                    tags=["parameters"]
                ))

            if path_map:
                path_counts = sorted([(p, len(y)) for p, y in path_map.items()], key=lambda x: -x[1])[:10]
                for path, yr_count in path_counts:
                    if INTERESTING_PATHS.search(path):
                        findings.append(IntelligenceFinding(
                            entity=path[:200],
                            type="Interesting Historical Path",
                            source="Wayback CDX Forensics",
                            confidence="Medium",
                            color="orange",
                            category="Historical Intel",
                            threat_level="Informational",
                            status="Interesting Path",
                            raw_data=f"Path {path} found across {yr_count} years",
                            tags=["path", "interesting"]
                        ))

        limited_params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode",
            "limit": "2000",
            "filter": "mimetype:text/html",
            "from": "2000",
            "to": "2015"
        }
        early_rows = await cdx_query(client, base_cdx, limited_params, "early")
        if early_rows:
            old_urls = set()
            for row in early_rows:
                if len(row) > 1:
                    old_urls.add(row[1])
            if old_urls:
                findings.append(IntelligenceFinding(
                    entity=f"{len(old_urls)} unique URLs from early archives (2000-2015)",
                    type="Early Archive Discovery",
                    source="Wayback CDX Forensics",
                    confidence="Medium",
                    color="purple",
                    category="Historical Intel",
                    threat_level="Informational",
                    status="Historical",
                    tags=["early-archive"]
                ))

        diff_params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "timestamp,original,digest",
            "limit": "3000",
            "collapse": "digest"
        }
        unique_rows = await cdx_query(client, base_cdx, diff_params, "unique")
        if unique_rows:
            digest_groups = defaultdict(list)
            for row in unique_rows:
                if len(row) >= 3:
                    digest_groups[row[2]].append(row)
            changed = [urls for urls in digest_groups.values() if len(urls) > 1]
            if changed:
                findings.append(IntelligenceFinding(
                    entity=f"{len(changed)} URLs with significant content changes across snapshots",
                    type="Content Change Detection",
                    source="Wayback CDX Forensics",
                    confidence="Medium",
                    color="blue",
                    category="Historical Intel",
                    threat_level="Informational",
                    status="Changed Content",
                    tags=["diff", "changes"]
                ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Archive forensics error: {str(e)[:100]}",
            type="Archive Forensics Error",
            source="Wayback CDX Forensics",
            confidence="Low",
            color="red",
            category="Historical Intel",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))

    return findings
