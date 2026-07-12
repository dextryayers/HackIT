import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".git/config", ".git/HEAD", ".gitignore",
    ".htaccess", ".htpasswd",
    "wp-config.php", "wp-config.bak",
    "config.php", "config.php.bak", "config.inc.php",
    "configuration.php", "config.yml", "config.yaml",
    "database.yml", "database.yaml",
    "db.php", "db.inc.php", "dbconnect.php",
    "dump.sql", "backup.sql", "db.sql",
    "admin.php", "admin.asp", "admin.aspx",
    "phpinfo.php", "info.php", "test.php",
    "debug.log", "error.log", "access.log",
    "composer.json", "composer.lock",
    "package.json", "package-lock.json",
    "Dockerfile", "docker-compose.yml",
    "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

COMMENT_PATTERNS = [
    r"<!--.*?(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND|todo|fixme).*?-->",
    r"//\s*(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND)",
    r"/\*.*?(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND).*?\*/",
]

ERROR_PAGE_TESTS = [
    ("/nonexistent_page_skdjfhkjsdhf", 404),
    ("/admin/config/../../etc/passwd", 403),
    ("/../../../etc/passwd", 403),
    ("/.env", None),
    ("/%00", 400),
    ("/admin', 1=1--", None),
]

async def check_header_leak(headers: dict) -> list:
    leaks = []
    verbose_headers = {
        "server": "Server information disclosure",
        "x-powered-by": "Technology stack disclosure",
        "x-aspnet-version": "ASP.NET version disclosure",
        "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
        "x-generator": "Generator info disclosure",
        "x-drupal-cache": "Drupal cache info",
        "x-drupal-dynamic-cache": "Drupal dynamic cache info",
        "x-varnish": "Varnish cache info",
        "x-served-by": "Server identifier disclosure",
        "x-request-id": "Request ID (internal tracking)",
        "x-amzn-trace-id": "AWS tracing info",
        "x-trace-id": "Trace ID disclosure",
        "x-trace-context": "Trace context disclosure",
        "x-backend-server": "Backend server info",
        "x-runtime": "Application runtime info",
        "x-version": "Application version info",
        "x-environment": "Environment info (dev/staging/prod)",
    }
    for hdr, desc in verbose_headers.items():
        if hdr in headers:
            leaks.append({"header": hdr, "value": headers[hdr][:100], "description": desc})
    return leaks

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            html = resp.text

            leaks = await check_header_leak(headers)
            if leaks:
                findings.append(make_finding(
                    entity=f"Information leaks from headers: {len(leaks)} found",
                    ftype="Leak: Header Leaks",
                    source="ServerLeakDetector",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    raw_data="\n".join([f"{l['header']}: {l['value']}" for l in leaks]),
                    tags=["leak", "header", "information-disclosure"]
                ))
                for leak in leaks[:8]:
                    findings.append(make_finding(
                        entity=f"Header leak: {leak['header']} = {leak['value'][:60]}",
                        ftype="Leak: Header Detail",
                        source="ServerLeakDetector",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        raw_data=f"{leak['header']}: {leak['value']}",
                        tags=["leak", "header", leak["header"].lower().replace("-", "_")]
                    ))
            else:
                findings.append(make_finding(
                    entity="No verbose information disclosure headers detected",
                    ftype="Leak: No Header Leaks",
                    source="ServerLeakDetector",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    tags=["leak", "header", "clean"]
                ))

            comments_found = []
            for pattern in COMMENT_PATTERNS:
                comments = re.findall(pattern, html, re.DOTALL)
                comments_found.extend(comments)

            if comments_found:
                findings.append(make_finding(
                    entity=f"Found {len(comments_found)} HTML/JS comments with TODO/FIXME/HACK/XXX/BUG keywords",
                    ftype="Leak: Comment Leaks",
                    source="ServerLeakDetector",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data="\n".join(comments_found[:10]),
                    tags=["leak", "comments", "information-disclosure"]
                ))

            server_header = headers.get("server", "")
            if server_header:
                findings.append(make_finding(
                    entity=f"Server header: {server_header}",
                    ftype="Leak: Server Header",
                    source="ServerLeakDetector",
                    confidence="High",
                    color="yellow",
                    threat_level="Informational",
                    raw_data=f"Server: {server_header}",
                    tags=["leak", "server-header"]
                ))
                if re.search(r"[\d.]+\.[\d.]+\.[\d.]+", server_header):
                    findings.append(make_finding(
                        entity=f"Server header contains version number: {server_header}",
                        ftype="Leak: Version Disclosure",
                        source="ServerLeakDetector",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"Server: {server_header}",
                        tags=["leak", "version-disclosure"]
                    ))

            via_header = headers.get("via", "")
            if via_header:
                findings.append(make_finding(
                    entity=f"Via header: {via_header[:80]}",
                    ftype="Leak: Via Header",
                    source="ServerLeakDetector",
                    confidence="Medium",
                    color="yellow",
                    threat_level="Informational",
                    raw_data=f"Via: {via_header}",
                    tags=["leak", "via-header"]
                ))

            for path, expected_status in ERROR_PAGE_TESTS:
                try:
                    r = await safe_fetch(client,f"{proto}://{domain}{path}", timeout=5.0, follow_redirects=False, headers={"User-Agent": UA})
                    content = r.text.lower()
                    leaks_in_error = []

                    if "stack trace" in content or "stacktrace" in content:
                        leaks_in_error.append("Stack trace detected")
                    if "php error" in content or "fatal error" in content:
                        leaks_in_error.append("PHP error info")
                    if "sql" in content and ("syntax" in content or "error" in content):
                        leaks_in_error.append("SQL error information")
                    if "file_get_contents" in content or "include(" in content or "require(" in content or "unlink(" in content:
                        leaks_in_error.append("File path disclosure in PHP error")
                    if "on line" in content and re.search(r"line \d+", content):
                        leaks_in_error.append("Line number disclosure")
                    if "/var/www/" in content or "C:\\" in content or "/home/" in content or "/root/" in content:
                        leaks_in_error.append("Absolute path disclosure")
                    if "warning" in content and "mysql_" in content:
                        leaks_in_error.append("MySQL function warning")
                    if "exception" in content and r.status_code >= 500:
                        leaks_in_error.append("Exception detail in error page")

                    if leaks_in_error:
                        findings.append(make_finding(
                            entity=f"Error page leaks on {path} (HTTP {r.status_code}): {', '.join(leaks_in_error[:3])}",
                            ftype="Leak: Error Page Leak",
                            source="ServerLeakDetector",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            raw_data=f"path={path}, status={r.status_code}, leaks={'; '.join(leaks_in_error)}",
                            tags=["leak", "error-page", "information-disclosure"]
                        ))
                except Exception:
                    continue

            trace_url = f"{proto}://{domain}"
            try:
                trace_resp = await safe_fetch(client, trace_url, method="TRACE", timeout=5.0, headers={"User-Agent": UA})
                if trace_resp.status_code == 200:
                    findings.append(make_finding(
                        entity="HTTP TRACE method enabled - XST vulnerability possible",
                        ftype="Leak: TRACE Method",
                        source="ServerLeakDetector",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Vulnerable",
                        tags=["leak", "trace", "xst", "vulnerability"]
                    ))
            except Exception:
                pass

            break
        except Exception:
            continue

    sensitive_checked = 0
    sensitive_found = 0
    for path in SENSITIVE_FILE_PATTERNS[:20]:
        sensitive_checked += 1
        try:
            resp = await safe_fetch(client,f"https://{domain}/{path}", timeout=5.0, follow_redirects=False, headers={"User-Agent": UA})
            if resp.status_code == 200:
                sensitive_found += 1
                findings.append(make_finding(
                    entity=f"Sensitive file accessible: /{path} (HTTP {resp.status_code}, {len(resp.content)} bytes)",
                    ftype="Leak: Sensitive File",
                    source="ServerLeakDetector",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    status="Exposed",
                    raw_data=f"path=/{path}, size={len(resp.content)}, status={resp.status_code}",
                    tags=["leak", "sensitive-file", "exposure"]
                ))
        except Exception:
            continue

    findings.append(make_finding(
        entity=f"Server Leak Analysis: {len(leaks)} header leaks, {sensitive_found}/{sensitive_checked} sensitive files exposed",
        ftype="Leak: Summary",
        source="ServerLeakDetector",
        confidence="High",
        color="red" if (leaks or sensitive_found) else "emerald",
        threat_level="High Risk" if (leaks or sensitive_found) else "Informational",
        raw_data=f"header_leaks={len(leaks)}, sensitive_files={sensitive_found}, sensitive_checked={sensitive_checked}",
        tags=["leak", "summary"]
    ))

    return findings
