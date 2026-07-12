import re, asyncio, time
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, make_finding
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

HONEYPOT_FIELD_PATTERNS = [
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"position\s*:\s*absolute",
    r"left\s*:\s*-\d{3,}",
    r"opacity\s*:\s*0",
    r"position\s*:\s*fixed;\s*(top|left)\s*:\s*-\d+",
    r"type\s*=\s*['\"]?hidden['\"]?",
    r"aria-hidden\s*=\s*['\"]?true['\"]?",
    r"tabindex\s*=\s*['\"]?-1['\"]?",
    r"height\s*:\s*0(?!important)",
    r"width\s*:\s*0(?!important)",
]

TRAP_DIRECTORIES = [
    "/admin", "/backup", "/wp-admin", "/administrator", "/cpanel",
    "/phpmyadmin", "/conftest", "/shell", "/cmd", "/exec",
    "/debug", "/test", "/dev", "/.git", "/.env", "/.aws",
    "/private", "/protected", "/secret", "/hidden",
    "/config", "/configuration", "/setting", "/settings",
    "/cgi-bin", "/scripts", "/bin", "/tmp", "/temp",
    "/.svn", "/.hg", "/.bzr", "/.cvs",
    "/_debug", "/_profiler", "/telescope",
    "/actuator", "/jolokia", "/metrics",
    "/phpinfo", "/info", "/status",
    "/db", "/database", "/sql", "/dump",
    "/log", "/logs", "/audit", "/error",
    "/old", "/new", "/bak", "/backup",
]

SUSPICIOUS_EMAIL_PATTERNS = [
    r"noreply@\S+\.(com|net|org)",
    r"no-reply@\S+",
    r"donotreply@\S+",
    r"spam@\S+",
    r"trap@\S+",
    r"honeypot@\S+",
    r"fake@\S+",
    r"decoy@\S+",
]

CONCURRENT_LIMIT = 25

async def check_directory(client, base_url, path, baseline_time):
    result = {"path": path, "status": 0, "is_honeypot": False, "indicators": [], "response_time": 0}
    try:
        start = time.monotonic()
        resp = await safe_fetch(client, f"{base_url}{path}", timeout=6.0, follow_redirects=False, headers={"User-Agent": UA})
        elapsed = time.monotonic() - start
        result["response_time"] = elapsed
        if resp:
            result["status"] = resp.status_code
            content = resp.text.lower()
            if "honeypot" in content or "decoy" in content or "trapped" in content:
                result["is_honeypot"] = True
                result["indicators"].append("Content mentions honeypot/decoy")
            if elapsed > baseline_time * 3:
                result["indicators"].append(f"Very slow response ({elapsed:.1f}s vs {baseline_time:.1f}s baseline)")
            if len(resp.headers) > 20:
                result["indicators"].append(f"Many headers ({len(resp.headers)})")
            server = resp.headers.get("server", "").lower()
            if any(w in server for w in ["cloudflare", "akamai", "incapsula", "sucuri"]):
                result["indicators"].append(f"WAF/CDN detected: {server}")
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"

    start = time.monotonic()
    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client, f"{proto}://{domain}", timeout=8.0, follow_redirects=True, headers={"User-Agent": UA})
            if resp:
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue
    baseline_time = time.monotonic() - start

    html = resp.text if resp else ""
    hidden_fields = []
    if html:
        for pattern in HONEYPOT_FIELD_PATTERNS:
            matches = re.findall(pattern, html, re.I)
            hidden_fields.extend(matches)

        if hidden_fields:
            findings.append(make_finding(
                entity=f"Detected {len(hidden_fields)} honeypot field indicators",
                ftype="Honeypot: Hidden Fields",
                source="HoneypotDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(hidden_fields[:10]),
                tags=["honeypot", "hidden-fields", "anti-bot"]
            ))

        fake_emails = []
        for pat in SUSPICIOUS_EMAIL_PATTERNS:
            fake_emails.extend(re.findall(pat, html, re.I))
        if fake_emails:
            findings.append(make_finding(
                entity=f"Found {len(set(fake_emails))} suspicious email addresses in HTML",
                ftype="Honeypot: Fake Emails",
                source="HoneypotDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(set(fake_emails[:10])),
                tags=["honeypot", "fake-emails"]
            ))

    sem = asyncio.Semaphore(CONCURRENT_LIMIT)

    async def check_dir(path):
        async with sem:
            return await check_directory(client, base_url, path, baseline_time)

    tasks = [check_dir(path) for path in TRAP_DIRECTORIES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    trap_dirs = []
    interesting_paths = []
    for r in results:
        if isinstance(r, Exception) or not isinstance(r, dict):
            continue
        if r["is_honeypot"]:
            trap_dirs.append(r)
        elif r["status"] in (200, 401, 403):
            interesting_paths.append(r)
        elif r["response_time"] > baseline_time * 5:
            interesting_paths.append(r)

    for t in trap_dirs:
        findings.append(make_finding(
            entity=f"Potential honeypot directory: {t['path']} (HTTP {t['status']})",
            ftype="Honeypot: Trap Directory",
            source="HoneypotDetector",
            confidence="Medium",
            color="red",
            threat_level="High Risk",
            raw_data=f"path={t['path']}, indicators={'; '.join(t['indicators'])}",
            tags=["honeypot", "trap-directory"]
        ))

    if interesting_paths:
        findings.append(make_finding(
            entity=f"{len(interesting_paths)} directories may be monitored/honeypotted",
            ftype="Honeypot: Monitored Paths",
            source="HoneypotDetector",
            confidence="Low",
            color="yellow",
            threat_level="Elevated Risk",
            raw_data="\n".join([f"{r['path']} -> {r['status']}" for r in interesting_paths[:15]]),
            tags=["honeypot", "interesting-paths"]
        ))

    findings.append(make_finding(
        entity=f"Honeypot Analysis: {len(hidden_fields)} field patterns, {len(trap_dirs)} trap dirs, {len(interesting_paths)} monitored paths, {len(TRAP_DIRECTORIES)} tested",
        ftype="Honeypot: Summary",
        source="HoneypotDetector",
        confidence="Medium",
        color="red" if trap_dirs else "emerald",
        threat_level="High Risk" if trap_dirs else "Informational",
        raw_data=f"fields={len(hidden_fields)}, traps={len(trap_dirs)}, monitored={len(interesting_paths)}",
        tags=["honeypot", "summary"]
    ))

    return findings
