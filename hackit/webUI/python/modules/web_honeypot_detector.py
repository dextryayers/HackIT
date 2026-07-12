import re
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
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
]

TRAP_DIRECTORIES = [
    "/admin", "/backup", "/wp-admin", "/administrator", "/cpanel",
    "/phpmyadmin", "/conftest", "/shell", "/cmd", "/exec",
    "/debug", "/test", "/dev", "/.git", "/.env", "/.aws",
    "/private", "/protected", "/secret", "/hidden",
]

SUSPICIOUS_EMAIL_PATTERNS = [
    r"noreply@\S+\.(com|net|org)",
    r"no-reply@\S+",
    r"donotreply@\S+",
    r"spam@\S+",
    r"trap@\S+",
    r"honeypot@\S+",
    r"fake@\S+",
]

async def check_directory(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    result = {"path": path, "status": 0, "is_honeypot": False, "indicators": []}
    try:
        resp = await safe_fetch(client,f"{base_url}{path}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
        result["status"] = resp.status_code
        if resp.status_code == 200:
            content = resp.text.lower()
            if "honeypot" in content or "decoy" in content or "trapped" in content:
                result["is_honeypot"] = True
                result["indicators"].append("Page content mentions honeypot/decoy/trap")
            if resp.elapsed and resp.elapsed.total_seconds() > 5:
                result["indicators"].append(f"Slow response ({resp.elapsed.total_seconds():.1f}s) - possible honeypot")
            if len(resp.headers) > 20:
                result["indicators"].append(f"Unusually many headers ({len(resp.headers)})")
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    base_url = f"https://{domain}"

    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            html = resp.text
            base_url = f"{proto}://{domain}"
            break
        except Exception:
            continue

    if html:
        hidden_fields = []
        for pattern in HONEYPOT_FIELD_PATTERNS:
            matches = re.findall(pattern, html, re.I)
            for m in matches:
                hidden_fields.append(m)

        if hidden_fields:
            findings.append(make_finding(
                entity=f"Detected {len(hidden_fields)} potential honeypot field indicators",
                ftype="Honeypot: Hidden Field Patterns",
                source="HoneypotDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(hidden_fields[:10]),
                tags=["honeypot", "hidden-fields", "anti-bot"]
            ))
        else:
            findings.append(make_finding(
                entity="No obvious honeypot field patterns detected in page source",
                ftype="Honeypot: Field Check",
                source="HoneypotDetector",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                tags=["honeypot", "clean"]
            ))

        fake_emails = []
        for pat in SUSPICIOUS_EMAIL_PATTERNS:
            matches = re.findall(pat, html, re.I)
            fake_emails.extend(matches)
        if fake_emails:
            findings.append(make_finding(
                entity=f"Found {len(set(fake_emails))} suspicious/honeypot email addresses",
                ftype="Honeypot: Suspicious Emails",
                source="HoneypotDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="\n".join(set(fake_emails[:10])),
                tags=["honeypot", "fake-emails"]
            ))

        honeypot_link_patterns = re.findall(
            r'href\s*=\s*["\']([^"\']*(?:honeypot|decoy|trap|fake|spam)[^"\']*?)["\']',
            html, re.I
        )
        if honeypot_link_patterns:
            findings.append(make_finding(
                entity=f"Found {len(honeypot_link_patterns)} links containing honeypot/decoy/trap keywords",
                ftype="Honeypot: Suspicious Links",
                source="HoneypotDetector",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                raw_data="\n".join(honeypot_link_patterns[:10]),
                tags=["honeypot", "suspicious-links"]
            ))

    findings.append(make_finding(
        entity=f"Testing {len(TRAP_DIRECTORIES)} common directories for honeypot behavior",
        ftype="Honeypot: Directory Scan Started",
        source="HoneypotDetector",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        tags=["honeypot", "directory-scan"]
    ))

    trap_results = []
    for path in TRAP_DIRECTORIES:
        result = await check_directory(client, base_url, path)
        trap_results.append(result)

    trap_dirs = [r for r in trap_results if r["is_honeypot"]]
    if trap_dirs:
        for t in trap_dirs:
            findings.append(make_finding(
                entity=f"Potential honeypot directory: {t['path']} (HTTP {t['status']})",
                ftype="Honeypot: Trap Directory",
                source="HoneypotDetector",
                confidence="Low",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"path={t['path']}, status={t['status']}, indicators={'; '.join(t['indicators'])}",
                tags=["honeypot", "trap-directory"]
            ))

    interesting_responses = [r for r in trap_results if r["status"] in (200, 401, 403) and not r["is_honeypot"]]
    if interesting_responses:
        findings.append(make_finding(
            entity=f"{len(interesting_responses)} directories returned HTTP {interesting_responses[0]['status']} (may be monitored)",
            ftype="Honeypot: Interesting Directories",
            source="HoneypotDetector",
            confidence="Low",
            color="yellow",
            threat_level="Elevated Risk",
            raw_data="\n".join([f"{r['path']} -> {r['status']}" for r in interesting_responses[:10]]),
            tags=["honeypot", "interesting-paths"]
        ))

    suspicious_ports = [22, 23, 3389, 5900, 8080, 8443, 4443, 2222, 10000, 31337]
    for port in suspicious_ports[:5]:
        try:
            resp = await safe_fetch(client,f"http://{domain}:{port}", timeout=5.0, headers={"User-Agent": UA})
            if resp.status_code < 500:
                findings.append(make_finding(
                    entity=f"Service on port {port} (HTTP {resp.status_code}) - possible honeyport",
                    ftype="Honeypot: Unusual Port",
                    source="HoneypotDetector",
                    confidence="Low",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"port={port}, http_status={resp.status_code}",
                    tags=["honeypot", "honeyport"]
                ))
        except Exception:
            continue

    findings.append(make_finding(
        entity=f"Honeypot Analysis: {len(hidden_fields) if 'hidden_fields' in dir() else 0} field patterns, {len(trap_dirs)} trap directories, {len(interesting_responses)} interesting paths",
        ftype="Honeypot: Summary",
        source="HoneypotDetector",
        confidence="Medium",
        color="orange" if trap_dirs else "emerald",
        threat_level="Elevated Risk" if trap_dirs else "Informational",
        raw_data=f"field_patterns={len(hidden_fields) if 'hidden_fields' in dir() else 0}, trap_dirs={len(trap_dirs)}, interesting={len(interesting_responses)}",
        tags=["honeypot", "summary"]
    ))

    return findings
