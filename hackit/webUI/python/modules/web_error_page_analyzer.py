import httpx
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

ERROR_PATHS = [
    "/nonexistent_page_abcdef123456", "/%00", "/../../etc/passwd",
    "/admin/.env", "/admin' OR '1'='1", "/<script>alert(1)</script>",
    "/..%5c..%5cwindows/win.ini", "/.git/config",
    "/admin/config.php", "/wp-admin/admin-ajax.php?action=invalid",
    "/index.php?page=../../etc/passwd",
]

FRAMEWORK_ERROR_SIGNATURES = {
    "WordPress": [r"WordPress", r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"Drupal", r"drupal"],
    "Joomla": [r"Joomla", r"joomla"],
    "Laravel": [r"Laravel", r"laravel"],
    "Symfony": [r"Symfony", r"symfony"],
    "CodeIgniter": [r"CodeIgniter", r"codeigniter"],
    "CakePHP": [r"CakePHP", r"cakephp"],
    "Rails": [r"Ruby on Rails", r"rails", r"weblog"],
    "Django": [r"Django", r"django", r"DJANGO"],
    "Flask": [r"Flask", r"flask", r"Werkzeug"],
    "Express": [r"Express", r"express"],
    "ASP.NET": [r"ASP\.NET", r"asp\.net", r".NET Framework"],
    "Spring": [r"Spring", r"spring"],
    "Tomcat": [r"Tomcat", r"tomcat", r"Apache Tomcat"],
    "JBoss": [r"JBoss", r"jboss"],
}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    for proto in ["https", "http"]:
        try:
            await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            break
        except Exception:
            continue

    findings.append(IntelligenceFinding(
        entity=f"Triggering {len(ERROR_PATHS)} error-inducing requests on {domain}",
        type="ErrorPage: Scan Started",
        source="ErrorPageAnalyzer",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        tags=["error-page", "scan"]
    ))

    detected_frameworks = set()
    found_errors = []

    for path in ERROR_PATHS:
        try:
            resp = await client.get(f"https://{domain}{path}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
            content = resp.text
            status = resp.status_code
            error_info = {"path": path, "status": status, "size": len(resp.content), "findings": [], "framework_hits": []}

            if status in (403, 404, 405, 500, 502, 503):
                error_info["is_error_page"] = True

            framework_detected = False
            for fw_name, signatures in FRAMEWORK_ERROR_SIGNATURES.items():
                for sig in signatures:
                    if re.search(sig, content, re.I):
                        if fw_name not in detected_frameworks:
                            detected_frameworks.add(fw_name)
                            error_info["framework_hits"].append(fw_name)
                            framework_detected = True

            if re.search(r"[A-Z]:\\[^<>]*", content):
                error_info["findings"].append("Windows absolute path disclosure")
            if re.search(r"/(var|home|root|usr|tmp|opt|etc)/[a-zA-Z0-9_/.-]+", content):
                error_info["findings"].append("Unix absolute path disclosure")
            if re.search(r"(Warning|Fatal error|Parse error|Notice):\s+", content, re.I):
                error_info["findings"].append("PHP error/warning message")
            if re.search(r"SQL syntax.*MySQL|Table '.*' doesn't exist|Unknown column|You have an error in your SQL syntax", content, re.I):
                error_info["findings"].append("SQL error message")
            if re.search(r"Stack trace:|#0\s", content, re.I):
                error_info["findings"].append("Stack trace disclosed")
            if re.search(r"on line \d+", content, re.I):
                error_info["findings"].append("Line number disclosure")
            if re.search(r"Class '.*' not found", content, re.I):
                error_info["findings"].append("PHP class path disclosure")
            if re.search(r"include\(.*\)|require\(.*\)", content, re.I):
                error_info["findings"].append("PHP include path disclosure")
            if re.search(r"Undefined variable|Undefined index|Undefined offset", content, re.I):
                error_info["findings"].append("PHP undefined variable/index warning")
            if "DEBUG" in content or "debug" in content.lower():
                error_info["findings"].append("Debug mode information")
            if re.search(r"version [\d.]+\.[\d.]+\.[\d.]+", content):
                error_info["findings"].append("Version number in error page")

            if re.search(r"<!DOCTYPE", content, re.I) or re.search(r"<html", content, re.I):
                if status in (403, 404):
                    if re.search(r"<title>(.*?)</title>", content, re.I):
                        title_match = re.search(r"<title>(.*?)</title>", content, re.I)
                        error_info["custom_error"] = title_match.group(1).strip()
                elif status >= 500:
                    if re.search(r"<title>(.*?)</title>", content, re.I):
                        title_match = re.search(r"<title>(.*?)</title>", content, re.I)
                        error_info["custom_error"] = title_match.group(1).strip()
            else:
                error_info["bare_error"] = content[:200].strip()

            if error_info.get("findings") or error_info.get("framework_hits"):
                found_errors.append(error_info)

        except Exception:
            continue

    for error in found_errors:
        if error.get("findings"):
            findings.append(IntelligenceFinding(
                entity=f"Error on {error['path']} (HTTP {error['status']}): {'; '.join(error['findings'][:3])}",
                type="ErrorPage: Information Leak",
                source="ErrorPageAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data=f"path={error['path']}, status={error['status']}, leaks={'; '.join(error['findings'])}",
                tags=["error-page", "information-disclosure", f"http-{error['status']}"]
            ))

        if error.get("framework_hits"):
            for fw in error["framework_hits"]:
                findings.append(IntelligenceFinding(
                    entity=f"Framework detected from error page: {fw}",
                    type="ErrorPage: Framework Detection",
                    source="ErrorPageAnalyzer",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"framework={fw}, path={error['path']}",
                    tags=["error-page", "framework", fw.lower()]
                ))

        if error.get("custom_error"):
            findings.append(IntelligenceFinding(
                entity=f"Custom error page: HTTP {error['status']} -> Title: {error['custom_error'][:80]}",
                type="ErrorPage: Custom Page",
                source="ErrorPageAnalyzer",
                confidence="Medium",
                color="yellow",
                threat_level="Informational",
                raw_data=f"path={error['path']}, title={error['custom_error']}",
                tags=["error-page", "custom", "branding"]
            ))

        if error.get("bare_error"):
            findings.append(IntelligenceFinding(
                entity=f"Bare/minimal error response on {error['path']}: {error['bare_error'][:80]}",
                type="ErrorPage: Bare Response",
                source="ErrorPageAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                raw_data=f"path={error['path']}, response={error['bare_error'][:200]}",
                tags=["error-page", "bare-error"]
            ))

    if not found_errors:
        findings.append(IntelligenceFinding(
            entity="No sensitive information found in error pages (good security posture)",
            type="ErrorPage: Clean",
            source="ErrorPageAnalyzer",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["error-page", "clean", "secure"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Error Page Analysis: {len(found_errors)} error(s) with info leaks, {len(detected_frameworks)} framework(s) detected",
        type="ErrorPage: Summary",
        source="ErrorPageAnalyzer",
        confidence="High",
        color="red" if found_errors else "emerald",
        threat_level="High Risk" if found_errors else "Informational",
        raw_data=f"error_leaks={len(found_errors)}, frameworks={len(detected_frameworks)}",
        tags=["error-page", "summary"]
    ))

    return findings
