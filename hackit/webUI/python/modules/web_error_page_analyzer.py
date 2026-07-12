import re, asyncio
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, make_finding
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

ERROR_PATHS = [
    "/nonexistent_page_abcdef123456", "/%00", "/../../etc/passwd",
    "/admin/.env", "/admin' OR '1'='1", "/<script>alert(1)</script>",
    "/..%5c..%5cwindows/win.ini", "/.git/config",
    "/admin/config.php", "/wp-admin/admin-ajax.php?action=invalid",
    "/index.php?page=../../etc/passwd",
    "/../../../etc/passwd", "/....//....//etc/passwd",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/cgi-bin/test.cgi", "/cgi-bin/test.pl",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/wp-login.php", "/wp-admin/install.php",
    "/administrator/", "/phpmyadmin/",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/debug/default/view", "/_profiler/phpinfo",
    "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env",
    "/swagger-resources", "/v2/api-docs",
    "/graphql", "/graphiql",
    "/console/", "/.well-known/debug",
    "/api/v1/debug", "/debug/pprof/",
    "/actuator/mappings", "/actuator/beans",
    "/jolokia", "/jolokia/list",
    "/solr/admin/", "/admin/console",
    "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websess",
    "/%0a%0d%0a%0dRCPT+TO:<>",
]

FRAMEWORK_ERROR_SIGNATURES = {
    "WordPress": [r"WordPress", r"wp-content", r"wp-includes", r"wp-json", r"wp-login"],
    "Drupal": [r"Drupal", r"drupal", r"Backdrop"],
    "Joomla": [r"Joomla", r"joomla", r"com_content"],
    "Laravel": [r"Laravel", r"laravel", r"Illuminate"],
    "Symfony": [r"Symfony", r"symfony", r"Twig"],
    "CodeIgniter": [r"CodeIgniter", r"codeigniter"],
    "CakePHP": [r"CakePHP", r"cakephp"],
    "Rails": [r"Ruby on Rails", r"rails", r"weblog", r"WEBrick"],
    "Django": [r"Django", r"django", r"DJANGO", r"csrfmiddleware"],
    "Flask": [r"Flask", r"flask", r"Werkzeug"],
    "FastAPI": [r"FastAPI", r"fastapi", r"Starlette"],
    "Express": [r"Express", r"express"],
    "ASP.NET": [r"ASP\.NET", r"asp\.net", r"\.NET Framework", r"Microsoft\.AspNet"],
    "Spring": [r"Spring", r"spring", r"Whitelabel Error"],
    "Tomcat": [r"Tomcat", r"tomcat", r"Apache Tomcat"],
    "JBoss": [r"JBoss", r"jboss", r"WildFly"],
    "Phoenix": [r"Phoenix", r"phoenix"],
    "Gin": [r"Gin", r"gin-gonic"],
    "Nginx": [r"nginx", r"NGINX"],
    "Apache": [r"Apache", r"apache"],
    "IIS": [r"IIS", r"Microsoft-IIS"],
    "Caddy": [r"Caddy", r"caddy"],
    "LiteSpeed": [r"LiteSpeed", r"litespeed"],
}

CONCURRENT_LIMIT = 20

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    sem = asyncio.Semaphore(CONCURRENT_LIMIT)

    async def probe_path(path):
        async with sem:
            try:
                resp = await safe_fetch(client, f"{base_url}{path}", timeout=6.0, follow_redirects=False, headers={"User-Agent": UA})
                if not resp:
                    return None
                content = resp.text
                status = resp.status_code
                info = {"path": path, "status": status, "size": len(resp.content), "findings": [], "frameworks": set()}

                if status in (403, 404, 405, 500, 502, 503):
                    info["is_error"] = True

                for fw_name, sigs in FRAMEWORK_ERROR_SIGNATURES.items():
                    for sig in sigs:
                        if re.search(sig, content, re.I):
                            info["frameworks"].add(fw_name)

                if re.search(r"[A-Z]:\\[^<>]*", content):
                    info["findings"].append("Windows path disclosure")
                if re.search(r"/(var|home|root|usr|tmp|opt|etc)/[a-zA-Z0-9_/.-]+", content):
                    info["findings"].append("Unix path disclosure")
                if re.search(r"(Warning|Fatal error|Parse error|Notice):\s+", content, re.I):
                    info["findings"].append("PHP error message")
                if re.search(r"SQL syntax.*MySQL|Table '.*' doesn't exist|Unknown column|You have an error in your SQL syntax|ORA-\d{5}", content, re.I):
                    info["findings"].append("SQL error message")
                if re.search(r"Stack trace:|#0\s", content, re.I):
                    info["findings"].append("Stack trace disclosed")
                if re.search(r"on line \d+", content, re.I):
                    info["findings"].append("Line number disclosure")
                if re.search(r"Class '.*' not found", content, re.I):
                    info["findings"].append("PHP class path disclosure")
                if re.search(r"Undefined variable|Undefined index|Undefined offset", content, re.I):
                    info["findings"].append("PHP undefined variable warning")
                if re.search(r"DEBUG|debug_mode|APP_DEBUG", content):
                    info["findings"].append("Debug mode information")
                if re.search(r"version [\d.]+\.[\d.]+\.[\d.]+", content):
                    info["findings"].append("Version number disclosed")
                if re.search(r"Traceback \(most recent call last\)", content):
                    info["findings"].append("Python traceback disclosed")
                if re.search(r"java\.lang\.\w+Exception|at com\.\w+", content):
                    info["findings"].append("Java stack trace disclosed")
                if re.search(r"Cannot find module|module not found", content, re.I):
                    info["findings"].append("Node.js module path disclosure")
                if re.search(r"panic:", content, re.I):
                    info["findings"].append("Go panic disclosed")

                title_match = re.search(r"<title>(.*?)</title>", content, re.I)
                if title_match:
                    info["title"] = title_match.group(1).strip()[:80]

                if info.get("findings") or info.get("frameworks"):
                    return info
            except Exception:
                pass
            return None

    tasks = [probe_path(p) for p in ERROR_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    found_errors = []
    detected_frameworks = set()
    waf_signatures = set()

    for r in results:
        if isinstance(r, Exception) or not r:
            continue
        found_errors.append(r)
        for fw in r.get("frameworks", set()):
            detected_frameworks.add(fw)
        content_lower = ""
        if re.search(r"403 Forbidden", str(r.get("status", ""))):
            if re.search(r"cloudflare|cf-ray|cf-cache-status", str(r), re.I):
                waf_signatures.add("Cloudflare")
            if re.search(r"awselb|amazons3", str(r), re.I):
                waf_signatures.add("AWS WAF")

    for error in found_errors:
        if error.get("findings"):
            findings.append(make_finding(
                entity=f"Error on {error['path']} (HTTP {error['status']}): {'; '.join(error['findings'][:3])}",
                ftype="ErrorPage: Information Leak",
                source="ErrorPageAnalyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data=f"path={error['path']}, status={error['status']}, leaks={'; '.join(error['findings'])}",
                tags=["error-page", "information-disclosure", f"http-{error['status']}"]
            ))

        if error.get("frameworks"):
            for fw in error["frameworks"]:
                findings.append(make_finding(
                    entity=f"Framework detected from error: {fw}",
                    ftype="ErrorPage: Framework Detection",
                    source="ErrorPageAnalyzer",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"framework={fw}, path={error['path']}",
                    tags=["error-page", "framework", fw.lower()]
                ))

        if error.get("title") and error["status"] in (403, 404, 500):
            findings.append(make_finding(
                entity=f"Custom error page: HTTP {error['status']} -> {error['title']}",
                ftype="ErrorPage: Custom Page",
                source="ErrorPageAnalyzer",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                raw_data=f"path={error['path']}, title={error['title']}",
                tags=["error-page", "custom"]
            ))

    for waf in waf_signatures:
        findings.append(make_finding(
            entity=f"WAF detected from error pages: {waf}",
            ftype="ErrorPage: WAF Detection",
            source="ErrorPageAnalyzer",
            confidence="Medium",
            color="cyan",
            threat_level="Informational",
            tags=["error-page", "waf"]
        ))

    if not found_errors:
        findings.append(make_finding(
            entity="No sensitive information found in error pages (good security posture)",
            ftype="ErrorPage: Clean",
            source="ErrorPageAnalyzer",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["error-page", "clean", "secure"]
        ))

    findings.append(make_finding(
        entity=f"Error Page Analysis: {len(found_errors)} error(s) with info leaks, {len(detected_frameworks)} framework(s), {len(ERROR_PATHS)} paths tested",
        ftype="ErrorPage: Summary",
        source="ErrorPageAnalyzer",
        confidence="High",
        color="red" if found_errors else "emerald",
        threat_level="High Risk" if found_errors else "Informational",
        raw_data=f"error_leaks={len(found_errors)}, frameworks={list(detected_frameworks)}, paths_tested={len(ERROR_PATHS)}",
        tags=["error-page", "summary"]
    ))

    return findings
