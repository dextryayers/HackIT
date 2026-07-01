import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

CDX_API = "https://web.archive.org/cdx/search/cdx"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

EXPOSURE_CATEGORIES = {
    "sensitive_files": [".sql", ".bak", ".old", ".backup", ".dump", ".tar.gz", ".zip", ".rar", ".7z", ".log", ".env"],
    "config_files": [".yml", ".yaml", ".json", ".xml", ".conf", ".ini", ".cfg", ".properties"],
    "key_files": [".pem", ".key", ".crt", ".cert", ".p12", ".pfx", ".der", ".csr"],
    "document_files": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt"],
    "source_files": [".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".php", ".rb", ".go", ".rs"],
}

COMMON_PATHS = [
    "/wp-admin", "/wp-content", "/wp-config.php", "/wp-includes",
    "/admin", "/administrator", "/backup", "/config", "/db",
    "/database", "/phpmyadmin", "/mysql", "/api", "/v1", "/v2",
    "/.git", "/.env", "/.htaccess", "/.svn", "/node_modules",
    "/vendor", "/composer.json", "/package.json", "/Dockerfile",
    "/docker-compose.yml", "/docker-compose.yaml", "/Jenkinsfile",
    "/.circleci", "/.github", "/.gitlab-ci.yml", "/.travis.yml",
]

async def query_cdx(domain: str, client: httpx.AsyncClient, limit: int = 500) -> list:
    results = []
    try:
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype,length",
            "limit": str(limit),
            "collapse": "urlkey",
        }
        resp = await client.get(CDX_API, params=params, timeout=30.0,
            headers={"User-Agent": UA})
        if resp.status_code == 200:
            lines = resp.text.strip().splitlines()
            for line in lines[1:]:
                try:
                    parts = json.loads(line) if line.startswith("[") else line.split(" ")
                    if isinstance(parts, list):
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

TECHNOLOGY_PATTERNS = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r"/wp-admin/", r"/wp-json/"],
    "Drupal": [r"/sites/default/", r"/modules/", r"/themes/", r"drupal.js"],
    "Joomla": [r"/components/", r"/modules/", r"/templates/", r"joomla"],
    "Laravel": [r"/vendor/", r"/storage/", r"laravel"],
    "Django": [r"/admin/", r"/static/", r"django"],
    "ASP.NET": [r"\.aspx", r"\.ashx", r"\.asmx", r"web\.config"],
    "Ruby on Rails": [r"/assets/", r"rails"],
    "Express": [r"express"],
    "Flask": [r"flask"],
    "Next.js": [r"/_next/"],
    "Nuxt.js": [r"/_nuxt/"],
    "Gatsby": [r"/static/", r"gatsby"],
    "Cloudflare": [r"cloudflare"],
    "Google Analytics": [r"google-analytics", r"gtag"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Font Awesome": [r"font-awesome", r"fontawesome"],
}

ADDITIONAL_COMMON_PATHS = [
    "/server-status", "/server-info", "/cgi-bin/", "/cgi-bin/test.cgi",
    "/phpinfo.php", "/info.php", "/test.php", "/php.php",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/sitemap.xml",
    "/robots.txt", "/security.txt", "/humans.txt",
    "/.well-known/", "/.well-known/security.txt",
    "/api/health", "/api/status", "/api/v1/", "/api/v2/",
    "/graphql", "/graphiql", "/swagger.json", "/api-docs",
    "/actuator/health", "/actuator/info",
    "/metrics", "/prometheus", "/healthz", "/readyz",
    "/console", "/manager/html", "/manager/status",
    "/actuator", "/swagger-ui.html", "/v2/api-docs",
    "/WEB-INF/web.xml", "/META-INF/", "/application.properties",
    "/application.yml", "/bootstrap.yml", "/logback.xml",
]

async def extract_subdomains_from_cdx(cdx_results: list) -> list:
    subdomains = set()
    for r in cdx_results:
        try:
            host = urlparse(r.get("url", "")).netloc
            parts = host.split(".")
            if len(parts) > 2:
                subdomains.add(".".join(parts[:-2]))
        except:
            pass
    return list(subdomains)

async def detect_technologies_in_urls(cdx_results: list) -> list:
    findings = []
    detected = defaultdict(list)
    for r in cdx_results:
        url = r.get("url", "").lower()
        for tech, patterns in TECHNOLOGY_PATTERNS.items():
            for p in patterns:
                if re.search(p, url):
                    if tech not in detected:
                        detected[tech] = []
                    detected[tech].append(url[:150])
                    break
    for tech, sample_urls in detected.items():
        findings.append(IntelligenceFinding(
            entity=f"Technology detected: {tech} ({len(sample_urls)} indicators)",
            type=f"Exposure Surface: Technology - {tech}",
            source="ExposureSurfaceDeep",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Detected",
            resolution="",
            tags=["exposure", "technology", tech.lower().replace(" ", "-")]
        ))
    return findings

async def analyze_subdomain_structure(cdx_results: list, domain: str) -> list:
    findings = []
    subdomains = set()
    for r in cdx_results:
        try:
            host = urlparse(r.get("url", "")).netloc
            if host.endswith("." + domain):
                subdomains.add(host)
        except:
            pass
    if subdomains:
        findings.append(IntelligenceFinding(
            entity=f"{len(subdomains)} unique subdomains found in archive ({', '.join(sorted(subdomains)[:5])}...)",
            type="Exposure Surface: Subdomain Discovery",
            source="ExposureSurfaceDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"{len(subdomains)} subdomains",
            resolution=domain,
            tags=["exposure", "subdomain", "discovery"]
        ))
        for sub in sorted(subdomains)[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Subdomain: {sub}",
                type="Exposure Surface: Subdomain Detail",
                source="ExposureSurfaceDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Discovered",
                resolution=domain,
                tags=["exposure", "subdomain", sub.replace(".", "-")]
            ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
        tech_results = await detect_technologies_in_urls(cdx_results)
        findings.extend(tech_results)

        sub_results = await analyze_subdomain_structure(cdx_results, t)
        findings.extend(sub_results)
        exposure_count = 0
        for r in cdx_results:
            url = r.get("url", "").lower()
            for cat, extensions in EXPOSURE_CATEGORIES.items():
                if any(url.endswith(ext) for ext in extensions):
                    exposure_count += 1
                    findings.append(IntelligenceFinding(
                        entity=f"{cat.replace('_', ' ').title()}: {url[:200]}",
                        type=f"Exposure Surface: {cat.replace('_', ' ').title()}",
                        source="ExposureSurfaceDeep",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        status="Exposed",
                        resolution=t,
                        tags=["exposure", cat, "archived"]
                    ))
                    break

        if exposure_count:
            findings.append(IntelligenceFinding(
                entity=f"{exposure_count} sensitive files exposed in archive",
                type="Exposure Surface: Total Exposure Count",
                source="ExposureSurfaceDeep",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status=f"{exposure_count} exposures",
                resolution=t,
                tags=["exposure", "total", "summary"]
            ))

    for path in COMMON_PATHS:
        findings.append(IntelligenceFinding(
            entity=f"Common path: {path}",
            type="Exposure Surface: Path Check",
            source="ExposureSurfaceDeep",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Listed",
            resolution=t,
            tags=["exposure", "path", path.replace("/", "-").strip("-")]
        ))

    for path in ADDITIONAL_COMMON_PATHS:
        findings.append(IntelligenceFinding(
            entity=f"Additional path: {path}",
            type="Exposure Surface: Extra Path Check",
            source="ExposureSurfaceDeep",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Listed",
            resolution=t,
            tags=["exposure", "path", "extra", path.replace("/", "-").strip("-")]
        ))

    combined_categories = dict(EXPOSURE_CATEGORIES)
    combined_categories.update(MORE_EXPOSURE_CATEGORIES)
    already_paths = set(p.lower() for p in COMMON_PATHS + ADDITIONAL_COMMON_PATHS)
    unique_extra_paths = [p for p in MORE_COMMON_PATHS if p.lower() not in already_paths]

    for ext, ext_list in MORE_EXPOSURE_CATEGORIES.items():
        findings.append(IntelligenceFinding(
            entity=f"Extended category: {ext} ({len(ext_list)} patterns)",
            type="Exposure Surface: Extended Category",
            source="ExposureSurfaceDeep",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["exposure", "extended", ext]
        ))

    for tech, patterns in MORE_TECHNOLOGY_PATTERNS.items():
        findings.append(IntelligenceFinding(
            entity=f"Tech signature: {tech} ({len(patterns)} patterns)",
            type="Exposure Surface: Extended Technology Pattern",
            source="ExposureSurfaceDeep",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["exposure", "technology", tech.lower().replace(" ", "-")]
        ))

    for path in unique_extra_paths:
        findings.append(IntelligenceFinding(
            entity=f"Extended path: {path}",
            type="Exposure Surface: Extended Path Check",
            source="ExposureSurfaceDeep",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["exposure", "extended-path", path.replace("/", "-").strip("-")]
        ))

    risk_scores_list = []
    for f in findings:
        entity = getattr(f, 'entity', '') or ''
        score = calculate_risk_score(entity)
        risk_scores_list.append(score)
        if score >= 7:
            remediation = get_remediation(entity)
            findings.append(IntelligenceFinding(
                entity=f"High risk exposure: {entity[:200]}",
                type="Exposure Surface: High Risk Item",
                source="ExposureSurfaceDeep",
                confidence="High",
                color="red",
                threat_level=format_risk_label(score),
                resolution=remediation[:300],
                tags=["exposure", "high-risk", "remediation-needed"]
            ))

    coverage = analyze_coverage(findings)
    total_items = sum(coverage.values())
    for cat, count in sorted(coverage.items(), key=lambda x: -x[1]):
        pct = round(count / total_items * 100, 1) if total_items > 0 else 0
        findings.append(IntelligenceFinding(
            entity=f"Coverage: {cat} ({count} items, {pct}%)",
            type="Exposure Surface: Coverage Analysis",
            source="ExposureSurfaceDeep",
            confidence="High",
            color="purple",
            threat_level="Informational",
            tags=["exposure", "coverage", cat.lower().replace(" ", "-").replace("/", "-")]
        ))

    if risk_scores_list:
        avg_risk = sum(risk_scores_list) / len(risk_scores_list)
        max_risk = max(risk_scores_list)
        high_risk_count = sum(1 for s in risk_scores_list if s >= 7)
        findings.append(IntelligenceFinding(
            entity=f"Attack surface: {total_items} items, avg risk {avg_risk:.1f}/10, max {max_risk}/10, {high_risk_count} high-risk",
            type="Exposure Surface: Attack Surface Analysis",
            source="ExposureSurfaceDeep",
            confidence="High",
            color="red" if high_risk_count > 0 else "orange",
            threat_level="High Risk" if high_risk_count > 0 else "Elevated Risk",
            tags=["exposure", "attack-surface", "analysis"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No exposure surface data for {t}",
            type="Exposure Surface: Complete",
            source="ExposureSurfaceDeep",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["exposure", "clean"]
        ))

    return findings
