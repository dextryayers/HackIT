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

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
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
