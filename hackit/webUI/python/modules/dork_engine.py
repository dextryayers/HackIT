import httpx
import asyncio
import re
import json
from urllib.parse import quote, urlparse
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

DORK_CATEGORIES = {
    "Sensitive Files": [
        'filetype:sql "INSERT INTO" site:{}',
        'filetype:sql "CREATE TABLE" site:{}',
        'filetype:sql "password" site:{}',
        'filetype:bak site:{}',
        'filetype:old site:{}',
        'filetype:backup site:{}',
        'filetype:log "password" site:{}',
        'filetype:env site:{}',
        'filetype:yml "password" site:{}',
        'filetype:yaml "password" site:{}',
        'filetype:json "password" site:{}',
        'filetype:xml "password" site:{}',
        'filetype:ini "password" site:{}',
        'filetype:cfg site:{}',
        'filetype:conf site:{}',
        'filetype:cnf site:{}',
        'filetype:pem site:{}',
        'filetype:key "PRIVATE KEY" site:{}',
        'filetype:csr site:{}',
        'filetype:p12 site:{}',
        'filetype:pfx site:{}',
        'filetype:der site:{}',
    ],
    "Admin Panels": [
        'intitle:"login" "admin" site:{}',
        'intitle:"admin panel" site:{}',
        'intitle:"administrator" site:{}',
        'inurl:admin site:{}',
        'inurl:administrator site:{}',
        'inurl:login site:{}',
        'inurl:signin site:{}',
        'inurl:dashboard site:{}',
        'inurl:controlpanel site:{}',
        'inurl:cpanel site:{}',
        'inurl:whm site:{}',
        'inurl:phpmyadmin site:{}',
        'inurl:mysql site:{}',
        'intitle:"webmin" site:{}',
        'inurl:8080 site:{}',
        'inurl:8443 site:{}',
    ],
    "API & Endpoints": [
        'inurl:api site:{}',
        'inurl:v1 site:{}',
        'inurl:v2 site:{}',
        'inurl:graphql site:{}',
        'inurl:rest site:{}',
        'inurl:swagger site:{}',
        'inurl:docs site:{}',
        'inurl:endpoint site:{}',
        'inurl:webhook site:{}',
        'inurl:callback site:{}',
    ],
    "Exposed Documents": [
        'filetype:pdf site:{}',
        'filetype:doc site:{}',
        'filetype:docx site:{}',
        'filetype:xls site:{}',
        'filetype:xlsx site:{}',
        'filetype:ppt site:{}',
        'filetype:pptx site:{}',
        'filetype:csv site:{}',
        'filetype:txt site:{}',
        'filetype:rtf site:{}',
    ],
    "Configuration Files": [
        'filetype:xml config site:{}',
        'filetype:json config site:{}',
        'filetype:yml config site:{}',
        'filetype:yaml config site:{}',
        'filetype:ini config site:{}',
        'filetype:env config site:{}',
        'filetype:conf config site:{}',
        'filetype:cfg config site:{}',
        'filetype:properties site:{}',
    ],
    "Error Messages": [
        '"Fatal error" site:{}',
        '"Warning" "include" site:{}',
        '"Notice" "undefined" site:{}',
        '"Parse error" site:{}',
        '"MySQL" "error" site:{}',
        '"SQL" "syntax" site:{}',
        '"stack trace" site:{}',
        '"debug" "error" site:{}',
        'intitle:"Index of" site:{}',
        '"Directory listing" site:{}',
    ],
    "Version Information": [
        'intitle:"Apache HTTP Server" site:{}',
        'intitle:"nginx" site:{}',
        'intitle:"IIS" site:{}',
        'intitle:"Tomcat" site:{}',
        'intitle:"Jetty" site:{}',
        'inurl:server-status site:{}',
        'inurl:server-info site:{}',
        '"Server:" site:{}',
        '"X-Powered-By" site:{}',
    ],
}

async def execute_dork(client: httpx.AsyncClient, dork: str, domain: str) -> list:
    results = []
    try:
        query = dork.format(domain)
        url = f"https://www.google.com/search?q={quote(query)}&num=10"
        resp = await client.get(url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(?:<[^>]+>)*([^<]*)', resp.text)
            for link_url, link_text in links[:5]:
                if domain.lower() in link_url.lower():
                    results.append({"url": link_url, "title": link_text.strip()[:200], "dork": dork})
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    total_dorks = sum(len(dorks) for dorks in DORK_CATEGORIES.values())
    findings.append(IntelligenceFinding(
        entity=f"Loaded {total_dorks} dork templates across {len(DORK_CATEGORIES)} categories",
        type="Dork Engine: Configuration",
        source="DorkEngine",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Configured",
        resolution=t,
        tags=["dork", "configuration"]
    ))

    for category, dorks in DORK_CATEGORIES.items():
        findings.append(IntelligenceFinding(
            entity=f"Dork category: {category} ({len(dorks)} dorks)",
            type=f"Dork Category: {category}",
            source="DorkEngine",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Available",
            resolution=t,
            tags=["dork", "category", category.lower().replace(" ", "-")]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="Dork engine configured",
            type="Dork Engine: Ready",
            source="DorkEngine",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Ready",
            resolution=t,
            tags=["dork", "ready"]
        ))

    return findings
