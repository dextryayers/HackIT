import httpx
import asyncio
import re
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

CDX_API = "https://web.archive.org/cdx/search/cdx"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

SENSITIVE_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*\S+', "Password Disclosure"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*\S+', "API Key Disclosure"),
    (r'(?:secret|secret[_-]?key)\s*[:=]\s*\S+', "Secret Key Disclosure"),
    (r'(?:access[_-]?key|accesskey)\s*[:=]\s*\S+', "Access Key Disclosure"),
    (r'(?:token|bearer|jwt)\s*[:=]\s*\S+', "Token Disclosure"),
    (r'(?:private[_-]?key|-----BEGIN)', "Private Key Disclosure"),
    (r'(?:aws[_-]?key|aws_secret)', "AWS Key Disclosure"),
    (r'(?:ssh[_-]?key|id_rsa|id_dsa)', "SSH Key Disclosure"),
    (r'database_url\s*[:=]\s*\S+', "Database URL Disclosure"),
]

SUBDOMAIN_PATTERN = re.compile(r'https?://([a-zA-Z0-9-]+)\.' + re.escape('example'))
PATH_TAKEOVER_PATTERNS = [
    r'(?:s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)',
    r'(?:github\.io|gitlab\.io|bitbucket\.io|herokuapp\.com)',
    r'(?:netlify\.app|vercel\.app|pages\.dev|firebaseapp\.com)',
    r'(?:surge\.sh|unubo\.app|pantheonsite\.io)',
]

async def query_cdx(domain: str, client: httpx.AsyncClient, limit: int = 300) -> list:
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
                    if isinstance(parts, list) and len(parts) >= 4:
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

async def check_sensitive_content(content: str) -> list:
    findings = []
    for pattern, label in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({"pattern": label, "count": len(matches), "samples": matches[:3]})
    return findings

async def check_takeover_all(urls: list) -> list:
    findings = []
    for r in urls:
        url = r.get("url", "")
        takeover = await check_takeover(url)
        if takeover:
            for tko in takeover:
                findings.append(IntelligenceFinding(
                    entity=f"Subdomain takeover risk: {url[:200]}",
                    type="Archive URL Mining: Takeover Risk",
                    source="Wayback CDX",
                    confidence="Low",
                    color="red",
                    threat_level="High Risk",
                    status="Vulnerable",
                    tags=["takeover", "subdomain"]
                ))
    return findings

async def check_takeover(url: str) -> list:
    findings = []
    for pattern in PATH_TAKEOVER_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            findings.append(f"Takeover pattern: {pattern}")
    return findings

URL_PATTERN_GROUPS = {
    "API Endpoints": [r"/api/", r"/v\d+/", r"/graphql", r"/rest/", r"/endpoint"],
    "Admin Panels": [r"/admin", r"/dashboard", r"/manage", r"/control", r"/panel"],
    "Authentication": [r"/login", r"/signin", r"/auth", r"/oauth", r"/token"],
    "File Upload": [r"/upload", r"/file", r"/attachment", r"/media", r"/assets"],
    "Database": [r"/db", r"/database", r"/sql", r"/mysql", r"/mongo"],
    "Configuration": [r"/config", r"/settings", r"/env", r"/\.env", r"/setup"],
    "Documentation": [r"/docs", r"/swagger", r"/api-doc", r"/help", r"/guide"],
    "Health/Status": [r"/health", r"/status", r"/ping", r"/metrics", r"/info"],
}

async def classify_urls_by_pattern(urls: list) -> list:
    findings = []
    pattern_matches = defaultdict(list)
    for r in urls:
        url = r.get("url", "")
        for group, patterns in URL_PATTERN_GROUPS.items():
            for p in patterns:
                if re.search(p, url, re.IGNORECASE):
                    pattern_matches[group].append(url)
                    break
    for group, matched_urls in sorted(pattern_matches.items(), key=lambda x: -len(x[1])):
        findings.append(IntelligenceFinding(
            entity=f"{group}: {len(matched_urls)} URLs",
            type=f"Archive URL Mining: {group}",
            source="Wayback CDX",
            confidence="Medium",
            color="slate" if group in ("Documentation", "Health/Status") else "orange",
            threat_level="Informational" if group in ("Documentation", "Health/Status") else "Elevated Risk",
            status=f"{len(matched_urls)} matches",
            resolution="",
            tags=["url-mining", "classification", group.lower().replace("/", "-").replace(" ", "-")]
        ))
    return findings

async def analyze_query_strings(urls: list) -> list:
    findings = []
    sensitive_params = {"password", "pass", "pwd", "secret", "token", "api_key", "apikey",
                        "key", "auth", "session", "sid", "csrf", "hash", "signature"}
    found_sensitive = set()
    param_freq = defaultdict(int)
    for r in urls:
        try:
            qs = urlparse(r.get("url", "")).query
            if qs:
                params = qs.split("&")
                for p in params:
                    if "=" in p:
                        name = p.split("=")[0].lower()
                        param_freq[name] += 1
                        if name in sensitive_params:
                            found_sensitive.add(name)
        except:
            pass
    if found_sensitive:
        for sp in found_sensitive:
            findings.append(IntelligenceFinding(
                entity=f"Sensitive parameter in URLs: '{sp}' ({param_freq[sp]} occurrences)",
                type="Archive URL Mining: Sensitive Parameters",
                source="Wayback CDX",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Exposed",
                resolution="",
                tags=["url-mining", "sensitive", "parameter", sp]
            ))
    if param_freq:
        top_params = sorted(param_freq.items(), key=lambda x: -x[1])[:10]
        for name, count in top_params:
            if name not in found_sensitive:
                findings.append(IntelligenceFinding(
                    entity=f"Parameter '{name}': {count} times",
                    type="Archive URL Mining: Common Parameters",
                    source="Wayback CDX",
                    confidence="Low",
                    color="slate",
                    status="Analyzed",
                    resolution="",
                    tags=["url-mining", "parameter", name]
                ))
    return findings

async def extract_js_css_urls(urls: list) -> list:
    findings = []
    js_urls = []
    css_urls = []
    for r in urls:
        url = r.get("url", "")
        if url.endswith(".js"):
            js_urls.append(url)
        elif url.endswith(".css"):
            css_urls.append(url)
    if js_urls:
        findings.append(IntelligenceFinding(
            entity=f"{len(js_urls)} JavaScript files archived (potential secret mining)",
            type="Archive URL Mining: JS Files",
            source="Wayback CDX",
            confidence="Medium",
            color="slate",
            status=f"{len(js_urls)} files",
            resolution="",
            tags=["url-mining", "javascript", "mining"]
        ))
    if css_urls:
        findings.append(IntelligenceFinding(
            entity=f"{len(css_urls)} CSS files archived",
            type="Archive URL Mining: CSS Files",
            source="Wayback CDX",
            confidence="Low",
            color="slate",
            status=f"{len(css_urls)} files",
            resolution="",
            tags=["url-mining", "css"]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
        pattern_results = await classify_urls_by_pattern(cdx_results)
        findings.extend(pattern_results)

        qs_results = await analyze_query_strings(cdx_results)
        findings.extend(qs_results)

        js_css_results = await extract_js_css_urls(cdx_results)
        findings.extend(js_css_results)

        takeover_check = await check_takeover_all(cdx_results)
        findings.extend(takeover_check)
        findings.append(IntelligenceFinding(
            entity=f"Mining {len(cdx_results)} archived URLs for {t}",
            type="Archive URL Mining: Results",
            source="Wayback CDX",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"{len(cdx_results)} URLs",
            resolution=t,
            tags=["url-mining", "archive", "discovery"]
        ))

        param_pattern = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]*)=')
        all_params = defaultdict(int)
        for r in cdx_results:
            try:
                qs = urlparse(r.get("url", "")).query
                params = param_pattern.findall(qs)
                for p in params:
                    all_params[p] += 1
            except:
                pass

        if all_params:
            for param, count in sorted(all_params.items(), key=lambda x: -x[1])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"URL parameter '{param}': {count} occurrences",
                    type="Archive URL Mining: Parameter Discovery",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Discovered",
                    resolution=t,
                    tags=["parameters", param]
                ))

        file_extensions = defaultdict(int)
        for r in cdx_results:
            try:
                path = urlparse(r.get("url", "")).path
                ext = path.split(".")[-1] if "." in path else ""
                if ext and len(ext) < 10:
                    file_extensions[ext] += 1
            except:
                pass

        if file_extensions:
            for ext, count in sorted(file_extensions.items(), key=lambda x: -x[1])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"File extension '.{ext}': {count} URLs",
                    type="Archive URL Mining: Extension Analysis",
                    source="Wayback CDX",
                    confidence="Medium",
                    color="slate",
                    status="Analyzed",
                    resolution=t,
                    tags=["extension", ext]
                ))

        for r in cdx_results[:20]:
            url = r.get("url", "")
            takeover = await check_takeover(url)
            if takeover:
                for tko in takeover:
                    findings.append(IntelligenceFinding(
                        entity=f"Subdomain takeover risk: {url[:200]}",
                        type="Archive URL Mining: Takeover Risk",
                        source="Wayback CDX",
                        confidence="Low",
                        color="red",
                        threat_level="High Risk",
                        status="Vulnerable",
                        resolution=t,
                        tags=["takeover", "subdomain"]
                    ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No archived URLs found for mining",
            type="Archive URL Mining: Complete",
            source="Wayback CDX",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["url-mining", "empty"]
        ))

    return findings
