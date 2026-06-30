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

async def check_takeover(url: str) -> list:
    findings = []
    for pattern in PATH_TAKEOVER_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            findings.append(f"Takeover pattern: {pattern}")
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    cdx_results = await query_cdx(t, client)

    if cdx_results:
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
