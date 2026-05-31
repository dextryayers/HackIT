import re
from urllib.parse import urlparse

import httpx

from osint_common import normalize_target, base_urls, absolute_url, extract_urls, make_finding, favicon_hash


SURFACE_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt", ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association", "humans.txt", "ads.txt", "app-ads.txt",
    "manifest.json", "favicon.ico", "crossdomain.xml", "clientaccesspolicy.xml",
]


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = normalize_target(target)
    working_base = None
    for base in base_urls(domain):
        try:
            resp = await client.get(base, timeout=8.0, follow_redirects=True)
            if resp.status_code < 500:
                working_base = str(resp.url).rstrip("/")
                findings.append(make_finding(str(resp.url), "Web Root", "Web Surface Mapper", "High", "emerald", status=str(resp.status_code)))
                break
        except Exception:
            continue

    if not working_base:
        return findings

    tasks = [client.get(absolute_url(working_base, path), timeout=8.0, follow_redirects=False) for path in SURFACE_PATHS]
    for path, task in zip(SURFACE_PATHS, tasks):
        try:
            resp = await task
            if resp.status_code in (200, 401, 403):
                ftype = "Public Metadata File"
                threat = "Informational"
                color = "slate"
                if path in ("robots.txt", "sitemap.xml"):
                    ftype = "Discovery File"
                if resp.status_code in (401, 403):
                    ftype = "Protected Surface Path"
                    color = "orange"
                    threat = "Elevated Risk"
                findings.append(make_finding(
                    absolute_url(working_base, path), ftype, "Web Surface Mapper", "High", color,
                    threat_level=threat, status=str(resp.status_code), raw_data=resp.text[:1200],
                    tags=["surface", path],
                ))
                if path == "favicon.ico" and resp.content:
                    findings.append(make_finding(favicon_hash(resp.content), "Favicon Hash", "Web Surface Mapper", "High", "purple"))
                if path in ("robots.txt", "sitemap.xml"):
                    for found_url in extract_urls(resp.text)[:80]:
                        findings.append(make_finding(found_url, "Discovered URL", "Web Surface Mapper", "Medium", "blue"))
                    for disallow in re.findall(r"(?im)^\s*disallow:\s*(\S+)", resp.text):
                        findings.append(make_finding(disallow, "Robots Disallow Path", "Web Surface Mapper", "Medium", "orange"))
        except Exception:
            continue

    return findings

