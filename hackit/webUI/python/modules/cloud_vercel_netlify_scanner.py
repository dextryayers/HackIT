import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

VERCEL_DOMAINS = [".vercel.app", ".now.sh", ".vercel.com"]
NETLIFY_DOMAINS = [".netlify.app", ".netlify.com"]

FRAMEWORK_PATTERNS = [
    ("__NEXT_DATA__", "Next.js", "vercel"),
    ("nuxt", "Nuxt.js", "vercel"),
    ("__NUXT__", "Nuxt.js", "vercel"),
    ("svelte", "SvelteKit", "vercel"),
    ("__svelte", "SvelteKit", "vercel"),
    ("astro", "Astro", "netlify"),
    ("gatsby", "Gatsby", "netlify"),
    ("__GATSBY", "Gatsby", "netlify"),
    ("remix", "Remix", "vercel"),
    ("__remix", "Remix", "vercel"),
    ("hugo", "Hugo", "netlify"),
    ("jekyll", "Jekyll", "netlify"),
    ("11ty", "Eleventy", "netlify"),
    ("eleventy", "Eleventy", "netlify"),
    ("hexo", "Hexo", "netlify"),
    ("vuepress", "VuePress", "netlify"),
    ("docusaurus", "Docusaurus", "netlify"),
    ("gridsome", "Gridsome", "netlify"),
    ("sapper", "Sapper", "vercel"),
    ("zola", "Zola", "netlify"),
    ("middleman", "Middleman", "netlify"),
]

VERCEL_HEADERS = ["x-vercel-id", "x-vercel-cache", "x-vercel-request-id", "x-vercel-deployment-url"]
NETLIFY_HEADERS = ["x-nf-request-id", "x-ns-server", "x-nf-route"]

VERCEL_IPS = [
    (("76.76.21.0", "76.76.21.255"), "Vercel Edge"),
    (("76.76.21.0", "76.76.23.255"), "Vercel Edge"),
]

NETLIFY_IPS = [
    (("75.2.0.0", "75.2.255.255"), "Netlify Edge"),
    (("99.83.0.0", "99.83.255.255"), "Netlify Edge"),
    (("104.198.0.0", "104.198.255.255"), "Netlify Edge"),
]

SERVERLESS_FUNCTION_PATTERNS = [
    "/api/", "/.netlify/functions/", "/api/", "/.vercel/functions/",
    "/.netlify/", "/api/functions/", "/functions/",
]

PREVIEW_DOMAIN_PATTERNS = ["-git-", "-preview-", "-staging-", "-dev-", "-pr-", "-branch-"]

async def _resolve_target(target: str) -> tuple:
    try:
        socket.inet_aton(target)
        return target, True
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, False
    except Exception as e:
        return None, str(e)

async def _check_dns_deployment(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for d in VERCEL_DOMAINS:
                    if d in cname:
                        findings.append(IntelligenceFinding(
                            entity="Vercel Deployment",
                            type="Vercel Platform (CNAME)",
                            source="VercelNetlifyScanner",
                            confidence="High",
                            color="purple",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=cname,
                            raw_data=f"CNAME {cname} points to Vercel ({d})",
                            tags=["cloud", "vercel", "deployment"]
                        ))
                for d in NETLIFY_DOMAINS:
                    if d in cname:
                        findings.append(IntelligenceFinding(
                            entity="Netlify Deployment",
                            type="Netlify Platform (CNAME)",
                            source="VercelNetlifyScanner",
                            confidence="High",
                            color="purple",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=cname,
                            raw_data=f"CNAME {cname} points to Netlify ({d})",
                            tags=["cloud", "netlify", "deployment"]
                        ))
        except Exception:
            pass
        try:
            answers_a = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'A'))
            for r in answers_a:
                ip_str = str(r)
                parts = ip_str.split(".")
                try:
                    ip_int = (int(parts[0])<<24)+(int(parts[1])<<16)+(int(parts[2])<<8)+int(parts[3])
                    for (s, e), rgn in VERCEL_IPS + NETLIFY_IPS:
                        sp = s.split("."); ep = e.split(".")
                        si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                        ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                        if si <= ip_int <= ei:
                            plat = "Vercel" if "Vercel" in rgn else "Netlify"
                            findings.append(IntelligenceFinding(
                                entity=f"{plat} Edge ({ip_str})",
                                type=f"{plat} IP Range",
                                source="VercelNetlifyScanner",
                                confidence="High",
                                color="orange",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Verified",
                                resolution=ip_str,
                                raw_data=f"IP {ip_str} in {plat} edge range",
                                tags=["cloud", plat.lower(), "edge"]
                            ))
                except Exception:
                    pass
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                if "vercel" in txt or "netlify" in txt:
                    plat = "Vercel" if "vercel" in txt else "Netlify"
                    findings.append(IntelligenceFinding(
                        entity=f"{plat} (TXT Verification)",
                        type=f"{plat} Domain Verification",
                        source="VercelNetlifyScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Verified",
                        raw_data=f"TXT: {txt[:100]}",
                        tags=["cloud", plat.lower(), "verification"]
                    ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await client.get(base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)

        for h in VERCEL_HEADERS:
            if h in headers:
                val = headers.get(h, "")
                findings.append(IntelligenceFinding(
                    entity=f"Vercel ({h}: {val[:50]})",
                    type="Vercel Platform (Header)",
                    source="VercelNetlifyScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"Vercel header {h}: {val}",
                    tags=["cloud", "vercel"]
                ))
        for h in NETLIFY_HEADERS:
            if h in headers:
                val = headers.get(h, "")
                findings.append(IntelligenceFinding(
                    entity=f"Netlify ({h}: {val[:50]})",
                    type="Netlify Platform (Header)",
                    source="VercelNetlifyScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"Netlify header {h}: {val}",
                    tags=["cloud", "netlify"]
                ))

        server = headers.get("server", "").lower()
        if "vercel" in server:
            findings.append(IntelligenceFinding(
                entity="Vercel (Server Header)",
                type="Vercel Platform (Header)",
                source="VercelNetlifyScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"Server header: {server}",
                tags=["cloud", "vercel"]
            ))
        if "netlify" in server:
            findings.append(IntelligenceFinding(
                entity="Netlify (Server Header)",
                type="Netlify Platform (Header)",
                source="VercelNetlifyScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"Server header: {server}",
                tags=["cloud", "netlify"]
            ))

        html = resp.text[:100000] if hasattr(resp, "text") else ""
        html_lower = html.lower()

        for pattern, fw_name, platform in FRAMEWORK_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                findings.append(IntelligenceFinding(
                    entity=f"{fw_name} Framework",
                    type=f"Framework ({platform.capitalize()})",
                    source="VercelNetlifyScanner",
                    confidence="High",
                    color="green",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Framework {fw_name} detected via '{pattern}' pattern",
                    tags=["tech", "framework", platform, fw_name.lower().replace(" ", "-")]
                ))

        for pat in SERVERLESS_FUNCTION_PATTERNS:
            if pat in html_lower:
                plat = "vercel" if "vercel" in pat else "netlify"
                findings.append(IntelligenceFinding(
                    entity=f"Serverless Function ({pat})",
                    type=f"Serverless Function ({plat.capitalize()})",
                    source="VercelNetlifyScanner",
                    confidence="Medium",
                    color="purple",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Serverless function path pattern found: {pat}",
                    tags=["cloud", plat, "serverless"]
                ))

        for pat in PREVIEW_DOMAIN_PATTERNS:
            if pat in target.lower():
                findings.append(IntelligenceFinding(
                    entity=f"Preview/Staging Deployment ({pat})",
                    type="Preview Deployment",
                    source="VercelNetlifyScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"URL pattern '{pat}' indicates preview/staging deployment",
                    tags=["cloud", "preview", "staging"]
                ))

        if "edge" in html_lower and ("vercel" in html_lower or "netlify" in html_lower):
            findings.append(IntelligenceFinding(
                entity="Edge Functions / Middleware",
                type="Edge Compute",
                source="VercelNetlifyScanner",
                confidence="Medium",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="Edge functions/middleware detected in page content",
                tags=["cloud", "edge"]
            ))

        cache_headers = ["x-vercel-cache", "x-nf-cache", "cf-cache-status"]
        for ch in cache_headers:
            if ch in headers:
                findings.append(IntelligenceFinding(
                    entity=f"CDN Caching ({headers[ch]})",
                    type="CDN Cache Status",
                    source="VercelNetlifyScanner",
                    confidence="Medium",
                    color="slate",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Cache header {ch}: {headers[ch]}",
                    tags=["cdn", "cache"]
                ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="VercelNetlify Scan Error",
            source="VercelNetlifyScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="VercelNetlifyScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="VercelNetlifyScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_dns_deployment(target))
    findings.extend(await _analyze_headers(target, client))

    is_vercel = any(f.type.startswith("Vercel") for f in findings)
    is_netlify = any(f.type.startswith("Netlify") for f in findings)
    fw_count = sum(1 for f in findings if f.type == "Framework (vercel)" or f.type == "Framework (netlify)")

    findings.append(IntelligenceFinding(
        entity=f"Platform: {'Vercel' if is_vercel else 'Netlify' if is_netlify else 'Unknown'}",
        type="Deployment Platform",
        source="VercelNetlifyScanner",
        confidence="High",
        color="purple",
        category="Cloud / Infrastructure OSINT",
        threat_level="Informational",
        status="Identified",
        tags=["cloud", "platform"]
    ))
    findings.append(IntelligenceFinding(entity=f"Frameworks detected: {fw_count}", type="Framework Count", source="VercelNetlifyScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["tech", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="Vercel/Netlify Scan Target", source="VercelNetlifyScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["target"]))
    findings.append(IntelligenceFinding(entity=f"Resolved IP: {ip}", type="Vercel/Netlify Resolved IP", source="VercelNetlifyScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["ip"]))
    findings.append(IntelligenceFinding(entity=f"Total findings: {len(findings)}", type="Vercel/Netlify Scan Summary", source="VercelNetlifyScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["summary"]))

    return findings
