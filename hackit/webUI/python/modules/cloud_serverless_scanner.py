import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

SERVERLESS_PLATFORMS = {
    "AWS Lambda + API Gateway": ["lambda.amazonaws.com", "lambda-url", "execute-api.", "amazonaws.com"],
    "GCP Cloud Functions": ["cloudfunctions.net", "cloudfunctions.googleapis.com"],
    "Azure Functions": ["azurewebsites.net", "azurefd.net", "scm.azurewebsites"],
    "Cloudflare Workers": ["workers.dev", "pages.dev", "worker"],
    "Vercel Functions": ["vercel.app", "vercel.com", ".now.sh"],
    "Netlify Functions": ["netlify.app", ".netlify.com", ".netlify/functions"],
    "Supabase Edge Functions": ["supabase.co", "supabase.in", "functions.supabase"],
    "Deno Deploy": ["deno.dev", "deno.com"],
    "Fly.io": ["fly.dev", "fly.io"],
    "Railway": ["railway.app", "railway.com"],
    "Koyeb": ["koyeb.app", "koyeb.com"],
    "DigitalOcean Functions": ["faas.digitalocean", "functions.digitalocean"],
    "Oracle Functions": ["functions.oraclecloud.com", "fn.oraclecloud"],
    "IBM Cloud Functions": ["functions.cloud.ibm", "cloudfunctions.net"],
    "Alibaba FC": ["fc.aliyuncs.com", "functioncompute"],
    "Tencent SCF": ["scf.tencentcloud.com", "scf.qcloud.com"],
    "Vercel Edge Functions": ["edge.vercel", "vercel.app"],
    "Netlify Edge Functions": ["edge.netlify", "netlify.app"],
    "Cloudflare Pages Functions": ["pages.dev", "functions.pages"],
    "Fly Machines": ["fly.io", ".fly.dev"],
}

FUNCTION_URL_PATTERNS = [
    r"/(api|functions|lambda|fn|scf|fc)/([a-zA-Z0-9_-]+)",
    r"\.netlify/functions/",
    r"\.vercel\.app/api/",
    r"cloudfunctions\.net/",
    r"workers\.dev/",
    r"pages\.dev/",
    r"deno\.dev/",
    r"fly\.dev/",
    r"railway\.app/",
    r"koyeb\.app/",
    r"supabase\.co/functions/",
]

CDN_PLATFORMS = {
    "Cloudflare Workers KV": ["workers.dev", "kv.workers"],
    "Vercel Edge Network": ["vercel.app", "edge.vercel"],
    "Netlify Edge CDN": ["netlify.app", "edge.netlify"],
    "Fly Anycast": ["fly.io"],
    "Fastly Compute": ["compute-edge", "fastly-edge"],
    "Akamai Edge": ["akamai", "edgesuite.net", "edgekey.net"],
}

COLD_START_HEADERS = ["x-lambda-coldstart", "x-coldstart", "x-vercel-coldstart", "x-nf-coldstart"]

DB_PATTERNS = {
    "Supabase": ["supabase.co", "supabase.in", "db.supabase"],
    "PlanetScale": ["planetscale.com", "psdb"],
    "Neon": ["neon.tech", "neon.build"],
    "Turso": ["turso.dev", "turso.io"],
    "Fauna": ["fauna.com", "fauna.db"],
    "D1 (Cloudflare)": ["d1.workers", "workers.dev"],
    "Upstash": ["upstash.io", "upstash.com"],
    "MongoDB Atlas": ["mongodb.net", "atlas.mongodb"],
    "Redis Cloud": ["redis.cloud", "redis.com"],
    "Convex": ["convex.cloud", "convex.dev"],
}

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_dns_platforms(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for plat, patterns in SERVERLESS_PLATFORMS.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=plat,
                                type="Serverless Platform (CNAME)",
                                source="ServerlessScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} points to {plat} (pattern: {pat})",
                                tags=["cloud", "serverless", plat.lower().replace(" ", "-").replace("+", "")]
                            ))
                            break
        except Exception:
            pass
        for plat, patterns in CDN_PLATFORMS.items():
            for pat in patterns:
                if pat in cname.lower() if 'cname' in dir() else False:
                    try:
                        answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
                        for r in answers:
                            cname = str(r.target).rstrip('.').lower()
                            if pat in cname:
                                findings.append(make_finding(
                                    entity=plat,
                                    type="Serverless CDN Platform",
                                    source="ServerlessScanner",
                                    confidence="High",
                                    color="blue",
                                    category="Cloud / Infrastructure OSINT",
                                    threat_level="Informational",
                                    status="Detected",
                                    resolution=cname,
                                    raw_data=f"CNAME {cname} indicates {plat} CDN",
                                    tags=["cloud", "serverless-cdn", plat.lower().replace(" ", "-")]
                                ))
                    except Exception:
                        pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                for plat, patterns in SERVERLESS_PLATFORMS.items():
                    for pat in patterns:
                        if pat in txt:
                            findings.append(make_finding(
                                entity=f"{plat} (TXT)",
                                type=f"Serverless Platform (TXT)",
                                source="ServerlessScanner",
                                confidence="Medium",
                                color="blue",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                raw_data=f"TXT record matches {plat}: {txt[:100]}",
                                tags=["cloud", "serverless", plat.lower().replace(" ", "-").replace("+", "")]
                            ))
                            break
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        for ch in COLD_START_HEADERS:
            if ch in headers:
                findings.append(make_finding(
                    entity=f"Cold Start Indicator ({ch})",
                    type="Serverless Cold Start",
                    source="ServerlessScanner",
                    confidence="High",
                    color="blue",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Cold start header {ch}: {headers[ch]}",
                    tags=["cloud", "serverless", "cold-start"]
                ))

        for plat_name, patterns in SERVERLESS_PLATFORMS.items():
            for pat in patterns:
                if pat in server or pat in all_vals:
                    findings.append(make_finding(
                        entity=plat_name,
                        type="Serverless Platform (Header)",
                        source="ServerlessScanner",
                        confidence="High",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Server/Via header matches {plat_name}: {server}",
                        tags=["cloud", "serverless", plat_name.lower().replace(" ", "-").replace("+", "")]
                    ))
                    break

        html = resp.text[:100000] if hasattr(resp, "text") else ""
        html_lower = html.lower()

        for pat in FUNCTION_URL_PATTERNS:
            if re.search(pat, html_lower):
                platform_hint = "serverless"
                if "vercel" in pat:
                    platform_hint = "vercel"
                elif "netlify" in pat:
                    platform_hint = "netlify"
                elif "cloudfunctions" in pat:
                    platform_hint = "gcp"
                elif "workers" in pat:
                    platform_hint = "cloudflare"
                elif "supabase" in pat:
                    platform_hint = "supabase"
                findings.append(make_finding(
                    entity=f"Function URL pattern: {pat}",
                    type=f"Serverless Function URL ({platform_hint})",
                    source="ServerlessScanner",
                    confidence="Medium",
                    color="purple",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Serverless function URL pattern found: {pat}",
                    tags=["cloud", platform_hint, "serverless", "function-url"]
                ))

        for db_name, db_patterns in DB_PATTERNS.items():
            for p in db_patterns:
                if p in html_lower:
                    findings.append(make_finding(
                        entity=f"{db_name} Database",
                        type="Serverless Database",
                        source="ServerlessScanner",
                        confidence="Medium",
                        color="purple",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        raw_data=f"Database {db_name} pattern '{p}' found in HTML",
                        tags=["cloud", "database", db_name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                    ))
                    break

    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Serverless Scan Error",
            source="ServerlessScanner",
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="ServerlessScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="ServerlessScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_dns_platforms(target))
    findings.extend(await _analyze_headers(target, client))

    plat_count = sum(1 for f in findings if "Serverless Platform" in f.type)
    fn_count = sum(1 for f in findings if "Function URL" in f.type)
    db_count = sum(1 for f in findings if "Serverless Database" in f.type)

    findings.append(make_finding(entity=f"Serverless platforms: {plat_count}", type="Serverless Platform Count", source="ServerlessScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["serverless", "summary"]))
    findings.append(make_finding(entity=f"Function URL patterns: {fn_count}", type="Serverless Function Count", source="ServerlessScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["serverless", "summary"]))
    findings.append(make_finding(entity=f"Serverless DBs detected: {db_count}", type="Serverless DB Count", source="ServerlessScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["serverless", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="Serverless Scan Target", source="ServerlessScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["serverless", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="Serverless Resolved IP", source="ServerlessScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["serverless", "ip"]))
    findings.append(make_finding(entity=f"Total serverless findings: {len(findings)}", type="Serverless Scan Summary", source="ServerlessScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["serverless", "summary"]))

    return findings
