import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

EDGE_PLATFORMS = {
    "Cloudflare Workers": {
        "cname": [".workers.dev", ".pages.dev", ".r2.dev"],
        "headers": ["cf-ray", "cf-worker", "x-cf-worker"],
        "server": ["cloudflare"],
        "type": "compute"
    },
    "Cloudflare Pages": {
        "cname": [".pages.dev"],
        "headers": ["cf-ray", "x-cf-worker"],
        "server": ["cloudflare"],
        "type": "hosting"
    },
    "Fastly Compute": {
        "cname": [".fastly.net", ".fastly-edge.com"],
        "headers": ["x-fastly-request-id", "x-timer", "x-served-by"],
        "server": ["fastly"],
        "type": "compute"
    },
    "Akamai EdgeWorkers": {
        "cname": [".akamaiedge.net", ".edgesuite.net"],
        "headers": ["x-akamai-transformed"],
        "server": ["akamai"],
        "type": "compute"
    },
    "AWS Lambda@Edge": {
        "cname": [".cloudfront.net"],
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront", "amazon"],
        "type": "compute"
    },
    "CloudFront Functions": {
        "headers": ["x-amz-cf-id"],
        "server": ["cloudfront"],
        "type": "compute",
        "meta": "cloudfront"
    },
    "Fly.io": {
        "cname": [".fly.dev", ".fly.io"],
        "headers": ["fly-request-id"],
        "server": ["fly", "flyio"],
        "type": "compute"
    },
    "Section.io": {
        "cname": [".section.io"],
        "headers": ["x-section"],
        "server": ["section"],
        "type": "edge"
    },
    "Akamai Ion": {
        "cname": [".akamaiedge.net", ".edgesuite.net"],
        "headers": [],
        "server": ["akamai"],
        "type": "performance"
    },
    "Edgio": {
        "cname": [".edg.io", ".llnw.net", ".edgecastcdn.net"],
        "headers": [],
        "server": [],
        "type": "cdn"
    },
    "StackPath Edge Compute": {
        "cname": [".stackpath.com"],
        "headers": ["x-stackpath-id"],
        "server": ["stackpath"],
        "type": "compute"
    },
}

EDGE_DB_PATTERNS = {
    "Cloudflare D1": ["d1.", "d1.workers", "workers.dev"],
    "Fauna": ["fauna.com", "fauna.db", "fauna.app"],
    "PlanetScale": ["planetscale.com", "psdb.cloud"],
    "Neon": ["neon.tech", "neon.build", "neon.db"],
    "Turso": ["turso.dev", "turso.io", "turso.app"],
    "Upstash Redis": ["upstash.io", "upstash.com", "redis.upstash"],
    "Upstash Kafka": ["kafka.upstash.io"],
    "MongoDB Atlas": ["mongodb.net", "atlas.mongodb.com"],
    "Supabase": ["supabase.co", "supabase.in"],
    "Convex": ["convex.cloud", "convex.dev"],
}

EDGE_KV_PATTERNS = {
    "Cloudflare Workers KV": ["kv.workers", "workers.dev", "r2.dev"],
    "Fastly KV": ["fastly-kv", "edge-kv"],
    "Akamai EdgeKV": ["edgekv", "akamai"],
    "Fly Machines": ["fly.io", "fly.dev"],
}

CACHE_BEHAVIOR_HEADERS = ["cf-cache-status", "x-cache", "x-cache-hits", "x-fastly-cache", "age"]

WORKER_URL_PATTERNS = [
    r"(https?://)?[a-zA-Z0-9-]+\.workers\.dev",
    r"(https?://)?[a-zA-Z0-9-]+\.pages\.dev",
    r"(https?://)?[a-zA-Z0-9-]+\.fly\.dev",
    r"(https?://)?[a-zA-Z0-9-]+\.edgecompute\.app",
    r"/cdn-cgi/",
]

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_dns_edge(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for plat, config in EDGE_PLATFORMS.items():
                    for cname_pat in config.get("cname", []):
                        if cname_pat in cname:
                            findings.append(make_finding(
                                entity=plat,
                                type=f"Edge Platform (CNAME): {config['type']}",
                                source="EdgeComputeScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} points to {plat} ({config['type']})",
                                tags=["edge", plat.lower().replace(" ", "-"), config["type"]]
                            ))
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                for db_name, pats in EDGE_DB_PATTERNS.items():
                    for p in pats:
                        if p in txt:
                            findings.append(make_finding(
                                entity=db_name,
                                type="Edge Database (TXT)",
                                source="EdgeComputeScanner",
                                confidence="Medium",
                                color="blue",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Suspected",
                                raw_data=f"TXT record suggests {db_name}: {txt[:100]}",
                                tags=["edge", "database", db_name.lower().replace(" ", "-")]
                            ))
                            break
                for kv_name, pats in EDGE_KV_PATTERNS.items():
                    for p in pats:
                        if p in txt:
                            findings.append(make_finding(
                                entity=kv_name,
                                type="Edge KV Store (TXT)",
                                source="EdgeComputeScanner",
                                confidence="Medium",
                                color="blue",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Suspected",
                                raw_data=f"TXT record suggests {kv_name}: {txt[:100]}",
                                tags=["edge", "kv", kv_name.lower().replace(" ", "-")]
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

        for plat, config in EDGE_PLATFORMS.items():
            found = False
            for h in config.get("headers", []):
                if h in headers:
                    found = True
                    break
            if not found and config.get("server"):
                for s in config["server"]:
                    if s in server:
                        found = True
                        break
            if found:
                findings.append(make_finding(
                    entity=plat,
                    type=f"Edge Platform: {config['type']}",
                    source="EdgeComputeScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"{plat} edge platform detected. Server: {server}",
                    tags=["edge", plat.lower().replace(" ", "-")]
                ))

        for ch in CACHE_BEHAVIOR_HEADERS:
            if ch in headers:
                val = headers[ch]
                findings.append(make_finding(
                    entity=f"Cache Status ({ch}): {val}",
                    type="Edge Cache Behavior",
                    source="EdgeComputeScanner",
                    confidence="Medium",
                    color="slate",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Cache header {ch}: {val}",
                    tags=["edge", "cache"]
                ))

        if "x-amz-cf-pop" in headers:
            pop = headers["x-amz-cf-pop"]
            findings.append(make_finding(
                entity=f"Lambda@Edge POP: {pop}",
                type="Edge Compute Location",
                source="EdgeComputeScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=pop,
                raw_data=f"AWS Lambda@Edge at {pop}",
                tags=["edge", "lambda-edge"]
            ))

        html = resp.text[:50000] if hasattr(resp, "text") else ""
        html_lower = html.lower()
        for pat in WORKER_URL_PATTERNS:
            if re.search(pat, html_lower):
                findings.append(make_finding(
                    entity=f"Edge Worker URL: {pat[:40]}",
                    type="Edge Worker URL Pattern",
                    source="EdgeComputeScanner",
                    confidence="Medium",
                    color="purple",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Edge worker/function URL pattern found: {pat}",
                    tags=["edge", "worker"]
                ))

        for db_name, pats in EDGE_DB_PATTERNS.items():
            for p in pats:
                if p in html_lower:
                    findings.append(make_finding(
                        entity=db_name,
                        type="Edge Database (HTML)",
                        source="EdgeComputeScanner",
                        confidence="Medium",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        raw_data=f"Edge database {db_name} suggested by HTML pattern '{p}'",
                        tags=["edge", "database", db_name.lower().replace(" ", "-")]
                    ))
                    break

        for kv_name, pats in EDGE_KV_PATTERNS.items():
            for p in pats:
                if p in html_lower:
                    findings.append(make_finding(
                        entity=kv_name,
                        type="Edge KV Store (HTML)",
                        source="EdgeComputeScanner",
                        confidence="Medium",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        raw_data=f"Edge KV store {kv_name} suggested by HTML pattern '{p}'",
                        tags=["edge", "kv", kv_name.lower().replace(" ", "-")]
                    ))
                    break

    except Exception as e:
        findings.append(make_finding(
            entity=f"Edge scan error: {str(e)[:100]}",
            type="Edge Scan Error",
            source="EdgeComputeScanner",
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="EdgeComputeScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="EdgeComputeScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_dns_edge(target))
    findings.extend(await _analyze_headers(target, client))

    edge_plat = sum(1 for f in findings if f.type.startswith("Edge Platform"))
    edge_db = sum(1 for f in findings if "Edge Database" in f.type)
    edge_kv = sum(1 for f in findings if "Edge KV" in f.type)
    edge_cache = sum(1 for f in findings if "Cache" in f.type)

    findings.append(make_finding(entity=f"Edge platforms detected: {edge_plat}", type="Edge Platform Count", source="EdgeComputeScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["edge", "summary"]))
    findings.append(make_finding(entity=f"Edge databases: {edge_db}", type="Edge DB Count", source="EdgeComputeScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["edge", "summary"]))
    findings.append(make_finding(entity=f"Edge KV stores: {edge_kv}", type="Edge KV Count", source="EdgeComputeScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["edge", "summary"]))
    findings.append(make_finding(entity=f"Cache behavior indicators: {edge_cache}", type="Edge Cache Count", source="EdgeComputeScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["edge", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="Edge Scan Target", source="EdgeComputeScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["edge", "target"]))
    findings.append(make_finding(entity=f"Total edge compute findings: {len(findings)}", type="Edge Scan Summary", source="EdgeComputeScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["edge", "summary"]))

    return findings
