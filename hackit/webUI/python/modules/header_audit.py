import httpx
import re
from models import IntelligenceFinding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("CSP", "critical", "Prevents XSS and data injection attacks"),
    "Strict-Transport-Security": ("HSTS", "critical", "Enforces HTTPS connections"),
    "X-Frame-Options": ("X-Frame-Options", "high", "Prevents clickjacking"),
    "X-Content-Type-Options": ("X-Content-Type-Options", "high", "Prevents MIME-type sniffing"),
    "Referrer-Policy": ("Referrer-Policy", "medium", "Controls referrer information"),
    "Permissions-Policy": ("Permissions-Policy", "medium", "Controls browser features"),
    "Cross-Origin-Opener-Policy": ("COOP", "medium", "Isolates cross-origin windows"),
    "Cross-Origin-Resource-Policy": ("CORP", "medium", "Controls resource sharing"),
    "Cross-Origin-Embedder-Policy": ("COEP", "medium", "Requires CORP for cross-origin resources"),
}

SECURITY_HEADERS_EXTRA = {
    "X-XSS-Protection": ("X-XSS-Protection", "high", "Enables browser XSS filter (legacy)"),
    "X-Powered-By": ("X-Powered-By", "low", "Information disclosure - technology stack"),
    "X-AspNet-Version": ("X-AspNet-Version", "low", "Information disclosure - ASP.NET version"),
    "X-AspNetMvc-Version": ("X-AspNetMvc-Version", "low", "Information disclosure - ASP.NET MVC version"),
    "X-Generator": ("X-Generator", "low", "Information disclosure - site generator"),
    "X-Drupal-Cache": ("X-Drupal-Cache", "low", "Drupal cache header"),
    "X-Drupal-Dynamic-Cache": ("X-Drupal-Dynamic-Cache", "low", "Drupal dynamic cache"),
    "X-Varnish": ("X-Varnish", "low", "Varnish cache header"),
    "X-Cache": ("X-Cache", "low", "Cache status header"),
    "X-Served-By": ("X-Served-By", "low", "Server identifier"),
    "X-Request-Id": ("X-Request-Id", "low", "Request tracking header"),
    "X-Trace-Id": ("X-Trace-Id", "low", "Trace identifier"),
    "X-Amzn-Trace-Id": ("X-Amzn-Trace-Id", "low", "AWS trace identifier"),
    "X-Runtime": ("X-Runtime", "low", "Application runtime indicator"),
    "X-Version": ("X-Version", "low", "Application version"),
    "X-Content-Duration": ("X-Content-Duration", "low", "Content duration"),
    "X-Frame-Options": ("X-Frame-Options", "high", "Prevents clickjacking (old name)"),
    "X-Content-Security-Policy": ("X-CSP (Legacy)", "medium", "Legary CSP header"),
    "X-WebKit-CSP": ("X-WebKit-CSP", "medium", "Legacy WebKit CSP"),
    "Access-Control-Allow-Origin": ("ACAO", "high", "CORS origin policy"),
    "Access-Control-Allow-Methods": ("ACAM", "medium", "CORS allowed methods"),
    "Access-Control-Allow-Headers": ("ACAH", "medium", "CORS allowed headers"),
    "Access-Control-Allow-Credentials": ("ACAC", "high", "CORS credentials"),
    "Access-Control-Expose-Headers": ("ACEH", "low", "CORS exposed headers"),
    "Access-Control-Max-Age": ("ACMA", "low", "CORS max age"),
    "Timing-Allow-Origin": ("TAO", "low", "Resource Timing API policy"),
    "Set-Cookie": ("Set-Cookie", "high", "Cookie configuration"),
    "Cache-Control": ("Cache-Control", "medium", "Cache policy"),
    "Pragma": ("Pragma", "low", "Legacy cache header"),
    "Expires": ("Expires", "low", "Content expiration"),
    "Last-Modified": ("Last-Modified", "low", "Last modified time"),
    "ETag": ("ETag", "low", "Entity tag"),
    "Link": ("Link", "low", "Link relations"),
    "Location": ("Location", "low", "Redirect target"),
    "Retry-After": ("Retry-After", "low", "Retry policy"),
    "WWW-Authenticate": ("WWW-Authenticate", "high", "Authentication requirement"),
    "Proxy-Authenticate": ("Proxy-Authenticate", "high", "Proxy authentication"),
    "X-Robots-Tag": ("X-Robots-Tag", "low", "Indexing policy"),
    "X-Permitted-Cross-Domain-Policies": ("X-Permitted-Cross-Domain-Policies", "medium", "Flash cross-domain policy"),
    "X-Download-Options": ("X-Download-Options", "medium", "IE download policy"),
    "Public-Key-Pins": ("HPKP", "high", "Certificate pinning (deprecated)"),
    "X-Content-Security-Policy": ("X-CSP", "medium", "Legacy CSP"),
    "Expect-CT": ("Expect-CT", "medium", "Certificate transparency"),
    "NEL": ("NEL", "low", "Network Error Logging"),
    "Report-To": ("Report-To", "low", "Reporting API"),
    "Feature-Policy": ("Feature-Policy", "medium", "Legacy feature policy (use Permissions-Policy)"),
    "X-Edge-Location": ("X-Edge-Location", "low", "Edge location header"),
    "X-Amz-Cf-Pop": ("X-Amz-Cf-Pop", "low", "CloudFront POP location"),
    "X-Amz-Cf-Id": ("X-Amz-Cf-Id", "low", "CloudFront distribution ID"),
    "X-Amzn-RequestId": ("X-Amzn-RequestId", "low", "AWS request ID"),
    "X-Amz-Rid": ("X-Amz-Rid", "low", "AWS request ID"),
    "X-Amz-Request-Id": ("X-Amz-Request-Id", "low", "AWS S3 request ID"),
    "X-Amz-Bucket-Region": ("X-Amz-Bucket-Region", "low", "S3 bucket region"),
    "X-Cache-Hits": ("X-Cache-Hits", "low", "Cache hit count"),
    "X-Cache-Status": ("X-Cache-Status", "low", "Cache status"),
    "X-Sucuri-Cache": ("X-Sucuri-Cache", "low", "Sucuri cache"),
    "X-Sucuri-ID": ("X-Sucuri-ID", "low", "Sucuri WAF ID"),
    "X-Edge-IP": ("X-Edge-IP", "low", "Edge server IP"),
    "X-Cache-Group": ("X-Cache-Group", "low", "Cache group"),
    "X-Host": ("X-Host", "low", "Original host"),
    "X-Forwarded-Proto": ("X-Forwarded-Proto", "low", "Forwarded protocol"),
    "X-Forwarded-For": ("X-Forwarded-For", "low", "Forwarded for"),
    "X-Real-IP": ("X-Real-IP", "low", "Real client IP"),
    "X-Correlation-ID": ("X-Correlation-ID", "low", "Correlation ID"),
    "X-Transaction-ID": ("X-Transaction-ID", "low", "Transaction ID"),
    "X-Session-ID": ("X-Session-ID", "low", "Session ID"),
    "X-Device-ID": ("X-Device-ID", "low", "Device ID"),
    "X-Client-ID": ("X-Client-ID", "low", "Client ID"),
    "X-Api-Version": ("X-Api-Version", "low", "API version header"),
    "X-Deprecation": ("X-Deprecation", "medium", "Deprecation warning"),
    "Sunset": ("Sunset", "medium", "API sunset header"),
    "X-RateLimit-Limit": ("X-RateLimit-Limit", "medium", "Rate limit quota"),
    "X-RateLimit-Remaining": ("X-RateLimit-Remaining", "medium", "Rate limit remaining"),
    "X-RateLimit-Reset": ("X-RateLimit-Reset", "medium", "Rate limit reset"),
    "Retry-After": ("Retry-After", "medium", "Rate limit retry"),
    "X-Content-Type-Options": ("XCTO", "high", "MIME sniffing prevention"),
    "X-Frame-Options": ("XFO", "high", "Clickjacking prevention"),
    "X-XSS-Protection": ("X-XSS", "high", "XSS filter"),
    "Referrer-Policy": ("Referrer-Policy", "medium", "Referrer information control"),
    "Permissions-Policy": ("Permissions-Policy", "medium", "Feature permissions"),
}

HSTS_PRELOAD_PATTERNS = [
    r"max-age=\d+",
    r"includeSubDomains",
    r"preload",
]

CDN_INDICATORS = {
    "cf-ray": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cdn": "Generic CDN",
    "x-sucuri-id": "Sucuri WAF",
    "x-sucuri-cache": "Sucuri Cache",
    "x-encoded-content-encoding": "Reverse Proxy",
    "x-cache": "Cache Server",
    "x-hw": "Hostway",
    "x-nginx-proxy": "Nginx Proxy",
    "x-proxy-cache": "Proxy Cache",
    "x-azure-ref": "Azure CDN",
    "x-amz-cf-pop": "CloudFront POP",
    "x-amz-cf-id": "CloudFront Distribution",
    "x-edge-location": "Edge Location",
    "x-cache-hits": "Cache Hits",
    "x-cache-status": "Cache Status",
}

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Runtime", "X-Version", "Via",
]

SERVER_SIGNATURES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "iis": "Microsoft IIS",
    "lighttpd": "Lighttpd",
    "caddy": "Caddy",
    "openresty": "OpenResty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "node": "Node.js",
    "express": "Express.js",
    "python": "Python",
    "java": "Java",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
    "netty": "Netty",
    "gws": "Google Web Server",
    "gfe": "Google Front End",
    "cloudfront": "AWS CloudFront",
    "amazon": "Amazon Web Server",
    "s3": "AWS S3",
    "azure": "Azure",
    "kestrel": "Kestrel (.NET Core)",
    "yandex": "Yandex",
    "hhvm": "HHVM",
    "openbsd": "OpenBSD httpd",
    "apache-traffic-server": "Apache Traffic Server",
    "ats": "Apache Traffic Server",
    "varnish": "Varnish Cache",
    "squid": "Squid Proxy",
    "haproxy": "HAProxy",
    "envoy": "Envoy Proxy",
    "traefik": "Traefik",
    "nginx plus": "Nginx Plus",
    "cowboy": "Cowboy (Erlang)",
    "mochiweb": "MochiWeb (Erlang)",
    "yaws": "Yaws (Erlang)",
    "webrick": "WEBrick (Ruby)",
    "thin": "Thin (Ruby)",
    "unicorn": "Unicorn (Ruby)",
    "puma": "Puma (Ruby)",
    "phusion": "Passenger (Ruby)",
    "mongrel": "Mongrel (Ruby)",
    "tornado": "Tornado (Python)",
    "twisted": "Twisted (Python)",
    "cherrypy": "CherryPy (Python)",
    "wsgi": "WSGI (Python)",
    "asgi": "ASGI (Python)",
    "aiohttp": "aiohttp (Python)",
    "sanic": "Sanic (Python)",
    "fastapi": "FastAPI (Python)",
    "flask": "Flask (Python)",
    "django": "Django (Python)",
    "jetty": "Eclipse Jetty",
    "oracle": "Oracle Application Server",
    "weblogic": "Oracle WebLogic",
    "websphere": "IBM WebSphere",
    "jboss": "JBoss/WildFly",
    "glassfish": "GlassFish",
    "payara": "Payara",
    "wildfly": "WildFly",
    "resin": "Caucho Resin",
    "litespeed": "LiteSpeed",
    "openlitespeed": "OpenLiteSpeed",
    "lsws": "LiteSpeed Web Server",
    "zeus": "Zeus Web Server",
    "roxy": "Roxy Server",
    "naxsi": "NAXSI WAF",
    "modsecurity": "ModSecurity",
    "comodo": "Comodo WAF",
    "sucuri": "Sucuri WAF",
    "barracuda": "Barracuda WAF",
    "f5": "F5 BIG-IP",
    "bigip": "F5 BIG-IP",
    "a10": "A10 Networks",
    "imperva": "Imperva WAF",
    "incapsula": "Incapsula WAF",
    "radware": "Radware WAF",
    "fortinet": "Fortinet WAF",
    "paloaltonetworks": "Palo Alto WAF",
    "cloudflare": "Cloudflare",
}

CACHE_HEADERS = ["Cache-Control", "Pragma", "Expires", "ETag", "Last-Modified", "Age", "X-Cache", "X-Cache-Hits"]

CACHE_DIRECTIVES = {
    "no-store": "Sensitive - no caching allowed",
    "no-cache": "Must revalidate before use",
    "must-revalidate": "Must revalidate",
    "public": "Publicly cacheable",
    "private": "Private cache only",
    "max-age=0": "No caching",
    "s-maxage": "Shared cache age",
    "proxy-revalidate": "Proxy revalidate",
    "immutable": "Immutable cached resource",
    "stale-while-revalidate": "Stale while revalidate",
}

COOKIE_FLAGS = {
    "secure": "Secure flag - only sent over HTTPS",
    "httponly": "HttpOnly flag - not accessible via JS",
    "samesite": "SameSite attribute",
    "samesite=strict": "SameSite=Strict - CSRF protection",
    "samesite=lax": "SameSite=Lax - moderate CSRF protection",
    "samesite=none": "SameSite=None - no CSRF protection",
    "domain": "Domain attribute",
    "path": "Path attribute",
    "max-age": "Max-Age attribute",
    "expires": "Expires attribute",
}

CORS_MISCONFIG_PATTERNS = [
    (r"\*", "Wildcard origin - allows any site"),
    (r"null", "Null origin - potentially insecure"),
    (r"https?://[^/]*\.[^/]+\.com", "Reflective origin pattern"),
    (r"\.cloudfront\.net", "CloudFront wildcard"),
]

GRADE_MAP = {
    10: "A+",
    9: "A",
    8: "B",
    7: "C",
    6: "D",
    5: "E",
    4: "F",
    3: "F",
    2: "F",
    1: "F",
    0: "F",
}


def _calculate_header_grade(headers: dict) -> tuple:
    score = 0
    max_score = 10
    details = []

    critical_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "XFO",
        "x-content-type-options": "XCTO",
    }
    for header, name in critical_headers.items():
        if header in headers:
            score += 2
            details.append(f"{name}:+2")
        else:
            details.append(f"{name}:0")

    medium_headers = ["referrer-policy", "permissions-policy", "cross-origin-opener-policy"]
    for header in medium_headers:
        if header in headers:
            score += 0.5
            details.append(f"{header}:+0.5")

    if "cache-control" in headers:
        cc = headers["cache-control"].lower()
        if "no-store" in cc:
            score += 0.5
            details.append("Cache:no-store+0.5")

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if not server or server == "":
        score += 0.5
        details.append("Server-hide:+0.5")
    if not powered or powered == "":
        score += 0.5
        details.append("Powered-hide:+0.5")

    grade = GRADE_MAP.get(int(score), "F")
    return grade, score, details


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, timeout=15.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        status = resp.status_code

        findings.append(IntelligenceFinding(
            entity=str(status),
            type="HTTP Status Code",
            source="HeaderAudit",
            confidence="High",
            color="emerald" if status < 400 else "orange",
            threat_level="Informational" if status < 400 else "Standard Target",
            raw_data=f"Response status: {status}"
        ))

        for header_key, (display, severity, desc) in SECURITY_HEADERS.items():
            val = headers.get(header_key.lower())
            if val:
                color = "emerald" if severity == "critical" else ("blue" if severity == "high" else "slate")
                findings.append(IntelligenceFinding(
                    entity=f"{display}: {val[:80]}{'...' if len(val) > 80 else ''}",
                    type=f"Security Header: {display} (Present)",
                    source="HeaderAudit",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Implemented",
                    raw_data=f"{header_key}: {val[:2000]}",
                    tags=[severity]
                ))

                if header_key == "Strict-Transport-Security":
                    hsts_val = val.lower()
                    hsts_features = []
                    if "max-age=" in hsts_val:
                        hsts_features.append("max-age set")
                    if "includesubdomains" in hsts_val:
                        hsts_features.append("includeSubDomains")
                    if "preload" in hsts_val:
                        hsts_features.append("preload ready")
                    if hsts_features:
                        findings.append(IntelligenceFinding(
                            entity=f"HSTS: {', '.join(hsts_features)}",
                            type="HSTS Configuration",
                            source="HeaderAudit",
                            confidence="High",
                            color="emerald" if "preload" in hsts_features else "blue",
                            threat_level="Informational",
                            tags=["hsts", "security"]
                        ))

                if header_key == "Content-Security-Policy":
                    csp_val = val.lower()
                    csp_issues = []
                    if "unsafe-inline" in csp_val:
                        csp_issues.append("allows unsafe-inline")
                    if "unsafe-eval" in csp_val:
                        csp_issues.append("allows unsafe-eval")
                    if "*" in csp_val and "default-src" in csp_val:
                        csp_issues.append("wildcard default-src")
                    if csp_issues:
                        findings.append(IntelligenceFinding(
                            entity=f"CSP issues: {', '.join(csp_issues)}",
                            type="CSP Weakness",
                            source="HeaderAudit",
                            confidence="High",
                            color="red",
                            threat_level="Elevated Risk",
                            raw_data=val[:500],
                            tags=["csp", "weakness"]
                        ))

                if header_key == "Access-Control-Allow-Origin":
                    if val == "*" or "null" in val.lower():
                        findings.append(IntelligenceFinding(
                            entity=f"CORS misconfiguration: ACAO = {val}",
                            type="CORS Misconfiguration",
                            source="HeaderAudit",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            raw_data=val[:500],
                            tags=["cors", "misconfiguration"]
                        ))

            else:
                findings.append(IntelligenceFinding(
                    entity=display,
                    type=f"Missing Security Header: {display}",
                    source="HeaderAudit",
                    confidence="High",
                    color="red" if severity == "critical" else ("orange" if severity == "high" else "yellow"),
                    category="Security & Exposure Analysis",
                    threat_level="High Risk" if severity == "critical" else ("Elevated Risk" if severity == "high" else "Informational"),
                    status="Missing",
                    raw_data=f"Missing: {header_key} - {desc}",
                    tags=[severity]
                ))

        for header_key, (display, severity, desc) in SECURITY_HEADERS_EXTRA.items():
            val = headers.get(header_key.lower())
            if val:
                tags = [severity]
                color = "slate"
                if severity == "high":
                    if header_key in ("Access-Control-Allow-Origin", "WWW-Authenticate", "Set-Cookie"):
                        color = "orange"
                    else:
                        color = "purple"
                findings.append(IntelligenceFinding(
                    entity=f"{display}: {val[:120]}{'...' if len(val) > 120 else ''}",
                    type=f"Extra Header: {display}",
                    source="HeaderAudit",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    status="Present",
                    raw_data=f"{header_key}: {val[:2000]}",
                    tags=tags
                ))

        for key, name in CDN_INDICATORS.items():
            if key in headers:
                findings.append(IntelligenceFinding(
                    entity=name,
                    type="CDN / Reverse Proxy",
                    source="HeaderAudit",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Detected via {key}: {headers[key]}"
                ))

        server = headers.get("server")
        if server:
            server_lower = server.lower()
            matched = False
            for sig, ftype in SERVER_SIGNATURES.items():
                if sig in server_lower:
                    findings.append(IntelligenceFinding(
                        entity=f"{ftype}: {server[:200]}",
                        type="Server Fingerprint",
                        source="HeaderAudit",
                        confidence="High",
                        color="indigo",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Server: {server}",
                        tags=["server", ftype.lower().replace(" ", "-")]
                    ))
                    matched = True
                    break
            if not matched:
                findings.append(IntelligenceFinding(
                    entity=server[:200],
                    type="Web Server (Unknown)",
                    source="HeaderAudit",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Server: {server}"
                ))
        else:
            findings.append(IntelligenceFinding(
                entity="No Server header - information hidden",
                type="Server Header Hidden",
                source="HeaderAudit",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                tags=["security", "server-hiding"]
            ))

        for info_h in INFO_HEADERS:
            val = headers.get(info_h.lower())
            if val and info_h.lower() != "server":
                findings.append(IntelligenceFinding(
                    entity=val[:200],
                    type=f"Technology: {info_h}",
                    source="HeaderAudit",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"{info_h}: {val[:500]}"
                ))

        cookies_raw = headers.get("set-cookie", "")
        if cookies_raw:
            for cookie in cookies_raw.split("\n"):
                cookie = cookie.strip()
                if cookie:
                    parts = cookie.split(";")[0]
                    findings.append(IntelligenceFinding(
                        entity=parts[:150],
                        type="Cookie Set",
                        source="HeaderAudit",
                        confidence="Medium",
                        color="yellow",
                        threat_level="Informational",
                        raw_data=cookie[:500]
                    ))

                    cookie_lower = cookie.lower()
                    cookie_findings = []
                    if "secure" not in cookie_lower:
                        cookie_findings.append("Missing Secure flag")
                    if "httponly" not in cookie_lower:
                        cookie_findings.append("Missing HttpOnly flag")
                    if "samesite" not in cookie_lower:
                        cookie_findings.append("Missing SameSite attribute")
                    if cookie_findings:
                        findings.append(IntelligenceFinding(
                            entity=f"Cookie '{parts[:50]}: {', '.join(cookie_findings)}",
                            type="Cookie Security Issue",
                            source="HeaderAudit",
                            confidence="High",
                            color="orange",
                            threat_level="Elevated Risk",
                            raw_data=cookie[:500],
                            tags=["cookie", "security"]
                        ))

                    if "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                        findings.append(IntelligenceFinding(
                            entity=f"Cookie '{parts[:50]}' SameSite=None without Secure",
                            type="Cookie Vulnerability",
                            source="HeaderAudit",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            raw_data=cookie[:500],
                            tags=["cookie", "vulnerability"]
                        ))

        cache_headers_found = {}
        for ch in CACHE_HEADERS:
            val = headers.get(ch.lower())
            if val:
                cache_headers_found[ch] = val

        if cache_headers_found:
            findings.append(IntelligenceFinding(
                entity=f"Cache headers: {', '.join(cache_headers_found.keys())}",
                type="Cache Headers Present",
                source="HeaderAudit",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=str(cache_headers_found)[:500],
                tags=["cache", "headers"]
            ))

        cc = headers.get("cache-control", "")
        if cc:
            cc_lower = cc.lower()
            for directive, meaning in CACHE_DIRECTIVES.items():
                if directive in cc_lower:
                    findings.append(IntelligenceFinding(
                        entity=f"Cache-Control: {directive} - {meaning}",
                        type="Cache Directive",
                        source="HeaderAudit",
                        confidence="High",
                        color="orange" if "no-store" in directive or "private" in directive else "slate",
                        threat_level="Elevated Risk" if "no-store" in directive else "Informational",
                        tags=["cache", directive]
                    ))

        location = headers.get("location")
        if location:
            findings.append(IntelligenceFinding(
                entity=location[:300],
                type="Redirect Target",
                source="HeaderAudit",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Redirects to: {location}"
            ))

        via = headers.get("via", "")
        if via:
            findings.append(IntelligenceFinding(
                entity=f"Via: {via[:200]}",
                type="Proxy Chain",
                source="HeaderAudit",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["proxy", "via"]
            ))

        x_frame = headers.get("x-frame-options", "").lower()
        if x_frame and x_frame not in ("deny", "sameorigin"):
            findings.append(IntelligenceFinding(
                entity=f"X-Frame-Options: {x_frame} - not DENY/SAMEORIGIN",
                type="Clickjacking Protection Issue",
                source="HeaderAudit",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                tags=["clickjacking"]
            ))

        grade, score, details = _calculate_header_grade(headers)
        findings.append(IntelligenceFinding(
            entity=f"Header Security Grade: {grade} (score: {score}/10)",
            type="Header Security Grade",
            source="HeaderAudit",
            confidence="High",
            color="emerald" if grade in ("A+", "A") else ("orange" if grade in ("B", "C") else "red"),
            threat_level="Informational" if grade in ("A+", "A", "B") else ("Elevated Risk" if grade in ("C", "D") else "High Risk"),
            status=grade,
            raw_data=f"Score: {score}/10 | Details: {', '.join(details)}",
            tags=["grade", "summary"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=str(e)[:150],
            type="Header Audit Error",
            source="HeaderAudit",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))

    return findings


async def _hsts_preload_check(target: str, client: httpx.AsyncClient, findings: list):
    try:
        resp = await client.get(f"https://hstspreload.org/api/v2/status?domain={target}", timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("status", "")
            if status == "preloaded":
                findings.append(IntelligenceFinding(
                    entity=f"HSTS preloaded: {target}",
                    type="HSTS Preload Status",
                    source="HeaderAudit",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["hsts", "preload"]
                ))
            elif status == "pending":
                findings.append(IntelligenceFinding(
                    entity=f"HSTS preload pending: {target}",
                    type="HSTS Preload Status",
                    source="HeaderAudit",
                    confidence="Medium",
                    color="yellow",
                    threat_level="Informational",
                    tags=["hsts", "pending"]
                ))
    except Exception:
        pass


async def _csp_deep_analyze(csp_val: str, findings: list):
    directives = [d.strip() for d in csp_val.split(";") if d.strip()]
    for directive in directives:
        dl = directive.lower()
        if "script-src" in dl:
            if "'unsafe-inline'" in dl:
                findings.append(IntelligenceFinding(
                    entity="CSP script-src allows unsafe-inline",
                    type="CSP Weakness: Unsafe Inline",
                    source="HeaderAudit",
                    confidence="High", color="red",
                    threat_level="High Risk",
                    raw_data=directive, tags=["csp", "xss"]
                ))
            if "'unsafe-eval'" in dl:
                findings.append(IntelligenceFinding(
                    entity="CSP script-src allows unsafe-eval",
                    type="CSP Weakness: Unsafe Eval",
                    source="HeaderAudit",
                    confidence="High", color="orange",
                    threat_level="Elevated Risk",
                    raw_data=directive, tags=["csp", "xss"]
                ))
        if "object-src" in dl and "'none'" not in dl:
            findings.append(IntelligenceFinding(
                entity="CSP object-src not restricted to 'none'",
                type="CSP Weakness: Object Src",
                source="HeaderAudit",
                confidence="Medium", color="orange",
                threat_level="Elevated Risk",
                raw_data=directive, tags=["csp", "plugin"]
            ))
        if "base-uri" in dl and "'none'" not in dl and "'self'" not in dl:
            findings.append(IntelligenceFinding(
                entity="CSP base-uri not restricted",
                type="CSP Weakness: Base URI",
                source="HeaderAudit",
                confidence="Medium", color="orange",
                threat_level="Elevated Risk",
                raw_data=directive, tags=["csp", "base-uri"]
            ))
        if "frame-ancestors" in dl:
            if "'none'" not in dl and "https://" not in dl:
                findings.append(IntelligenceFinding(
                    entity="CSP frame-ancestors may allow clickjacking",
                    type="CSP Weakness: Frame Ancestors",
                    source="HeaderAudit",
                    confidence="Medium", color="orange",
                    threat_level="Elevated Risk",
                    raw_data=directive, tags=["csp", "clickjacking"]
                ))
        if "default-src" in dl and "'none'" not in dl and "'self'" not in dl:
            findings.append(IntelligenceFinding(
                entity="CSP default-src is too permissive",
                type="CSP Weakness: Default Src",
                source="HeaderAudit",
                confidence="Medium", color="yellow",
                threat_level="Informational",
                raw_data=directive, tags=["csp", "default-src"]
            ))
