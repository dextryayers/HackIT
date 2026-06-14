import httpx
import re
from models import IntelligenceFinding

API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/graphql", "/api/graphql", "/graphiql", "/graphql/explorer",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
    "/swagger/v1", "/swagger/v2",
    "/api-docs", "/api-docs/", "/api/docs", "/api/documentation",
    "/openapi.json", "/api/openapi.json", "/swagger.json",
    "/api/swagger.json", "/v1/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/docs", "/docs/", "/api/doc", "/api-doc",
    "/redoc", "/api/redoc",
    "/health", "/healthz", "/api/health", "/status", "/api/status",
    "/ping", "/api/ping",
    "/info", "/api/info", "/api/version",
    "/auth", "/api/auth", "/login", "/api/login",
    "/register", "/api/register",
    "/token", "/api/token", "/oauth/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/users", "/api/users", "/admin", "/api/admin",
    "/config", "/api/config", "/configuration",
    "/.env", "/api/.env",
    "/robots.txt",
    "/sitemap.xml",
    "/ws", "/api/ws", "/socket.io/",
    "/webhook", "/api/webhook",
    "/callback", "/api/callback",
    "/metrics", "/api/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/api/private", "/private",
    "/internal", "/api/internal",
    "/api/console", "/console",
    "/api/explore", "/explore",
]

API_FRAMEWORK_PATTERNS = {
    "swagger-ui": {"name": "Swagger UI", "color": "emerald"},
    "swagger": {"name": "Swagger UI", "color": "emerald"},
    "redoc": {"name": "ReDoc", "color": "emerald"},
    "graphiql": {"name": "GraphiQL Playground", "color": "emerald"},
    "graphql": {"name": "GraphQL", "color": "cyan"},
    "openapi": {"name": "OpenAPI Spec", "color": "emerald"},
    "rapidoc": {"name": "RapiDoc", "color": "emerald"},
    "elements": {"name": "Stoplight Elements", "color": "emerald"},
    "scalar": {"name": "Scalar API Reference", "color": "emerald"},
    "postman": {"name": "Postman Docs", "color": "orange"},
    "drf-yasg": {"name": "Django REST Swagger", "color": "emerald"},
    "springfox": {"name": "Springfox Swagger", "color": "emerald"},
    "knockout": {"name": "Swashbuckle Swagger", "color": "emerald"},
}

SWAGGER_HTML_PATTERNS = [
    r"swagger-ui", r"swagger", r"openapi", r"api-docs",
    r"SwaggerUIBundle", r"SwaggerUIStandalonePreset",
    r"swagger\.json", r"openapi\.json",
    r"ReDoc", r"redoc\.standalone",
    r"GraphiQL", r"graphql",
    r"RapiDoc", r"rapidoc",
    r"stoplight", r"elements",
    r"scalar",
]

JSON_API_SIGNATURES = {
    "swagger": "2.0",
    "openapi": ["3.0", "3.1"],
}

AUTH_DETECT_PATHS = [
    "/api/auth", "/api/login", "/api/token",
    "/api/register", "/api/signup",
    "/oauth/token", "/api/oauth",
    "/api/v1/auth", "/api/v2/auth",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

async def _probe_path(target: str, path: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    url = f"{base.rstrip('/')}{path}"
    try:
        resp = await client.get(url, timeout=8.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                     "Accept": "application/json, text/html, */*"})

        if resp.status_code in (200, 201, 202, 203, 204, 206):
            body = resp.text[:5000].lower()
            content_type = (resp.headers.get("content-type") or "").lower()
            server = (resp.headers.get("server") or "").lower()
            auth_header = resp.headers.get("www-authenticate", "")

            framework_hit = None
            for fw_key, fw_info in API_FRAMEWORK_PATTERNS.items():
                if fw_key in body:
                    framework_hit = fw_info
                    break

            is_json = "json" in content_type
            has_auth = bool(auth_header)

            raw_snippet = body[:300]

            finding_type = "API Endpoint (Public)"
            color = "purple"
            threat = "Informational"

            if has_auth:
                finding_type = "API Endpoint (Auth Required)"
                threat = "Standard Target"

            findings.append(IntelligenceFinding(
                entity=f"Found: {path}",
                type=finding_type,
                source="APIScanner",
                confidence="High",
                color=color,
                threat_level=threat,
                status="Open",
                resolution=f"Status {resp.status_code}",
                raw_data=f"URL: {url}, CT: {content_type}, Auth: {auth_header[:100]}, Snippet: {raw_snippet}",
                tags=["api", "exposed-endpoint"]
            ))

            if framework_hit:
                findings.append(IntelligenceFinding(
                    entity=f"{framework_hit['name']} detected at {path}",
                    type="API Framework",
                    source="APIScanner",
                    confidence="High",
                    color=framework_hit["color"],
                    threat_level="Standard Target",
                    status="Open",
                    resolution=f"Framework: {framework_hit['name']}",
                    raw_data=f"Framework signature found in {path}: {framework_hit['name']}",
                    tags=["api", "framework"]
                ))

            if is_json and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        for key in data:
                            if key.lower() in ("error", "errors", "message", "code", "status"):
                                continue
                        keys_str = ", ".join(list(data.keys())[:10])
                        findings.append(IntelligenceFinding(
                            entity=f"API JSON response at {path}: {{{keys_str}}}",
                            type="API JSON Structure",
                            source="APIScanner",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Response keys: {keys_str}",
                            tags=["api", "json"]
                        ))
                except Exception:
                    pass

        elif resp.status_code == 401:
            findings.append(IntelligenceFinding(
                entity=f"Protected: {path} (401 Unauthorized)",
                type="API Endpoint (Auth Required)",
                source="APIScanner",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="Authenticated",
                resolution="Requires authentication",
                raw_data=f"URL: {url}, Status: 401",
                tags=["api", "protected"]
            ))

        elif resp.status_code == 403:
            auth_header = resp.headers.get("www-authenticate", "")
            findings.append(IntelligenceFinding(
                entity=f"Forbidden: {path} (403)",
                type="API Endpoint (Restricted)",
                source="APIScanner",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                status="Restricted",
                resolution="Forbidden access",
                raw_data=f"URL: {url}, Auth: {auth_header[:200]}",
                tags=["api", "restricted"]
            ))

        elif resp.status_code == 405:
            findings.append(IntelligenceFinding(
                entity=f"Method not allowed: {path} (405)",
                type="API Endpoint (Exists)",
                source="APIScanner",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Exists",
                resolution="Invalid HTTP method",
                raw_data=f"URL: {url}, Status: 405",
                tags=["api"]
            ))

        elif resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            findings.append(IntelligenceFinding(
                entity=f"Redirect: {path} -> {location[:100]}",
                type="API Endpoint (Redirect)",
                source="APIScanner",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Redirect",
                resolution=location[:200],
                raw_data=f"URL: {url} -> {location}",
                tags=["api"]
            ))

    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    probe_tasks = [_probe_path(target, path, client, findings) for path in API_PATHS]
    await asyncio.gather(*probe_tasks, return_exceptions=True)

    base = f"https://{target}"
    try:
        resp = await client.get(f"{base}/api", timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
        allow_header = resp.headers.get("allow", resp.headers.get("access-control-allow-methods", ""))
        if allow_header:
            findings.append(IntelligenceFinding(
                entity=f"API CORS/Allowed Methods: {allow_header}",
                type="API CORS Configuration",
                source="APIScanner",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                resolution=f"Allowed: {allow_header}",
                raw_data=f"Allow header on /api: {allow_header}",
                tags=["api", "cors"]
            ))
    except Exception:
        pass

    open_count = sum(1 for f in findings if f.status == "Open" or f.status == "Exists")
    auth_count = sum(1 for f in findings if "Auth Required" in f.type or "Restricted" in f.type or f.status == "Authenticated")
    if open_count > 0 or auth_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"API Scan Complete: {open_count} open endpoints, {auth_count} auth-required",
            type="API Scanner Summary",
            source="APIScanner",
            confidence="High",
            color="purple",
            threat_level="Elevated Risk" if open_count > 5 else "Standard Target",
            status="Complete",
            resolution=f"{len(findings)} total findings",
            raw_data=f"Total endpoints probed: {len(API_PATHS)}, Open: {open_count}, Auth: {auth_count}",
            tags=["api", "summary"]
        ))

    return findings


import asyncio
