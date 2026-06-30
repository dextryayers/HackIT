import httpx
import re
import asyncio
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
    "/v1", "/v2", "/v3", "/v4", "/v5",
    "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/", "/api/v5/",
    "/api/v1.0", "/api/v1.1", "/api/v2.0", "/api/v3.0",
    "/graphql", "/api/graphql", "/graphiql", "/graphql/explorer", "/graphql/v1",
    "/graphql/v2", "/graphql/playground", "/api/graphql/v1", "/api/graphql/v2",
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
    "/swagger/v1", "/swagger/v2", "/swagger/v3",
    "/swagger/index.html", "/swagger-ui/index.html",
    "/swagger-resources", "/swagger-resources/",
    "/api-docs", "/api-docs/", "/api/docs", "/api/documentation",
    "/openapi.json", "/api/openapi.json", "/swagger.json",
    "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/api/v3/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml",
    "/docs", "/docs/", "/api/doc", "/api-doc",
    "/redoc", "/api/redoc", "/redoc/", "/api/redoc/",
    "/health", "/healthz", "/api/health", "/status", "/api/status",
    "/readyz", "/livez", "/api/readyz", "/api/livez",
    "/ping", "/api/ping", "/pong", "/api/pong",
    "/info", "/api/info", "/api/version", "/version",
    "/auth", "/api/auth", "/login", "/api/login",
    "/register", "/api/register", "/signup", "/api/signup",
    "/token", "/api/token", "/oauth/token", "/oauth2/token",
    "/oauth", "/api/oauth", "/oauth2", "/api/oauth2",
    "/oauth/authorize", "/oauth2/authorize",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/webfinger",
    "/users", "/api/users", "/admin", "/api/admin",
    "/config", "/api/config", "/configuration",
    "/.env", "/api/.env",
    "/robots.txt", "/sitemap.xml",
    "/ws", "/api/ws", "/socket.io/", "/ws/v1", "/ws/v2",
    "/webhook", "/api/webhook", "/webhooks", "/api/webhooks",
    "/callback", "/api/callback", "/callbacks", "/api/callbacks",
    "/metrics", "/api/metrics", "/prometheus", "/api/prometheus",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/actuator/configprops", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/loggers",
    "/actuator/metrics", "/actuator/prometheus",
    "/actuator/gateway", "/actuator/refresh",
    "/api/private", "/private", "/api/internal", "/internal",
    "/api/console", "/console", "/api/explore", "/explore",
    "/api/healthcheck", "/healthcheck",
    "/api/search", "/search", "/api/query", "/query",
    "/api/upload", "/upload", "/api/download", "/download",
    "/api/export", "/export", "/api/import", "/import",
    "/api/notify", "/notify", "/api/notification", "/notification",
    "/api/payment", "/payment", "/api/checkout", "/checkout",
    "/api/order", "/order", "/api/invoice", "/invoice",
    "/api/subscription", "/subscription",
    "/api/profile", "/profile", "/api/account", "/account",
    "/api/settings", "/settings", "/api/preferences", "/preferences",
    "/api/feedback", "/feedback",
    "/api/report", "/report", "/api/analytics", "/analytics",
    "/api/dashboard", "/dashboard",
    "/api/monitor", "/monitor", "/api/logs", "/logs",
    "/api/cache", "/cache", "/api/queue", "/queue",
    "/api/job", "/job", "/api/task", "/task",
    "/api/schedule", "/schedule", "/api/cron", "/cron",
    "/api/batch", "/batch", "/api/bulk", "/bulk",
    "/api/email", "/email", "/api/sms", "/sms",
    "/api/push", "/push", "/api/message", "/message",
    "/api/chat", "/chat", "/api/room", "/room",
    "/api/file", "/file", "/api/storage", "/storage",
    "/api/blob", "/blob", "/api/asset", "/asset",
    "/api/media", "/media", "/api/image", "/image",
    "/api/video", "/video", "/api/audio", "/audio",
    "/api/document", "/document",
    "/api/template", "/template", "/api/render", "/render",
    "/api/location", "/location", "/api/geocode", "/geocode",
    "/api/map", "/map", "/api/place", "/place",
    "/api/weather", "/weather",
    "/api/translate", "/translate", "/api/language", "/language",
    "/api/verify", "/verify", "/api/validate", "/validate",
    "/api/confirm", "/confirm", "/api/approve", "/approve",
    "/api/reject", "/reject", "/api/cancel", "/cancel",
    "/api/retry", "/retry", "/api/reset", "/reset",
    "/api/forgot", "/forgot", "/api/recover", "/recover",
    "/rest", "/rest/", "/rest/v1", "/rest/v2", "/rest/v3",
    "/api/rest", "/api/rest/v1",
    "/soap", "/soap/", "/api/soap",
    "/xmlrpc", "/xmlrpc/", "/api/xmlrpc",
    "/jsonrpc", "/jsonrpc/", "/api/jsonrpc",
    "/odata", "/odata/", "/api/odata",
    "/service", "/services", "/api/service", "/api/services",
    "/sdk", "/api/sdk",
    "/rpc", "/api/rpc",
    "/trpc", "/api/trpc",
    "/feathers", "/api/feathers",
    "/loopback", "/api/loopback",
    "/parse", "/api/parse",
    "/firebase", "/api/firebase",
    "/supabase", "/api/supabase",
    "/pocketbase", "/api/pocketbase",
    "/directus", "/api/directus",
    "/strapi", "/api/strapi",
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
    "swashbuckle": {"name": "Swashbuckle", "color": "emerald"},
    "nsvag": {"name": "NSwag", "color": "emerald"},
    "api-platform": {"name": "API Platform", "color": "emerald"},
    "apiplatform": {"name": "API Platform", "color": "emerald"},
    "flasgger": {"name": "Flasgger", "color": "emerald"},
    "fastapi": {"name": "FastAPI", "color": "cyan"},
    "django-rest": {"name": "Django REST Framework", "color": "emerald"},
    "drf-spectacular": {"name": "DRF Spectacular", "color": "emerald"},
    "express-swagger": {"name": "Express Swagger", "color": "emerald"},
    "loopback": {"name": "LoopBack API", "color": "cyan"},
    "feathers": {"name": "FeathersJS", "color": "cyan"},
    "parse-dashboard": {"name": "Parse Dashboard", "color": "emerald"},
    "directus": {"name": "Directus", "color": "emerald"},
    "strapi": {"name": "Strapi", "color": "emerald"},
    "supabase": {"name": "Supabase", "color": "emerald"},
    "pocketbase": {"name": "PocketBase", "color": "emerald"},
    "hasura": {"name": "Hasura", "color": "cyan"},
    "graphile": {"name": "Graphile", "color": "cyan"},
    "appolo": {"name": "Apollo GraphQL", "color": "cyan"},
    "apollo": {"name": "Apollo GraphQL", "color": "cyan"},
    "altair": {"name": "Altair GraphQL", "color": "emerald"},
    "playground": {"name": "GraphQL Playground", "color": "emerald"},
    "voyager": {"name": "GraphQL Voyager", "color": "emerald"},
    "spring-restdocs": {"name": "Spring REST Docs", "color": "emerald"},
    "readme.io": {"name": "ReadMe.io", "color": "emerald"},
    "stoplight": {"name": "Stoplight", "color": "emerald"},
}

SWAGGER_HTML_PATTERNS = [
    r"swagger-ui", r"swagger", r"openapi", r"api-docs",
    r"SwaggerUIBundle", r"SwaggerUIStandalonePreset",
    r"swagger\.json", r"openapi\.json",
    r"ReDoc", r"redoc\.standalone",
    r"GraphiQL", r"graphql",
    r"RapiDoc", r"rapidoc",
    r"stoplight", r"elements",
    r"scalar", r"api-platform",
    r"flasgger", r"fastapi",
    r"django-rest-framework", r"drf-spectacular",
    r"nsvag", r"swashbuckle",
    r"hasura", r"graphile",
    r"apollo", r"altair",
    r"voyager", r"loopback",
    r"feathers", r"parse-dashboard",
    r"directus", r"strapi",
    r"supabase", r"pocketbase",
]

JSON_API_SIGNATURES = {
    "swagger": "2.0",
    "openapi": ["3.0", "3.1"],
}

AUTH_DETECT_PATHS = [
    "/api/auth", "/api/login", "/api/token",
    "/api/register", "/api/signup",
    "/oauth/token", "/api/oauth",
    "/api/v1/auth", "/api/v2/auth", "/api/v3/auth",
    "/api/v1/login", "/api/v2/login",
    "/oauth/authorize", "/api/oauth/authorize",
    "/token/refresh", "/api/token/refresh",
    "/auth/refresh", "/api/auth/refresh",
    "/api/logout", "/logout",
    "/api/verify", "/verify",
    "/api/reset", "/reset",
    "/api/forgot", "/forgot",
    "/api/oauth2", "/oauth2",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/api/session", "/session",
    "/api/me", "/me",
    "/api/user", "/user",
    "/api/identity", "/identity",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

AUTH_HEADER_PATTERNS = {
    "Bearer": r"(?i)bearer\s+[A-Za-z0-9_\-\.]+",
    "Basic": r"(?i)basic\s+[A-Za-z0-9+/=]+",
    "APIKey": r"(?i)apikey\s+[A-Za-z0-9_\-]+",
    "JWT": r"(?i)bearer\s+eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "OAuth": r"(?i)oauth\s+[A-Za-z0-9_\-\.]+",
    "Digest": r"(?i)digest\s+[A-Za-z0-9=, ]+",
    "AWS4-HMAC-SHA256": r"(?i)aws4-hmac-sha256\s+[A-Za-z0-9=/+]+",
    "X-API-Key": r"(?i)x-api-key",
    "X-Auth-Token": r"(?i)x-auth-token",
}

API_VERSION_PATTERNS = [
    r"/v(\d+)/", r"/v(\d+)\.(\d+)/",
    r"version[=:]\s*(\d+)",
    r"apiVersion[=:]\s*[\"']?(\d+(?:\.\d+)?)[\"']?",
    r"\"version\":\s*\"(\d+(?:\.\d+)?)\"",
    r"\"apiVersion\":\s*\"(\d+(?:\.\d+)?)\"",
]

CONTENT_TYPE_PATTERNS = {
    "json": r"application/json",
    "xml": r"application/xml",
    "yaml": r"application/x-yaml",
    "form": r"application/x-www-form-urlencoded",
    "multipart": r"multipart/form-data",
    "plain": r"text/plain",
    "html": r"text/html",
    "protobuf": r"application/protobuf",
    "grpc": r"application/grpc",
    "msgpack": r"application/msgpack",
    "graphql-response": r"application/graphql-response+json",
}

UNCOMMON_METHODS = ["TRACE", "CONNECT", "TRACK", "MOVE", "COPY", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "PROPPATCH", "MKCOL"]

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
            body_length = len(resp.text)

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

            auth_type_detected = None
            if auth_header:
                for auth_name, auth_re in AUTH_HEADER_PATTERNS.items():
                    if re.search(auth_re, auth_header):
                        auth_type_detected = auth_name
                        break

            version_detected = None
            for vpat in API_VERSION_PATTERNS:
                vm = re.search(vpat, body)
                if vm:
                    version_detected = vm.group(0)[:50]
                    break

            findings.append(IntelligenceFinding(
                entity=f"Found: {path}",
                type=finding_type,
                source="APIScanner",
                confidence="High",
                color=color,
                threat_level=threat,
                status="Open",
                resolution=f"Status {resp.status_code}",
                raw_data=f"URL: {url}, CT: {content_type}, Auth: {auth_header[:100]}, Size: {body_length}, Snippet: {raw_snippet}",
                tags=["api", "exposed-endpoint"]
            ))

            if body_length > 0:
                findings.append(IntelligenceFinding(
                    entity=f"Response body: {body_length} bytes at {path}",
                    type="API Response Size",
                    source="APIScanner",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Content-Length: {body_length}",
                    tags=["api", "response-size"]
                ))

            if auth_type_detected:
                findings.append(IntelligenceFinding(
                    entity=f"{auth_type_detected} authentication at {path}",
                    type="API Auth Method",
                    source="APIScanner",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Auth header: {auth_header[:200]}",
                    tags=["api", "auth", auth_type_detected.lower()]
                ))

            if version_detected:
                findings.append(IntelligenceFinding(
                    entity=f"API version: {version_detected} at {path}",
                    type="API Versioning",
                    source="APIScanner",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Version pattern: {version_detected}",
                    tags=["api", "versioning"]
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

            if server:
                findings.append(IntelligenceFinding(
                    entity=f"Server: {server[:100]} at {path}",
                    type="API Server Header",
                    source="APIScanner",
                    confidence="High",
                    color="indigo",
                    threat_level="Informational",
                    raw_data=f"Server: {server[:200]}",
                    tags=["api", "server"]
                ))

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

        elif resp.status_code == 501:
            findings.append(IntelligenceFinding(
                entity=f"Not Implemented: {path} (501)",
                type="API Endpoint (Not Implemented)",
                source="APIScanner",
                confidence="High",
                color="yellow",
                threat_level="Informational",
                status="Not Implemented",
                raw_data=f"URL: {url}, Status: 501",
                tags=["api"]
            ))

        elif resp.status_code == 400:
            findings.append(IntelligenceFinding(
                entity=f"Bad Request: {path} (400)",
                type="API Endpoint (Bad Request)",
                source="APIScanner",
                confidence="Medium",
                color="yellow",
                threat_level="Informational",
                raw_data=f"URL: {url}, Status: 400",
                tags=["api"]
            ))

    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass


async def _probe_methods(target: str, path: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    url = f"{base.rstrip('/')}{path}"
    for method in UNCOMMON_METHODS:
        try:
            resp = await client.request(method, url, timeout=5.0, follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"})
            status = resp.status_code
            if status not in (405, 501, 400):
                findings.append(IntelligenceFinding(
                    entity=f"Uncommon method {method} allowed on {path} (HTTP {status})",
                    type="API Uncommon HTTP Method",
                    source="APIScanner",
                    confidence="Medium",
                    color="red" if method in ("TRACE", "CONNECT") else "orange",
                    threat_level="High Risk" if method in ("TRACE", "CONNECT") else "Elevated Risk",
                    raw_data=f"Method {method} returned HTTP {status} on {url}",
                    tags=["api", "http-method", method.lower()]
                ))
        except Exception:
            pass


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        target = urlparse(target).netloc

    probe_tasks = [_probe_path(target, path, client, findings) for path in API_PATHS]
    await asyncio.gather(*probe_tasks, return_exceptions=True)

    method_tasks = [_probe_methods(target, path, client, findings) for path in ["/api", "/api/v1", "/admin", "/"]]
    await asyncio.gather(*method_tasks, return_exceptions=True)

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

    try:
        resp = await client.get(base, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"})
        headers = dict(resp.headers)
        cors_headers = {
            "access-control-allow-origin": "ACAO",
            "access-control-allow-methods": "ACAM",
            "access-control-allow-credentials": "ACAC",
            "access-control-allow-headers": "ACAH",
            "access-control-expose-headers": "ACEH",
            "access-control-max-age": "ACMA",
        }
        for ch, label in cors_headers.items():
            val = headers.get(ch)
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{label}: {val[:100]}",
                    type="CORS Header",
                    source="APIScanner",
                    confidence="High",
                    color="orange" if val == "*" else "emerald",
                    threat_level="Elevated Risk" if val == "*" else "Informational",
                    tags=["api", "cors", label.lower()]
                ))
    except Exception:
        pass

    try:
        resp = await client.options(base, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"})
        allow = resp.headers.get("allow", "")
        if allow:
            findings.append(IntelligenceFinding(
                entity=f"OPTIONS allowed methods: {allow}",
                type="API OPTIONS Discovery",
                source="APIScanner",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=allow[:500],
                tags=["api", "options"]
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
