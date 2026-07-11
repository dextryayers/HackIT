import httpx
import re
import asyncio
import json
from urllib.parse import urlparse
from module_common import safe_fetch, make_finding
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
    "/api/v6", "/api/v7", "/api/v8", "/api/v9", "/api/v10",
    "/v6", "/v7", "/v8", "/v9", "/v10",
    "/api/v6/", "/api/v7/", "/api/v8/", "/api/v9/", "/api/v10/",
    "/api/latest", "/api/stable", "/api/edge", "/api/canary", "/api/beta",
    "/api/alpha", "/api/deprecated", "/api/experimental", "/api/rfc",
    "/api/hub", "/api/billing", "/api/inventory", "/api/warehouse",
    "/api/fulfillment", "/api/shipping", "/api/tracking", "/api/logistics",
    "/api/catalog", "/api/catalogue", "/api/merchant", "/api/vendor",
    "/api/reseller", "/api/distributor", "/api/franchise", "/api/wholesale",
    "/api/retail", "/api/pos", "/api/terminal", "/api/register",
    "/api/compliance", "/api/audit", "/api/tax", "/api/taxonomy",
    "/api/regulation", "/api/license", "/api/permit", "/api/certification",
    "/api/identity", "/api/verification", "/api/kba", "/api/mfa",
    "/api/2fa", "/api/totp", "/api/hotp", "/api/u2f",
    "/api/fido", "/api/webauthn", "/api/passkey", "/api/biometric",
    "/api/kyc", "/api/aml", "/api/sanctions", "/api/screening",
    "/api/onboarding", "/api/offboarding", "/api/provisioning",
    "/api/delegation", "/api/escalation", "/api/routing",
    "/api/federation", "/api/directory", "/api/ldap", "/api/scim",
    "/api/saml", "/api/oidc", "/api/cas", "/api/sso",
    "/api/idp", "/api/sp", "/api/relying-party",
    "/api/entitlement", "/api/permission", "/api/role", "/api/scope",
    "/api/namespace", "/api/tenant", "/api/organization", "/api/division",
    "/api/department", "/api/unit", "/api/cost-center", "/api/budget",
    "/api/forecast", "/api/revenue", "/api/profit", "/api/margin",
    "/api/expense", "/api/refund", "/api/dispute", "/api/chargeback",
    "/api/collection", "/api/reconciliation", "/api/settlement",
    "/api/payout", "/api/commission", "/api/royalty", "/api/dividend",
    "/api/trading", "/api/exchange", "/api/market", "/api/auction",
    "/api/bid", "/api/offer", "/api/listing", "/api/classified",
    "/api/registry", "/api/repository", "/api/artifact", "/api/package",
    "/api/release", "/api/changelog", "/api/migration", "/api/rollback",
    "/api/snapshot", "/api/backup", "/api/restore", "/api/archive",
    "/api/retention", "/api/purge", "/api/cleanup", "/api/garbage",
    "/api/compaction", "/api/defrag", "/api/optimize", "/api/analyze",
    "/api/explain", "/api/profile", "/api/trace", "/api/debug",
    "/api/benchmark", "/api/stress", "/api/load", "/api/performance",
    "/api/latency", "/api/throughput", "/api/saturation", "/api/availability",
    "/api/reliability", "/api/resilience", "/api/failover", "/api/replica",
    "/api/shard", "/api/partition", "/api/distribution", "/api/cluster",
    "/api/node", "/api/peer", "/api/gossip", "/api/consensus",
    "/api/election", "/api/leader", "/api/follower", "/api/observer",
    "/api/coordinator", "/api/orchestrator", "/api/scheduler",
    "/api/workflow", "/api/pipeline", "/api/step", "/api/stage",
    "/api/phase", "/api/milestone", "/api/gate", "/api/checkpoint",
    "/api/review", "/api/approval", "/api/signoff", "/api/attestation",
    "/api/ack", "/api/nack", "/api/heartbeat", "/api/keepalive",
    "/api/discover", "/api/register", "/api/subscribe", "/api/unsubscribe",
    "/api/publish", "/api/broadcast", "/api/multicast", "/api/anycast",
    "/api/unicast", "/api/relay", "/api/bridge", "/api/gateway",
    "/api/tunnel", "/api/proxy", "/api/forward", "/api/redirect",
    "/api/dns", "/api/dhcp", "/api/ntp", "/api/ldap",
    "/api/smtp", "/api/pop3", "/api/imap", "/api/sieve",
    "/api/mta", "/api/mda", "/api/mua", "/api/ml",
    "/api/fax", "/api/voip", "/api/sip", "/api/rtp",
    "/api/rtsp", "/api/hls", "/api/dash", "/api/mpeg",
    "/api/stream", "/api/ingest", "/api/transcode", "/api/package",
    "/api/playback", "/api/recording", "/api/vod", "/api/live",
    "/api/clip", "/api/thumbnail", "/api/preview", "/api/poster",
    "/api/segment", "/api/playlist", "/api/channel", "/api/station",
    "/api/schedule", "/api/guide", "/api/rating", "/api/review",
    "/api/collection", "/api/folder", "/api/album", "/api/playlist",
    "/api/library", "/api/shelf", "/api/tag", "/api/category",
    "/api/facet", "/api/filter", "/api/sort", "/api/paginate",
    "/api/cursor", "/api/offset", "/api/limit", "/api/page",
    "/api/scroll", "/api/search_after", "/api/search_before",
    "/api/aggregation", "/api/facet", "/api/bucket", "/api/metric",
    "/api/dimension", "/api/hierarchy", "/api/rollup", "/api/drilldown",
    "/api/pivot", "/api/cube", "/api/olap", "/api/datamart",
    "/api/warehouse", "/api/lake", "/api/delta", "/api/iceberg",
    "/api/hudi", "/api/parquet", "/api/avro", "/api/arrow",
    "/api/flight", "/api/grpc", "/api/protobuf", "/api/thrift",
    "/api/avro", "/api/flatbuffers", "/api/capnproto",
    "/api/soap/v1", "/api/soap/v2", "/api/soap/action",
    "/rest/v4", "/rest/v5", "/rest/v6", "/rest/v7",
    "/api/v1/graphql", "/api/v2/graphql", "/api/v3/graphql",
    "/subscriptions", "/api/subscriptions", "/subscription/v1",
    "/events", "/api/events", "/event/v1",
    "/sse", "/api/sse", "/eventsource",
    "/streaming", "/api/streaming",
    "/realtime", "/api/realtime",
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
    "NTLM": r"(?i)ntlm\s+[A-Za-z0-9+/=]+",
    "Negotiate": r"(?i)negotiate\s+[A-Za-z0-9+/=]+",
    "Hawk": r"(?i)hawk\s+[A-Za-z0-9=, ]+",
    "Signature": r"(?i)signature\s+[A-Za-z0-9=, ]+",
    "DPoP": r"(?i)dpop\s+[A-Za-z0-9_\-\.]+",
    "Mutual": r"(?i)mutual\s+[A-Za-z0-9=, ]+",
    "SCRAM": r"(?i)scram\s+[A-Za-z0-9=, ]+",
    "AWS-Signature": r"(?i)aws\s*[-_]?signature\s*[-_]?version\s*[-_]?4",
    "GCP-Bearer": r"(?i)ya29\.[A-Za-z0-9_\-]+",
    "GitHub-Token": r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
    "GitLab-Token": r"(?i)glpat-[A-Za-z0-9_\-]{20,}",
    "Slack-Token": r"(?i)xox[abposr]-[A-Za-z0-9\-]{10,}",
    "Stripe-Signature": r"(?i)stripe-signature\s+[A-Za-z0-9=, ]+",
    "X-Forwarded-User": r"(?i)x-forwarded-user",
    "X-Real-IP": r"(?i)x-real-ip",
    "CF-Access": r"(?i)cf-access-token",
    "Authorization-User": r"(?i)x-authorization-user",
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
        resp = await safe_fetch(client, url, timeout=8.0, follow_redirects=True,
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

            findings.append(make_finding(
                entity=f"Found: {path}",
                ftype=finding_type,
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
                findings.append(make_finding(
                    entity=f"Response body: {body_length} bytes at {path}",
                    ftype="API Response Size",
                    source="APIScanner",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Content-Length: {body_length}",
                    tags=["api", "response-size"]
                ))

            if auth_type_detected:
                findings.append(make_finding(
                    entity=f"{auth_type_detected} authentication at {path}",
                    ftype="API Auth Method",
                    source="APIScanner",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Auth header: {auth_header[:200]}",
                    tags=["api", "auth", auth_type_detected.lower()]
                ))

            if version_detected:
                findings.append(make_finding(
                    entity=f"API version: {version_detected} at {path}",
                    ftype="API Versioning",
                    source="APIScanner",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Version pattern: {version_detected}",
                    tags=["api", "versioning"]
                ))

            if framework_hit:
                findings.append(make_finding(
                    entity=f"{framework_hit['name']} detected at {path}",
                    ftype="API Framework",
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
                        findings.append(make_finding(
                            entity=f"API JSON response at {path}: {{{keys_str}}}",
                            ftype="API JSON Structure",
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
                findings.append(make_finding(
                    entity=f"Server: {server[:100]} at {path}",
                    ftype="API Server Header",
                    source="APIScanner",
                    confidence="High",
                    color="indigo",
                    threat_level="Informational",
                    raw_data=f"Server: {server[:200]}",
                    tags=["api", "server"]
                ))

        elif resp.status_code == 401:
            findings.append(make_finding(
                entity=f"Protected: {path} (401 Unauthorized)",
                ftype="API Endpoint (Auth Required)",
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
            findings.append(make_finding(
                entity=f"Forbidden: {path} (403)",
                ftype="API Endpoint (Restricted)",
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
            findings.append(make_finding(
                entity=f"Method not allowed: {path} (405)",
                ftype="API Endpoint (Exists)",
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
            findings.append(make_finding(
                entity=f"Redirect: {path} -> {location[:100]}",
                ftype="API Endpoint (Redirect)",
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
            findings.append(make_finding(
                entity=f"Not Implemented: {path} (501)",
                ftype="API Endpoint (Not Implemented)",
                source="APIScanner",
                confidence="High",
                color="yellow",
                threat_level="Informational",
                status="Not Implemented",
                raw_data=f"URL: {url}, Status: 501",
                tags=["api"]
            ))

        elif resp.status_code == 400:
            findings.append(make_finding(
                entity=f"Bad Request: {path} (400)",
                ftype="API Endpoint (Bad Request)",
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
                findings.append(make_finding(
                    entity=f"Uncommon method {method} allowed on {path} (HTTP {status})",
                    ftype="API Uncommon HTTP Method",
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
        resp = await safe_fetch(client, f"{base}/api", timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
        allow_header = resp.headers.get("allow", resp.headers.get("access-control-allow-methods", ""))
        if allow_header:
            findings.append(make_finding(
                entity=f"API CORS/Allowed Methods: {allow_header}",
                ftype="API CORS Configuration",
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
        resp = await safe_fetch(client, base, timeout=10.0, follow_redirects=True,
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
                findings.append(make_finding(
                    entity=f"{label}: {val[:100]}",
                    ftype="CORS Header",
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
            findings.append(make_finding(
                entity=f"OPTIONS allowed methods: {allow}",
                ftype="API OPTIONS Discovery",
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
        findings.append(make_finding(
            entity=f"API Scan Complete: {open_count} open endpoints, {auth_count} auth-required",
            ftype="API Scanner Summary",
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

GRAPHQL_INTROSPECTION_QUERY = """
{"query":"query { __schema { types { name fields { name type { name kind } } } } }"}
"""

async def _probe_content_negotation(target: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    accept_headers = [
        ("application/json", "JSON"),
        ("application/xml", "XML"),
        ("text/yaml", "YAML"),
        ("application/x-yaml", "YAML"),
        ("text/csv", "CSV"),
        ("application/msgpack", "MessagePack"),
        ("application/protobuf", "Protobuf"),
        ("application/grpc", "gRPC"),
        ("text/plain", "Plain Text"),
        ("*/*", "Wildcard"),
    ]
    for accept, label in accept_headers:
        try:
            resp = await safe_fetch(client, f"{base}/api", timeout=5.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0", "Accept": accept})
            ct = resp.headers.get("content-type", "")
            if accept.split("/")[0] in ct or ct.startswith(accept):
                findings.append(make_finding(
                    entity=f"Content negotiation: '{accept}' -> {ct[:60]}",
                    ftype=f"API Content Negotiation ({label})",
                    source="APIScanner",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Accept: {accept} -> Content-Type: {ct}",
                    tags=["api", "content-negotiation"]
                ))
        except Exception:
            pass

async def _graphql_introspection_check(target: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    for gql_path in ["/graphql", "/api/graphql", "/graphql/v1", "/graphql/v2", "/graphql/playground"]:
        try:
            resp = await safe_fetch(client, f"{base}{gql_path}", method="POST",
                content=GRAPHQL_INTROSPECTION_QUERY,
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
            if resp.status_code == 200:
                body = resp.text.lower()
                if "__schema" in body or "types" in body:
                    findings.append(make_finding(
                        entity=f"GraphQL introspection ENABLED at {gql_path}",
                        ftype="API GraphQL Introspection",
                        source="APIScanner",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"GraphQL introspection is enabled at {gql_path}. Consider disabling in production.",
                        tags=["api", "graphql", "introspection"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"GraphQL endpoint exists at {gql_path} (introspection disabled)",
                        ftype="API GraphQL Endpoint",
                        source="APIScanner",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["api", "graphql"]
                    ))
        except Exception:
            pass

async def _rate_limit_detection(target: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    headers_list = []
    for _ in range(5):
        try:
            resp = await safe_fetch(client, f"{base}/api", timeout=3.0,
                headers={"User-Agent": "Mozilla/5.0"})
            headers_list.append(dict(resp.headers))
            statuses = [r.get("retry-after", "") for r in headers_list]
            if any(s.strip() for s in statuses):
                findings.append(make_finding(
                    entity=f"Rate limiting detected via Retry-After header",
                    ftype="API Rate Limiting",
                    source="APIScanner",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Retry-After headers: {[s for s in statuses if s.strip()]}",
                    tags=["api", "rate-limit"]
                ))
                break
        except Exception:
            pass
    if headers_list:
        last = headers_list[-1]
        if int(last.get("x-ratelimit-remaining", "1")) == 0 or int(last.get("x-rate-limit-remaining", "1")) == 0:
            findings.append(make_finding(
                entity=f"API rate limit exhausted or nearly exhausted",
                ftype="API Rate Limit Status",
                source="APIScanner",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                raw_data=f"Rate limit headers: {last}",
                tags=["api", "rate-limit"]
            ))

async def _detect_waf(target: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    waf_payloads = [
        ("' OR '1'='1", "SQL Injection"),
        ("<script>alert(1)</script>", "XSS"),
        ("../../../etc/passwd", "Path Traversal"),
        ("${7*7}", "SSTI"),
        ("1 UNION SELECT * FROM users", "SQL Union"),
    ]
    for payload, waf_type in waf_payloads:
        try:
            resp = await safe_fetch(client, f"{base}/api?q={payload}", timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
            status = resp.status_code
            body = resp.text.lower()
            waf_indicators = ["blocked", "forbidden", "denied", "waf", "mod_security", "cloudflare",
                            "challenge", "attention required", "security rule", "malicious"]
            if any(w in body for w in waf_indicators) or status in (406, 403):
                findings.append(make_finding(
                    entity=f"WAF/IDS detected ({waf_type} payload blocked, HTTP {status})",
                    ftype="API WAF Detection",
                    source="APIScanner",
                    confidence="Medium",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Payload: {payload[:60]} triggered WAF (HTTP {status})",
                    tags=["api", "waf", waf_type.lower().replace(" ", "-")]
                ))
                break
        except Exception:
            pass

async def _analyze_response_schema(target: str, client: httpx.AsyncClient, findings: list):
    base = f"https://{target}" if not target.startswith("http") else target
    error_paths = ["/api/nonexistent12345", "/api/v1/nonexistent", "/api/users/9999999999"]
    for ep in error_paths:
        try:
            resp = await safe_fetch(client, f"{base}{ep}", timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            if resp.status_code in (400, 404, 405, 500) and "json" in resp.headers.get("content-type", ""):
                body_snippet = resp.text[:500]
                findings.append(make_finding(
                    entity=f"Error response schema at {ep}: HTTP {resp.status_code}",
                    ftype="API Error Response Schema",
                    source="APIScanner",
                    confidence="Medium",
                    color="slate" if resp.status_code == 404 else "orange",
                    threat_level="Informational" if resp.status_code == 404 else "Elevated Risk",
                    raw_data=f"URL: {base}{ep}, Status: {resp.status_code}, Body: {body_snippet}",
                    tags=["api", "error-handling"]
                ))
                stack_patterns = ["stacktrace", "stack trace", "at ", "line ", "file ",
                                "traceback", "exception", "error:"]
                if any(p in resp.text.lower() for p in stack_patterns):
                    findings.append(make_finding(
                        entity=f"Stack trace disclosure at {ep}",
                        ftype="API Stack Trace Disclosure",
                        source="APIScanner",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"Stack trace found in response: {resp.text[:1000]}",
                        tags=["api", "information-disclosure"]
                    ))
        except Exception:
            pass
