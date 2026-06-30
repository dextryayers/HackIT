import httpx
import json
import re
from urllib.parse import urljoin, parse_qs, urlencode
from models import IntelligenceFinding

API_BASE_PATHS = [
    "", "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/v5", "v1", "v2", "v3", "latest",
    "rest", "rest/v1", "rest/v2", "graphql", "swagger", "docs", "api/docs", "api/swagger",
    "api/graphql", "api/rest", "admin", "api/admin", "internal", "api/internal",
    "beta", "dev", "staging", "test", "api/test", "api/health", "health", "api/status", "status",
    "api/config", "config", "api/settings", "settings", "api/metrics", "metrics", "api/info", "info",
    "api/version", "version", "api/ping", "ping", "api/echo", "echo",
    "api/users", "users", "api/auth", "auth", "api/login", "login",
    "api/register", "register", "api/search", "search", "api/data", "data", "api/query", "query",
    "api/execute", "execute", "api/export", "export", "api/import", "import",
    "api/debug", "debug", "api/trace", "trace", "api/ws", "ws", "api/socket", "socket",
    "api/webhook", "webhook", "api/callback", "callback", "api/proxy", "proxy",
    "api/redirect", "redirect", "api/upload", "upload", "api/download", "download",
    "api/media", "media", "api/files", "files", "api/report", "report", "api/analytics", "analytics",
    "api/event", "event", "api/log", "log", "api/logs", "logs",
    ".well-known/", ".well-known/security.txt", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "client-access-policy.xml", "openapi.json",
    "api/users/me", "api/users/login", "api/users/register", "api/users/profile",
    "api/users/settings", "api/users/password", "api/users/reset-password",
    "api/products", "api/products/", "api/orders", "api/orders/", "api/payments",
    "api/checkout", "api/cart", "api/cart/", "api/wishlist", "api/categories",
    "api/reviews", "api/ratings", "api/comments", "api/posts", "api/articles",
    "api/blog", "api/news", "api/notifications", "api/messages", "api/inbox",
    "api/conversations", "api/chats", "api/rooms", "api/groups",
    "api/friends", "api/followers", "api/following", "api/contacts",
    "api/subscriptions", "api/subscribers", "api/channels",
    "api/playlists", "api/favorites", "api/likes", "api/dislikes",
    "api/shares", "api/saved", "api/history", "api/recent",
    "api/trending", "api/popular", "api/featured", "api/recommended",
    "api/feed", "api/timeline", "api/activities", "api/updates",
    "api/playlists", "api/videos", "api/photos", "api/albums",
    "api/galleries", "api/collections", "api/items",
    "api/tags", "api/categories", "api/labels",
    "api/locations", "api/places", "api/venues", "api/events",
    "api/tickets", "api/bookings", "api/reservations",
    "api/schedules", "api/calendar", "api/appointments",
    "api/availability", "api/slots", "api/sessions",
    "api/teachers", "api/students", "api/courses", "api/classes",
    "api/enrollments", "api/assignments", "api/submissions",
    "api/grades", "api/transcripts", "api/certificates",
    "api/projects", "api/tasks", "api/issues", "api/milestones",
    "api/sprints", "api/epics", "api/stories", "api/backlog",
    "api/boards", "api/cards", "api/lists", "api/kanban",
    "api/teams", "api/members", "api/roles", "api/permissions",
    "api/organizations", "api/companies", "api/departments",
    "api/invoices", "api/bills", "api/receipts", "api/transactions",
    "api/budgets", "api/expenses", "api/revenue", "api/profits",
    "api/taxes", "api/fees", "api/charges", "api/refunds",
    "api/accounts", "api/wallets", "api/balances", "api/transfers",
    "api/deposits", "api/withdrawals", "api/exchanges",
    "api/assets", "api/portfolios", "api/investments",
    "api/stocks", "api/crypto", "api/currencies", "api/rates",
    "api/notifications/settings", "api/preferences", "api/configuration",
    "api/features", "api/flags", "api/toggles",
    "api/themes", "api/layouts", "api/templates",
    "api/translations", "api/locales", "api/languages",
    "api/timezones", "api/countries", "api/states", "api/cities",
    "api/currencies", "api/units", "api/measurements",
    "api/shipping", "api/delivery", "api/tracking", "api/returns",
    "api/inventory", "api/warehouse", "api/suppliers",
    "api/customers", "api/clients", "api/partners", "api/vendors",
    "api/leads", "api/deals", "api/pipelines", "api/funnels",
    "api/campaigns", "api/emails", "api/sms", "api/push",
    "api/templates", "api/workflows", "api/automations",
    "api/triggers", "api/actions", "api/rules", "api/policies",
    "api/audit", "api/audit-log", "api/activity-log",
    "api/analytics/overview", "api/analytics/realtime",
    "api/reports/daily", "api/reports/weekly", "api/reports/monthly",
    "api/reports/yearly", "api/dashboard",
    "api/health/readiness", "api/health/liveness", "api/health/check",
    "api/metrics/cpu", "api/metrics/memory", "api/metrics/disk",
    "api/metrics/network", "api/metrics/database",
    "api/monitoring", "api/alerting", "api/incidents",
    "api/logs/error", "api/logs/info", "api/logs/debug",
    "api/backup", "api/restore", "api/migration",
    "api/sync", "api/replication", "api/cluster",
    "api/cache", "api/queue", "api/jobs", "api/tasks",
    "api/scheduler", "api/cron", "api/workers",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT", "PURGE"]

FRAMEWORK_PATTERNS = {
    "Flask": [r"flask", r"werkzeug", r"session=[.\w]+"],
    "Express": [r"express", r"connect\.sid", r"x-powered-by:\s*express"],
    "Django REST": [r"django", r"csrftoken", r"sessionid", r"django-rest"],
    "FastAPI": [r"fastapi", r"uvicorn", r"openapi\.json"],
    "Spring Boot": [r"spring", r"java", r"x-application-context", r"actuator"],
    "Rails": [r"rails", r"rails-api", r"x-request-id"],
    "Laravel": [r"laravel", r"laravel_session"],
    "ASP.NET": [r"asp\.net", r"x-aspnet-version", r"aspnet_session"],
    "Next.js": [r"next\.js", r"x-nextjs", r"__next"],
    "Nuxt.js": [r"nuxt", r"__nuxt"],
    "Gin": [r"gin", r"gin-gonic"],
    "Fiber": [r"fiber", r"gofiber"],
    "Echo": [r"labstack/echo", r"echo"],
    "Koa": [r"koa"],
    "Sails": [r"sails"],
    "LoopBack": [r"loopback"],
    "Phoenix": [r"phoenix"],
    "Play": [r"play framework"],
    "Dropwizard": [r"dropwizard"],
}

AUTH_HEADERS = [
    {},
    {"Authorization": "Bearer test"},
    {"Authorization": "Basic dGVzdDp0ZXN0"},
    {"X-API-Key": "test"},
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.test"},
    {"X-Auth-Token": "test"},
    {"X-Token": "test"},
    {"Token": "test"},
    {"Api-Key": "test"},
    {"X-Access-Token": "test"},
]

QUERY_PARAM_PAYLOADS = [
    {"debug": "1"},
    {"test": "1"},
    {"admin": "1"},
    {"mode": "debug"},
    {"env": "test"},
    {"_": str(hash("test"))},
    {"callback": "jsonp_test"},
    {"format": "json"},
    {"pretty": "1"},
    {"verbose": "1"},
]

POST_BODY_PAYLOADS = [
    {},
    {"test": "value"},
    {"admin": "true"},
    {"debug": "true"},
    {"mode": "test"},
]

API_RESPONSE_PATTERNS = [
    re.compile(r'["\'](?:error|message|status|success|data|result)["\']\s*:', re.IGNORECASE),
    re.compile(r'{"[^}]+":\s*"[^}]+"}'),
    re.compile(r'<(\?xml|html)', re.IGNORECASE),
    re.compile(r'(?:api_|api-)\w+["\':]', re.IGNORECASE),
    re.compile(r'(?:error_code|error_message|error_description)', re.IGNORECASE),
    re.compile(r'(?:total_count|page_size|page_number|total_pages)', re.IGNORECASE),
]

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    try:
        discovered_endpoints = []
        framework_hints = []
        rate_limited = False
        auth_bypass_found = False
        frameworks_detected = {}

        for method in HTTP_METHODS:
            try:
                resp = await client.request(method, base_url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    follow_redirects=False)
                headers_str = str(dict(resp.headers)).lower()
                for fw_name, patterns in FRAMEWORK_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, headers_str, re.IGNORECASE):
                            frameworks_detected[fw_name] = frameworks_detected.get(fw_name, 0) + 1
                            break
            except Exception:
                pass

        for path in API_BASE_PATHS:
            if rate_limited:
                break
            url = f"{base_url}/{path}"
            if path == "":
                url = base_url
            url = url.replace("//", "/").replace(":/", "://")

            for method in HTTP_METHODS:
                try:
                    resp = await client.request(method, url, timeout=5.0,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                                 "Accept": "application/json, text/plain, */*"},
                        follow_redirects=False)

                    if resp.status_code == 429 or resp.status_code == 503:
                        rate_limited = True
                        findings.append(IntelligenceFinding(
                            entity=f"Rate limited (429/503) on {url}",
                            type="API Rate Limiting",
                            source="APIFuzzer",
                            confidence="High",
                            color="orange",
                            threat_level="Informational",
                            raw_data=f"Rate limited when requesting {url} with {method}",
                            tags=["rate-limit", "api"]
                        ))
                        break

                    if resp.status_code in (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 406, 415, 500, 501):
                        content_type = resp.headers.get("content-type", "")
                        is_json = "json" in content_type
                        is_xml = "xml" in content_type
                        body = resp.text[:2000] if hasattr(resp, "text") else ""

                        is_api = False
                        if is_json or is_xml:
                            is_api = True
                        else:
                            for pat in API_RESPONSE_PATTERNS:
                                if pat.search(body):
                                    is_api = True
                                    break

                        if resp.status_code == 401 and method == "GET" and not path:
                            findings.append(IntelligenceFinding(
                                entity=f"Auth required: {url}",
                                type="API Authentication Required",
                                source="APIFuzzer",
                                confidence="High",
                                color="orange",
                                threat_level="Informational",
                                raw_data=f"401 on {url} with {method}",
                                tags=["auth", "api"]
                            ))

                        response_time = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else 0
                        response_size = len(body)

                        for auth_headers in AUTH_HEADERS[1:]:
                            if auth_bypass_found:
                                break
                            try:
                                test_resp = await client.request(method, url, timeout=5.0,
                                    headers={**{"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*"}, **auth_headers},
                                    follow_redirects=False)
                                if test_resp.status_code in (200, 201, 202) and resp.status_code in (401, 403):
                                    auth_bypass_found = True
                                    findings.append(IntelligenceFinding(
                                        entity=f"Auth bypass on {url} ({method})",
                                        type="API Auth Bypass",
                                        source="APIFuzzer",
                                        confidence="Medium",
                                        color="red",
                                        threat_level="Critical",
                                        raw_data=f"Bypassed auth on {url} using {list(auth_headers.keys())[0]} header | Original: {resp.status_code} -> After: {test_resp.status_code}",
                                        tags=["auth-bypass", "api", "vulnerability"]
                                    ))
                            except Exception:
                                pass

                        for qp_payload in QUERY_PARAM_PAYLOADS:
                            try:
                                qp_url = f"{url}?{urlencode(qp_payload)}"
                                qp_resp = await client.request(method, qp_url, timeout=5.0,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                                             "Accept": "application/json, text/plain, */*"},
                                    follow_redirects=False)
                                if qp_resp.status_code not in (0, 404) and qp_resp.status_code not in (resp.status_code,):
                                    params_str = ", ".join(qp_payload.keys())
                                    findings.append(IntelligenceFinding(
                                        entity=f"Parameter fuzzing: ?{params_str} on {method} {url} -> {qp_resp.status_code}",
                                        type="API Parameter Fuzzing",
                                        source="APIFuzzer",
                                        confidence="Medium",
                                        color="slate",
                                        threat_level="Informational",
                                        raw_data=f"URL: {qp_url} | Status: {qp_resp.status_code} | Params: {qp_payload}",
                                        tags=["api", "fuzzing", "parameter"]
                                    ))
                            except Exception:
                                pass

                        if is_api or resp.status_code in (200, 201, 202, 405) or (resp.status_code == 401 and path):
                            ep_key = f"{method} {url} -> {resp.status_code} ({response_time:.2f}s, {response_size}B)"
                            if ep_key not in discovered_endpoints:
                                discovered_endpoints.append(ep_key)
                                color = "emerald"
                                if resp.status_code in (401, 403):
                                    color = "orange"
                                elif resp.status_code >= 500:
                                    color = "red"
                                elif resp.status_code in (301, 302, 303, 307, 308):
                                    color = "slate"
                                elif is_json or is_api:
                                    color = "cyan"

                                findings.append(IntelligenceFinding(
                                    entity=f"{method} {url} [{resp.status_code}] ({response_time:.2f}s)",
                                    type="API Endpoint",
                                    source="APIFuzzer",
                                    confidence="High",
                                    color=color,
                                    threat_level="Elevated Risk" if resp.status_code in (401, 403) else "Informational",
                                    raw_data=f"Method: {method} | URL: {url} | Status: {resp.status_code} | Content-Type: {content_type} | Time: {response_time:.2f}s | Size: {response_size}B",
                                    tags=["api", "endpoint", method.lower()]
                                ))

                                if resp.status_code == 405 and method != "OPTIONS":
                                    findings.append(IntelligenceFinding(
                                        entity=f"Method {method} not allowed on {url} (405)",
                                        type="API Method Discovery",
                                        source="APIFuzzer",
                                        confidence="High",
                                        color="purple",
                                        threat_level="Informational",
                                        raw_data=f"HTTP method {method} is not allowed on {url} - but endpoint exists",
                                        tags=["api", "method", method.lower()]
                                    ))

                                if method == "TRACE" and resp.status_code == 200:
                                    findings.append(IntelligenceFinding(
                                        entity=f"TRACE method enabled on {url}",
                                        type="API TRACE Method Enabled",
                                        source="APIFuzzer",
                                        confidence="High",
                                        color="red",
                                        threat_level="Elevated Risk",
                                        raw_data=f"TRACE method enabled - potential XST attack vector",
                                        tags=["api", "trace", "xst", "vulnerability"]
                                    ))

                                if method == "OPTIONS" and resp.status_code == 200:
                                    allow = resp.headers.get("allow", "")
                                    if allow:
                                        findings.append(IntelligenceFinding(
                                            entity=f"Allowed methods: {allow} on {url}",
                                            type="API Allowed Methods",
                                            source="APIFuzzer",
                                            confidence="High",
                                            color="slate",
                                            threat_level="Informational",
                                            raw_data=f"OPTIONS {url}: Allow: {allow}",
                                            tags=["api", "options", "methods"]
                                        ))

                            if is_json and body:
                                try:
                                    json_body = json.loads(body)
                                    if isinstance(json_body, dict):
                                        keys = ", ".join(list(json_body.keys())[:10])
                                        findings.append(IntelligenceFinding(
                                            entity=f"JSON response keys: {keys}",
                                            type="API JSON Response Structure",
                                            source="APIFuzzer",
                                            confidence="Medium",
                                            color="slate",
                                            threat_level="Informational",
                                            raw_data=body[:500],
                                            tags=["api", "json", "response"]
                                        ))
                                        total_count = json_body.get("total_count") or json_body.get("total") or json_body.get("count")
                                        if total_count is not None:
                                            findings.append(IntelligenceFinding(
                                                entity=f"Paginated response: total={total_count}",
                                                type="API Paginated Response",
                                                source="APIFuzzer",
                                                confidence="Medium",
                                                color="slate",
                                                threat_level="Informational",
                                                tags=["api", "pagination"]
                                            ))
                                except Exception:
                                    pass

                except (httpx.TimeoutException, httpx.ConnectError):
                    continue
                except Exception:
                    continue

        for fw_name, count in sorted(frameworks_detected.items(), key=lambda x: -x[1])[:5]:
            findings.append(IntelligenceFinding(
                entity=fw_name,
                type="API Framework",
                source="APIFuzzer",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                raw_data=f"Framework signals: {count}",
                tags=["api", "framework", fw_name.lower().replace(" ", "-")]
            ))

        if discovered_endpoints:
            allowed_methods = sum(1 for f in findings if f.type == "API Allowed Methods")
            findings.append(IntelligenceFinding(
                entity=f"{len(discovered_endpoints)} API endpoints discovered, {len(frameworks_detected)} frameworks, {allowed_methods} method configs",
                type="API Fuzzing Summary",
                source="APIFuzzer",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                raw_data=f"Discovered endpoints: {'; '.join(discovered_endpoints[:15])}",
                tags=["api", "summary"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity="No API endpoints discovered",
                type="API Fuzzing Summary",
                source="APIFuzzer",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["api", "summary"]
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"API Fuzzer error: {str(e)[:100]}",
            type="API Fuzzer Error",
            source="APIFuzzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
