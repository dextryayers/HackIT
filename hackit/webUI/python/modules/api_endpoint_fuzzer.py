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

        all_api_paths = API_BASE_PATHS + MORE_API_PATHS
        rate_limit_info = await detect_rate_limiting(client, base_url)
        if rate_limit_info.get("rate_limited"):
            findings.append(IntelligenceFinding(
                entity="Rate limiting active (429 responses)",
                type="API Rate Limiting Confirmed",
                source="APIFuzzer",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=f"Retry-After: {rate_limit_info.get('retry_after', 'unknown')}",
                tags=["rate-limit", "detected"]
            ))
        if rate_limit_info.get("rate_limit_headers"):
            for k, v in rate_limit_info["rate_limit_headers"].items():
                findings.append(IntelligenceFinding(
                    entity=f"Rate limit header: {k}: {v[:100]}",
                    type="API Rate Limit Header",
                    source="APIFuzzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["rate-limit", k]
                ))

        common_auth = analyze_auth_methods(headers if 'headers' in dir() else {}, str(resp.headers) if 'resp' in dir() else "")
        if common_auth.get("type"):
            findings.append(IntelligenceFinding(
                entity=f"Auth method: {common_auth['type']}",
                type="API Authentication Method",
                source="APIFuzzer",
                confidence="High",
                color="orange",
                threat_level="Informational",
                tags=["auth", common_auth.get("type", "").lower().replace(" ", "-")]
            ))

        for method in MORE_HTTP_METHODS:
            try:
                resp = await client.request(method, base_url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    follow_redirects=False)
                if resp.status_code not in (0, 405, 404):
                    findings.append(IntelligenceFinding(
                        entity=f"{method} {base_url} -> {resp.status_code}",
                        type="API Method Discovery",
                        source="APIFuzzer",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"Method {method} returned {resp.status_code}",
                        tags=["api", "method", method.lower()]
                    ))
            except Exception:
                continue

        try:
            query_resp = await client.get(f"{base_url}/api/users?limit=1&offset=1&page=1&filter=test&sort=id&order=asc",
                timeout=5.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=False)
            if query_resp.status_code not in (0, 404):
                findings.append(IntelligenceFinding(
                    entity=f"Common API params accepted: {base_url} -> {query_resp.status_code}",
                    type="API Common Parameters Accepted",
                    source="APIFuzzer",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["api", "parameter-fuzzing"]
                ))
        except Exception:
            pass

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


# === EXTENDED UPGRADE: 500+ API paths, param fuzzing, auth detection, response analysis ===

MORE_API_PATHS = [
    "api/v6", "api/v7", "api/v8", "api/v9", "api/v10",
    "api/private", "api/public", "api/external", "api/internal/v1", "api/internal/v2",
    "api/partner", "api/partners", "api/vendor", "api/vendors",
    "api/third-party", "api/thirdparty", "api/sso", "api/saml",
    "api/oauth", "api/oauth2", "api/oauth/token", "api/oidc",
    "api/authorize", "api/consent", "api/scopes", "api/permissions",
    "api/rbac", "api/acl", "api/roles/permissions", "api/users/roles",
    "api/apikey", "api/api-key", "api/api_key", "api/keys",
    "api/tokens", "api/token/refresh", "api/token/validate",
    "api/session", "api/sessions", "api/session/validate",
    "api/device", "api/devices", "api/device/register", "api/mfa",
    "api/2fa", "api/totp", "api/otp", "api/verify",
    "api/password/reset", "api/password/change", "api/password/forgot",
    "api/email/verify", "api/email/resend", "api/phone/verify",
    "api/profile", "api/profiles", "api/account", "api/accounts",
    "api/account/delete", "api/account/deactivate", "api/account/export",
    "api/billing", "api/billing/info", "api/billing/plan", "api/billing/invoice",
    "api/payment", "api/payments", "api/payment/methods", "api/payment/intent",
    "api/subscription", "api/subscriptions", "api/plan", "api/plans",
    "api/pricing", "api/trial", "api/coupon", "api/coupons",
    "api/notification", "api/notifications/mark-read", "api/notifications/send",
    "api/push/register", "api/push/send", "api/sms/send",
    "api/email/send", "api/email/template", "api/email/templates",
    "api/invite", "api/invites", "api/invitation", "api/referral",
    "api/share", "api/social/share", "api/social/login", "api/social/connect",
    "api/upload/file", "api/upload/image", "api/upload/document",
    "api/file", "api/files/upload", "api/files/download", "api/files/delete",
    "api/image", "api/images", "api/images/upload", "api/images/resize",
    "api/video", "api/videos", "api/videos/upload", "api/videos/stream",
    "api/audio", "api/audios", "api/audio/transcribe",
    "api/document", "api/documents", "api/document/convert",
    "api/export/csv", "api/export/pdf", "api/export/xml", "api/export/json",
    "api/import/csv", "api/import/xml", "api/import/json",
    "api/report/generate", "api/report/schedule", "api/report/download",
    "api/analytics/events", "api/analytics/users", "api/analytics/sessions",
    "api/analytics/pageviews", "api/analytics/conversions", "api/analytics/funnel",
    "api/stats", "api/statistics", "api/statistics/summary",
    "api/dashboard/stats", "api/dashboard/widgets", "api/dashboard/config",
    "api/search/users", "api/search/products", "api/search/orders",
    "api/search/global", "api/search/suggest", "api/search/autocomplete",
    "api/filter", "api/filters", "api/sort", "api/order",
    "api/pagination", "api/page", "api/offset", "api/limit",
    "api/geo", "api/geolocation", "api/geocode", "api/reverse-geocode",
    "api/ip", "api/ip/lookup", "api/ip/geolocate",
    "api/domain", "api/domain/lookup", "api/domain/whois",
    "api/dns", "api/dns/lookup", "api/dns/resolve",
    "api/ssl", "api/certificate", "api/certificate/check",
    "api/security/scan", "api/security/headers", "api/security/vulnerabilities",
    "api/performance", "api/performance/metrics", "api/benchmark",
    "api/cache/clear", "api/cache/flush", "api/cache/status",
    "api/cdn/purge", "api/cdn/flush", "api/cdn/status",
    "api/queue/status", "api/queue/purge", "api/jobs/status",
    "api/cron", "api/scheduler/jobs", "api/scheduler/run",
    "api/webhook/register", "api/webhook/test", "api/webhook/logs",
    "api/webhooks/github", "api/webhooks/gitlab", "api/webhooks/slack",
    "api/callback/order", "api/callback/payment", "api/callback/shipping",
    "api/integration", "api/integrations", "api/integration/status",
    "api/plugin", "api/plugins", "api/plugin/install", "api/plugin/config",
    "api/module", "api/modules", "api/extension", "api/extensions",
    "api/widget", "api/widgets", "api/embed", "api/embeds",
    "api/theme", "api/themes", "api/theme/activate", "api/theme/customize",
    "api/layout", "api/layouts", "api/template", "api/templates",
    "api/component", "api/components", "api/block", "api/blocks",
    "api/menu", "api/menus", "api/menu/items", "api/navigation",
    "api/sidebar", "api/footer", "api/header", "api/banner",
    "api/slider", "api/sliders", "api/carousel", "api/gallery",
    "api/testimonial", "api/testimonials", "api/faq", "api/faqs",
    "api/review", "api/reviews/approve", "api/reviews/reject",
    "api/rating", "api/ratings/stats", "api/feedback",
    "api/comment", "api/comments/approve", "api/comments/spam",
    "api/forum", "api/forums", "api/thread", "api/threads",
    "api/post", "api/posts/featured", "api/posts/related", "api/posts/archive",
    "api/article", "api/articles/publish", "api/articles/draft",
    "api/page", "api/pages/publish", "api/pages/draft",
    "api/category", "api/categories/tree", "api/categories/featured",
    "api/tag", "api/tags/trending", "api/tags/related",
    "api/media", "api/medias", "api/media/upload", "api/media/search",
    "api/attachment", "api/attachments", "api/attachment/upload",
    "api/resource", "api/resources", "api/resource/access",
    "api/asset", "api/assets", "api/asset/version", "api/asset/download",
    "api/link", "api/links", "api/redirect", "api/redirects",
    "api/url", "api/urls", "api/url/shorten", "api/url/expand",
    "api/qrcode", "api/qr", "api/barcode",
    "api/export/data", "api/export/history", "api/export/status",
    "api/import/data", "api/import/history", "api/import/validate",
    "api/migration/status", "api/migration/run", "api/migration/rollback",
    "api/backup/create", "api/backup/restore", "api/backup/list",
    "api/snapshot", "api/snapshots", "api/snapshot/create",
    "api/replicate", "api/replication/status",
    "api/cluster/status", "api/cluster/nodes", "api/cluster/health",
    "api/loadbalancer/status", "api/loadbalancer/pools",
    "api/firewall/rules", "api/firewall/status", "api/waf/rules",
    "api/ratelimit", "api/ratelimit/status", "api/throttle",
    "api/ip/block", "api/ip/allow", "api/ip/whitelist", "api/ip/blacklist",
    "api/geoblock", "api/country/block", "api/country/allow",
    "api/antivirus/scan", "api/malware/scan", "api/security/sqli",
    "api/xss", "api/csrf", "api/ssrf",
    "api/encrypt", "api/decrypt", "api/hash", "api/sign",
    "api/verify/signature", "api/verify/certificate",
    "api/jwt/decode", "api/jwt/encode", "api/jwt/verify",
    "api/oauth/introspect", "api/oauth/revoke", "api/oauth/jwks",
    "api/saml/metadata", "api/saml/acs", "api/saml/slo",
    "api/ldap/search", "api/ldap/auth", "api/ldap/sync",
    "api/directory/users", "api/directory/groups", "api/directory/search",
    "api/schema", "api/schemas", "api/schema/validate",
    "api/validation", "api/validate/email", "api/validate/phone",
    "api/validate/url", "api/validate/ip",
    "api/format", "api/format/json", "api/format/xml", "api/format/yaml",
    "api/transform", "api/transformation", "api/convert",
    "api/parser", "api/parse/html", "api/parse/csv", "api/parse/json",
    "api/template/render", "api/template/preview",
    "api/ai/completion", "api/ai/chat", "api/ai/embedding",
    "api/ai/classify", "api/ai/sentiment", "api/ai/summarize",
    "api/ai/translate", "api/ai/detect-language",
    "api/ml/predict", "api/ml/train", "api/ml/model",
    "api/recommend", "api/recommendations", "api/personalize",
    "api/abtest", "api/experiment", "api/experiments",
    "api/feature/flag", "api/feature/flags", "api/feature/toggle",
    "api/config/reload", "api/config/validate", "api/config/diff",
    "api/setting", "api/settings/bulk", "api/settings/export",
    "api/preference", "api/preferences/save",
    "api/profile/complete", "api/onboarding/status",
    "api/tutorial", "api/guide", "api/help",
    "api/status/code", "api/status/message",
    "api/error/log", "api/error/report", "api/error/trace",
    "api/debug/sql", "api/debug/routes", "api/debug/events",
    "api/health/db", "api/health/cache", "api/health/queue",
    "api/health/services", "api/health/external",
    "api/readiness", "api/liveness", "api/startup",
    "api/metrics/custom", "api/metrics/histogram", "api/metrics/counter",
    "api/trace", "api/tracing", "api/span",
    "api/log/stream", "api/log/tail", "api/log/search",
    "api/audit/events", "api/audit/search", "api/audit/export",
    "api/compliance/check", "api/compliance/report",
    "api/gdpr/export", "api/gdpr/delete", "api/ccpa/opt-out",
    "api/consent/record", "api/consent/history", "api/consent/preferences",
    "api/data/retention", "api/data/purge", "api/data/archive",
    "api/data/export", "api/data/import", "api/data/sync",
    "api/database/query", "api/database/backup", "api/database/optimize",
    "api/storage/upload", "api/storage/download", "api/storage/delete",
    "api/cdn/upload", "api/cdn/invalidate", "api/cdn/statistics",
    "api/edge/function", "api/edge/functions", "api/edge/deploy",
    "api/serverless/function", "api/serverless/deploy", "api/serverless/logs",
    "api/container/start", "api/container/stop", "api/container/logs",
    "api/kubernetes/pods", "api/kubernetes/services", "api/kubernetes/deploy",
    "api/docker/ps", "api/docker/images", "api/docker/build",
    "api/ssh/key", "api/ssh/keys", "api/ssh/session",
    "api/terminal", "api/shell", "api/exec",
    "api/command", "api/commands/run", "api/script/execute",
]

COMMON_API_PARAMS = [
    "id", "ids", "type", "types", "name", "names", "key", "keys",
    "token", "tokens", "secret", "secrets", "api_key", "api-key",
    "apikey", "access_token", "access-key", "accesskey",
    "limit", "offset", "page", "pages", "per_page", "per-page",
    "size", "page_size", "page-size", "max", "min",
    "sort", "sort_by", "sort-by", "sort_order", "order",
    "filter", "filters", "query", "q", "search", "term",
    "fields", "select", "include", "expand", "embed",
    "lang", "locale", "language", "country", "region",
    "format", "callback", "jsonp", "pretty", "verbose",
    "debug", "test", "dry_run", "dry-run", "validate",
    "scope", "scopes", "permission", "permissions",
    "role", "roles", "group", "groups", "team", "teams",
    "user", "users", "admin", "admins",
    "from", "to", "start", "end", "since", "until",
    "before", "after", "date", "dates", "range",
    "created_at", "updated_at", "modified_at",
    "timestamp", "time", "datetime",
    "status", "state", "stage", "step",
    "active", "enabled", "disabled", "archived",
    "category", "categories", "tag", "tags", "label", "labels",
    "source", "medium", "campaign", "content",
    "url", "uri", "path", "slug", "redirect",
    "version", "v", "api-version", "api_version",
    "client_id", "client-id", "client_secret", "client-secret",
    "redirect_uri", "redirect_uri", "response_type", "grant_type",
    "code", "state", "nonce", "challenge", "session_id",
    "email", "phone", "address", "zip", "postal",
    "lat", "lon", "latitude", "longitude", "coordinates",
    "radius", "distance", "near", "within",
    "provider", "platform", "channel", "integration",
    "checksum", "hash", "signature", "digest",
    "meta", "metadata", "data", "attributes",
    "device_id", "device-type", "platform-type",
    "app_id", "app-version", "build-number",
]

MORE_HTTP_METHODS = ["MOVE", "COPY", "LINK", "UNLINK", "WRAPPED", "LOCK", "UNLOCK", "PROPFIND", "PROPPATCH", "MKCOL", "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "POLL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MERGE", "BASELINE", "MKWORKSPACE"]

CONTENT_TYPES_TO_CHECK = [
    "application/json", "application/xml", "text/xml", "application/x-yaml",
    "application/graphql-response+json", "application/vnd.api+json",
    "application/ld+json", "application/hal+json", "application/problem+json",
    "application/grpc", "application/x-protobuf", "application/octet-stream",
    "multipart/form-data", "application/x-www-form-urlencoded",
]

async def detect_rate_limiting(client, base_url):
    results = {}
    try:
        for _ in range(10):
            resp = await client.get(base_url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 429:
                results["rate_limited"] = True
                results["retry_after"] = resp.headers.get("retry-after", "unknown")
                return results
        headers = {}
        for _ in range(5):
            resp = await client.get(base_url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            h = dict(resp.headers)
            for k, v in h.items():
                if "x-ratelimit" in k.lower() or "ratelimit" in k.lower() or "rate" in k.lower():
                    headers[k] = v
        if headers:
            results["rate_limit_headers"] = headers
    except Exception:
        pass
    return results

def analyze_auth_methods(headers, body):
    auth = {}
    try:
        www_auth = headers.get("www-authenticate", "")
        if www_auth:
            auth["www_authenticate"] = www_auth
            if "bearer" in www_auth.lower():
                auth["type"] = "Bearer Token"
            elif "basic" in www_auth.lower():
                auth["type"] = "Basic Auth"
            elif "digest" in www_auth.lower():
                auth["type"] = "Digest Auth"
            elif "negotiate" in www_auth.lower():
                auth["type"] = "Negotiate (Kerberos/NTLM)"
            elif "ntlm" in www_auth.lower():
                auth["type"] = "NTLM"
        if "access_token" in body.lower() or "access-token" in body.lower():
            auth["access_token_found"] = True
        if "jwt" in body.lower() or "json web token" in body.lower():
            auth["jwt_found"] = True
    except Exception:
        pass
    return auth

def analyze_response_body(body, content_type):
    analysis = {}
    try:
        if not body:
            return analysis
        if "json" in content_type.lower():
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    analysis["keys"] = list(data.keys())[:20]
                    for sensitive in ["password", "secret", "token", "api_key", "credit_card", "ssn"]:
                        if sensitive in str(data).lower():
                            analysis["sensitive_leak"] = sensitive
            except Exception:
                pass
        elif "xml" in content_type.lower():
            analysis["xml_format"] = True
        lines = body.split('\n')
        analysis["line_count"] = len(lines)
        analysis["size"] = len(body)
        error_keywords = ["error", "exception", "traceback", "stack trace", "not found", "invalid", "failed"]
        for kw in error_keywords:
            if kw in body.lower()[:5000]:
                analysis["error_keyword"] = kw
                break
    except Exception:
        pass
    return analysis
