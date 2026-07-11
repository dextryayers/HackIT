import httpx
import re
import ssl
import socket
import asyncio
from datetime import datetime
from module_common import safe_fetch, make_finding

HEADER_SIGNATURES = {
    "server": ("Web Server", "High"),
    "x-powered-by": ("Tech Stack", "High"),
    "x-generator": ("CMS/Gear", "High"),
    "x-drupal-cache": ("CMS: Drupal", "High"),
    "x-drupal-dynamic-cache": ("CMS: Drupal", "High"),
    "x-varnish": ("Cache: Varnish", "High"),
    "x-cache": ("Cache System", "Medium"),
    "x-cache-hit": ("Cache: Hit", "Medium"),
    "x-cache-hits": ("Cache: Hits", "Medium"),
    "cf-ray": ("CDN: Cloudflare", "High"),
    "x-amz-cf-id": ("CDN: CloudFront", "High"),
    "x-amz-request-id": ("AWS: S3/CloudFront", "High"),
    "x-amz-cf-pop": ("CDN: CloudFront POP", "Medium"),
    "x-served-by": ("Proxy/Server", "Medium"),
    "x-aspnet-version": ("Tech: ASP.NET", "High"),
    "x-aspnetmvc-version": ("Tech: ASP.NET MVC", "High"),
    "x-application-context": ("Tech: Spring Boot", "High"),
    "x-frame-options": ("Security: ClickJacking", "Medium"),
    "x-content-type-options": ("Security: MIME Sniff", "Medium"),
    "x-xss-protection": ("Security: XSS Filter", "Medium"),
    "strict-transport-security": ("Security: HSTS", "High"),
    "content-security-policy": ("Security: CSP", "High"),
    "referrer-policy": ("Security: Referrer", "Medium"),
    "permissions-policy": ("Security: Permissions", "Medium"),
    "x-robots-tag": ("SEO: Robots", "Low"),
    "x-ua-compatible": ("Browser Compat", "Low"),
    "x-redirect-by": ("Redirect By", "Medium"),
    "x-pingback": ("Pingback", "Medium"),
    "link": ("Link Header", "Medium"),
    "x-nextjs-cache": ("Tech: Next.js", "High"),
    "x-vercel-id": ("Platform: Vercel", "High"),
    "x-vercel-cache": ("Platform: Vercel", "High"),
    "x-nginx-proxy": ("Proxy: Nginx", "High"),
    "x-openresty": ("Tech: OpenResty", "High"),
    "x-debug-token": ("Debug: Symfony", "High"),
    "x-debug": ("Debug mode", "Medium"),
    "x-turbo-charged-by": ("Tech: Turbo", "High"),
    "x-varnish": ("Cache: Varnish", "High"),
    "x-via": ("Proxy: Via", "Medium"),
    "x-cache-status": ("Cache: Status", "Medium"),
    "x-proxy-cache": ("Cache: Proxy", "Medium"),
    "x-rack-cache": ("Cache: Rack", "Medium"),
    "x-github-request-id": ("Platform: GitHub", "Medium"),
    "x-gitlab-request-id": ("Platform: GitLab", "Medium"),
}

CMS_META_PATTERNS = {
    "WordPress": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', "wp-admin", "wp-content", "wp-includes"),
    ],
    "Drupal": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]+)', "sites/default", "files/"),
    ],
    "Joomla": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s*([\d.]+)', "com_content", "option=com_"),
    ],
    "Magento": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Magento\s*([\d.]+)', "mage/", "skin/frontend"),
    ],
    "Shopify": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Shopify', "myshopify.com", "/cdn/shop/"),
    ],
    "Wix": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Wix\.com', "wix-static", "WixCode"),
    ],
    "Ghost": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([\d.]+)', "ghost"),
    ],
    "Squarespace": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Squarespace', "squarespace"),
    ],
    "Weebly": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Weebly', "weebly"),
    ],
    "Blogger": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Blogger', "blogger"),
    ],
    "TYPO3": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']TYPO3\s*([\d.]+)', "typo3"),
    ],
    "PrestaShop": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']PrestaShop', "prestashop"),
    ],
    "OpenCart": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']OpenCart', "opencart"),
    ],
    "Django CMS": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Django CMS', "django-cms"),
    ],
    "Concrete CMS": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Concrete CMS', "concrete"),
    ],
}

JS_FRAMEWORK_PATTERNS = {
    "React": [r"__NEXT_DATA__", r"react\.js", r"/static/react", r"react-dom", r"React\.createElement", r"ReactDOM"],
    "Vue.js": [r"vue\.js", r"vue\.min\.js", r"_vue", r"__VUE_DEVTOOLS__", r"new Vue", r"createApp\("],
    "Angular": [r"angular\.js", r"angular\.min\.js", r"ng-app", r"ng-version", r"angular/core", r"_ngContent"],
    "Svelte": [r"svelte", r"__svelte"],
    "jQuery": [r"jquery", r"\$\.ajax", r"\$\(function", r"jQuery\("],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static", r"next\.js"],
    "Nuxt.js": [r"__NUXT__", r"/_nuxt/"],
    "Gatsby": [r"gatsby", r"___gatsby"],
    "Alpine.js": [r"alpinejs", r"x-data", r"x-init", r"x-on:"],
    "HTMX": [r"htmx", r"hx-get", r"hx-post", r"hx-target"],
    "Tailwind CSS": [r"tailwindcss", r"<style[^>]*tailwind", r"@tailwind"],
    "Bootstrap": [r"bootstrap", r"data-bs-", r'class="[^"]*col-(?:xs|sm|md|lg|xl)'],
    "Foundation": [r"foundation\.js", r"foundation\.min\.js"],
    "Bulma": [r"bulma\.css", r"bulma\.min\.css"],
    "Materialize": [r"materialize\.css", r"materialize\.min\.css"],
    "Semantic UI": [r"semantic\.css", r"semantic\.min\.css", r"semantic-ui"],
    "UIKit": [r"uikit\.js", r"uikit\.min\.js"],
    "PureCSS": [r"pure\.css", r"pure-min\.css"],
    "Preact": [r"preact", r"preact/compat"],
    "Lit": [r"lit-element", r"lit-html", r"@lit/"],
    "Stencil": [r"stencil", r"@stencil/"],
    "Ember": [r"ember\.js", r"Ember"],
    "Backbone": [r"backbone\.js", r"Backbone"],
    "Knockout": [r"knockout\.js", r"ko\."],
    "Mithril": [r"mithril", r"m\."],
    "Riot": [r"riot\.js", r"riot\("],
    "Stimulus": [r"stimulus", r"data-controller"],
    "Turbo": [r"turbo\.js", r"@hotwired/turbo"],
    "Hotwire": [r"hotwire", r"@hotwired/"],
    "Livewire": [r"livewire", r"@livewire/"],
    "Inertia": [r"inertia", r"@inertiajs/"],
    "Remix": [r"remix", r"@remix-run/"],
    "Astro": [r"astro", r"__ASTRO__"],
    "Solid": [r"solid-js", r"Solid"],
    "Qwik": [r"qwik", r"@builder.io/qwik"],
    "Marko": [r"marko", r"@marko/"],
    "Meteor": [r"meteor", r"__meteor__"],
    "Aurelia": [r"aurelia", r"au-"],
    "Dojo": [r"dojo", r"dojo/"],
    "Ext JS": [r"ext\.js", r"Ext\.", r"sencha"],
    "YUI": [r"yui\.js", r"YUI"],
    "Prototype": [r"prototype\.js", r"Prototype"],
    "Script.aculo.us": [r"script\.aculo\.us", r"scriptaculous"],
    "MooTools": [r"mootools", r"MooTools"],
    "Polymer": [r"polymer", r"@polymer/"],
    "Shoelace": [r"shoelace", r"@shoelace-style/"],
}

CSS_PATTERNS = {
    "WordPress": [r"wp-block-", r"wp-site-blocks"],
    "Bootstrap": [r"col-(?:xs|sm|md|lg|xl)-\d+", r"container-fluid", r"navbar-expand"],
    "Tailwind": [r'class="[^"]*\b(?:flex|grid|container|mx-auto|px-\d|py-\d|text-\w+|bg-\w+)\b'],
    "Material UI": [r"Mui[A-Z]"],
    "Chakra UI": [r"css-\w{6}", r"chakra-"],
    "Ant Design": [r"ant-", r"anticon"],
    "PrimeFaces": [r"ui-widget", r"ui-state"],
    "Fomantic UI": [r"fomantic", r"ui menu"],
    "NES.css": [r"nes-"],
    "98.css": [r"window", r"title-bar"],
    "Water.css": [r"water\.css"],
    "MVP.css": [r"mvp\.css"],
    "Basscss": [r"basscss", r"flex"],
    "Tachyons": [r"tachyons"],
}

PATH_SIGNATURES = {
    "/wp-admin/": "CMS: WordPress",
    "/wp-content/": "CMS: WordPress",
    "/wp-includes/": "CMS: WordPress",
    "/administrator/": "CMS: Joomla",
    "/administrator/index.php": "CMS: Joomla",
    "/sites/default/": "CMS: Drupal",
    "/node/": "CMS: Drupal",
    "/user/": "CMS: Drupal",
    "/admin/": "CMS (generic)",
    "/artifactory/": "DevOps: Artifactory",
    "/jenkins/": "DevOps: Jenkins",
    "/confluence/": "DevOps: Confluence",
    "/jira/": "DevOps: Jira",
    "/gitlab/": "DevOps: GitLab",
    "/grafana/": "Monitoring: Grafana",
    "/prometheus/": "Monitoring: Prometheus",
    "/kibana/": "Monitoring: Kibana",
    "/_next/static/": "Tech: Next.js",
    "/__nuxt/": "Tech: Nuxt.js",
    "/assets/vue/": "Tech: Vue.js",
    "/assets/react/": "Tech: React",
    "/api/": "API endpoint",
    "/graphql": "API: GraphQL",
    "/swagger": "API: Swagger/OpenAPI",
    "/.env": "Config leak risk",
    "/.git/": "Source leak: Git",
    "/.git/config": "Source leak: Git",
    "/vendor/": "Tech: PHP Composer",
    "/node_modules/": "Tech: Node.js",
    "/bower_components/": "Tech: Bower (legacy)",
    "/composer.json": "Tech: PHP Composer",
    "/package.json": "Tech: Node.js/npm",
    "/webpack.config.js": "Build: Webpack",
    "/vite.config.js": "Build: Vite",
    "/.htaccess": "Apache Config",
    "/nginx.conf": "Nginx Config",
    "/robots.txt": "SEO: Robots.txt",
    "/sitemap.xml": "SEO: Sitemap",
    "/Dockerfile": "Config: Docker",
    "/docker-compose.yml": "Config: Docker Compose",
    "/.helm/": "Config: Helm",
    "/k8s/": "Config: Kubernetes",
    "/terraform/": "Config: Terraform",
    "/ansible/": "Config: Ansible",
    "/.circleci/": "CI/CD: CircleCI",
    "/.github/": "CI/CD: GitHub Actions",
    "/.gitlab-ci.yml": "CI/CD: GitLab CI",
    "/Jenkinsfile": "CI/CD: Jenkins Pipeline",
    "/bitbucket-pipelines.yml": "CI/CD: Bitbucket",
    "/cockpit/": "Monitoring: Cockpit",
    "/netdata/": "Monitoring: Netdata",
    "/portainer/": "DevOps: Portainer",
    "/phpmyadmin/": "Tool: phpMyAdmin",
    "/adminer.php": "Tool: Adminer",
    "/pma/": "Tool: phpMyAdmin",
    "/server-status": "Apache: Server Status",
    "/server-info": "Apache: Server Info",
    "/actuator/": "Spring: Actuator",
    "/actuator/health": "Spring: Health",
    "/actuator/env": "Spring: Env Leak",
    "/actuator/beans": "Spring: Beans",
    "/swagger-ui.html": "API: Swagger UI",
    "/v2/api-docs": "API: Swagger Docs",
    "/v3/api-docs": "API: OpenAPI Docs",
    "/favicon.ico": "General: Favicon",
    "/.well-known/": "General: Well-known",
}

CDN_PATTERNS = {
    r"cloudflare": "CDN: Cloudflare",
    r"cloudfront": "CDN: AWS CloudFront",
    r"akamai": "CDN: Akamai",
    r"fastly": "CDN: Fastly",
    r"incapsula|imperva": "CDN/WAAP: Imperva/Incapsula",
    r"stackpath": "CDN: StackPath",
    r"keycdn": "CDN: KeyCDN",
    r"bunnycdn": "CDN: BunnyCDN",
    r"cdn\.jsdelivr": "CDN: jsDelivr",
    r"cdnjs\.cloudflare": "CDN: cdnjs",
    r"unpkg\.com": "CDN: unpkg",
    r"cachefly": "CDN: CacheFly",
    r"section\.io": "CDN: Section.io",
    r"belugacdn": "CDN: BelugaCDN",
    r"cdn\.ampproject": "CDN: AMP Project",
    r"azurefd|azureedge": "CDN: Azure CDN",
    r"gcpcdn|cdn\.google": "CDN: Google Cloud CDN",
    r"edgecast": "CDN: EdgeCast",
    r"cdn\.net": "CDN: CDN.net",
    r"ovh\.net": "CDN: OVH CDN",
    r"cdnvideo": "CDN: CDNvideo",
    r"gcore": "CDN: G-Core",
    r"quantil": "CDN: Quantil",
    r"chinacache": "CDN: ChinaCache",
}

ANALYTICS_PATTERNS = {
    r"google-analytics|googletagmanager": "Analytics: Google Analytics/Tag Manager",
    r"facebook.*(?:pixel|tr)": "Analytics: Meta Pixel",
    r"hotjar": "Analytics: Hotjar",
    r"fullstory": "Analytics: FullStory",
    r"amplitude": "Analytics: Amplitude",
    r"mixpanel": "Analytics: Mixpanel",
    r"segment.*analytics": "Analytics: Segment",
    r"heap.*analytics": "Analytics: Heap",
    r"crazyegg": "Analytics: CrazyEgg",
    r"luckyorange": "Analytics: LuckyOrange",
    r"mouseflow": "Analytics: Mouseflow",
    r"clicktale": "Analytics: Clicktale",
    r"optimizely": "Analytics: Optimizely",
    r"vwo": "Analytics: VWO",
    r"matomo|piwik": "Analytics: Matomo/Piwik",
    r"plausible": "Analytics: Plausible",
    r"fathom": "Analytics: Fathom",
    r"simpleanalytics": "Analytics: Simple Analytics",
    r"umami": "Analytics: Umami",
    r"newrelic": "Monitoring: New Relic",
    r"datadog": "Monitoring: Datadog",
    r"sentry": "Monitoring: Sentry",
    r"logrocket": "Monitoring: LogRocket",
    r"posthog": "Analytics: PostHog",
    r"smartlook": "Analytics: SmartLook",
    r"openreplay": "Monitoring: OpenReplay",
    r"quantcast": "Analytics: Quantcast",
    r"comscore": "Analytics: comScore",
    r"chartbeat": "Analytics: Chartbeat",
    r"parsely": "Analytics: Parse.ly",
    r"branch\.io": "Analytics: Branch.io",
    r"adjust\.com": "Analytics: Adjust",
    r"appsflyer": "Analytics: AppsFlyer",
    r"adobe.*analytics|adobedtm": "Analytics: Adobe Analytics",
    r"yandex.*metrica|mc\.yandex": "Analytics: Yandex Metrica",
    r"baidu.*tongji|hm\.baidu": "Analytics: Baidu Tongji",
}

SSL_ISSUER_SIGNATURES = {
    "Let's Encrypt": "SSL: Let's Encrypt",
    "Cloudflare, Inc": "CDN: Cloudflare",
    "Google Trust Services": "SSL: Google Trust",
    "Amazon": "Cloud: AWS",
    "Microsoft": "Cloud: Azure",
    "DigiCert": "SSL: DigiCert",
    "Comodo": "SSL: Comodo",
    "Sectigo": "SSL: Sectigo",
    "GlobalSign": "SSL: GlobalSign",
    "GoDaddy": "SSL: GoDaddy",
    "cPanel": "Hosting: cPanel",
    "ZeroSSL": "SSL: ZeroSSL",
    "BuyPass": "SSL: BuyPass",
    "Entrust": "SSL: Entrust",
    "GeoTrust": "SSL: GeoTrust",
    "Thawte": "SSL: Thawte",
    "RapidSSL": "SSL: RapidSSL",
    "VeriSign": "SSL: VeriSign",
    "Certum": "SSL: Certum",
    "IdenTrust": "SSL: IdenTrust",
}

PATH_PROBE_PATHS = [
    "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/",
    "/administrator/", "/admin/", "/node/", "/user/",
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/api/", "/graphql", "/swagger.json", "/openapi.json",
    "/favicon.ico", "/composer.json", "/package.json",
    "/_next/static/", "/__nuxt/", "/assets/vue/",
    "/assets/react/", "/version", "/health", "/status",
    "/crossdomain.xml", "/client-access-policy.xml",
    "/Dockerfile", "/docker-compose.yml",
    "/nginx.conf", "/.htaccess", "/web.config",
    "/actuator/", "/actuator/health", "/actuator/env",
    "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
    "/jenkins/", "/jira/", "/confluence/", "/gitlab/",
    "/grafana/", "/prometheus/", "/kibana/",
    "/phpmyadmin/", "/pma/", "/adminer.php",
    "/server-status", "/server-info",
    "/metrics", "/debug/", "/debug.php",
    "/info.php", "/phpinfo.php", "/test.php",
    "/backup/", "/backups/", "/dump/", "/sql/",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/sitemap.xml", "/robots.txt",
    "/security.txt", "/humans.txt",
]

EXTENSION_PATTERNS = {
    ".php": "Tech: PHP",
    ".asp": "Tech: ASP Classic",
    ".aspx": "Tech: ASP.NET",
    ".jsp": "Tech: JSP",
    ".do": "Tech: Java Struts",
    ".action": "Tech: Java Struts2",
    ".py": "Tech: Python",
    ".rb": "Tech: Ruby",
    ".cfm": "Tech: ColdFusion",
    ".shtml": "Tech: SSI",
    ".pl": "Tech: Perl",
    ".cgi": "Tech: CGI",
    ".vue": "Tech: Vue SFC",
    ".jsx": "Tech: React JSX",
    ".ts": "Tech: TypeScript",
    ".tsx": "Tech: React TSX",
    ".go": "Tech: Go",
    ".java": "Tech: Java",
    ".scala": "Tech: Scala",
    ".kt": "Tech: Kotlin",
    ".swift": "Tech: Swift",
    ".rs": "Tech: Rust",
    ".ex": "Tech: Elixir",
    ".exs": "Tech: Elixir",
    ".cr": "Tech: Crystal",
    ".jl": "Tech: Julia",
    ".clj": "Tech: Clojure",
    ".erl": "Tech: Erlang",
    ".hs": "Tech: Haskell",
    ".lua": "Tech: Lua",
    ".rkt": "Tech: Racket",
    ".scm": "Tech: Scheme",
    ".ml": "Tech: OCaml",
    ".fs": "Tech: F#",
    ".fsx": "Tech: F#",
    ".dart": "Tech: Dart",
    ".zig": "Tech: Zig",
    ".nim": "Tech: Nim",
    ".v": "Tech: V",
    ".cbl": "Tech: COBOL",
}

TECHNOLOGY_TIMELINE = {
    "jQuery": 2006,
    "MooTools": 2006,
    "Prototype": 2005,
    "AngularJS": 2010,
    "Backbone.js": 2010,
    "Ember.js": 2011,
    "React": 2013,
    "Vue.js": 2014,
    "Svelte": 2016,
    "Next.js": 2016,
    "Nuxt.js": 2016,
    "Gatsby": 2015,
    "Bootstrap": 2011,
    "Tailwind CSS": 2017,
    "Bulma": 2016,
    "Foundation": 2012,
    "WordPress": 2003,
    "Drupal": 2001,
    "Joomla": 2005,
    "Magento": 2008,
    "Shopify": 2006,
    "Wix": 2006,
    "Squarespace": 2003,
    "Django": 2005,
    "Flask": 2010,
    "Laravel": 2011,
    "Symfony": 2005,
    "Ruby on Rails": 2005,
    "Express.js": 2010,
    "Spring": 2002,
    "ASP.NET": 2002,
    "Node.js": 2009,
    "Deno": 2018,
    "Bun": 2022,
}

PROXY_DB_PATTERNS = {
    "mysql": r"mysql|mariadb",
    "postgresql": r"postgresql|postgres|pgsql",
    "mongodb": r"mongodb|mongo",
    "redis": r"redis",
    "elasticsearch": r"elasticsearch|elastic",
    "cassandra": r"cassandra",
    "couchdb": r"couchdb",
    "sqlite": r"sqlite",
    "mssql": r"mssql|sqlserver|sql server",
    "oracle": r"oracle",
    "firebase": r"firebase|firestore",
    "supabase": r"supabase",
    "dynamodb": r"dynamodb",
    "neo4j": r"neo4j",
}

async def probe_path(host, path, client):
    try:
        url = f"https://{host}{path}"
        resp = await safe_fetch(client, url, timeout=5.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            follow_redirects=False)
        return resp.status_code, dict(resp.headers), resp.text[:10000] if hasattr(resp, "text") else ""
    except Exception:
        return 0, {}, ""

async def get_cert_issuer_info(host):
    try:
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, 443), timeout=3.0)),
            timeout=3.0
        )
        sock.settimeout(3.0)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()
        cert = ssock.getpeercert()
        ssock.close()
        sock.close()
        if cert:
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "")
            cn = issuer.get("commonName", "")
            return f"{org} ({cn})" if org and cn else (org or cn)
    except Exception:
        pass
    return ""

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    try:
        base_url = f"https://{host}"
        resp = await safe_fetch(client, base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        html = resp.text[:200000]
        cookies_list = list(resp.cookies) if hasattr(resp, "cookies") else []

        layer_findings = {
            "web_server": [], "cms": [], "framework": [], "cdn": [],
            "analytics": [], "security": [], "cache": [], "os": [],
            "database": [], "payments": [], "devops": [],
        }

        for header_key, (ftype, confidence) in HEADER_SIGNATURES.items():
            val = headers.get(header_key)
            if val:
                layer = "security" if "Security:" in ftype else ("cache" if "Cache:" in ftype else "web_server")
                findings.append(make_finding(
                    entity=val[:200] if val else ftype,
                    ftype=ftype,
                    source="TechStackProfiler",
                    confidence=confidence,
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"{header_key}: {val[:500] if val else ''}",
                    tags=["technology", header_key]
                ))

        cms_findings = {}
        for cms_name, patterns in CMS_META_PATTERNS.items():
            for pattern_set in patterns:
                meta_pattern = pattern_set[0]
                path_patterns = pattern_set[1:]
                m = re.search(meta_pattern, html, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                    cms_findings[cms_name] = version
                    break
                has_paths = all(p in html.lower() for p in path_patterns)
                if has_paths:
                    cms_findings[cms_name] = ""
                    break

        for cms_name, version in cms_findings.items():
            entity = f"{cms_name} {version}" if version else cms_name
            confidence = "High" if version else "Medium"
            timeline_year = TECHNOLOGY_TIMELINE.get(cms_name, "Unknown")
            findings.append(make_finding(
                entity=entity,
                ftype=f"CMS: {cms_name}",
                source="TechStackProfiler",
                confidence=confidence,
                color="blue",
                threat_level="Informational",
                raw_data=f"CMS: {cms_name} | Version: {version or 'unknown'} | Meta/Path indicators found | Released: {timeline_year}",
                tags=["cms", cms_name.lower()]
            ))

        for fw_name, patterns in JS_FRAMEWORK_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    timeline_year = TECHNOLOGY_TIMELINE.get(fw_name, "Unknown")
                    findings.append(make_finding(
                        entity=fw_name,
                        ftype="JavaScript Framework",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="cyan",
                        threat_level="Informational",
                        raw_data=f"Framework: {fw_name} | Pattern: {pat} | Released: {timeline_year}",
                        tags=["javascript", "framework", fw_name.lower().replace(".", "-").replace(" ", "-")]
                    ))
                    break

        for css_name, patterns in CSS_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    findings.append(make_finding(
                        entity=css_name,
                        ftype="CSS Framework",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        tags=["css", "framework", css_name.lower().replace(" ", "-")]
                    ))
                    break

        for path, ftype in PATH_SIGNATURES.items():
            status, _, body = await probe_path(host, path, client)
            if status not in (0, 404, 403):
                findings.append(make_finding(
                    entity=f"{path} [{status}]",
                    ftype=ftype,
                    source="TechStackProfiler",
                    confidence="High" if status == 200 else "Medium",
                    color="slate",
                    threat_level="Elevated Risk" if "leak" in ftype.lower() or "config" in ftype.lower() else "Informational",
                    raw_data=f"Path: {path} | Status: {status}",
                    tags=["path-probe", path.strip("/").replace("/", "-")]
                ))

        headers_str = str(headers).lower()
        for pattern, ftype in CDN_PATTERNS.items():
            if re.search(pattern, headers_str, re.IGNORECASE):
                findings.append(make_finding(
                    entity=ftype.replace("CDN: ", "").replace("CDN/WAAP: ", ""),
                    ftype=ftype,
                    source="TechStackProfiler",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"CDN indicator: {pattern} found in headers",
                    tags=["cdn", ftype.lower().replace(":", "").replace(" ", "-").replace("/", "-")]
                ))

        html_lower = html.lower()
        for pattern, ftype in ANALYTICS_PATTERNS.items():
            if re.search(pattern, html_lower, re.IGNORECASE):
                findings.append(make_finding(
                    entity=ftype.replace("Analytics: ", "").replace("Monitoring: ", ""),
                    ftype=ftype,
                    source="TechStackProfiler",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Analytics/Monitoring: {ftype}",
                    tags=["analytics", "monitoring", ftype.lower().replace(":", "").replace(" ", "-").replace("/", "-")]
                ))

        for db_name, db_pattern in PROXY_DB_PATTERNS.items():
            if re.search(db_pattern, html_lower, re.IGNORECASE) or re.search(db_pattern, headers_str, re.IGNORECASE):
                findings.append(make_finding(
                    entity=db_name.title(),
                    ftype=f"Database: {db_name.title()}",
                    source="TechStackProfiler",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["database", db_name]
                ))

        issuer_info = await get_cert_issuer_info(host)
        if issuer_info:
            for issuer_name, ftype in SSL_ISSUER_SIGNATURES.items():
                if issuer_name.lower() in issuer_info.lower():
                    findings.append(make_finding(
                        entity=issuer_info[:200],
                        ftype=ftype,
                        source="TechStackProfiler",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"SSL Issuer: {issuer_info}",
                        tags=["ssl", "issuer", ftype.lower().replace(":", "").replace(" ", "-")]
                    ))
                    break

        for cookie in cookies_list:
            cookie_name = cookie.name if hasattr(cookie, "name") else str(cookie).split("=")[0]
            if "php" in cookie_name.lower():
                findings.append(make_finding(
                    entity="PHP (via PHPSESSID cookie)",
                    ftype="Tech: PHP",
                    source="TechStackProfiler",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    tags=["technology", "php"]
                ))
            elif "asp.net" in cookie_name.lower() or "aspnet" in cookie_name.lower():
                findings.append(make_finding(
                    entity="ASP.NET (via ASP.NET_SessionId cookie)",
                    ftype="Tech: ASP.NET",
                    source="TechStackProfiler",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["technology", "aspnet"]
                ))
            elif "laravel" in cookie_name.lower():
                findings.append(make_finding(
                    entity="Laravel (via laravel_session cookie)",
                    ftype="Tech: Laravel (PHP)",
                    source="TechStackProfiler",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    tags=["technology", "laravel"]
                ))
            elif "connect.sid" == cookie_name.lower():
                findings.append(make_finding(
                    entity="Express.js/Node.js (via connect.sid cookie)",
                    ftype="Tech: Express.js",
                    source="TechStackProfiler",
                    confidence="High",
                    color="green",
                    threat_level="Informational",
                    tags=["technology", "express", "nodejs"]
                ))

        server_h = headers.get("server", "").lower()
        os_indicators = {
            "ubuntu": "OS: Ubuntu Linux",
            "debian": "OS: Debian Linux",
            "centos": "OS: CentOS Linux",
            "red hat": "OS: Red Hat Linux",
            "freebsd": "OS: FreeBSD",
            "windows": "OS: Microsoft Windows",
            "darwin": "OS: macOS",
            "alpine": "OS: Alpine Linux",
            "fedora": "OS: Fedora Linux",
            "suse": "OS: SUSE Linux",
            "opensuse": "OS: OpenSUSE Linux",
            "arch": "OS: Arch Linux",
            "gentoo": "OS: Gentoo Linux",
            "solaris": "OS: Solaris",
            "aix": "OS: IBM AIX",
            "hp-ux": "OS: HP-UX",
        }
        for os_sig, os_type in os_indicators.items():
            if os_sig in server_h:
                findings.append(make_finding(
                    entity=os_type.replace("OS: ", ""),
                    ftype=os_type,
                    source="TechStackProfiler",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"OS indicator: {os_sig} in Server header",
                    tags=["os", os_sig]
                ))
                break

        for hdr_key, (ftype, conf) in MORE_HEADER_SIGNATURES.items():
            val = headers.get(hdr_key)
            if val:
                findings.append(make_finding(
                    entity=val[:200] if val else ftype,
                    ftype=ftype,
                    source="TechStackProfiler",
                    confidence=conf,
                    color="slate",
                    threat_level="Informational",
                    tags=["technology", hdr_key, "extended"]
                ))

        for cms_name, patterns in ADDITIONAL_CMS_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    era = detect_technology_era(cms_name)
                    findings.append(make_finding(
                        entity=cms_name,
                        ftype=f"CMS: {cms_name}",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        raw_data=f"CMS: {cms_name} | Released: {era or 'unknown'}",
                        tags=["cms", cms_name.lower().replace(" ", "-").replace(".", "-")]
                    ))
                    break

        for fw_name, patterns in MORE_JS_FRAMEWORKS.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    era = detect_technology_era(fw_name)
                    findings.append(make_finding(
                        entity=fw_name,
                        ftype="JavaScript Framework",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="cyan",
                        threat_level="Informational",
                        raw_data=f"Framework: {fw_name} | Pattern: {pat} | Released: {era or 'unknown'}",
                        tags=["javascript", "framework", fw_name.lower().replace(".", "-").replace(" ", "-")]
                    ))
                    break

        for css_name, patterns in ADDITIONAL_CSS_FRAMEWORKS.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    era = detect_technology_era(css_name)
                    findings.append(make_finding(
                        entity=css_name,
                        ftype="CSS Framework",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        tags=["css", "framework", css_name.lower().replace(" ", "-")]
                    ))
                    break

        additional_paths = list(set(ADDITIONAL_PATH_PROBES) - set(PATH_PROBE_PATHS))
        for path in additional_paths:
            status, _, body = await probe_path(host, path, client)
            if status not in (0, 404, 403):
                findings.append(make_finding(
                    entity=f"{path} [{status}]",
                    ftype="Extended Path Discovery",
                    source="TechStackProfiler",
                    confidence="High" if status == 200 else "Medium",
                    color="slate",
                    threat_level="Elevated Risk" if any(x in path for x in [".env", ".git", "config", "settings", "backup", "dump", "log"]) else "Informational",
                    raw_data=f"Path: {path} | Status: {status}",
                    tags=["path-probe", "extended", path.strip("/").replace("/", "-")]
                ))

        payment_processors = detect_payment_processors(html)
        for pp in payment_processors:
            findings.append(make_finding(
                entity=pp.replace("Payment: ", ""),
                ftype=pp,
                source="TechStackProfiler",
                confidence="Medium",
                color="amber",
                threat_level="Informational",
                tags=["payment", pp.lower().replace(":", "").replace(" ", "-")]
            ))

        fonts = detect_fonts(html)
        for font in fonts:
            findings.append(make_finding(
                entity=font.replace("Font: ", ""),
                ftype=font,
                source="TechStackProfiler",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["font", font.lower().replace(":", "").replace(" ", "-")]
            ))

        third_party = detect_third_party_integrations(html)
        for tp, pattern in third_party:
            findings.append(make_finding(
                entity=tp.replace("Third-party: ", ""),
                ftype=tp,
                source="TechStackProfiler",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Third-party integration: {tp} | Pattern: {pattern}",
                tags=["third-party", tp.lower().replace(":", "").replace(" ", "-").replace("/", "-")]
            ))

        build_tools = detect_build_tools(html)
        for bt in build_tools:
            findings.append(make_finding(
                entity=bt,
                ftype=bt,
                source="TechStackProfiler",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
                tags=["build-tool", bt.lower().replace(":", "").replace(" ", "-")]
            ))

        test_tools = detect_test_frameworks(html)
        for tt in test_tools:
            findings.append(make_finding(
                entity=tt,
                ftype=tt,
                source="TechStackProfiler",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
                tags=["testing", tt.lower().replace(":", "").replace(" ", "-")]
            ))

        sec_findings = analyze_security_headers(headers)
        for sec_type, sec_msg, sec_severity, sec_color in sec_findings:
            threat = "Elevated Risk" if sec_severity == "High" else ("Medium Risk" if sec_severity == "Medium" else "Informational")
            findings.append(make_finding(
                entity=sec_msg[:200],
                ftype=f"Security Header: {sec_type}",
                source="TechStackProfiler",
                confidence="High",
                color=sec_color,
                threat_level=threat,
                tags=["security", "header", sec_type.lower().replace(" ", "-")]
            ))

        for finding in findings[:]:
            entity = finding.entity if hasattr(finding, 'entity') else ""
            tech_name = entity.split(" ")[0] if entity else ""
            version_str = extract_version_from_string(entity, tech_name)
            if version_str:
                eol_year, is_eol = check_eol(tech_name, version_str)
                if is_eol:
                    findings.append(make_finding(
                        entity=f"{tech_name} {version_str} (EOL {eol_year})",
                        ftype=f"End-of-Life: {tech_name}",
                        source="TechStackProfiler",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"{tech_name} version {version_str} reached EOL in {eol_year} - no security updates",
                        tags=["eol", "security", tech_name.lower()]
                    ))
                known_cve = check_version_vulnerability(tech_name, version_str)
                if known_cve:
                    findings.append(make_finding(
                        entity=f"{tech_name} {version_str}: {known_cve}",
                        ftype=f"CVE: {known_cve.split('(')[0].strip()}",
                        source="TechStackProfiler",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        tags=["cve", "vulnerability", tech_name.lower()]
                    ))

            era = detect_technology_era(tech_name)
            if era:
                age = 2026 - era
                if age > 15:
                    findings.append(make_finding(
                        entity=f"{tech_name} (Released {era}, {age} years old)",
                        ftype="Legacy Technology",
                        source="TechStackProfiler",
                        confidence="Low",
                        color="orange",
                        threat_level="Informational",
                        tags=["legacy", tech_name.lower()]
                    ))

        tech_categories_used = set()
        for finding in findings:
            entity = finding.entity if hasattr(finding, 'entity') else ""
            cat = detect_tech_category(entity)
            for cname in TECH_CATEGORIES.get(cat, []):
                if cname.lower() in entity.lower():
                    tech_categories_used.add(cat)
                    break

        for cat in sorted(tech_categories_used):
            findings.append(make_finding(
                entity=cat,
                ftype=f"Technology Category: {cat}",
                source="TechStackProfiler",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                tags=["category", cat.lower().replace(" ", "-")]
            ))

        if findings:
            findings.append(make_finding(
                entity=f"{len(findings)} technologies detected",
                ftype="Technology Stack Summary",
                source="TechStackProfiler",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"Total techs: {len(findings)} | Host: {host}",
                tags=["technology", "summary"]
            ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Tech Stack Profiler error: {str(e)[:100]}",
            ftype="Tech Stack Error",
            source="TechStackProfiler",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings

# === EXTENDED UPGRADE: 300+ more signatures, EOL detection, dependency mapping, confidence scoring ===

EOL_DATES = {
    "WordPress": {"5.0": "2019", "5.1": "2019", "5.2": "2019", "5.3": "2019", "5.4": "2020", "5.5": "2020", "5.6": "2021", "5.7": "2021", "5.8": "2021", "5.9": "2022", "6.0": "2022", "6.1": "2022"},
    "jQuery": {"1.12": "2016", "2.2": "2016", "3.0": "2016", "3.1": "2016", "3.2": "2017", "3.3": "2018", "3.4": "2019", "3.5": "2020", "3.6": "2021"},
    "AngularJS": {"1.0": "2012", "1.2": "2014", "1.3": "2014", "1.4": "2015", "1.5": "2016", "1.6": "2016", "1.7": "2018", "1.8": "2022"},
    "Bootstrap": {"3.0": "2013", "3.3": "2015", "3.4": "2019", "4.0": "2018", "4.1": "2018", "4.2": "2018", "4.3": "2019", "4.4": "2019", "4.5": "2020", "4.6": "2021"},
    "React": {"15.0": "2016", "16.0": "2017", "16.8": "2019", "17.0": "2020"},
    "Vue.js": {"2.0": "2016", "2.6": "2019", "2.7": "2022", "3.0": "2020"},
    "Angular": {"2.0": "2016", "4.0": "2017", "5.0": "2017", "6.0": "2018", "7.0": "2018", "8.0": "2019", "9.0": "2020", "10.0": "2020", "11.0": "2020", "12.0": "2021", "13.0": "2021", "14.0": "2022", "15.0": "2022"},
    "Drupal": {"6": "2011", "7": "2015", "8": "2019", "9": "2021"},
    "Joomla": {"1.5": "2012", "1.6": "2011", "1.7": "2011", "2.5": "2014", "3.0": "2012", "3.4": "2015", "3.5": "2016", "3.6": "2016", "3.7": "2017", "3.8": "2017", "3.9": "2018", "3.10": "2021"},
    "ASP.NET": {"4.0": "2010", "4.5": "2012", "4.5.1": "2013", "4.5.2": "2014", "4.6": "2015", "4.6.1": "2015", "4.6.2": "2016", "4.7": "2017", "4.7.1": "2017", "4.7.2": "2018", "4.8": "2019"},
    "Magento": {"1.9": "2012", "2.0": "2015", "2.1": "2016", "2.2": "2017", "2.3": "2018"},
    "Laravel": {"5.0": "2015", "5.1": "2015", "5.2": "2015", "5.3": "2016", "5.4": "2017", "5.5": "2017", "5.6": "2018", "5.7": "2018", "5.8": "2019", "6.0": "2019", "7.0": "2020", "8.0": "2020", "9.0": "2022"},
    "Symfony": {"2.0": "2011", "2.8": "2015", "3.0": "2015", "3.4": "2017", "4.0": "2017", "4.4": "2019", "5.0": "2019", "5.4": "2021"},
    "Django": {"1.11": "2017", "2.0": "2017", "2.1": "2018", "2.2": "2019", "3.0": "2019", "3.1": "2020", "3.2": "2021", "4.0": "2021", "4.1": "2022"},
    "Ruby on Rails": {"4.2": "2016", "5.0": "2016", "5.1": "2017", "5.2": "2018", "6.0": "2019", "6.1": "2020", "7.0": "2021"},
    "Node.js": {"10": "2018", "12": "2019", "14": "2020", "16": "2021", "18": "2022", "20": "2023"},
    "Go": {"1.14": "2020", "1.15": "2020", "1.16": "2021", "1.17": "2021", "1.18": "2022", "1.19": "2022", "1.20": "2023"},
    "Python": {"3.6": "2016", "3.7": "2018", "3.8": "2019", "3.9": "2020", "3.10": "2021", "3.11": "2022", "3.12": "2023"},
}

TECH_CATEGORIES = {
    "CMS": ["WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Squarespace", "Ghost", "Weebly", "Blogger", "TYPO3", "PrestaShop", "OpenCart", "Concrete CMS", "Django CMS", "Sitecore", "Umbraco", "Kentico", "Contentful", "Strapi"],
    "JavaScript Framework": ["React", "Vue.js", "Angular", "Svelte", "Solid", "Qwik", "Preact", "Lit", "Stencil", "Ember", "Backbone", "Knockout", "Mithril", "Riot", "Aurelia", "Dojo", "Ext JS", "YUI", "MooTools", "Prototype"],
    "CSS Framework": ["Bootstrap", "Tailwind CSS", "Foundation", "Bulma", "Materialize", "Semantic UI", "UIKit", "PureCSS", "Chakra UI", "Ant Design", "PrimeFaces", "Fomantic UI"],
    "SSR/Meta-framework": ["Next.js", "Nuxt.js", "Gatsby", "Remix", "Astro", "Fresh", "SvelteKit", "Analog"],
    "Web Server": ["nginx", "Apache", "IIS", "Caddy", "Lighttpd", "Tomcat", "Jetty", "WildFly", "Node.js (built-in)", "Express", "Kestrel"],
    "Programming Language": ["PHP", "Python", "Ruby", "Java", "JavaScript/TypeScript", "C#", "Go", "Rust", "Perl", "Kotlin", "Scala", "Elixir", "Swift"],
    "Database": ["MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "Cassandra", "CouchDB", "SQLite", "MSSQL", "Oracle", "Firebase", "Supabase", "DynamoDB", "Neo4j"],
    "CDN": ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Imperva", "StackPath", "KeyCDN", "BunnyCDN", "jsDelivr", "Azure CDN", "Google Cloud CDN"],
    "Analytics": ["Google Analytics", "Meta Pixel", "Hotjar", "FullStory", "Amplitude", "Mixpanel", "Plausible", "Matomo", "Fathom", "Umami", "Adobe Analytics", "Yandex Metrica"],
    "Monitoring": ["Sentry", "New Relic", "Datadog", "LogRocket", "OpenReplay", "Grafana", "Prometheus", "Kibana", "Cockpit", "Netdata"],
    "Cloud Platform": ["AWS", "Azure", "GCP", "Vercel", "Netlify", "Cloudflare Pages", "Fly.io", "Railway", "Heroku", "DigitalOcean"],
    "DevOps/CI/CD": ["Jenkins", "GitLab CI", "GitHub Actions", "CircleCI", "Travis CI", "Bitbucket Pipelines", "ArgoCD", "Helm", "Terraform", "Ansible", "Docker", "Kubernetes"],
    "Payment": ["Stripe", "PayPal", "Square", "Braintree", "Adyen", "Shopify Payments", "WooCommerce Payments", "Mollie", "Razorpay", "PayU"],
    "Security": ["HSTS", "CSP", "CORS", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Expect-CT", "Feature-Policy"],
    "Email": ["Mailchimp", "SendGrid", "Postmark", "Mailgun", "Amazon SES", "MailerLite", "ConvertKit", "SparkPost", "Resend"],
    "Auth": ["Auth0", "Firebase Auth", "Okta", "Keycloak", "Clerk", "NextAuth.js", "Passport.js", "SuperTokens"],
    "Headless CMS": ["Contentful", "Strapi", "Sanity", "Prismic", "Hygraph", "Directus", "Ghost (headless)"],
    "Search": ["Elasticsearch", "Algolia", "Meilisearch", "Typesense", "Search.io", "Swiftype"],
    "Video": ["YouTube", "Vimeo", "Wistia", "JW Player", "Video.js", "Mux", "Brightcove"],
    "Font/CDN": ["Google Fonts", "Font Awesome", "Adobe Fonts/Typekit", "Fontsource", "icomoon"],
}

MORE_HEADER_SIGNATURES = {
    "x-sql": ("Tech: SQL/PHP", "Medium"),
    "x-powered-by-plesk": ("Hosting: Plesk", "High"),
    "x-powered-by-wordpress": ("CMS: WordPress", "High"),
    "x-joomla-cache": ("CMS: Joomla", "High"),
    "x-drupal-cache": ("CMS: Drupal", "High"),
    "x-magento-init": ("CMS: Magento", "High"),
    "x-magento-cache": ("CMS: Magento Cache", "High"),
    "x-prestashop": ("CMS: PrestaShop", "High"),
    "x-mod-pagespeed": ("Tech: PageSpeed", "Medium"),
    "x-pagespeed": ("Tech: PageSpeed", "Medium"),
    "x-b3-traceid": ("Tech: Zipkin/Jaeger Trace", "Medium"),
    "x-b3-spanid": ("Tech: Zipkin/Jaeger Trace", "Medium"),
    "x-request-id": ("Tech: Request Tracing", "Medium"),
    "x-trace-id": ("Tech: Request Tracing", "Medium"),
    "x-datadog-trace-id": ("Tech: Datadog APM", "High"),
    "x-datadog-parent-id": ("Tech: Datadog APM", "High"),
    "x-newrelic-id": ("Tech: New Relic APM", "High"),
    "x-newrelic-transaction": ("Tech: New Relic APM", "High"),
    "x-hacker": ("Security: Defensive Header", "Low"),
    "x-404": ("Security: Defensive Header", "Low"),
    "x-cache-status": ("Cache: Status", "Medium"),
    "x-hcdn-served-by": ("CDN: Custom", "Medium"),
    "x-hcdn-request-id": ("CDN: Custom", "Medium"),
    "x-optimizely": ("Analytics: Optimizely", "Medium"),
    "x-litespeed-cache": ("Cache: LiteSpeed", "High"),
    "x-iinfo": ("CDN: Incapsula/Imperva", "High"),
    "x-cdn": ("CDN: Custom Header", "Medium"),
    "x-proxy-cache": ("Cache: Proxy", "Medium"),
    "x-docker": ("Tech: Docker", "High"),
    "x-docker-registry": ("Tech: Docker Registry", "High"),
    "x-kubernetes": ("Tech: Kubernetes", "High"),
    "x-k8s": ("Tech: Kubernetes", "High"),
    "x-rancher": ("Tech: Rancher", "High"),
    "x-openshift": ("Tech: OpenShift", "High"),
    "x-nomad": ("Tech: HashiCorp Nomad", "High"),
    "x-consul": ("Tech: HashiCorp Consul", "High"),
    "x-vault": ("Tech: HashiCorp Vault", "High"),
    "x-amz-server-side-encryption": ("Cloud: AWS SSE", "High"),
    "x-amz-version-id": ("Cloud: AWS S3 Version", "Medium"),
    "x-amz-delete-marker": ("Cloud: AWS S3 Delete", "Medium"),
    "x-amz-storage-class": ("Cloud: AWS Storage", "Medium"),
    "x-guploader-uploadid": ("Cloud: GCS Upload", "Medium"),
    "x-goog-generation": ("Cloud: GCS Generation", "Medium"),
    "x-azure-ref": ("Cloud: Azure CDN Ref", "Medium"),
    "x-ms-request-id": ("Cloud: Azure Request", "Medium"),
    "x-served-by": ("Proxy: Served By", "Medium"),
    "x-cache-hdr": ("Cache: Header", "Medium"),
    "x-err": ("Error: Internal", "Low"),
    "x-debug": ("Debug: Info", "Low"),
}

ADDITIONAL_CMS_PATTERNS = {
    "Sitecore": [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Sitecore'],
    "Umbraco": [r'umbraco', r'__UMBRACO__'],
    "Kentico": [r'kentico', r'CMS\.Kentico'],
    "Contentful": [r'contentful', r'ctfassets\.net'],
    "Strapi": [r'strapi', r'_strapi'],
    "Sanity": [r'sanity', r'@sanity'],
    "Prismic": [r'prismic\.io', r'@prismicio'],
    "Webflow": [r'webflow', r'data-wf-'],
    "Craft CMS": [r'craftcms', r'craft\.js'],
    "Statamic": [r'statamic', r'/statamic/'],
    "October CMS": [r'octobercms', r'October\.CMS'],
    "Kirby": [r'kirby', r'/kirby/'],
    "Grav": [r'grav', r'/grav/'],
    "Bolt CMS": [r'bolt\.cm', r'/bolt/'],
    "SilverStripe": [r'silverstripe', r'SilverStripeNavigator'],
    "Concrete5": [r'concrete5', r'CCM_'],
    "ProcessWire": [r'processwire', r'/wire/'],
    "MODX": [r'modx', r'MODX_REVP'],
    "Textpattern": [r'textpattern', r'/textpattern/'],
    "DotNetNuke": [r'dnn|dotnetnuke', r'DNNPlatform'],
}

MORE_JS_FRAMEWORKS = {
    "Alpine.js": [r'alpinejs', r'x-data', r'x-init', r'x-on:', r'x-bind', r'x-model', r'x-show', r'x-if', r'x-for', r'x-text', r'x-html', r'x-ref', r'x-cloak', r'x-teleport', r'x-id', r'x-effect', r'x-transition'],
    "Stimulus": [r'stimulus', r'data-controller', r'data-action', r'data-target', r'data-reflex'],
    "HTMX": [r'htmx', r'hx-get', r'hx-post', r'hx-put', r'hx-delete', r'hx-patch', r'hx-trigger', r'hx-target', r'hx-swap', r'hx-indicator', r'hx-boost', r'hx-push-url', r'hx-select'],
    "Hotwire Turbo": [r'turbo\.js', r'@hotwired/turbo', r'turbo-frame', r'turbo-stream', r'data-turbo'],
    "Hyperscript": [r'hyperscript', r'_\s*\.js'],
    "Petite Vue": [r'petite-vue', r'@vue/petite'],
    "Marko": [r'marko', r'@marko/'],
    "Shoelace": [r'@shoelace-style', r'shoelace'],
    "Ionic": [r'ionic', r'@ionic/'],
    "Onsen UI": [r'onsen', r'ons-'],
    "Framework7": [r'framework7', r'f7-'],
    "Quasar": [r'quasar', r'@quasar/'],
    "Vuetify": [r'vuetify', r'v-'],
    "Element Plus": [r'element-plus', r'el-'],
    "PrimeVue": [r'primevue', r'pv-'],
    "Ant Design Vue": [r'ant-design-vue', r'a-'],
    "Naive UI": [r'naive-ui', r'n-'],
    "Nuxt UI": [r'@nuxt/ui', r'/nuxt/'],
}

ADDITIONAL_CSS_FRAMEWORKS = {
    "Open Props": [r'open-props', r'--md-sys'],
    "Pico CSS": [r'pico\.css', r'pico.min.css'],
    "PureCSS": [r'pure\.css', r'pure-min\.css', r'pure/grids'],
    "MVP.css": [r'mvp\.css', r'mvp\.min\.css'],
    "Water.css": [r'water\.css', r'water-dark\.css'],
    "Milligram": [r'milligram\.css', r'milligram\.min\.css'],
    "Skeleton": [r'skeleton\.css', r'skeleton\.min\.css'],
    "Mini.css": [r'mini\.css', r'mini\.min\.css'],
    "Chota": [r'chota\.css', r'chota\.min\.css'],
    "Picnic CSS": [r'picnic\.css', r'picnic\.min\.css'],
    "Siimple": [r'siimple\.css', r'siimple\.min\.css'],
    "Kulala": [r'kulala\.css', r'kulala\.min\.css'],
    "Awsm": [r'awsm\.css', r'awsm\.min\.css'],
    "Tacit": [r'tacit\.css', r'tacit\.min\.css'],
    "Bahunya": [r'bahunya\.css', r'bahunya\.min\.css'],
    "Vanilla CSS": [r'vanilla-framework', r'vanilla\.css'],
    "Fomantic UI": [r'fomantic', r'fomantic-ui'],
    "UIkit": [r'uikit\.css', r'uikit\.min\.css', r'uk-'],
    "NES.css": [r'nes\.css', r'nes\.min\.css'],
    "98.css": [r'98\.css', r'98\.min\.css'],
    "XP.css": [r'xp\.css', r'xp\.min\.css'],
    "7.css": [r'7\.css', r'7\.min\.css'],
    "Bolt CSS": [r'bolt\.css', r'bolt\.min\.css'],
}

PAYMENT_PATTERNS = {
    r"stripe\.com/billing": "Payment: Stripe",
    r"paypal\.com|paypalobjects": "Payment: PayPal",
    r"square\.com|squareup": "Payment: Square",
    r"braintreepayments": "Payment: Braintree",
    r"adyen": "Payment: Adyen",
    r"mollie": "Payment: Mollie",
    r"razorpay": "Payment: Razorpay",
    r"payumoney|payu\.in": "Payment: PayU",
    r"2checkout|avangate": "Payment: 2Checkout",
    r"authorize\.net": "Payment: Authorize.Net",
    r"worldpay": "Payment: Worldpay",
    r"checkout\.com": "Payment: Checkout.com",
    r"klarna": "Payment: Klarna",
    r"shopify.*pay|shopify_payments": "Payment: Shopify Payments",
    r"woocommerce.*gateway|wc-gateway": "Payment: WooCommerce Gateway",
}

FONT_PATTERNS = {
    r"fonts\.googleapis\.com|fonts\.gstatic\.com": "Font: Google Fonts",
    r"fontawesome|fa-": "Font: Font Awesome",
    r"use\.typekit\.net|p\.typekit\.net": "Font: Adobe Fonts/Typekit",
    r"fonts\.fontshare\.com": "Font: Fontshare",
    r"fonts\.bunny\.net": "Font: Bunny Fonts (Privacy-friendly)",
    r"cdn\.fontsource\.org": "Font: Fontsource",
    r"icomoon\.io": "Font: Icomoon",
    r"use\.fontawesome\.com": "Font: Font Awesome Pro",
}

ADDITIONAL_PATH_PROBES = [
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server", "/.well-known/change-password",
    "/.well-known/apple-app-site-association", "/.well-known/assetlinks.json",
    "/security.txt", "/humans.txt", "/ads.txt", "/robots.txt",
    "/sitemap.xml", "/sitemap_index.xml", "/sitemaps.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/api/health", "/api/status", "/api/version",
    "/healthz", "/readyz", "/livez",
    "/metrics", "/debug/pprof/", "/debug/vars",
    "/actuator/prometheus", "/actuator/metrics",
    "/env", "/config", "/dump",
    "/info", "/status", "/ping", "/version",
    "/swagger-resources", "/swagger-ui/swagger-initializer.js",
    "/api/docs", "/api/schema", "/api/swagger",
    "/openapi.json", "/api/openapi.json",
    "/node_modules/.package-lock.json",
    "/yarn.lock", "/pnpm-lock.yaml", "/package-lock.json",
    "/docker-compose.override.yml", "/Dockerfile.prod", "/Dockerfile.dev",
    "/terraform.tfstate", "/terraform.tfvars",
    "/.env.backup", "/.env.local", "/.env.production",
    "/.gitignore", "/.gitattributes",
    "/.dockerignore", "/.editorconfig",
    "/CONTRIBUTING.md", "/CHANGELOG.md", "/CHANGELOG",
    "/SECURITY.md", "/CODE_OF_CONDUCT.md",
    "/webpack.config.js", "/vite.config.ts", "/next.config.js",
    "/nuxt.config.js", "/astro.config.mjs",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-cron.php",
    "/administrator/logs/", "/error.log",
    "/sites/default/settings.php",
    "/app/etc/local.xml", "/app/etc/env.php",
    "/shell/", "/mage/",
    "/.maintenance", "/maintenance.html",
    "/livereload.js", "/browser-sync",
    "/socket.io/", "/socket.io/?EIO=4",
    "/webpack-dev-server/",
]

THIRD_PARTY_API_PATTERNS = {
    r"maps\.googleapis\.com": "Third-party: Google Maps",
    r"maps\.api": "Third-party: Map Integration",
    r"player\.vimeo\.com": "Third-party: Vimeo",
    r"youtube\.com/embed": "Third-party: YouTube Embed",
    r"platform\.twitter\.com": "Third-party: Twitter/X Widget",
    r"platform\.instagram\.com": "Third-party: Instagram Embed",
    r"connect\.facebook\.net": "Third-party: Facebook SDK",
    r"www\.google\.com/recaptcha": "Third-party: reCAPTCHA",
    r"www\.gstatic\.com/recaptcha": "Third-party: reCAPTCHA",
    r"cdn\.ampproject\.org": "Third-party: AMP",
    r"disqus\.com": "Third-party: Disqus Comments",
    r"cse\.google\.com": "Third-party: Google Custom Search",
    r"www\.googletagservices\.com": "Third-party: Google Ad Services",
    r"doubleclick\.net": "Third-party: DoubleClick",
    r"adservice\.google\.com": "Third-party: Google Ads",
    r"cdn\.cookielaw\.org": "Third-party: Cookie Consent (OneTrust)",
    r"cdn\.consentmanager\.net": "Third-party: Consent Management",
    r"widget\.trovit\.com": "Third-party: Widget",
    r"zendesk\.com|zdassets": "Third-party: Zendesk",
    r"intercom\.io|intercomcdn": "Third-party: Intercom",
    r"crisp\.chat|client\.crisp": "Third-party: Crisp Chat",
    r"tawk\.to": "Third-party: Tawk.to Chat",
    r"livechatinc\.com": "Third-party: LiveChat",
    r"drift\.com|driftt\.com": "Third-party: Drift Chat",
    r"olark\.com": "Third-party: Olark Chat",
    r"tidio\.co": "Third-party: Tidio Chat",
    r"smartsuppchat": "Third-party: Smartsupp Chat",
    r"chatra\.io": "Third-party: Chatra",
}

def check_eol(tech_name, version_str):
    try:
        if tech_name in EOL_DATES:
            versions = EOL_DATES[tech_name]
            for ver, year in versions.items():
                if version_str.startswith(ver):
                    return year, int(year) <= 2023
    except Exception:
        pass
    return None, None

def calculate_confidence(layer, indicators_count):
    if indicators_count >= 3:
        return "Very High"
    elif indicators_count >= 2:
        return "High"
    elif indicators_count >= 1:
        return "Medium"
    return "Low"

def detect_tech_category(tech_name):
    for category, techs in TECH_CATEGORIES.items():
        if tech_name in techs:
            return category
    return "General"

def extract_version_from_string(text, tech_name):
    try:
        pattern = re.escape(tech_name) + r'\s*[/v]?\s*([\d.]+)'
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""

def detect_technology_era(tech_name):
    timeline = {
        "Prototype": 2005, "jQuery": 2006, "MooTools": 2006, "Dojo": 2005, "YUI": 2005,
        "Ext JS": 2007, "Script.aculo.us": 2005, "AngularJS": 2010, "Backbone.js": 2010,
        "Ember.js": 2011, "Knockout": 2010, "Bootstrap": 2011, "Foundation": 2012,
        "React": 2013, "Vue.js": 2014, "Angular": 2016, "Svelte": 2016, "Preact": 2015,
        "Lit": 2019, "Solid": 2021, "Qwik": 2022, "Alpine.js": 2020, "HTMX": 2020,
        "Tailwind CSS": 2017, "Chakra UI": 2019, "Ant Design": 2017,
        "WordPress": 2003, "Drupal": 2001, "Joomla": 2005, "Magento": 2008,
        "Shopify": 2006, "Wix": 2006, "Squarespace": 2003, "Ghost": 2013,
        "Strapi": 2020, "Contentful": 2016, "Sanity": 2017, "Prismic": 2015,
        "Next.js": 2016, "Nuxt.js": 2016, "Gatsby": 2015, "Remix": 2021, "Astro": 2021,
        "SvelteKit": 2021, "Express.js": 2010, "Fastify": 2020, "Hono": 2022,
        "Flask": 2010, "Django": 2005, "Laravel": 2011, "Symfony": 2005,
        "Ruby on Rails": 2005, "Spring": 2002, "ASP.NET": 2002, "Phoenix": 2015,
        "Node.js": 2009, "Deno": 2018, "Bun": 2022, "Go": 2009, "Rust": 2010,
        "nginx": 2004, "Apache": 1995, "IIS": 1995, "Caddy": 2015, "Lighttpd": 2003,
        "Cloudflare": 2009, "AWS": 2006, "Azure": 2010, "GCP": 2008,
        "Vercel": 2021, "Netlify": 2015, "Fly.io": 2020, "Railway": 2021,
        "Terraform": 2014, "Docker": 2013, "Kubernetes": 2015,
        "Stripe": 2011, "PayPal": 1998, "Square": 2009,
        "Google Analytics": 2005, "Matomo": 2007, "Plausible": 2019, "Fathom": 2019,
    }
    return timeline.get(tech_name, None)

def detect_payment_processors(html):
    findings_list = []
    try:
        for pattern, ftype in PAYMENT_PATTERNS.items():
            if re.search(pattern, html, re.IGNORECASE):
                findings_list.append(ftype)
    except Exception:
        pass
    return findings_list

def detect_fonts(html):
    findings_list = []
    try:
        for pattern, ftype in FONT_PATTERNS.items():
            if re.search(pattern, html, re.IGNORECASE):
                findings_list.append(ftype)
    except Exception:
        pass
    return findings_list

def detect_third_party_integrations(html):
    findings_list = []
    try:
        for pattern, ftype in THIRD_PARTY_API_PATTERNS.items():
            if re.search(pattern, html, re.IGNORECASE):
                findings_list.append((ftype, pattern))
    except Exception:
        pass
    return findings_list

def check_version_vulnerability(tech_name, version_str):
    known_vulns = {
        "WordPress": {"4.7": "CVE-2017-1001000 (REST API)", "5.0": "CVE-2019-9787 (CSRF)", "5.5": "CVE-2020-28032 (Stored XSS)"},
        "jQuery": {"1.12": "CVE-2020-11023 (XSS)", "3.4": "CVE-2020-11023 (XSS)"},
        "AngularJS": {"1.6": "CVE-2017-16087 (XSS)", "1.7": "CVE-2022-25844 (Prototype Pollution)"},
        "Bootstrap": {"3.4": "CVE-2019-8331 (XSS)", "4.3": "CVE-2019-8331 (XSS)"},
        "React": {"16.0": "CVE-2018-6341 (SSRF)", "16.8": "CVE-2022-23530 (DoS)"},
        "Drupal": {"7": "CVE-2019-6340 (RCE)", "8": "CVE-2019-6342 (RCE)"},
        "Laravel": {"5.7": "CVE-2018-15133 (RCE)", "8.0": "CVE-2021-21263 (XSS)"},
    }
    try:
        if tech_name in known_vulns:
            for ver, cve in known_vulns[tech_name].items():
                if version_str.startswith(ver):
                    return cve
    except Exception:
        pass
    return ""

def analyze_security_headers(headers):
    findings_list = []
    try:
        h = {k.lower(): v for k, v in headers.items()}
        security_checks = {
            "strict-transport-security": ("HSTS", "HSTS header present", "Missing HSTS header", "High"),
            "content-security-policy": ("CSP", "CSP header present", "Missing CSP header", "High"),
            "x-frame-options": ("ClickJacking", "X-Frame-Options present", "Missing clickjacking protection", "Medium"),
            "x-content-type-options": ("MIME-Sniff", "X-Content-Type-Options present", "Missing MIME-sniffing protection", "Medium"),
            "x-xss-protection": ("XSS", "X-XSS-Protection present", "", "Medium"),
            "referrer-policy": ("Referrer", "Referrer-Policy present", "Missing referrer policy", "Low"),
            "permissions-policy": ("Permissions", "Permissions-Policy present", "Missing permissions policy", "Medium"),
            "cross-origin-opener-policy": ("COOP", "COOP header present", "Missing COOP header", "Medium"),
            "cross-origin-resource-policy": ("CORP", "CORP header present", "Missing CORP header", "Low"),
            "cross-origin-embedder-policy": ("COEP", "COEP header present", "Missing COEP header", "Low"),
        }
        for hdr, (name, present_msg, missing_msg, severity) in security_checks.items():
            if hdr in h:
                findings_list.append(("Security Header", f"✓ {present_msg}: {h[hdr][:80]}", severity, "emerald"))
            elif missing_msg:
                findings_list.append(("Security Gap", f"✗ {missing_msg}", severity, "orange"))
    except Exception:
        pass
    return findings_list

def detect_build_tools(html):
    tools = []
    try:
        if re.search(r'webpack|__webpack_require__', html):
            tools.append("Build: Webpack")
        if re.search(r'vite|__vite__', html):
            tools.append("Build: Vite")
        if re.search(r'parcel|__parcel__', html):
            tools.append("Build: Parcel")
        if re.search(r'esbuild', html):
            tools.append("Build: esbuild")
        if re.search(r'snowpack', html):
            tools.append("Build: Snowpack")
        if re.search(r'turbopack', html):
            tools.append("Build: Turbopack")
        if re.search(r'rollup|__rollup__', html):
            tools.append("Build: Rollup")
        if re.search(r'gulp\.js|gulpfile', html):
            tools.append("Build: Gulp")
        if re.search(r'grunt|gruntfile', html):
            tools.append("Build: Grunt")
        if re.search(r'browserify|__browserify__', html):
            tools.append("Build: Browserify")
        if re.search(r'babel.*polyfill|@babel/', html):
            tools.append("Transpiler: Babel")
        if re.search(r'swc|@swc/', html):
            tools.append("Transpiler: SWC")
        if re.search(r'typescript|\.ts\b', html):
            tools.append("Language: TypeScript")
        if re.search(r'coffeescript', html):
            tools.append("Language: CoffeeScript")
        if re.search(r'dart.*js|dart2js', html):
            tools.append("Language: Dart")
    except Exception:
        pass
    return tools

def detect_test_frameworks(html):
    tools = []
    try:
        if re.search(r'jest|__jest__', html):
            tools.append("Testing: Jest")
        if re.search(r'vitest|__vitest__', html):
            tools.append("Testing: Vitest")
        if re.search(r'mocha|__mocha__', html):
            tools.append("Testing: Mocha")
        if re.search(r'jasmine|__jasmine__', html):
            tools.append("Testing: Jasmine")
        if re.search(r'cypress', html):
            tools.append("Testing: Cypress")
        if re.search(r'playwright', html):
            tools.append("Testing: Playwright")
        if re.search(r'puppeteer', html):
            tools.append("Testing: Puppeteer")
        if re.search(r'karma', html):
            tools.append("Testing: Karma")
        if re.search(r'availability|ava', html):
            tools.append("Testing: AVA")
        if re.search(r'tape.*js', html):
            tools.append("Testing: Tape")
    except Exception:
        pass
    return tools
