import httpx
import re
import ssl
import socket
import asyncio
from models import IntelligenceFinding
from datetime import datetime

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
        resp = await client.get(url, timeout=5.0,
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
        resp = await client.get(base_url, follow_redirects=True,
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
                findings.append(IntelligenceFinding(
                    entity=val[:200] if val else ftype,
                    type=ftype,
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
            findings.append(IntelligenceFinding(
                entity=entity,
                type=f"CMS: {cms_name}",
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
                    findings.append(IntelligenceFinding(
                        entity=fw_name,
                        type="JavaScript Framework",
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
                    findings.append(IntelligenceFinding(
                        entity=css_name,
                        type="CSS Framework",
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
                findings.append(IntelligenceFinding(
                    entity=f"{path} [{status}]",
                    type=ftype,
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
                findings.append(IntelligenceFinding(
                    entity=ftype.replace("CDN: ", "").replace("CDN/WAAP: ", ""),
                    type=ftype,
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
                findings.append(IntelligenceFinding(
                    entity=ftype.replace("Analytics: ", "").replace("Monitoring: ", ""),
                    type=ftype,
                    source="TechStackProfiler",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Analytics/Monitoring: {ftype}",
                    tags=["analytics", "monitoring", ftype.lower().replace(":", "").replace(" ", "-").replace("/", "-")]
                ))

        for db_name, db_pattern in PROXY_DB_PATTERNS.items():
            if re.search(db_pattern, html_lower, re.IGNORECASE) or re.search(db_pattern, headers_str, re.IGNORECASE):
                findings.append(IntelligenceFinding(
                    entity=db_name.title(),
                    type=f"Database: {db_name.title()}",
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
                    findings.append(IntelligenceFinding(
                        entity=issuer_info[:200],
                        type=ftype,
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
                findings.append(IntelligenceFinding(
                    entity="PHP (via PHPSESSID cookie)",
                    type="Tech: PHP",
                    source="TechStackProfiler",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    tags=["technology", "php"]
                ))
            elif "asp.net" in cookie_name.lower() or "aspnet" in cookie_name.lower():
                findings.append(IntelligenceFinding(
                    entity="ASP.NET (via ASP.NET_SessionId cookie)",
                    type="Tech: ASP.NET",
                    source="TechStackProfiler",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["technology", "aspnet"]
                ))
            elif "laravel" in cookie_name.lower():
                findings.append(IntelligenceFinding(
                    entity="Laravel (via laravel_session cookie)",
                    type="Tech: Laravel (PHP)",
                    source="TechStackProfiler",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    tags=["technology", "laravel"]
                ))
            elif "connect.sid" == cookie_name.lower():
                findings.append(IntelligenceFinding(
                    entity="Express.js/Node.js (via connect.sid cookie)",
                    type="Tech: Express.js",
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
                findings.append(IntelligenceFinding(
                    entity=os_type.replace("OS: ", ""),
                    type=os_type,
                    source="TechStackProfiler",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"OS indicator: {os_sig} in Server header",
                    tags=["os", os_sig]
                ))
                break

        if findings:
            findings.append(IntelligenceFinding(
                entity=f"{len(findings)} technologies detected",
                type="Technology Stack Summary",
                source="TechStackProfiler",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"Total techs: {len(findings)} | Host: {host}",
                tags=["technology", "summary"]
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Tech Stack Profiler error: {str(e)[:100]}",
            type="Tech Stack Error",
            source="TechStackProfiler",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
