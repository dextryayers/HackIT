import httpx
import re
from collections import defaultdict
from urllib.parse import urlparse, urljoin
from models import IntelligenceFinding

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

SOCIAL_DOMAINS = {
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "youtube.com", "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com",
    "t.me", "telegram.me", "whatsapp.com", "discord.com", "discord.gg",
    "github.com", "gitlab.com", "bitbucket.org", "medium.com", "dev.to",
    "stackoverflow.com", "stackexchange.com"
}

ASSET_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".mp4", ".webm",
    ".pdf", ".zip", ".gz", ".json", ".xml", ".yaml", ".yml"}

PATH_PATTERNS = [
    "/", "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/v1/", "/v2/", "/v3/",
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/manager", "/backend", "/dashboard", "/panel", "/cpanel",
    "/login", "/login.php", "/signin", "/register",
    "/logout", "/forgot", "/reset",
    "/user", "/users", "/admin/user", "/admin/users",
    "/profile", "/account", "/settings",
    "/config", "/configuration", "/settings",
    "/.env", "/env", "/environment",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/humans.txt", "/ads.txt",
    "/well-known/", "/.well-known/security.txt",
    "/swagger", "/swagger-ui", "/swagger.json",
    "/openapi.json", "/api-docs", "/docs", "/redoc",
    "/graphql", "/graphiql",
    "/wp-admin", "/wp-content", "/wp-includes", "/wp-json",
    "/wp-login.php", "/wp-config.php",
    "/joomla", "/drupal", "/magento",
    "/phpmyadmin", "/pma", "/adminer.php",
    "/backup", "/backup.zip", "/backup.sql",
    "/dump.sql", "/db.sql", "/database.sql",
    "/error.log", "/access.log", "/debug.log",
    "/log.txt", "/logs", "/log",
    "/.git/config", "/.gitignore", "/.git/HEAD",
    "/.svn/entries", "/.svn/wc.db",
    "/.DS_Store", "/Thumbs.db",
    "/.htaccess", "/.htpasswd",
    "/id_rsa", "/id_rsa.pub",
    "/.ssh/id_rsa", "/.ssh/id_rsa.pub",
    "/.aws/credentials", "/.aws/config",
    "/.azure/credentials", "/.azure/config",
    "/.gcloud/credentials", "/.gcloud/config",
    "/.npmrc", "/.dockercfg", "/.netrc",
    "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Jenkinsfile", "/Makefile",
    "/.github/workflows/", "/.gitlab-ci.yml",
    "/.travis.yml", "/.circleci/config.yml",
    "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
    "/requirements.txt", "/Pipfile", "/Gemfile",
    "/composer.json", "/package.json",
    "/yarn.lock", "/pnpm-lock.yaml",
    "/webpack.config.js", "/vite.config.js",
    "/tsconfig.json", "/babel.config.js",
    "/.eslintrc", "/.prettierrc",
    "/Procfile", "/runtime.txt",
    "/Vagrantfile", "/terraform/",
    "/ansible/", "/playbook.yml",
    "/k8s/", "/kubernetes/",
    "/helm/", "/Chart.yaml",
    "/nginx.conf", "/httpd.conf", "/apache.conf",
    "/pom.xml", "/build.gradle",
    "/web.xml", "/application.properties",
    "/application.yml", "/application.json",
    "/logback.xml", "/log4j.properties",
    "/appsettings.json", "/appsettings.Development.json",
    "/.env.production", "/.env.development",
    "/.env.local", "/.env.example",
    "/index.php", "/index.html", "/index.asp", "/index.aspx",
    "/default.aspx", "/default.asp",
    "/phpinfo.php", "/info.php", "/test.php",
    "/health", "/healthz", "/status",
    "/metrics", "/prometheus",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/metrics",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/threaddump", "/actuator/heapdump",
    "/actuator/loggers", "/actuator/configprops",
    "/actuator/gateway", "/actuator/refresh",
    "/favicon.ico", "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/manifest.json", "/manifest.webmanifest",
    "/service-worker.js", "/sw.js",
    "/browserconfig.xml",
    "/rss.xml", "/atom.xml", "/feed.xml",
    "/opensearch.xml",
    "/search", "/search/", "/search-results",
    "/contact", "/contact-us", "/about", "/about-us",
    "/faq", "/help", "/support",
    "/terms", "/privacy", "/privacy-policy",
    "/pricing", "/plans", "/enterprise",
    "/blog", "/news", "/articles", "/posts",
    "/careers", "/jobs", "/team",
    "/portfolio", "/gallery", "/showcase",
    "/services", "/features", "/solutions",
    "/testimonials", "/reviews", "/case-studies",
    "/partners", "/affiliates", "/referrals",
    "/developers", "/api/docs", "/documentation",
    "/status", "/uptime", "/changelog",
    "/sitemap", "/sitemaps",
    "/page-sitemap.xml", "/post-sitemap.xml",
    "/category-sitemap.xml", "/tag-sitemap.xml",
    "/amp", "/amp/", "/amp.html",
    "/mobile", "/mobile/",
    "/app", "/apps", "/app-download",
    "/webapp", "/pwa",
    "/cdn-cgi/", "/cdn-cgi/l/email-protection",
    "/.well-known/acme-challenge/",
    "/.well-known/pki-validation/",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/google-services.json",
    "/GoogleService-Info.plist",
    "/.env.vault", "/env.vault",
    "/sendgrid.env", "/mailgun.env",
    "/.stripe.env", "/stripe.env",
    "/.pgpass", "/pgpass",
    "/my.cnf", "/.my.cnf",
    "/.mylogin.cnf",
    "/databases", "/database",
    "/mongodb", "/redis", "/elasticsearch",
    "/kibana", "/grafana", "/prometheus",
    "/rabbitmq", "/beanstalkd", "/memcached",
    "/jenkins", "/jira", "/confluence",
    "/gitlab", "/gitea", "/gogs",
    "/sonarqube", "/nexus", "/artifactory",
    "/rancher", "/portainer", "/traefik",
    "/minio", "/s3", "/storage",
    "/webmail", "/roundcube", "/squirrelmail",
    "/rainloop", "/snappymail",
    "/mail", "/email",
    "/owa", "/exchange", "/ecp",
    "/remote", "/rdp", "/vnc",
    "/vpn", "/openvpn", "/wireguard",
    "/proxy", "/squid",
    "/webdav", "/dav",
]

CT_CLASSIFICATION = {
    "text/html": "HTML Document",
    "text/plain": "Plain Text",
    "text/css": "CSS Stylesheet",
    "text/javascript": "JavaScript",
    "application/javascript": "JavaScript",
    "application/json": "JSON Data",
    "application/xml": "XML Data",
    "application/pdf": "PDF Document",
    "application/zip": "ZIP Archive",
    "application/gzip": "GZIP Archive",
    "image/png": "PNG Image",
    "image/jpeg": "JPEG Image",
    "image/gif": "GIF Image",
    "image/svg+xml": "SVG Image",
    "image/webp": "WebP Image",
    "image/x-icon": "Favicon",
    "application/font-woff": "WOFF Font",
    "application/font-woff2": "WOFF2 Font",
    "font/ttf": "TTF Font",
    "font/otf": "OTF Font",
    "application/x-font-ttf": "TTF Font",
    "application/x-font-otf": "OTF Font",
    "application/vnd.ms-fontobject": "EOT Font",
}


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse as up
        parsed = up(domain)
        domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    else:
        base_url = f"https://{domain}"

    try:
        resp = await client.get(
            base_url,
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT}
        )
        html = resp.text
        final_url = str(resp.url)
        final_parsed = urlparse(final_url)
        final_domain = final_parsed.netloc

        content_type = resp.headers.get("content-type", "")
        content_length = resp.headers.get("content-length", "0")
        js_detected = False

        ct_class = "Unknown"
        for ct_key, ct_label in CT_CLASSIFICATION.items():
            if ct_key in content_type:
                ct_class = ct_label
                break

        if "text/html" not in content_type:
            findings.append(IntelligenceFinding(
                entity=f"Content-Type: {content_type} ({ct_class})",
                type="Non-HTML Response",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=f"Expected HTML but got {content_type}",
                tags=["content-type", "unusual"]
            ))
            return findings

        if resp.status_code != 200:
            findings.append(IntelligenceFinding(
                entity=f"HTTP {resp.status_code} for {base_url}",
                type="Non-200 Response",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange" if resp.status_code in (301, 302, 307, 308) else "red",
                threat_level="Informational" if resp.status_code in (301, 302, 307, 308) else "Elevated Risk",
                raw_data=f"Status: {resp.status_code} | Final URL: {final_url}",
                tags=["http-status"]
            ))

        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title_text = re.sub(r'\s+', ' ', title_match.group(1)).strip()[:200]
            if title_text:
                findings.append(IntelligenceFinding(
                    entity=title_text,
                    type="Page Title",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["metadata"]
                ))

        meta_description = re.search(r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if not meta_description:
            meta_description = re.search(r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']description["\']', html, re.IGNORECASE)
        if meta_description:
            desc = meta_description.group(1).strip()[:200]
            if desc:
                findings.append(IntelligenceFinding(
                    entity=desc[:200],
                    type="Meta Description",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["metadata"]
                ))

        meta_keywords = re.search(r'<meta\s+[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if meta_keywords:
            keywords = meta_keywords.group(1).strip()[:200]
            if keywords:
                findings.append(IntelligenceFinding(
                    entity=keywords[:200],
                    type="Meta Keywords",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["metadata"]
                ))

        meta_author = re.search(r'<meta\s+[^>]*name=["\']author["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if meta_author:
            author = meta_author.group(1).strip()[:200]
            if author:
                findings.append(IntelligenceFinding(
                    entity=author[:200],
                    type="Page Author",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["metadata"]
                ))

        meta_generator = re.search(r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if meta_generator:
            generator = meta_generator.group(1).strip()[:200]
            if generator:
                findings.append(IntelligenceFinding(
                    entity=generator[:200],
                    type="Generator Meta Tag",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["metadata", "generator"]
                ))

        favicon = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if favicon:
            fav_url = favicon.group(1)
            full_fav_url = urljoin(final_url, fav_url)
            findings.append(IntelligenceFinding(
                entity=full_fav_url[:200],
                type="Favicon",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["asset", "favicon"]
            ))

        script_sources = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            full_src = urljoin(final_url, src)
            script_sources.add(full_src)
            is_inline = not src.startswith("http") and not src.startswith("//")
            findings.append(IntelligenceFinding(
                entity=full_src[:200],
                type="Script Source",
                source="WebSurfaceMapper",
                confidence="High",
                color="cyan" if not is_inline else "slate",
                threat_level="Informational",
                tags=["script", "resource"]
            ))
            if full_src.endswith(".js"):
                js_detected = True

        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        if inline_scripts:
            inline_count = sum(1 for s in inline_scripts if s.strip())
            if inline_count:
                findings.append(IntelligenceFinding(
                    entity=f"{inline_count} inline script blocks",
                    type="Inline Scripts",
                    source="WebSurfaceMapper",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["script", "inline"]
                ))

        for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            full_href = urljoin(final_url, href)
            rel_match = re.search(r'rel=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
            rel_type = rel_match.group(1) if rel_match else "unknown"
            color = "purple" if "stylesheet" in rel_type.lower() else "slate"
            findings.append(IntelligenceFinding(
                entity=full_href[:200],
                type=f"Link Resource ({rel_type})",
                source="WebSurfaceMapper",
                confidence="High",
                color=color,
                threat_level="Informational",
                tags=["resource", "link"]
            ))

        img_count = 0
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            full_src = urljoin(final_url, src)
            img_count += 1
            if img_count <= 20:
                findings.append(IntelligenceFinding(
                    entity=full_src[:200],
                    type="Image Source",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["image", "resource"]
                ))
        if img_count > 20:
            findings.append(IntelligenceFinding(
                entity=f"{img_count} images found (showing first 20)",
                type="Image Count",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["image", "summary"]
            ))

        for m in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            full_src = urljoin(final_url, src)
            findings.append(IntelligenceFinding(
                entity=full_src[:200],
                type="IFrame Source",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                tags=["iframe", "resource"]
            ))

        for m in re.finditer(r'<video[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            full_src = urljoin(final_url, src)
            findings.append(IntelligenceFinding(
                entity=full_src[:200],
                type="Video Source",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["video", "resource"]
            ))

        for m in re.finditer(r'<audio[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = m.group(1)
            full_src = urljoin(final_url, src)
            findings.append(IntelligenceFinding(
                entity=full_src[:200],
                type="Audio Source",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["audio", "resource"]
            ))

        for m in re.finditer(r'<object[^>]+data=["\']([^"\']+)["\']', html, re.IGNORECASE):
            data = m.group(1)
            full_data = urljoin(final_url, data)
            findings.append(IntelligenceFinding(
                entity=full_data[:200],
                type="Object Embed",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["object", "resource"]
            ))

        font_srcs = set()
        for pattern in [r'<link[^>]+href=["\']([^"\']+\.(?:woff|woff2|ttf|eot|otf))["\']',
                        r'url\(["\']?([^"\')]+\.(?:woff|woff2|ttf|eot|otf))["\']?\)']:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                font_url = m.group(1)
                full_font = urljoin(final_url, font_url)
                if full_font not in font_srcs:
                    font_srcs.add(full_font)
                    findings.append(IntelligenceFinding(
                        entity=full_font[:200],
                        type="Font Resource",
                        source="WebSurfaceMapper",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["font", "resource"]
                    ))

        forms_found = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        for form_action in forms_found[:10]:
            action = form_action or "(self)"
            full_action = urljoin(final_url, action) if action != "(self)" else final_url
            findings.append(IntelligenceFinding(
                entity=full_action[:150],
                type="Form Endpoint",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                tags=["form"]
            ))

        internal_links = set()
        external_links = set()
        social_links = set()
        asset_links = set()

        for m in re.finditer(r'<a[^>]+href=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            parsed_href = urlparse(href)
            href_domain = parsed_href.netloc.lower()

            if domain in href_domain or final_domain in href_domain:
                if href not in internal_links:
                    internal_links.add(href)
            elif any(sd in href_domain for sd in SOCIAL_DOMAINS):
                social_links.add(href)
            elif any(href.lower().endswith(ext) for ext in ASSET_EXTENSIONS):
                asset_links.add(href)
            else:
                external_links.add(href)

        for link in sorted(social_links)[:10]:
            findings.append(IntelligenceFinding(
                entity=link[:200],
                type="Social Link",
                source="WebSurfaceMapper",
                confidence="High",
                color="blue",
                threat_level="Informational",
                tags=["social", "link"]
            ))

        for link in sorted(external_links)[:10]:
            findings.append(IntelligenceFinding(
                entity=link[:200],
                type="External Link",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["external", "link"]
            ))

        for link in sorted(internal_links)[:15]:
            findings.append(IntelligenceFinding(
                entity=link[:200],
                type="Internal Link",
                source="WebSurfaceMapper",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                tags=["internal", "link"]
            ))

        for link in sorted(asset_links)[:10]:
            findings.append(IntelligenceFinding(
                entity=link[:200],
                type="Asset Link",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["asset", "link"]
            ))

        hidden_inputs = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.IGNORECASE)
        if hidden_inputs:
            for inp in hidden_inputs[:10]:
                hidden_name = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                hidden_val = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if hidden_name:
                    name = hidden_name.group(1)
                    val = hidden_val.group(1)[:100] if hidden_val else "(empty)"
                    findings.append(IntelligenceFinding(
                        entity=f"Hidden: {name} = {val}",
                        type="Hidden Form Field",
                        source="WebSurfaceMapper",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        tags=["hidden", "form-field"]
                    ))

        comment_leaks = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comment_leaks[:8]:
            stripped = comment.strip()
            if stripped and len(stripped) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"HTML comment: {stripped[:180]}",
                    type="HTML Comment",
                    source="WebSurfaceMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["comment", "leak"]
                ))

        api_patterns = re.findall(r'(?:/api/|/v\d+/|/graphql|/rest/|/endpoint/|/webhook/)(?:[a-zA-Z0-9_./?-]+)', html, re.IGNORECASE)
        for api_path in set(api_patterns)[:10]:
            full_api = urljoin(final_url, api_path)
            findings.append(IntelligenceFinding(
                entity=full_api[:200],
                type="API Endpoint",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                tags=["api", "endpoint"]
            ))

        for script_url in script_sources:
            api_in_scripts = re.findall(r'(https?://[^/]+/(?:api|v\d|rest|graphql|endpoint)[^\s"\'<>]*)', script_url, re.IGNORECASE)
            for api_url in api_in_scripts[:5]:
                findings.append(IntelligenceFinding(
                    entity=api_url[:200],
                    type="API Endpoint (from script src)",
                    source="WebSurfaceMapper",
                    confidence="Low",
                    color="purple",
                    threat_level="Informational",
                    tags=["api", "discovery"]
                ))

        file_type_dist = defaultdict(int)
        for ext in ASSET_EXTENSIONS:
            file_type_dist[ext] = html.lower().count(ext)
        file_type_str = ", ".join(f"{k}:{v}" for k, v in sorted(file_type_dist.items(), key=lambda x: -x[1]) if v > 0)
        if file_type_str:
            findings.append(IntelligenceFinding(
                entity=f"File type distribution: {file_type_str[:200]}",
                type="File Type Distribution",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["summary", "files"]
            ))

        structured_data = re.findall(r'<script[^>]*type=["\']application/ld\+json["\']>([\s\S]*?)</script>', html, re.I)
        if structured_data:
            findings.append(IntelligenceFinding(
                entity=f"{len(structured_data)} JSON-LD blocks detected",
                type="Structured Data",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["seo", "structured-data"]
            ))

        links_summary = f"Internal: {len(internal_links)} | External: {len(external_links)} | Social: {len(social_links)} | Assets: {len(asset_links)}"
        findings.append(IntelligenceFinding(
            entity=f"Link summary for {domain}: {links_summary}",
            type="Link Classification Summary",
            source="WebSurfaceMapper",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=links_summary,
            tags=["summary", "links"]
        ))

        content_type_classification = ct_class if ct_class != "Unknown" else content_type[:50]
        findings.append(IntelligenceFinding(
            entity=f"Content-Type: {content_type_classification}",
            type="Content Type Classification",
            source="WebSurfaceMapper",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"CT: {content_type} | Length: {content_length}",
            tags=["content-type", "classification"]
        ))

        if not js_detected and not inline_scripts:
            findings.append(IntelligenceFinding(
                entity="No JavaScript detected",
                type="JavaScript Detection",
                source="WebSurfaceMapper",
                confidence="Low",
                color="emerald",
                threat_level="Informational",
                tags=["javascript", "static"]
            ))

        await _analyze_security_headers_surface(dict(resp.headers), findings)
        await _analyze_response_cache_headers(dict(resp.headers), findings)

        dir_findings = await _map_directory_structure(base_url, domain, client)
        findings.extend(dir_findings)

    except httpx.TimeoutException:
        findings.append(IntelligenceFinding(
            entity=f"Timeout fetching {base_url}",
            type="Fetch Error",
            source="WebSurfaceMapper",
            confidence="Medium",
            color="red",
            threat_level="Informational",
            status="Timeout",
            tags=["error", "timeout"]
        ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Web surface error: {str(e)[:100]}",
            type="WebSurfaceMapper Error",
            source="WebSurfaceMapper",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))

    return findings


PATH_CATEGORIES = {
    "Admin/Management": ["/admin", "/administrator", "/manager", "/backend", "/dashboard", "/panel", "/cpanel", "/whm", "/directadmin", "/plesk", "/webmin", "/cgi-sys/"],
    "API/Dev": ["/api", "/v1", "/v2", "/v3", "/v4", "/graphql", "/swagger", "/docs", "/redoc", "/openapi.json", "/swagger.json", "/health", "/healthz", "/status", "/metrics"],
    "CMS/SiteMgmt": ["/wp-admin", "/wp-login", "/administrator", "/admin/", "/joomla", "/drupal", "/magento", "/umbraco", "/sitefinity", "/webflow", "/wix"],
    "Security/Auth": ["/login", "/signin", "/register", "/logout", "/forgot", "/reset", "/oauth", "/saml", "/oidc", "/auth", "/authenticate"],
    "Config/Secrets": ["/.env", "/config", "/configuration", "/settings", "/.git", "/.svn", "/.hg", "/.aws", "/.azure", "/.gcloud", "/.ssh", "/.npmrc", "/.dockercfg"],
    "Storage/Db": ["/backup", "/backups", "/storage", "/uploads", "/files", "/download", "/database", "/db", "/sql", "/dump", "/phpmyadmin", "/adminer.php", "/mysql", "/mongo-express"],
    "Monitoring": ["/actuator", "/prometheus", "/grafana", "/kibana", "/jenkins", "/sonarqube", "/phpinfo.php", "/info.php", "/server-status", "/server-info"],
    "CI/CD": ["/jenkins", "/.github", "/.gitlab-ci.yml", "/.circleci", "/.travis.yml", "/Jenkinsfile", "/Dockerfile", "/terraform/", "/ansible/", "/k8s/", "/helm/"],
}

RESPONSE_CODE_GROUPS = {
    200: "Success",
    201: "Created",
    204: "No Content",
    301: "Redirect",
    302: "Redirect",
    307: "Redirect",
    308: "Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    408: "Request Timeout",
    429: "Rate Limited",
    500: "Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


async def _map_directory_structure(base_url: str, domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        checked = {}
        category_counts = defaultdict(int)
        code_distribution = defaultdict(int)

        for cat_name, paths in PATH_CATEGORIES.items():
            for path in paths[:8]:
                url = urljoin(base_url, path)
                try:
                    resp = await client.get(
                        url, timeout=5.0, follow_redirects=False,
                        headers={"User-Agent": USER_AGENT},
                    )
                    status = resp.status_code
                    checked[url] = status
                    code_distribution[status] += 1

                    if status in (200, 204):
                        category_counts[cat_name] += 1
                        body_snippet = (resp.text or "")[:200]
                        is_dir_listing = any(ind in body_snippet for ind in ["Index of /", "<title>Index of", "Parent Directory</a>"])
                        extra_tags = ["directory-listing"] if is_dir_listing else []
                        findings.append(IntelligenceFinding(
                            entity=url,
                            type=f"Accessible Path [{cat_name}]",
                            source="WebSurfaceMapper",
                            confidence="High",
                            color="red" if is_dir_listing else "orange",
                            threat_level="High Risk" if is_dir_listing else "Elevated Risk",
                            status=f"HTTP {status}",
                            tags=["path", cat_name.lower().replace("/", "_").replace(" ", "_")] + extra_tags,
                        ))

                    elif status == 401:
                        category_counts[cat_name] += 1
                        findings.append(IntelligenceFinding(
                            entity=url,
                            type=f"Protected Path [{cat_name}]",
                            source="WebSurfaceMapper",
                            confidence="High",
                            color="orange",
                            threat_level="Medium Risk",
                            status=f"HTTP {status}",
                            tags=["path", "protected", cat_name.lower().replace(" ", "_")],
                        ))

                    elif status == 403:
                        category_counts[cat_name] += 1
                        findings.append(IntelligenceFinding(
                            entity=url,
                            type=f"Restricted Path [{cat_name}]",
                            source="WebSurfaceMapper",
                            confidence="High",
                            color="orange",
                            threat_level="Restricted Access",
                            status=f"HTTP {status}",
                            tags=["path", "restricted"],
                        ))

                except Exception:
                    pass

        if category_counts:
            cat_summary = ", ".join([f"{k}: {v}" for k, v in sorted(category_counts.items(), key=lambda x: -x[1]) if v > 0])
            findings.append(IntelligenceFinding(
                entity=f"Directory structure: {cat_summary[:200]}",
                type="Directory Structure Summary",
                source="WebSurfaceMapper",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["summary", "structure"],
            ))

        if code_distribution:
            code_summary = ", ".join([f"HTTP {k}: {v}" for k, v in sorted(code_distribution.items(), key=lambda x: -x[1])])
            findings.append(IntelligenceFinding(
                entity=f"Response code distribution: {code_summary}",
                type="Response Code Distribution",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["summary", "response-codes"],
            ))

    except Exception:
        pass
    return findings


async def _analyze_security_headers_surface(headers: dict, findings: list):
    try:
        important_missing = []
        security_header_checks = {
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "XCTO",
            "X-Frame-Options": "XFO",
            "Strict-Transport-Security": "HSTS",
            "X-XSS-Protection": "XXSSP",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "Access-Control-Allow-Origin": "CORS",
            "Cross-Origin-Resource-Policy": "CORP",
            "Cross-Origin-Opener-Policy": "COOP",
            "Cross-Origin-Embedder-Policy": "COEP",
        }
        for hdr, label in security_header_checks.items():
            if hdr.lower() not in {k.lower(): v for k, v in headers.items()}:
                important_missing.append(label)
        if important_missing:
            findings.append(IntelligenceFinding(
                entity=f"Missing security headers: {', '.join(important_missing[:5])}",
                type="Missing Security Headers",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                tags=["security", "headers", "missing"],
            ))

        server_hdr = headers.get("Server", "") or headers.get("server", "")
        if server_hdr and server_hdr not in ("", "cloudflare", "nginx", "Apache"):
            findings.append(IntelligenceFinding(
                entity=f"Web Server: {server_hdr}",
                type="Server Header",
                source="WebSurfaceMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["server", "technology"],
            ))

        powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
        if powered_by:
            findings.append(IntelligenceFinding(
                entity=f"X-Powered-By: {powered_by}",
                type="Powered-By Header",
                source="WebSurfaceMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                tags=["technology", "leak"],
            ))
    except Exception:
        pass


async def _analyze_response_cache_headers(headers: dict, findings: list):
    try:
        cache_control = headers.get("Cache-Control", "") or headers.get("cache-control", "")
        if cache_control and "no-store" not in cache_control.lower() and "private" not in cache_control.lower():
            findings.append(IntelligenceFinding(
                entity=f"Cache-Control: {cache_control}",
                type="Cache Configuration",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["cache", "performance"],
            ))

        pragma = headers.get("Pragma", "") or headers.get("pragma", "")
        if pragma:
            findings.append(IntelligenceFinding(
                entity=f"Pragma: {pragma}",
                type="Pragma Header",
                source="WebSurfaceMapper",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["cache", "header"],
            ))

        expires = headers.get("Expires", "") or headers.get("expires", "")
        if expires:
            findings.append(IntelligenceFinding(
                entity=f"Expires: {expires}",
                type="Expires Header",
                source="WebSurfaceMapper",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["cache", "header"],
            ))

        age = headers.get("Age", "") or headers.get("age", "")
        if age:
            findings.append(IntelligenceFinding(
                entity=f"Age: {age}s in cache",
                type="Cache Age",
                source="WebSurfaceMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["cache", "cdn"],
            ))
    except Exception:
        pass
