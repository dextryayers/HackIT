import httpx
import asyncio
import re
import gzip
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

LINK_RE = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
SCRIPT_RE = re.compile(r'<script[^>]*src=["\'](.*?)["\']', re.IGNORECASE)
FORM_RE = re.compile(r'<form[^>]*action=["\'](.*?)["\']', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]*name=["\'](.*?)["\']', re.IGNORECASE)
TITLE_RE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
META_RE = re.compile(r'<meta[^>]+name=["\'](.*?)["\'][^>]*content=["\'](.*?)["\']', re.IGNORECASE)
SITEMAP_LINK_RE = re.compile(r'<loc[^>]*>(.*?)</loc>', re.IGNORECASE | re.DOTALL)
SITEMAP_ATTR_RE = re.compile(r'<(?:lastmod|changefreq|priority)[^>]*>(.*?)</\w+>', re.IGNORECASE | re.DOTALL)
ROBOTS_SITEMAP_RE = re.compile(r'Sitemap:\s*(.*)', re.IGNORECASE)
CRAWL_DELAY_RE = re.compile(r'Crawl-delay:\s*(\d+)', re.IGNORECASE)

LOGIN_FORM_KEYWORDS = ["login", "signin", "sign-in", "log in", "log_in", "username", "password"]
SEARCH_FORM_KEYWORDS = ["search", "q=", "query", "find"]
CONTACT_FORM_KEYWORDS = ["contact", "feedback", "support", "inquiry"]

HIDDEN_PARAM_NAMES = {"debug", "test", "dev", "admin", "mode", "source",
    "token", "api_key", "apikey", "key", "secret", "password", "passwd",
    "auth", "access", "bypass", "override", "config", "env", "environment"}

EXTENSION_PRIORITY = {
    ".php": "Dynamic PHP",
    ".asp": "Dynamic ASP",
    ".aspx": "Dynamic ASPX",
    ".jsp": "Dynamic JSP",
    ".js": "JavaScript",
    ".json": "JSON API",
    ".xml": "XML Data",
    ".csv": "Data Export",
    ".pdf": "Document",
    ".zip": "Archive",
    ".sql": "Database Dump",
    ".env": "Environment Config",
    ".git": "Git Exposure",
}

CRAWL_PATHS = [
    "/", "/index.html", "/index.php", "/index.asp", "/index.aspx", "/index.jsp",
    "/home", "/home.html", "/home.php",
    "/about", "/about.html", "/about.php", "/about-us", "/about_us",
    "/contact", "/contact.html", "/contact.php", "/contact-us", "/contact_us",
    "/services", "/service", "/products", "/product", "/portfolio",
    "/blog", "/news", "/articles", "/posts", "/category", "/tags",
    "/login", "/signin", "/register", "/signup", "/logout", "/forgot",
    "/admin", "/administrator", "/dashboard", "/panel", "/cpanel",
    "/search", "/results", "/search-results",
    "/faq", "/help", "/support", "/tickets", "/knowledge-base",
    "/terms", "/privacy", "/privacy-policy", "/cookie-policy",
    "/sitemap", "/sitemap.xml", "/sitemap_index.xml", "/robots.txt",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/swagger", "/swagger-ui", "/docs",
    "/health", "/healthz", "/status", "/info", "/version", "/ping",
    ".env", "/.env", "/config", "/configuration",
    "/backup", "/backups", "/backup.zip", "/backup.sql", "/dump.sql",
    "/wp-admin", "/wp-content", "/wp-includes", "/wp-json", "/wp-login",
    "/administrator", "/joomla", "/drupal",
    "/css", "/css/", "/styles", "/stylesheets",
    "/js", "/js/", "/javascript", "/scripts",
    "/images", "/img", "/assets", "/static", "/public", "/uploads",
    "/download", "/downloads", "/files", "/file",
    "/fonts", "/font", "/webfonts",
    "/favicon.ico", "/favicon.png", "/apple-touch-icon.png",
    "/manifest.json", "/service-worker.js", "/sw.js",
    "/.well-known/", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/robots.txt", "/humans.txt", "/security.txt",
    "/404", "/500", "/error", "/error.html",
    "/test", "/tests", "/testing", "/dev", "/development",
    "/staging", "/stage", "/beta", "/alpha",
    "/v1", "/v2", "/v3", "/v4",
    "/external", "/internal", "/private", "/public",
    "/archive", "/archives", "/old", "/temp", "/tmp",
    "/cache", "/cached", "/cdn-cgi",
    "/stats", "/statistics", "/analytics", "/metrics",
    "/monitor", "/monitoring", "/status",
    "/webhook", "/webhooks", "/callback", "/callbacks",
    "/oauth", "/oauth2", "/oidc", "/saml",
    "/sso", "/auth", "/authorize", "/authenticate",
    "/session", "/sessions", "/token", "/tokens",
    "/profile", "/profiles", "/account", "/accounts",
    "/user", "/users", "/member", "/members",
    "/group", "/groups", "/team", "/teams",
    "/organization", "/organizations", "/org",
    "/setting", "/settings", "/preference", "/preferences",
    "/notification", "/notifications", "/notify",
    "/message", "/messages", "/inbox", "/outbox",
    "/comment", "/comments", "/review", "/reviews",
    "/rating", "/ratings", "/vote", "/votes",
    "/subscription", "/subscriptions", "/subscribe",
    "/payment", "/payments", "/checkout", "/cart",
    "/order", "/orders", "/invoice", "/invoices",
    "/receipt", "/receipts", "/transaction", "/transactions",
    "/shipping", "/tracking", "/delivery",
    "/wishlist", "/favorite", "/favorites", "/like", "/likes",
    "/follow", "/following", "/follower", "/followers",
    "/share", "/shared", "/social",
    "/upload", "/uploads", "/download", "/downloads",
    "/import", "/exports", "/export",
    "/report", "/reports", "/print", "/pdf",
    "/calendar", "/event", "/events", "/schedule",
    "/gallery", "/photo", "/photos", "/video", "/videos",
    "/media", "/medias",
    "/rss", "/feed", "/feeds", "/atom.xml", "/rss.xml",
    "/sitemap.xml.gz", "/sitemap.gz", "/sitemapindex.xml",
    "/amp", "/amp/", "/mobile", "/mobile/",
    "/app", "/apps", "/api/app",
    "/locale", "/locales", "/language", "/languages",
    "/country", "/region", "/city", "/location",
    "/map", "/maps", "/directions",
    "/weather", "/time", "/date",
    "/calculator", "/converter", "/tool", "/tools",
    "/widget", "/widgets", "/embed",
    "/banner", "/banners", "/ad", "/ads",
    "/promo", "/promotions", "/coupon", "/coupons",
    "/affiliate", "/referral", "/refer",
    "/partner", "/partners", "/vendor", "/vendors",
    "/career", "/careers", "/job", "/jobs",
    "/internship", "/volunteer",
    "/investor", "/investors", "/press", "/press-release",
    "/legal", "/compliance", "/gdpr", "/ccpa",
    "/accessibility", "/a11y", "/disability",
    "/security", "/responsible-disclosure",
    "/bug-bounty", "/hall-of-fame", "/credits",
    "/changelog", "/release-notes", "/roadmap",
    "/status", "/uptime", "/incident", "/incidents",
    "/remote", "/remote-work", "/hybrid",
    "/pricing", "/plans", "/enterprise", "/business",
    "/startup", "/nonprofit", "/education", "/student",
    "/demo", "/trial", "/free-trial", "/request-demo",
    "/webinar", "/workshop", "/training", "/tutorial",
    "/documentation", "/docs", "/wiki", "/knowledge",
    "/manual", "/guide", "/handbook", "/playbook",
    "/faq", "/questions", "/answers",
    "/forum", "/forums", "/community", "/discuss",
    "/chat", "/live-chat", "/messenger",
    "/newsletter", "/newsletters", "/digest",
    "/webmail", "/email", "/mail",
    "/owa", "/exchange", "/outlook",
    "/remote-desktop", "/rdp", "/vnc",
    "/vpn", "/remote-access", "/ssh",
    "/proxy", "/gateway", "/tunnel",
    "/mysql", "/phpmyadmin", "/pma", "/adminer",
    "/redis", "/memcached", "/rabbitmq",
    "/elasticsearch", "/kibana", "/grafana",
    "/prometheus", "/alertmanager",
    "/jenkins", "/jira", "/confluence", "/gitlab",
    "/sonarqube", "/nexus", "/artifactory",
    "/k8s", "/kubernetes", "/docker", "/swarm",
    "/rancher", "/openshift", "/nomad",
    "/consul", "/vault", "/etcd",
    "/terraform", "/ansible", "/puppet", "/chef",
    "/.git", "/.git/", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn", "/.svn/entries", "/.svn/wc.db",
    "/.hg", "/.hg/hgrc", "/.hg/store/",
    "/.bzr", "/.bzr/branch/",
    "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.htaccess", "/.htpasswd", "/.htgroup",
    "/.aws/credentials", "/.aws/config",
    "/.azure/credentials", "/.azure/config",
    "/.gcloud/credentials", "/.gcloud/config.json",
    "/.ssh/id_rsa", "/.ssh/id_rsa.pub", "/.ssh/authorized_keys",
    "/.ssh/config", "/.ssh/known_hosts",
    "/.npmrc", "/.dockercfg", "/.s3cfg", "/.netrc",
    "/id_rsa", "/id_rsa.pub", "/authorized_keys",
    "/.git-credentials", "/.gitconfig",
    "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml",
    "/api/openapi.json", "/api/openapi.yaml",
    "/api/docs", "/rest/", "/graphql", "/graphiql", "/voyager",
    "/.travis.yml", "/.circleci/config.yml",
    "/.github/workflows/", "/.gitlab-ci.yml",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
    "/Makefile", "/.gitmodules",
    "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
    "/environment.ts", "/environment.prod.ts", "/.flaskenv", "/.env.yaml",
    "/build.env", "/package.env",
    "/security.txt", "/.well-known/security.txt",
    "/ssl.crt", "/ssl.key", "/server.crt", "/server.key",
    "/cert.pem", "/key.pem", "/fullchain.pem",
    "/privkey.pem", "/chain.pem",
    "/.well-known/", "/acme-challenge/",
    "/.git/objects/", "/.git/refs/",
    "/tmp/", "/temp/", "/cache/",
    "/files/", "/uploads/", "/upload/",
    "/downloads/", "/download/",
    "/assets/", "/static/", "/public/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/tests/", "/test/", "/testing/",
    "/phpunit.xml", "/phpunit.xml.dist",
    "/phpinfo.php.bak", "/info.php.bak",
    "/.phpunit.result.cache",
    "/heapdump", "/heapdump.json",
    "/trace",
    "/__init__.py",
    "/server-status", "/server-info", "/cgi-bin/",
    "/cgi-bin/test.cgi", "/cgi-bin/php", "/cgi-bin/status",
    "/aws.yml", "/aws.json", "/aws_config",
    "/google-services.json", "/GoogleService-Info.plist",
    "/firebase.json", "/firebase.php", "/firebase.config",
    "/Procfile", "/.slugignore", "/runtime.txt",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/Gemfile", "/Gemfile.lock", "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/Gruntfile.js", "/gulpfile.js", "/webpack.config.js",
    "/rollup.config.js", "/vite.config.js", "/tsconfig.json",
    "/.babelrc", "/.eslintrc", "/.prettierrc",
    "/nginx.conf", "/apache.conf", "/httpd.conf",
    "/.htaccess.bak", "/.htaccess.old", "/.htaccess.sav",
    "/htaccess.txt", "/htpasswd",
    "/passwd", "/shadow", "/group",
    "/sudoers", "/sudoers.d/",
    "/mysql_history", "/psql_history", "/bash_history",
    "/zsh_history", "/fish_history",
    "/.mysql_history", "/.psql_history",
    "/.bash_history", "/.zsh_history",
    "/server.key", "/server.csr", "/server.crt",
    "/ca.key", "/ca.crt", "/ca.csr",
    "/client.key", "/client.crt", "/client.csr",
    "/private.key", "/private.pem", "/public.pem",
    "/certificate.pem", "/certificate.crt",
    "/keystore.jks", "/keystore", "/truststore.jks",
    "/.p12", "/.pfx", "/.jks",
    "/.maintenance", "/maintenance.php",
    "/app/.env", "/app/config.php", "/app/settings.php",
    "/api/config", "/api/health", "/api/status",
    "/v1/graphql", "/v2/graphql",
    "/.elasticbeanstalk/", "/ebextensions/",
    "/.platform/", "/.buildpacks",
    "/Vagrantfile", "/.vagrant/",
    "/.terraform/", "/terraform.tfstate",
    "/terraform.tfvars", "/backend.tf",
    "/.serverless/", "/serverless.yml",
    "/samconfig.toml", "/template.yaml",
    "/cloudformation.yaml", "/cloudformation.json",
    "/Pulumi.yaml", "/pulumi/",
    "/ansible.cfg", "/ansible/", "/playbook.yml",
    "/docker-entrypoint.sh",
    "/k8s/", "/kubernetes/", "/deployment.yaml",
    "/service.yaml", "/kustomization.yaml",
    "/Chart.yaml", "/helm/", "/values.yaml",
    "/Podfile", "/Podfile.lock",
    "/go.mod", "/go.sum", "/Gopkg.toml",
    "/Cargo.toml", "/Cargo.lock",
    "/build.gradle", "/gradle.properties",
    "/pom.xml", "/settings.xml",
    "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
    "/META-INF/context.xml",
    "/struts.xml", "/struts-config.xml",
    "/hibernate.cfg.xml", "/mybatis-config.xml",
    "/application.properties", "/application.yml",
    "/bootstrap.properties", "/bootstrap.yml",
    "/logback.xml", "/log4j.properties", "/log4j2.xml",
    "/appsettings.json", "/appsettings.Development.json",
    "/.well-known/acme-challenge/",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/sitemap.xml.gz", "/sitemaps.xml",
    "/robots.txt.bak", "/robots.txt.old",
    "/CVS/", "/CVS/Root", "/CVS/Entries",
    "/.bzr.log", "/.bzr/README",
    "/.hgignore", "/.hgtags",
    "/error.html", "/404.html", "/500.html",
    "/maintenance.html", "/under-construction.html",
    "/.bashrc", "/.bash_profile", "/.profile",
    "/.vimrc", "/.viminfo", "/.exrc",
    "/.gitattributes", "/.editorconfig",
    "/.python-version", "/.pythonrc",
    "/.ruby-version", "/.ruby-gemset",
    "/.yarnrc", "/.yarn/",
    "/.npm/", "/.node_repl_history",
    "/composer.lock", "/vendor/",
    "/phpunit.phar", "/phpunit",
    "/behat.yml", "/.behat/",
    "/sonar-project.properties",
    "/.idea/", "/.vscode/", "/.vs/",
    "/artisan", "/.env.example",
    "/auth.json", "/composer/auth.json",
]

async def fetch_url_with_fallback(client, url, timeout=10.0):
    for scheme in ["https", "http"]:
        try:
            full = f"{scheme}://{url.lstrip('http://').lstrip('https://')}"
            full = full.replace("https://https://", "https://").replace("http://http://", "http://")
            resp = await client.get(full, timeout=timeout,
                headers={"User-Agent": UA}, follow_redirects=True)
            if resp.status_code < 500:
                return resp
        except:
            pass
    return None

async def parse_sitemap_xml(client, sitemap_url, visited_sitemaps):
    findings = []
    urls_found = []
    if sitemap_url in visited_sitemaps:
        return findings, urls_found
    visited_sitemaps.add(sitemap_url)

    try:
        resp = await client.get(sitemap_url, timeout=10.0,
            headers={"User-Agent": UA}, follow_redirects=True)
        if resp.status_code != 200:
            return findings, urls_found

        content = resp.text
        if sitemap_url.endswith(".gz"):
            try:
                content = gzip.decompress(resp.content).decode("utf-8")
            except:
                pass

        sub_sitemaps = SITEMAP_LINK_RE.findall(content)
        for sub in sub_sitemaps:
            sub = sub.strip()
            if sub not in visited_sitemaps and "sitemap" in sub.lower():
                sub_results, sub_urls = await parse_sitemap_xml(client, sub, visited_sitemaps)
                findings.extend(sub_results)
                urls_found.extend(sub_urls)

        try:
            root = ET.fromstring(content)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for url_elem in root.findall(".//sm:url", ns):
                loc = url_elem.find("sm:loc", ns)
                if loc is not None and loc.text:
                    u = loc.text.strip()
                    urls_found.append(u)
                    lastmod = url_elem.find("sm:lastmod", ns)
                    changefreq = url_elem.find("sm:changefreq", ns)
                    priority = url_elem.find("sm:priority", ns)
                    attrs = []
                    if lastmod is not None and lastmod.text:
                        attrs.append(f"lastmod={lastmod.text}")
                    if changefreq is not None and changefreq.text:
                        attrs.append(f"freq={changefreq.text}")
                    if priority is not None and priority.text:
                        attrs.append(f"pri={priority.text}")
                    if attrs:
                        findings.append(IntelligenceFinding(
                            entity=u[:200],
                            type="Sitemap URL (with attributes)",
                            source="CrawlerCore",
                            confidence="High",
                            color="blue",
                            category="Web Crawling & Content Discovery",
                            threat_level="Informational",
                            status="Sitemap Entry",
                            raw_data=f"Attributes: {', '.join(attrs)}",
                            tags=["sitemap"]
                        ))
        except ET.ParseError:
            for loc_match in SITEMAP_LINK_RE.finditer(content):
                u = loc_match.group(1).strip()
                urls_found.append(u)

    except:
        pass
    return findings, urls_found

async def analyze_robots_txt(client, base_url):
    findings = []
    sitemaps_found = []
    try:
        resp = await client.get(f"{base_url}/robots.txt", timeout=8.0,
            headers={"User-Agent": UA})
        if resp.status_code == 200:
            text = resp.text
            findings.append(IntelligenceFinding(
                entity=f"{base_url}/robots.txt",
                type="Robots.txt Detected",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Detected",
                raw_data=text[:2000],
                tags=["robots"]
            ))

            sitemaps = ROBOTS_SITEMAP_RE.findall(text)
            for sm in sitemaps:
                sitemaps_found.append(sm.strip())

            delays = CRAWL_DELAY_RE.findall(text)
            if delays:
                findings.append(IntelligenceFinding(
                    entity=f"Crawl-Delay: {delays[0]}s",
                    type="Robots.txt Crawl Delay",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Detected",
                    tags=["robots", "crawl-delay"]
                ))

            user_agents = re.findall(r"User-agent:\s*(.+)", text)
            if user_agents:
                findings.append(IntelligenceFinding(
                    entity=f"User-Agents targeted: {', '.join(set(user_agents))[:200]}",
                    type="Robots.txt User-Agents",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Analyzed",
                    tags=["robots"]
                ))

            disallowed = re.findall(r"Disallow:\s*(.*)", text)
            allowed = re.findall(r"Allow:\s*(.*)", text)
            for path in disallowed[:10]:
                if path.strip():
                    findings.append(IntelligenceFinding(
                        entity=path.strip()[:200],
                        type="Disallowed Path (robots.txt)",
                        source="CrawlerCore",
                        confidence="High",
                        color="orange" if not path.strip().startswith("/") else "slate",
                        category="Web Crawling & Content Discovery",
                        threat_level="Informational",
                        status="Disallowed",
                        tags=["robots", "disallowed"]
                    ))
            for path in allowed[:5]:
                if path.strip():
                    findings.append(IntelligenceFinding(
                        entity=path.strip()[:200],
                        type="Allowed Path (robots.txt)",
                        source="CrawlerCore",
                        confidence="High",
                        color="slate",
                        category="Web Crawling & Content Discovery",
                        threat_level="Informational",
                        status="Allowed",
                        tags=["robots", "allowed"]
                    ))

            crawl_rules = re.findall(r"(User-agent|Disallow|Allow|Crawl-delay|Sitemap|Host|Clean-param):\s*(.*)", text)
            if crawl_rules:
                for rule_type, rule_val in crawl_rules:
                    if rule_type.strip().lower() not in ("user-agent", "disallow", "allow"):
                        findings.append(IntelligenceFinding(
                            entity=f"{rule_type}: {rule_val.strip()[:100]}",
                            type="Robots.txt Extra Directive",
                            source="CrawlerCore",
                            confidence="High",
                            color="slate",
                            category="Web Crawling & Content Discovery",
                            threat_level="Informational",
                            tags=["robots", "directive"]
                        ))
    except:
        pass
    return findings, sitemaps_found

async def analyze_page(client, url, domain):
    findings = []
    try:
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": UA}, follow_redirects=True)
        if resp.status_code != 200:
            return findings
        html = resp.text

        content_type = resp.headers.get("content-type", "")
        if content_type:
            findings.append(IntelligenceFinding(
                entity=f"Content-Type: {content_type[:100]}",
                type="Page Content Type",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["metadata", "content-type"]
            ))

        links = LINK_RE.findall(html)
        internal_links = set()
        external_links = set()
        for link in links:
            link = link.strip()
            if not link or link.startswith("#") or link.startswith("javascript:"):
                continue
            full = urljoin(url, link)
            parsed = urlparse(full)
            if domain in parsed.netloc or not parsed.netloc:
                internal_links.add(full.split("?")[0])
            elif parsed.netloc:
                external_links.add(full)

        if internal_links:
            findings.append(IntelligenceFinding(
                entity=f"{len(internal_links)} internal links found on {url[:80]}",
                type="Internal Link Discovery",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Links Found",
                raw_data="\n".join(list(internal_links)[:20]),
                tags=["links", "internal"]
            ))

        if external_links:
            ext_domains = set()
            for el in external_links:
                ext_domains.add(urlparse(el).netloc)
            findings.append(IntelligenceFinding(
                entity=f"{len(ext_domains)} external domains linked from {url[:80]}",
                type="External Link Discovery",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="External Links",
                raw_data="\n".join(list(ext_domains)[:10]),
                tags=["links", "external"]
            ))

        scripts = SCRIPT_RE.findall(html)
        if scripts:
            unique_scripts = set(scripts)
            findings.append(IntelligenceFinding(
                entity=f"{len(unique_scripts)} JavaScript files referenced",
                type="JavaScript Discovery",
                source="CrawlerCore",
                confidence="High",
                color="orange",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="JS Found",
                raw_data="\n".join(list(unique_scripts)[:10]),
                tags=["javascript"]
            ))

        forms = FORM_RE.findall(html)
        if forms:
            form_count = len(forms)
            form_types = []
            for form_action in forms:
                form_tag_match = re.search(r'<form[^>]*action=["\']' + re.escape(form_action) + r'["\'][^>]*>', html[:30000], re.I)
                if form_tag_match:
                    form_html = form_tag_match.group(0).lower()
                    if any(k in form_html for k in LOGIN_FORM_KEYWORDS):
                        form_types.append("login")
                    elif any(k in form_html for k in SEARCH_FORM_KEYWORDS):
                        form_types.append("search")
                    elif any(k in form_html for k in CONTACT_FORM_KEYWORDS):
                        form_types.append("contact")
                    else:
                        form_types.append("generic")
                else:
                    form_types.append("generic")

            findings.append(IntelligenceFinding(
                entity=f"{form_count} forms detected ({', '.join(set(form_types))})",
                type="Form Discovery",
                source="CrawlerCore",
                confidence="High",
                color="orange",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Forms Found",
                raw_data="\n".join(forms[:5]),
                tags=["forms"]
            ))

            if "login" in form_types:
                findings.append(IntelligenceFinding(
                    entity=f"Login form(s) detected on {url[:80]}",
                    type="Login Form Discovery",
                    source="CrawlerCore",
                    confidence="High",
                    color="red",
                    category="Web Crawling & Content Discovery",
                    threat_level="Elevated Risk",
                    status="Login Form",
                    tags=["forms", "login", "authentication"]
                ))

            if "search" in form_types:
                findings.append(IntelligenceFinding(
                    entity=f"Search form(s) detected on {url[:80]}",
                    type="Search Form Discovery",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Search Form",
                    tags=["forms", "search"]
                ))

            inputs = INPUT_RE.findall(html)
            hidden_inputs = [i for i in inputs if any(p in i.lower() for p in HIDDEN_PARAM_NAMES)]
            for hi in hidden_inputs[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"Hidden/interesting param: {hi}",
                    type="Hidden Parameter Detection",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Hidden Param",
                    tags=["parameters", "hidden"]
                ))

        title_match = TITLE_RE.search(html)
        if title_match:
            findings.append(IntelligenceFinding(
                entity=f"Page Title: {title_match.group(1).strip()[:200]}",
                type="Page Title",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Title",
                tags=["metadata"]
            ))

        meta_tags = META_RE.findall(html)
        for name, content in meta_tags[:5]:
            if name.lower() in ("description", "keywords", "robots", "author", "viewport", "generator"):
                findings.append(IntelligenceFinding(
                    entity=f"Meta {name}: {content[:200]}",
                    type="Meta Tag",
                    source="CrawlerCore",
                    confidence="High",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Meta",
                    tags=["metadata"]
                ))

        url_params = parse_qs(urlparse(url).query)
        for param in url_params:
            if param.lower() in HIDDEN_PARAM_NAMES:
                findings.append(IntelligenceFinding(
                    entity=f"URL parameter: {param}={url_params[param][0][:100]}",
                    type="Interesting URL Parameter",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    status="Interesting",
                    tags=["parameters"]
                ))

        css_files = re.findall(r'<link[^>]+href=["\']([^"\']*\.css[^"\']*)["\']', html, re.I)
        if css_files:
            findings.append(IntelligenceFinding(
                entity=f"{len(css_files)} CSS files referenced",
                type="CSS Discovery",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["css", "assets"]
            ))

        images = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I)
        if images:
            findings.append(IntelligenceFinding(
                entity=f"{len(images)} images found on {url[:80]}",
                type="Image Discovery",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["images", "assets"]
            ))

        fonts = re.findall(r'url\(["\']?([^"\')]+\.(?:woff|woff2|ttf|eot|otf))["\']?\)', html, re.I)
        font_links = re.findall(r'<link[^>]+href=["\']([^"\']*\.(?:woff|woff2|ttf|eot|otf)[^"\']*)["\']', html, re.I)
        all_fonts = set(fonts + font_links)
        if all_fonts:
            findings.append(IntelligenceFinding(
                entity=f"{len(all_fonts)} font resources found",
                type="Font Discovery",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["fonts", "assets"]
            ))

        iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I)
        if iframes:
            findings.append(IntelligenceFinding(
                entity=f"{len(iframes)} iframes found on {url[:80]}",
                type="IFrame Discovery",
                source="CrawlerCore",
                confidence="High",
                color="orange",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["iframes", "embedded"]
            ))

        structured_data = re.findall(r'<script[^>]+type=["\']application/ld\+json["\']>([\s\S]*?)</script>', html, re.I)
        if structured_data:
            findings.append(IntelligenceFinding(
                entity=f"{len(structured_data)} JSON-LD structured data blocks",
                type="Structured Data Discovery",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["structured-data", "seo"]
            ))

    except:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    base_url = f"https://{domain}"

    robots_results, extra_sitemaps = await analyze_robots_txt(client, base_url)
    findings.extend(robots_results)

    sitemap_urls_to_check = [f"{base_url}/sitemap.xml"]
    sitemap_urls_to_check.extend(extra_sitemaps)
    sitemap_urls_to_check.extend([
        f"{base_url}/sitemap_index.xml",
        f"{base_url}/sitemap1.xml",
        f"{base_url}/sitemapindex.xml",
        f"{base_url}/sitemap.xml.gz",
        f"{base_url}/sitemap_index.xml.gz",
    ])

    visited = set()
    all_sitemap_findings = []
    all_sitemap_urls = []
    for sm_url in sitemap_urls_to_check:
        sm_findings, sm_urls = await parse_sitemap_xml(client, sm_url, visited)
        all_sitemap_findings.extend(sm_findings)
        all_sitemap_urls.extend(sm_urls)

    findings.extend(all_sitemap_findings)

    if all_sitemap_urls:
        findings.append(IntelligenceFinding(
            entity=f"{len(all_sitemap_urls)} URLs discovered in sitemaps",
            type="Sitemap URL Count",
            source="CrawlerCore",
            confidence="High",
            color="blue",
            category="Web Crawling & Content Discovery",
            threat_level="Informational",
            status="Sitemap Complete",
            tags=["sitemap", "count"]
        ))

        ext_count = defaultdict(int)
        for u in all_sitemap_urls:
            parsed = urlparse(u)
            path = parsed.path.lower()
            for ext, label in EXTENSION_PRIORITY.items():
                if path.endswith(ext):
                    ext_count[label] += 1
        if ext_count:
            ext_str = ", ".join(f"{k}:{v}" for k, v in sorted(ext_count.items(), key=lambda x: -x[1]))
            findings.append(IntelligenceFinding(
                entity=f"Sitemap content: {ext_str}",
                type="Sitemap Content Breakdown",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                status="Analyzed",
                tags=["sitemap", "content"]
            ))

        sample_urls = all_sitemap_urls[:20]
        page_tasks = [analyze_page(client, u, domain) for u in sample_urls]
        page_results = await asyncio.gather(*page_tasks, return_exceptions=True)
        for pr in page_results:
            if isinstance(pr, list):
                findings.extend(pr)

    else:
        page_results_initial = await analyze_page(client, base_url, domain)
        findings.extend(page_results_initial)

    path_discovery_tasks = [analyze_page(client, urljoin(base_url, p), domain) for p in CRAWL_PATHS[:20]]
    path_results = await asyncio.gather(*path_discovery_tasks, return_exceptions=True)
    for pr in path_results:
        if isinstance(pr, list):
            findings.extend(pr)

    return findings


RSS_PATTERN = re.compile(r'<link[^>]*type=["\']application/rss\+xml["\'][^>]*href=["\']([^"\']+)["\']', re.I)
ATOM_PATTERN = re.compile(r'<link[^>]*type=["\']application/atom\+xml["\'][^>]*href=["\']([^"\']+)["\']', re.I)
JSONLD_PATTERN = re.compile(r'<script[^>]*type=["\']application/ld\+json["\']>([\s\S]*?)</script>', re.I)
CANONICAL_PATTERN = re.compile(r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']', re.I)


CSRF_PATTERNS = [
    r'csrf[_-]?token',
    r'csrfmiddlewaretoken',
    r'__csrf',
    r'csrf_key',
    r'csrfName',
    r'csrfParam',
    r'_csrf',
    r'csrf_test_name',
    r'YII_CSRF_TOKEN',
    r'CRAFT_CSRF_TOKEN',
]


async def _analyze_rss_feeds(client, base_url, findings):
    urls_to_check = [f"{base_url}/rss.xml", f"{base_url}/atom.xml", f"{base_url}/feed.xml", f"{base_url}/rss", f"{base_url}/feed"]
    for url in urls_to_check:
        try:
            resp = await client.get(url, timeout=5.0, headers={"User-Agent": UA}, follow_redirects=True)
            if resp.status_code == 200 and "xml" in resp.headers.get("content-type", ""):
                findings.append(IntelligenceFinding(
                    entity=url,
                    type="RSS/Feed Discovery",
                    source="CrawlerCore",
                    confidence="High",
                    color="orange",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    tags=["rss", "feed"]
                ))
        except Exception:
            pass


async def analyze_page_deep(client, url, domain, findings):
    try:
        resp = await client.get(url, timeout=10.0, headers={"User-Agent": UA}, follow_redirects=True)
        if resp.status_code != 200:
            return
        html = resp.text
        rss_feeds = RSS_PATTERN.findall(html)
        for feed in rss_feeds[:3]:
            findings.append(IntelligenceFinding(
                entity=urljoin(url, feed),
                type="RSS Feed Link",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["rss"]
            ))
        canonical = CANONICAL_PATTERN.search(html)
        if canonical:
            findings.append(IntelligenceFinding(
                entity=canonical.group(1),
                type="Canonical URL",
                source="CrawlerCore",
                confidence="High",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["seo", "canonical"]
            ))
        for csrf_pat in CSRF_PATTERNS:
            if re.search(csrf_pat, html, re.I):
                findings.append(IntelligenceFinding(
                    entity=f"CSRF protection detected via pattern: {csrf_pat}",
                    type="CSRF Token Detection",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="emerald",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    tags=["csrf", "security"]
                ))
                break
        open_graph = re.findall(r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if open_graph:
            findings.append(IntelligenceFinding(
                entity=f"Open Graph tags found: {len(open_graph)} properties",
                type="Open Graph Meta",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["opengraph", "seo"]
            ))
        twitter_cards = re.findall(r'<meta[^>]+name=["\']twitter:([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if twitter_cards:
            findings.append(IntelligenceFinding(
                entity=f"Twitter Card tags found: {len(twitter_cards)} properties",
                type="Twitter Card Meta",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["twitter", "seo"]
            ))
        jsonld = JSONLD_PATTERN.findall(html)
        if jsonld:
            for block in jsonld[:3]:
                truncated = block[:200]
                findings.append(IntelligenceFinding(
                    entity=f"JSON-LD: {truncated}",
                    type="JSON-LD Structured Data",
                    source="CrawlerCore",
                    confidence="Medium",
                    color="slate",
                    category="Web Crawling & Content Discovery",
                    threat_level="Informational",
                    tags=["structured-data", "seo"]
                ))
        iframe_sandbox = re.findall(r'<iframe[^>]+sandbox[^>]*>', html, re.I)
        if iframe_sandbox:
            findings.append(IntelligenceFinding(
                entity=f"{len(iframe_sandbox)} iframes with sandbox attribute",
                type="IFrame Sandbox Attribute",
                source="CrawlerCore",
                confidence="Medium",
                color="slate",
                category="Web Crawling & Content Discovery",
                threat_level="Informational",
                tags=["iframe", "security"]
            ))
    except Exception:
        pass
