import httpx
import re
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

COOKIE_TECH_PATTERNS = {
    "PHPSESSID": "PHP", "ASP.NET_SessionId": "ASP.NET", "JSESSIONID": "Java/J2EE",
    "JSESSION": "Java", "CFID": "ColdFusion", "CFTOKEN": "ColdFusion",
    "laravel_session": "Laravel PHP", "XSRF-TOKEN": "Laravel",
    "drupal.settings": "Drupal", "wp-settings": "WordPress",
    "_session": "Generic Session", "connect.sid": "Express.js",
    "sessionid": "Django", "csrftoken": "Django",
    "rack.session": "Ruby on Rails", "_csrf": "CSRF Protection",
    "AWSALB": "AWS ALB", "AWSELB": "AWS ELB",
}

URL_TECH_PATTERNS = {
    r'\.php': "PHP", r'\.asp': "ASP Classic", r'\.aspx': "ASP.NET",
    r'\.jsp': "Java JSP", r'\.do': "Java Struts", r'\.action': "Java Struts2",
    r'\.cfm': "ColdFusion", r'\.shtml': "SSI (Server Side Includes)",
    r'\.pl': "Perl", r'\.cgi': "CGI", r'\.py': "Python",
    r'\.rb': "Ruby", r'\.wsdl': "SOAP Web Service",
    r'/graphql': "GraphQL API", r'/api/': "REST API",
    r'/wp-': "WordPress", r'wp-content': "WordPress",
    r'/admin/': "Admin Panel", r'/login': "Login Page",
}

HTML_CLASS_PATTERNS = {
    "tailwind": "Tailwind CSS", "bootstrap": "Bootstrap",
    "col-md-": "Bootstrap Grid", "col-sm-": "Bootstrap Grid",
    "col-lg-": "Bootstrap Grid", "col-xs-": "Bootstrap Grid",
    "fa-": "Font Awesome", "fas fa-": "Font Awesome Solid",
    "far fa-": "Font Awesome Regular", "fab fa-": "Font Awesome Brand",
    "material-icons": "Material Icons", "icon-": "Icon Library",
    "ui-": "jQuery UI", "ng-": "Angular", "_ngcontent": "Angular",
    "v-bind": "Vue.js", "v-if": "Vue.js", "v-for": "Vue.js",
    "v-model": "Vue.js", ":class=": "Vue.js Binding",
    "@click": "Vue.js Event", "@submit": "Vue.js Event",
    "svelte-": "Svelte", "sc-": "Styled Components",
    "css-": "CSS Modules",
}

ERROR_PAGE_SIGNATURES = {
    "404 Not Found": "Generic 404", "500 Internal Server Error": "Generic 500",
    "403 Forbidden": "Generic 403", "Apache": "Apache HTTP Server",
    "nginx": "Nginx", "IIS": "Microsoft IIS",
    "Tomcat": "Apache Tomcat", "Jetty": "Jetty",
    "JBoss": "JBoss/WildFly", "WebLogic": "Oracle WebLogic",
    "PHP Parse error": "PHP", "Fatal error:": "PHP",
    "Warning:": "PHP", "Notice:": "PHP",
    "Stack Trace:": "Java/.NET", "at ": "Java Stack Trace",
    "in <b>": "PHP Error", "SQLite": "SQLite",
    "MySQL": "MySQL", "PostgreSQL": "PostgreSQL",
    "MongoDB": "MongoDB", "SQLSTATE": "Database Error",
    "PDO": "PHP PDO", "RuntimeError": "Python",
    "SyntaxError": "JavaScript/Python",
}

META_GENERATORS = {
    "WordPress": r'<meta[^>]+name="generator"[^>]+content="WordPress',
    "Drupal": r'<meta[^>]+name="generator"[^>]+content="Drupal',
    "Joomla": r'<meta[^>]+name="generator"[^>]+content="Joomla',
    "Magento": r'<meta[^>]+name="generator"[^>]+content="Magento',
    "Shopify": r'Shopify',
    "Wix": r'<meta[^>]+name="generator"[^>]+content="Wix',
    "Squarespace": r'<meta[^>]+name="generator"[^>]+content="Squarespace',
    "Weebly": r'<meta[^>]+name="generator"[^>]+content="Weebly',
    "Blogger": r'<meta[^>]+name="generator"[^>]+content="Blogger',
    "Ghost": r'<meta[^>]+name="generator"[^>]+content="Ghost',
    "Hugo": r'<meta[^>]+name="generator"[^>]+content="Hugo',
    "Jekyll": r'<meta[^>]+name="generator"[^>]+content="Jekyll',
    "Gatsby": r'<meta[^>]+name="generator"[^>]+content="Gatsby',
    "Next.js": r'<meta[^>]+name="generator"[^>]+content="Next',
    "Nuxt": r'<meta[^>]+name="generator"[^>]+content="Nuxt',
    "Hexo": r'<meta[^>]+name="generator"[^>]+content="Hexo',
    "Strapi": r'<meta[^>]+name="generator"[^>]+content="Strapi',
}

async def _fetch_archive_snapshots(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=30&filter=statuscode:200&collapse=urlkey",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            data = resp.json()
            snapshots_taken = set()
            for row in data[1:20]:
                if isinstance(row, list) and len(row) >= 3:
                    orig_url = row[0]
                    ts = row[1]
                    if ts[:8] in snapshots_taken:
                        continue
                    snapshots_taken.add(ts[:8])
                    try:
                        snap = await client.get(
                            f"http://web.archive.org/web/{ts}if_/{orig_url}",
                            timeout=15.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if snap.status_code == 200:
                            html = snap.text[:80000]
                            hdrs = snap.headers
                            server = hdrs.get("server", "")
                            powered = hdrs.get("x-powered-by", "")
                            if server:
                                findings.append(IntelligenceFinding(
                                    entity=f"Server: {server} [{ts[:8]}]",
                                    type="Tech Stack - Server Header (Archive)",
                                    source="Wayback Machine",
                                    confidence="High",
                                    color="orange",
                                    status="Historical",
                                    raw_data=f"Server header: {server} from {ts[:8]}",
                                    tags=["tech-stack", "server", "historical"]
                                ))
                            if powered:
                                findings.append(IntelligenceFinding(
                                    entity=f"X-Powered-By: {powered} [{ts[:8]}]",
                                    type="Tech Stack - Platform Header (Archive)",
                                    source="Wayback Machine",
                                    confidence="High",
                                    color="orange",
                                    raw_data=f"X-Powered-By: {powered} from {ts[:8]}",
                                    tags=["tech-stack", "platform", "historical"]
                                ))
                            cookie = hdrs.get("set-cookie", "")
                            if cookie:
                                for pattern, tech in COOKIE_TECH_PATTERNS.items():
                                    if pattern.lower() in cookie.lower():
                                        findings.append(IntelligenceFinding(
                                            entity=f"{tech} (via cookie pattern: {pattern}) [{ts[:8]}]",
                                            type="Tech Stack - Cookie Pattern (Archive)",
                                            source="Wayback Machine",
                                            confidence="High",
                                            color="slate",
                                            raw_data=f"Cookie {pattern} indicates {tech}",
                                            tags=["tech-stack", tech.lower().replace(" ", "-")]
                                        ))
                            for pattern, tech in URL_TECH_PATTERNS.items():
                                if re.search(pattern, orig_url, re.I):
                                    findings.append(IntelligenceFinding(
                                        entity=f"{tech} (URL pattern: {pattern})",
                                        type="Tech Stack - URL Extension (Archive)",
                                        source="Wayback Machine",
                                        confidence="High",
                                        color="slate",
                                        raw_data=f"URL {orig_url} matches pattern {pattern}",
                                        tags=["tech-stack", "url-pattern"]
                                    ))
                            for gen_name, gen_pattern in META_GENERATORS.items():
                                if re.search(gen_pattern, html, re.I):
                                    findings.append(IntelligenceFinding(
                                        entity=f"{gen_name} (generator meta tag) [{ts[:8]}]",
                                        type="Tech Stack - CMS/Generator (Archive)",
                                        source="Wayback Machine",
                                        confidence="High",
                                        color="blue",
                                        raw_data=f"Meta generator indicates {gen_name}",
                                        tags=["tech-stack", gen_name.lower().replace(" ", "-")]
                                    ))
                            for class_pattern, tech in HTML_CLASS_PATTERNS.items():
                                if class_pattern in html.lower():
                                    findings.append(IntelligenceFinding(
                                        entity=f"{tech} (CSS/HTML pattern: {class_pattern})",
                                        type="Tech Stack - CSS Framework (Archive)",
                                        source="Wayback Machine",
                                        confidence="Medium",
                                        color="purple",
                                        raw_data=f"Class pattern '{class_pattern}' indicates {tech}",
                                        tags=["tech-stack", tech.lower().replace(" ", "-")]
                                    ))
                            for err_pattern, err_desc in ERROR_PAGE_SIGNATURES.items():
                                if err_pattern.lower() in html.lower():
                                    findings.append(IntelligenceFinding(
                                        entity=f"Error page signature: {err_desc}",
                                        type="Tech Stack - Error Page Fingerprint",
                                        source="Wayback Machine",
                                        confidence="Medium",
                                        color="slate",
                                        raw_data=f"Error page contains '{err_pattern}'",
                                        tags=["tech-stack", "error-page"]
                                    ))
                            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
                            for src in script_srcs[:10]:
                                if "cdnjs.cloudflare.com" in src:
                                    lib_m = re.search(r'ajax/libs/([\w-]+)/([\d.]+)', src)
                                    if lib_m:
                                        findings.append(IntelligenceFinding(
                                            entity=f"CDN Library: {lib_m.group(1)} v{lib_m.group(2)}",
                                            type="Tech Stack - CDN JS Library",
                                            source="Wayback Machine",
                                            confidence="High",
                                            color="slate",
                                            raw_data=f"cdnjs: {lib_m.group(1)} v{lib_m.group(2)}",
                                            tags=["tech-stack", "cdn-library"]
                                        ))
                                elif "unpkg.com" in src:
                                    lib_m = re.search(r'unpkg\.com/([\w-]+)@?([\d.]+)?', src)
                                    if lib_m:
                                        findings.append(IntelligenceFinding(
                                            entity=f"UNPKG Library: {lib_m.group(1)} v{lib_m.group(2) or 'latest'}",
                                            type="Tech Stack - UNPKG Library",
                                            source="Wayback Machine",
                                            confidence="High",
                                            color="slate",
                                            tags=["tech-stack", "unpkg"]
                                        ))
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def _fetch_sitemap_analysis(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    sitemap_urls = [
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/robots.txt",
    ]
    for url in sitemap_urls:
        try:
            resp = await client.get(url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                content = resp.text[:30000]
                findings.append(IntelligenceFinding(
                    entity=f"{url} accessible ({len(content)} bytes)",
                    type="Tech Stack - Sitemap/Robots Found",
                    source="Passive Technology Stack",
                    confidence="High",
                    color="slate",
                    raw_data=f"Accessible: {url}",
                    tags=["tech-stack", "sitemap", "robots"]
                ))
                for pattern, tech in URL_TECH_PATTERNS.items():
                    if re.search(pattern, content, re.I):
                        findings.append(IntelligenceFinding(
                            entity=f"{tech} (from sitemap URL pattern: {pattern})",
                            type="Tech Stack - Sitemap Tech Indicator",
                            source="Passive Technology Stack",
                            confidence="High",
                            color="slate",
                            tags=["tech-stack", tech.lower().replace(" ", "-")]
                        ))
        except Exception:
            pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    archive_findings = await _fetch_archive_snapshots(domain, client)
    findings.extend(archive_findings)

    sitemap_findings = await _fetch_sitemap_analysis(domain, client)
    findings.extend(sitemap_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Technology Stack Reconstruction complete: {len(findings)} findings",
            type="Tech Stack - Summary",
            source="Passive Technology Stack",
            confidence="High", color="purple",
            status="Complete",
            tags=["tech-stack", "summary"]
        ))

    return findings
