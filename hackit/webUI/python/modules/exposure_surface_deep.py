import httpx
import re
from models import IntelligenceFinding
from urllib.parse import urlparse

SENSITIVE_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.example",
    "/.env.production",
    "/.env.local",
    "/.aws/credentials",
    "/.aws/config",
    "/.azure/config",
    "/.gcloud/config",
    "/config.json",
    "/config.php",
    "/configuration.php",
    "/wp-config.php",
    "/wp-config.bak",
    "/config/database.php",
    "/database.yml",
    "/db.yml",
    "/settings.py",
    "/settings.php",
    "/app/config/parameters.yml",
    "/parameters.yml",
    "/config.yml",
    "/config.yaml",
    "/config.xml",
    "/application/config/config.php",
    "/admin/config.php",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/api/test",
    "/api/health",
    "/api/status",
    "/server-status",
    "/server-info",
    "/status",
    "/health",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api/docs",
    "/api/swagger",
    "/docs",
    "/openapi.json",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/sitemap.xml",
    "/robots.txt",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/admin/login.php",
    "/login",
    "/login.php",
    "/wp-login.php",
    "/cpanel",
    "/plesk",
    "/webmail",
    "/mail/",
    "/roundcube/",
    "/squirrelmail/",
    "/phpMyAdmin/",
    "/phpmyadmin/",
    "/pma/",
    "/mysql/",
    "/adminer.php",
    "/console/",
    "/shell.php",
    "/cmd.php",
    "/exec.php",
    "/cgi-bin/",
    "/cgi-bin/test.cgi",
    "/backup/",
    "/backup.sql",
    "/db_backup.sql",
    "/dump.sql",
    "/backups/",
    "/.bak",
    "/.old",
    "/.swp",
    "/~root",
    "/~admin",
    "/web.config",
    "/.htaccess",
    "/.htpasswd",
    "/.ftpconfig",
    "/filezilla.xml",
    "/recaptcha/api.js",
]

API_KEY_PATTERNS = [
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"sk-[0-9a-zA-Z]{20,60}", "Stripe Secret Key"),
    (r"pk-[0-9a-zA-Z]{20,60}", "Stripe Publishable Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"SG\.[a-zA-Z0-9_-]{20,50}\.[a-zA-Z0-9_-]{20,50}", "SendGrid API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"github_pat_[a-zA-Z0-9]{36,100}", "GitHub Fine-Grained Token"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,48}", "Slack Token"),
    (r"sk_live_[0-9a-zA-Z]{20,40}", "Stripe Live Secret Key"),
    (r"pk_live_[0-9a-zA-Z]{20,40}", "Stripe Live Publishable Key"),
    (r"sk_test_[0-9a-zA-Z]{20,40}", "Stripe Test Secret Key"),
    (r"pk_test_[0-9a-zA-Z]{20,40}", "Stripe Test Publishable Key"),
    (r"facebook.*['\"][0-9a-f]{32}", "Facebook App Secret"),
    (r"client_secret=['\"][0-9a-zA-Z]{24}", "Google OAuth Secret"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key (PEM)"),
    (r"mongodb(?:\+srv)?://[^\s'\"<>]+", "MongoDB Connection String"),
    (r"postgresql://[^\s'\"<>]+", "PostgreSQL Connection String"),
    (r"mysql://[^\s'\"<>]+", "MySQL Connection String"),
    (r"redis://[^\s'\"<>]+", "Redis Connection String"),
    (r"https://hooks\.slack\.com/services/[a-zA-Z0-9/+]{40,80}", "Slack Webhook"),
]

COMMENT_PATTERNS = [
    (r"<!--\s*(TODO|FIXME|HACK|XXX|BUG|FIX|WORKAROUND|HARDCODED|PASSWORD|SECRET|API_KEY|TOKEN)[^>]*-->", "HTML Comment"),
    (r"//\s*(TODO|FIXME|HACK|XXX|BUG|FIX|WORKAROUND|HARDCODED|PASSWORD|SECRET|API_KEY|TOKEN)", "JS Comment"),
    (r"/\*\s*(TODO|FIXME|HACK|XXX|BUG|FIX|WORKAROUND|HARDCODED|PASSWORD|SECRET|API_KEY|TOKEN)", "Block Comment"),
]

PAYMENT_PROCESSOR_PATTERNS = [
    (r"stripe\.com|Stripe\.js|stripe\.js|pk_live_|sk_live_", "Stripe"),
    (r"paypal\.com|paypal\.objects|PAYPAL|paypalcheckout", "PayPal"),
    (r"square\.com|Square\.js|sqpaymentform", "Square"),
    (r"braintree.*gateway|braintree\.js|btoken=", "Braintree"),
    (r"amazon.*pay|amazonpayments|OffAmazonPayments", "Amazon Pay"),
    (r"adyen\.com|adyen\.js|adyen\.encrypt", "Adyen"),
    (r"shopify.*pay|shopify\.js|shopify.*checkout", "Shopify Payments"),
    (r"recurly\.com|recurly\.js", "Recurly"),
    (r"chargebee\.com|chargebee\.js", "Chargebee"),
    (r"paddle\.com|paddle\.js", "Paddle"),
    (r"mollie\.com|mollie\.js", "Mollie"),
    (r"razorpay\.com|razorpay-", "Razorpay"),
    (r"instamojo\.com|instamojo-", "Instamojo"),
    (r"paystack\.com|paystack\.js", "Paystack"),
    (r"mercadopago\.com|mercadopago\.js", "Mercado Pago"),
    (r"pagseguro\.com|pagseguro\.js", "PagSeguro"),
    (r"2checkout\.com|2co\.com|twocheckout", "2Checkout"),
    (r"authorize\.net|accept\.js|AuthorizeNet", "Authorize.net"),
    (r"worldpay\.com|worldpay\.js", "Worldpay"),
    (r"eway\.com|eway\.js|eWAY", "eWay"),
    (r"nmi\.com|nmi\.js", "NMI"),
]

TECH_KEYWORDS = {
    "wordpress": "WordPress CMS",
    "drupal": "Drupal CMS",
    "joomla": "Joomla CMS",
    "magento": "Magento E-commerce",
    "shopify": "Shopify E-commerce",
    "woocommerce": "WooCommerce",
    "laravel": "Laravel Framework",
    "symfony": "Symfony Framework",
    "django": "Django Framework",
    "rails": "Ruby on Rails",
    "asp.net": "ASP.NET",
    "react": "React.js",
    "vue": "Vue.js",
    "angular": "Angular",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "tailwind": "Tailwind CSS",
    "next.js": "Next.js",
    "nuxt": "Nuxt.js",
    "gatsby": "Gatsby",
    "express": "Express.js",
    "socket.io": "Socket.io",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "IIS",
}

async def check_path(client: httpx.AsyncClient, base_url: str, path: str) -> tuple:
    url = f"{base_url}{path}"
    try:
        resp = await client.get(url, timeout=8.0, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            body_lower = resp.text.lower()[:500] if hasattr(resp, "text") else ""
            return (path, resp.status_code, len(resp.text) if hasattr(resp, "text") else 0, body_lower)
        elif resp.status_code in (301, 302, 307, 308):
            return (path, resp.status_code, 0, "")
        elif resp.status_code == 403:
            return (path, resp.status_code, 0, "")
        elif resp.status_code == 401:
            return (path, resp.status_code, 0, "")
    except Exception:
        return (path, 0, 0, "")
    return (path, 0, 0, "")

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        base_url = domain.rstrip("/")
    else:
        base_url = f"https://{domain}"

    try:
        resp = await client.get(base_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text if hasattr(resp, "text") else ""
        headers = dict(resp.headers)
        status_code = resp.status_code
    except Exception:
        try:
            base_url = f"http://{domain}"
            resp = await client.get(base_url, timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            html = resp.text if hasattr(resp, "text") else ""
            headers = dict(resp.headers)
            status_code = resp.status_code
        except Exception:
            return findings

    sensitive_results = []
    path_tasks = []
    base_for_paths = base_url.rstrip("/")

    import asyncio
    sem = asyncio.Semaphore(5)

    async def limited_check(p):
        async with sem:
            return await check_path(client, base_for_paths, p)

    for path in SENSITIVE_PATHS:
        path_tasks.append(limited_check(path))

    results = await asyncio.gather(*path_tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            continue
        path, code, body_len, body_lower = result
        if code == 200 and body_len > 0:
            path_type = "Sensitive File Exposure"
            color = "red"
            threat = "High Risk"
            if "/admin" in path or "/login" in path or "/cpanel" in path:
                path_type = "Admin/Login Panel"
                color = "orange"
                threat = "Standard Target"
            elif path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                path_type = "Informational Endpoint"
                color = "slate"
                threat = "Informational"
            elif "/.git" in path:
                path_type = "Git Repository Exposure"
                color = "red"
                threat = "Critical Risk"
            elif ".env" in path:
                path_type = "Environment File Exposure"
                color = "red"
                threat = "Critical Risk"
            elif "phpinfo" in path or "info.php" in path or "phpinfo.php" in path:
                path_type = "PHPInfo Exposure"
                color = "red"
                threat = "High Risk"
            elif "actuator" in path:
                path_type = "Spring Boot Actuator Exposure"
                color = "red"
                threat = "High Risk"
            elif "swagger" in path or "docs" in path or "openapi" in path:
                path_type = "API Documentation Exposure"
                color = "orange"
                threat = "Elevated Risk"
            elif "backup" in path or ".sql" in path or ".bak" in path:
                path_type = "Backup File Exposure"
                color = "red"
                threat = "High Risk"
            elif "/cgi-bin" in path:
                path_type = "CGI Script Exposure"
                color = "orange"
                threat = "Elevated Risk"
            elif "phpMyAdmin" in path or "pma" in path:
                path_type = "Database Admin Exposure"
                color = "red"
                threat = "High Risk"
            elif "wp-config" in path or "config" in path:
                path_type = "Configuration File Exposure"
                color = "red"
                threat = "High Risk"
            elif "/.well-known" in path:
                path_type = "Well-Known Endpoint"
                color = "slate"
                threat = "Informational"
            elif "/server-status" in path or "/server-info" in path:
                path_type = "Server Status Exposure"
                color = "red"
                threat = "High Risk"
            elif path in ("/web.config", "/.htaccess", "/.htpasswd"):
                path_type = "Server Config Exposure"
                color = "red"
                threat = "High Risk"

            sensitive_results.append((path, code, body_len, body_lower, path_type, color, threat))

    for path, code, body_len, body_lower, path_type, color, threat in sensitive_results:
        truncated = body_lower[:200] if body_len > 0 else ""
        findings.append(IntelligenceFinding(
            entity=path[:200],
            type=path_type,
            source="ExposureSurfaceDeep",
            confidence="High",
            color=color,
            threat_level=threat,
            status=f"HTTP {code}",
            resolution=f"{body_len} bytes returned",
            raw_data=f"Path: {path} | Status: {code} | Size: {body_len}b | Content: {truncated[:300]}",
            tags=["exposure", "scan"]
        ))

    if sensitive_results:
        total = len(sensitive_results)
        critical = sum(1 for _, _, _, _, _, _, t in sensitive_results if "Critical" in t)
        high = sum(1 for _, _, _, _, _, _, t in sensitive_results if "High" in t and "Critical" not in t)
        findings.append(IntelligenceFinding(
            entity=f"{total} exposed paths found ({critical} critical, {high} high risk)",
            type="Exposure Surface - Summary",
            source="ExposureSurfaceDeep",
            confidence="High",
            color="red" if critical > 0 else "orange",
            threat_level="Critical Risk" if critical > 0 else ("High Risk" if high > 0 else "Informational"),
            raw_data=f"Total: {total} | Critical: {critical} | High: {high}",
            tags=["exposure", "summary"]
        ))

    try:
        for pattern, key_type in API_KEY_PATTERNS:
            matches = re.findall(pattern, html)
            for m in matches[:3]:
                masked = m[:8] + "..." + m[-4:] if len(m) > 14 else m[:4] + "..."
                findings.append(IntelligenceFinding(
                    entity=f"Potential {key_type}: {masked}",
                    type="Exposure - API Key / Secret",
                    source="ExposureSurfaceDeep",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Pattern: {key_type} | Found: {m[:100]}",
                    tags=["api-key", "secret", "exposure"]
                ))
    except Exception:
        pass

    try:
        for pattern, comment_type in COMMENT_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches[:5]:
                comment_text = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                findings.append(IntelligenceFinding(
                    entity=f"{comment_type}: {comment_text[:150]}",
                    type="Exposure - Sensitive Comment",
                    source="ExposureSurfaceDeep",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"Found in source: {comment_text[:300]}",
                    tags=["comment", "leak"]
                ))
    except Exception:
        pass

    try:
        directory_listing_paths = ["/", "/images/", "/css/", "/js/", "/assets/", "/static/",
                                   "/uploads/", "/files/", "/media/", "/downloads/", "/backup/",
                                   "/admin/", "/includes/", "/templates/", "/src/"]
        for dl_path in directory_listing_paths:
            dl_url = f"{base_for_paths}{dl_path}"
            try:
                dl_resp = await client.get(dl_url, timeout=8.0,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
                if dl_resp.status_code == 200:
                    dl_text = dl_resp.text.lower() if hasattr(dl_resp, "text") else ""
                    dl_indicators = ["index of", "parent directory", "directory listing",
                                     "<title>index of", "name</a>", "last modified"]
                    if any(ind in dl_text for ind in dl_indicators):
                        findings.append(IntelligenceFinding(
                            entity=dl_path,
                            type="Exposure - Directory Listing Enabled",
                            source="ExposureSurfaceDeep",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            raw_data=f"Directory listing at {dl_url}",
                            tags=["directory-listing", "exposure"]
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass

    try:
        robots_url = f"{base_for_paths}/robots.txt"
        robots_resp = await client.get(robots_url, timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if robots_resp.status_code == 200:
            robots_text = robots_resp.text
            disallowed = []
            allowed = []
            sitemaps = []
            for line in robots_text.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    if val:
                        disallowed.append(val)
                elif line.lower().startswith("allow:"):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    if val:
                        allowed.append(val)
                elif line.lower().startswith("sitemap:"):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    if val:
                        sitemaps.append(val)

            interesting_hidden = [d for d in disallowed if any(k in d.lower() for k in (
                "admin", "login", "wp-", "backup", "secret", "private", "internal",
                "api", "config", "db_", "sql", ".git", ".env", "hidden", "dev",
                "test", "staging", "beta", "debug", "console", "monitor"))]

            if disallowed:
                findings.append(IntelligenceFinding(
                    entity=f"robots.txt: {len(disallowed)} Disallow rules",
                    type="Exposure - robots.txt Analysis",
                    source="ExposureSurfaceDeep",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=robots_text[:1000],
                    tags=["robots.txt", "crawl"]
                ))

            for hidden in interesting_hidden[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"robots.txt hides: {hidden[:200]}",
                    type="Exposure - Hidden Path Discovered",
                    source="ExposureSurfaceDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Disallowed path: {hidden}",
                    tags=["robots.txt", "hidden-path"]
                ))

            for sm in sitemaps[:5]:
                findings.append(IntelligenceFinding(
                    entity=sm[:200],
                    type="Exposure - Sitemap Found",
                    source="ExposureSurfaceDeep",
                    confidence="High",
                    color="slate",
                    tags=["sitemap"]
                ))
    except Exception:
        pass

    try:
        for pattern, tech_name in TECH_KEYWORDS.items():
            if pattern in html.lower():
                findings.append(IntelligenceFinding(
                    entity=tech_name,
                    type="Exposure - Technology Detected",
                    source="ExposureSurfaceDeep",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    tags=["technology"]
                ))
    except Exception:
        pass

    try:
        for header in ["x-powered-by", "x-aspnet-version", "x-framework",
                       "x-drupal-cache", "x-drupal-dynamic-cache",
                       "x-generator", "x-varnish", "cf-ray", "x-cache",
                       "x-amz-cf-id", "x-amz-request-id", "x-served-by"]:
            val = headers.get(header)
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{header}: {val[:200]}",
                    type="Exposure - Server Header Leak",
                    source="ExposureSurfaceDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"{header}: {val[:500]}",
                    tags=["header", "information-disclosure"]
                ))
    except Exception:
        pass

    try:
        payment_found = set()
        for pattern, proc_name in PAYMENT_PROCESSOR_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                if proc_name not in payment_found:
                    payment_found.add(proc_name)
                    findings.append(IntelligenceFinding(
                        entity=f"Payment Processor: {proc_name}",
                        type="Exposure - Payment Processor Detected",
                        source="ExposureSurfaceDeep",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"Found {proc_name} indicators in page source",
                        tags=["payment", "processor"]
                    ))
    except Exception:
        pass

    try:
        hibp_resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            timeout=12.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json"
            }
        )
        if hibp_resp.status_code == 200:
            breaches = hibp_resp.json() if isinstance(hibp_resp.text, str) and hibp_resp.text.startswith("[") else []
            for breach in breaches[:15]:
                if isinstance(breach, dict):
                    bname = breach.get("Name", "")
                    bdate = breach.get("BreachDate", "")
                    bcount = breach.get("PwnCount", 0)
                    bdata = breach.get("DataClasses", [])
                    if bname:
                        findings.append(IntelligenceFinding(
                            entity=f"{bname} ({bdate}) - {bcount:,} accounts",
                            type="Exposure - Data Breach",
                            source="ExposureSurfaceDeep (HIBP)",
                            confidence="High",
                            color="red",
                            threat_level="Critical Risk",
                            raw_data=f"Breach: {bname} | Date: {bdate} | Accounts: {bcount} | Data: {', '.join(bdata)}",
                            tags=["breach", "hibp"]
                        ))
            if breaches:
                findings.append(IntelligenceFinding(
                    entity=f"{len(breaches)} known data breaches for {domain}",
                    type="Exposure - Breach Summary",
                    source="ExposureSurfaceDeep (HIBP)",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["breach", "summary"]
                ))
    except Exception:
        pass

    try:
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        emails = set(re.findall(email_pattern, html))
        domain_emails = {e for e in emails if e.lower().endswith(domain) or e.lower().endswith("." + domain)}
        other_emails = emails - domain_emails
        if domain_emails:
            for e in list(domain_emails)[:10]:
                findings.append(IntelligenceFinding(
                    entity=e,
                    type="Exposure - Email Address in Source",
                    source="ExposureSurfaceDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Email found in HTML: {e}",
                    tags=["email", "leak"]
                ))
    except Exception:
        pass

    try:
        if ".git" in html:
            git_findings = [f for f in findings if "Git Repository" in f.type]
            if not git_findings:
                git_matches = re.findall(r'https?://[^\s"\'<>]+\.git[^\s"\'<>]*', html)
                for gm in git_matches[:3]:
                    findings.append(IntelligenceFinding(
                        entity=gm[:200],
                        type="Exposure - Git URL Found",
                        source="ExposureSurfaceDeep",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        tags=["git", "exposure"]
                    ))
    except Exception:
        pass

    return findings
