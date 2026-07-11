import httpx
import re
import asyncio
from urllib.parse import urlparse, quote
from module_common import safe_fetch, make_finding

BUILTWITH_API = "https://api.builtwith.com/free1/api.json"
SIMILAR_WEB_CSS_PATTERNS = [
    (r'google-analytics\.com/ga\.js', "Google Analytics (Universal)"),
    (r'googletagmanager\.com/gtag/js', "Google Tag Manager"),
    (r'gtag\(\'config\'', "Google Analytics 4 (gtag)"),
    (r'fbq\(|\/facebook.*(?:pixel|tr)', "Facebook Pixel"),
    (r'snap\.licdn\.com', "LinkedIn Insight Tag"),
    (r'static\.ads-twitter\.com', "Twitter Conversion Tracking"),
    (r'pixel\.quantserve\.com', "Quantcast"),
    (r'scorecardresearch\.com', "ScorecardResearch"),
    (r'hotjar\.com', "Hotjar Analytics"),
    (r'cdn\.cookielaw\.org', "CookieLaw / OneTrust"),
    (r'doubleclick\.net', "DoubleClick / Google Ads"),
    (r'cdn\.taboola\.com', "Taboola"),
    (r'amazon-adsystem\.com', "Amazon Ads"),
    (r'criteo\.net', "Criteo"),
    (r'newrelic\.com', "New Relic"),
    (r'cdn\.mxpnl\.com', "Mixpanel"),
    (r'segment\.com|cdn\.segment\.(?:io|com)', "Segment"),
    (r'intercom\.io', "Intercom"),
    (r'zendesk\.com', "Zendesk"),
    (r'sentry\.(?:io|cdn)', "Sentry"),
    (r'datadog\.(?:com|eu)', "Datadog"),
    (r'optimizely\.com', "Optimizely"),
    (r'fullstory\.com', "FullStory"),
    (r'heap\.io', "Heap Analytics"),
    (r'amplitude\.com', "Amplitude"),
    (r'mixpanel\.com', "Mixpanel"),
]

EXPOSED_PATTERNS = [
    (r'["\'](?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}["\']', "Stripe API Key"),
    (r'["\']AIza[0-9A-Za-z_-]{35}["\']', "Google API Key"),
    (r'["\']AKIA[0-9A-Z]{16}["\']', "AWS Access Key"),
    (r'["\'](?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}["\']', "GitHub Token"),
    (r'["\'](?:xox[abpsr]|xapp|xoxe)-[A-Za-z0-9-]{10,}["\']', "Slack Token"),
    (r'["\']sk_live_[0-9a-zA-Z]{10,}["\']', "Stripe Secret Key"),
    (r'["\'](?:pk|sk)\.(?:test|live)\.[A-Za-z0-9]{10,}["\']', "Stripe Key (modern)"),
    (r'["\']SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}["\']', "SendGrid API Key"),
    (r'["\']key-[0-9a-zA-Z]{32}["\']', "Mailgun API Key"),
    (r'["\'](?:api|apikey|secret)["\']\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Generic API Key"),
    (r'["\']eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}["\']', "JWT Token"),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key (PEM)"),
    (r'["\'](?:sk|pk)_[a-z]+_[A-Za-z0-9]{10,}["\']', "Secret/Public Key (legacy)"),
    (r'["\'](?:password|passwd|pwd)["\']\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded Password"),
    (r'["\'](?:token|access_token|auth_token)["\']\s*[:=]\s*["\'][^"\']{8,}["\']', "Access Token"),
]

CDN_JS_PATTERNS = [
    (r'(?:cdnjs|cdn)\.cloudflare\.com/ajax/libs/([^/]+)', "Cloudflare CDN (cdnjs)"),
    (r'ajax\.googleapis\.com/ajax/libs/([^/]+)', "Google CDN"),
    (r'cdn\.jsdelivr\.net/(?:npm|gh)/([^/]+)', "jsDelivr CDN"),
    (r'unpkg\.com/([^/]+)', "Unpkg CDN"),
    (r'maxcdn\.bootstrapcdn\.com/([^/]+)', "Bootstrap CDN (MaxCDN)"),
    (r'stackpath\.bootstrapcdn\.com/([^/]+)', "Bootstrap CDN (StackPath)"),
    (r'code\.jquery\.com/([^/]+)', "jQuery CDN"),
    (r'cdn\.mathjax\.org/([^/]+)', "MathJax CDN"),
    (r'cdn\.polyfill\.io/([^/]*)', "Polyfill.io CDN"),
    (r'cdn\.jsdelivr\.net/([^/]+)', "jsDelivr (other)"),
]

ANALYTICS_ID_PATTERNS = [
    (r'UA-\d{4,10}-\d{1,4}', "Google Analytics (UA)"),
    (r'G-[A-Z0-9]{10,}', "Google Analytics 4 (G- tag)"),
    (r'AW-\d{4,12}', "Google Ads"),
    (r'DC-\d{4,12}', "Google DoubleClick"),
    (r'GTM-[A-Z0-9]{5,10}', "Google Tag Manager"),
    (r'FB-\d{4,12}', "Facebook Pixel ID"),
    (r'pub-\d{16}', "Google AdSense Publisher"),
    (r'ca-pub-\d{16}', "Google AdSense Publisher"),
    (r'mc[as]id_[A-Za-z0-9_-]{10,}', "Mailchimp Account"),
    (r'^[A-Z0-9]{5,15}$', "Google Optimize ID"),
]

TECH_SIGNATURES = {
    "wordpress": "WordPress CMS",
    "wp-content": "WordPress CMS",
    "wp-includes": "WordPress CMS",
    "drupal": "Drupal CMS",
    "joomla": "Joomla CMS",
    "magento": "Magento CMS",
    "shopify": "Shopify CMS",
    "squarespace": "Squarespace CMS",
    "wix": "Wix CMS",
    "react": "React JS",
    "react-dom": "React JS",
    "vue": "Vue.js",
    "angular": "Angular",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "tailwind": "Tailwind CSS",
    "font-awesome": "Font Awesome",
    "material-icons": "Material Icons",
    "materialize": "Materialize CSS",
    "semantic-ui": "Semantic UI",
    "foundation": "Foundation CSS",
    "bulma": "Bulma CSS",
    "chart.js": "Chart.js",
    "d3.js": "D3.js",
    "moment.js": "Moment.js",
    "lodash": "Lodash",
    "underscore": "Underscore.js",
    "axios": "Axios",
    "fetch": "Fetch API",
    "slick": "Slick Slider",
    "swiper": "Swiper Slider",
    "owl.carousel": "Owl Carousel",
    "select2": "Select2",
    "flatpickr": "Flatpickr",
    "datatables": "DataTables",
    "tinymce": "TinyMCE Editor",
    "ckeditor": "CKEditor",
    "summernote": "Summernote Editor",
    "socket.io": "Socket.io",
    "next.js": "Next.js",
    "nuxt": "Nuxt.js",
    "gatsby": "Gatsby.js",
    "amp-boilerplate": "Google AMP",
    "cloudflare": "Cloudflare",
    "cdn-cgi": "Cloudflare",
}

FRAMEWORK_SIGNATURES = {
    "laravel": "Laravel PHP",
    "csrf-token": "Laravel/PHP CSRF",
    "symfony": "Symfony PHP",
    "codeigniter": "CodeIgniter PHP",
    "cakephp": "CakePHP",
    "yii": "Yii PHP",
    "zend": "Zend PHP",
    "thinkphp": "ThinkPHP",
    "django": "Django Python",
    "flask": "Flask Python",
    "tornado": "Tornado Python",
    "fastapi": "FastAPI Python",
    "express": "Express.js Node",
    "koa": "Koa.js Node",
    "nest": "Nest.js Node",
    "rails": "Ruby on Rails",
    "rack": "Rack Ruby",
    "sinatra": "Sinatra Ruby",
    "spring": "Spring Java",
    "servlet": "Java Servlet",
    "struts": "Struts Java",
    "hibernate": "Hibernate Java",
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET Core",
    "webform": "ASP.NET WebForms",
    "sharepoint": "SharePoint",
}

async def scrape_publicwww(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        search_url = f"https://publicwww.com/websites/{quote(target)}/?export=csv"
        resp = await safe_fetch(client, search_url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
        if resp.status_code == 200:
            text = resp.text
            count_match = re.search(r'(\d[\d,]*)\s+(?:result|pages?)', text, re.IGNORECASE)
            if count_match:
                count = count_match.group(1).replace(",", "")
                findings.append(make_finding(
                    entity=f"{count} indexed pages on PublicWWW",
                    ftype="PublicWWW Index Count",
                    source="PublicWWW",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status=f"{count} results",
                    tags=["publicwww", "index-count"]
                ))
            snippet_matches = re.findall(
                r'<em>([^<]{20,})</em>',
                text
            )[:8]
            for snippet in snippet_matches:
                findings.append(make_finding(
                    entity=snippet[:150],
                    ftype="PublicWWW Code Snippet",
                    source="PublicWWW",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    raw_data=snippet[:500],
                    tags=["publicwww", "snippet"]
                ))
        elif resp.status_code == 503 or resp.status_code == 429:
            findings.append(make_finding(
                entity="PublicWWW: Rate limited or blocked",
                ftype="PublicWWW Status",
                source="PublicWWW",
                confidence="Low",
                color="orange",
                threat_level="Informational",
                status="Rate limited",
                tags=["publicwww", "rate-limit"]
            ))
    except:
        pass
    return findings

async def analyze_html(html: str, target: str) -> list:
    findings = []

    # Track third-party JS
    js_src = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    seen_domains = set()
    for src in js_src:
        try:
            parsed = urlparse(src)
            domain = parsed.netloc.lower()
            if domain and domain not in seen_domains and domain not in target:
                seen_domains.add(domain)
                findings.append(make_finding(
                    entity=domain,
                    ftype="Third-Party JS Include",
                    source="PublicWWW (HTML)",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status=f"Served from {domain}",
                    raw_data=f"JS: {src[:200]}",
                    tags=["third-party", "javascript", domain.replace(".", "-")]
                ))
        except:
            pass

    # CDN libraries
    for pattern, label in CDN_JS_PATTERNS:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            lib = m.group(1)
            findings.append(make_finding(
                entity=lib[:100],
                ftype=f"CDN Library: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=m.group(0)[:200],
                tags=["cdn", label.lower().replace(" ", "-")]
            ))

    # Analytics IDs
    for pattern, label in ANALYTICS_ID_PATTERNS:
        matches = re.findall(pattern, html)
        for m in set(matches[:3]):
            findings.append(make_finding(
                entity=m[:50],
                ftype=f"Analytics ID: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["analytics", label.lower().replace(" ", "-"), m[:30]]
            ))

    # Third-party integrations
    for pattern, label in SIMILAR_WEB_CSS_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(make_finding(
                entity=label,
                ftype="Third-Party Integration",
                source="PublicWWW (HTML)",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["integration", label.lower().replace(" ", "-")]
            ))

    return findings

async def check_inline_exposed_secrets(html: str, target: str) -> list:
    findings = []
    for pattern, label in EXPOSED_PATTERNS:
        matches = re.findall(pattern, html)
        for m in set(matches[:3]):
            findings.append(make_finding(
                entity=f"{label}: {m[:30]}...",
                ftype=f"Exposed Secret/Key: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Exposed in source",
                raw_data=m[:200],
                tags=["secret-exposure", "security", label.lower().replace(" ", "-")]
            ))
    return findings

async def check_email_exposure(html: str, target: str) -> list:
    findings = []
    emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', html)
    domain = target.lower()
    for email in set(emails[:20]):
        email_domain = email.split("@")[-1].lower()
        if email_domain == domain:
            findings.append(make_finding(
                entity=email,
                ftype="Public Email (Same Domain)",
                source="PublicWWW (HTML)",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Found in page source",
                tags=["email", "exposure"]
            ))
    unique_domains = set(e.split("@")[-1].lower() for e in emails if e.split("@")[-1].lower() != domain)
    for em_domain in unique_domains:
        if em_domain:
            findings.append(make_finding(
                entity=em_domain,
                ftype="Email Domain (Third Party)",
                source="PublicWWW (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["email-domain", "third-party"]
            ))
    return findings

async def check_builtwith(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://api.builtwith.com/free1/api.json?LOOKUP={target}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            groups = data.get("groups", [])
            for group in groups:
                name = group.get("name", "")
                techs = group.get("technologies", [])
                if isinstance(techs, list):
                    for tech in techs[:3]:
                        t_name = tech.get("name") if isinstance(tech, dict) else str(tech)
                        findings.append(make_finding(
                            entity=t_name[:200] if t_name else "",
                            ftype=f"Technology Stack: {name}",
                            source="PublicWWW (BuiltWith)",
                            confidence="Medium",
                            color="orange",
                            threat_level="Informational",
                            tags=["technology", name.lower().replace(" ", "-")]
                        ))
    except:
        pass
    return findings

async def check_comment_references(html: str, target: str) -> list:
    findings = []
    html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    for comment in html_comments[:15]:
        stripped = comment.strip()
        if len(stripped) > 5 and any(x in stripped.lower() for x in ["todo", "fixme", "hack", "bug", "temp", "note", "author", "developer"]):
            findings.append(make_finding(
                entity=stripped[:150],
                ftype="HTML Comment with Context",
                source="PublicWWW (HTML)",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Interesting HTML comment",
                raw_data=stripped[:500],
                tags=["html-comment", "information-leak"]
            ))
    return findings

async def detect_technology_from_source(html: str, target: str) -> list:
    findings = []
    html_lower = html.lower()
    meta_generator = re.search(r'<meta\s+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if meta_generator:
        generator = meta_generator.group(1).strip()
        findings.append(make_finding(
            entity=f"Meta Generator: {generator}",
            ftype="Technology Source: Meta Generator",
            source="PublicWWW (HTML)",
            confidence="High",
            color="orange",
            threat_level="Informational",
            raw_data=f"Generator meta tag: {generator}",
            tags=["technology", "meta-generator"]
        ))

    detected_techs = set()
    for sig, tech_name in TECH_SIGNATURES.items():
        if sig in html_lower:
            detected_techs.add(tech_name)
    for tech in sorted(detected_techs)[:15]:
        findings.append(make_finding(
            entity=tech,
            ftype="Technology Detection: Source Code",
            source="PublicWWW (HTML)",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            tags=["technology", tech.lower().replace(" ", "-")]
        ))

    detected_frameworks = set()
    for sig, framework in FRAMEWORK_SIGNATURES.items():
        if sig in html_lower:
            detected_frameworks.add(framework)
    for fw in sorted(detected_frameworks)[:10]:
        findings.append(make_finding(
            entity=fw,
            ftype="Framework Detection: Source Code",
            source="PublicWWW (HTML)",
            confidence="Medium",
            color="blue",
            threat_level="Informational",
            tags=["framework", fw.lower().replace(" ", "-")]
        ))

    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    try:
        resp = await safe_fetch(client, 
            f"https://{domain}",
            follow_redirects=True, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        )
        html = resp.text[:200000] if hasattr(resp, 'text') else ""
    except:
        pass

    tasks = [
        scrape_publicwww(domain, client),
        check_builtwith(domain, client),
    ]

    if html:
        tasks.append(analyze_html(html, domain))
        tasks.append(check_inline_exposed_secrets(html, domain))
        tasks.append(check_email_exposure(html, domain))
        tasks.append(check_comment_references(html, domain))
        tasks.append(detect_technology_from_source(html, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    third_party = sum(1 for f in findings if "Third-Party" in f.type or "Integration" in f.type)
    analytics = sum(1 for f in findings if "Analytics" in f.type)
    secrets = sum(1 for f in findings if "Secret" in f.type or "Key" in f.type)
    tech = sum(1 for f in findings if "Technology" in f.type or "Framework" in f.type)

    findings.append(make_finding(
        entity=f"Public Code Search: {third_party} integrations, {analytics} analytics, {secrets} secrets, {tech} tech/framework",
        ftype="PublicWWW Summary",
        source="PublicWWW",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{len(findings)} findings",
        tags=["publicwww", "summary"]
    ))

    return findings
