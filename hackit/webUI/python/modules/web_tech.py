import httpx
import ssl
import socket
import asyncio
import re
from osint_common import get_ssl_cert_info, parse_cert_to_dict
from module_common import safe_fetch, make_finding

TECH_SIGNATURES = {
    "X-Powered-By": ("Tech Stack", "orange"),
    "X-Generator": ("CMS Detection", "orange"),
    "X-Drupal-Cache": ("CMS: Drupal", "blue"),
    "X-Drupal-Dynamic-Cache": ("CMS: Drupal", "blue"),
    "X-Generator": ("CMS Detection", "orange"),
    "X-ExpressionEngine": ("CMS: ExpressionEngine", "blue"),
    "X-Drupal-Cache": ("Drupal Cache", "blue"),
    "X-Site-Name": ("Site Name", "slate"),
}

SERVER_SIGNATURES = {
    "nginx": "Web Server: Nginx",
    "apache": "Web Server: Apache",
    "cloudflare": "CDN: Cloudflare",
    "akamai": "CDN: Akamai",
    "iis": "Web Server: IIS",
    "lighttpd": "Web Server: Lighttpd",
    "caddy": "Web Server: Caddy",
    "openresty": "Web Server: OpenResty",
    "gunicorn": "Web Server: Gunicorn",
    "uvicorn": "Web Server: Uvicorn",
    "node": "Tech: Node.js",
    "express": "Tech: Express.js",
    "next.js": "Tech: Next.js",
    "python": "Tech: Python",
    "java": "Tech: Java",
    "tomcat": "Tech: Apache Tomcat",
    "jetty": "Tech: Jetty",
    "netty": "Tech: Netty",
    "gws": "Tech: Google Web Server",
    "gfe": "Tech: Google Front End",
    "kestrel": "Tech: Kestrel (.NET)",
    "cloudfront": "CDN: CloudFront",
    "amazon": "Cloud: AWS",
    "azure": "Cloud: Azure",
    "azurewebsites": "Cloud: Azure App Service",
    "azureedge": "CDN: Azure CDN",
}

HEADER_TECH_PATTERNS = {
    "x-powered-by": [("php", "PHP", "red"), ("asp.net", "ASP.NET", "blue"), ("express", "Express.js", "green"), ("next.js", "Next.js", "slate")],
    "x-generator": [("drupal", "Drupal", "blue"), ("wordpress", "WordPress", "blue"), ("joomla", "Joomla", "blue"), ("wix", "Wix", "purple")],
    "x-drupal-cache": [("hit", "Drupal", "blue"), ("miss", "Drupal", "blue")],
    "x-joomla-cache": [("1", "Joomla", "blue")],
    "x-aspnet-version": [(".*", "ASP.NET", "blue")],
    "x-aspnetmvc-version": [(".*", "ASP.NET MVC", "blue")],
    "x-runtime": [(".*", "Ruby/Rails", "red")],
    "x-powered-by-plesk": [(".*", "Plesk", "orange")],
    "x-silverlight-version": [(".*", "Silverlight", "slate")],
}

HTML_TECH_PATTERNS = {
    "WordPress": {"patterns": [r"wp-content", r"wp-includes", r"wp-json", r"wordpress"], "category": "CMS", "color": "blue"},
    "Joomla": {"patterns": [r"joomla", r"com_content", r"com_modules"], "category": "CMS", "color": "blue"},
    "Drupal": {"patterns": [r"drupal", r"drupalSettings", r"sites/all"], "category": "CMS", "color": "blue"},
    "Magento": {"patterns": [r"magento", r"mage/", r"skin/frontend"], "category": "E-commerce", "color": "purple"},
    "Shopify": {"patterns": [r"shopify", r"myshopify", r"cdn\.shopify\.com"], "category": "E-commerce", "color": "purple"},
    "WooCommerce": {"patterns": [r"woocommerce", r"wc-api", r"woo-variation"], "category": "E-commerce", "color": "purple"},
    "Laravel": {"patterns": [r"laravel", r"csrf-token", r"livewire"], "category": "Framework", "color": "orange"},
    "Django": {"patterns": [r"django", r"csrfmiddlewaretoken", r"__admin__"], "category": "Framework", "color": "orange"},
    "Ruby on Rails": {"patterns": [r"rails", r"turbolinks", r"csrf-param", r"rails-ujs"], "category": "Framework", "color": "orange"},
    "React": {"patterns": [r"react\.js", r"react\.min\.js", r"reactroot", r"__react", r"react-dom"], "category": "JavaScript Framework", "color": "cyan"},
    "Vue.js": {"patterns": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"v-bind", r"v-if", r"v-for"], "category": "JavaScript Framework", "color": "cyan"},
    "Angular": {"patterns": [r"angular\.js", r"angular\.min\.js", r"ng-app", r"ng-version", r"_ngcontent"], "category": "JavaScript Framework", "color": "cyan"},
    "Svelte": {"patterns": [r"svelte", r"__svelte"], "category": "JavaScript Framework", "color": "cyan"},
    "jQuery": {"patterns": [r"jquery", r"jQuery"], "category": "JavaScript Library", "color": "slate"},
    "Bootstrap": {"patterns": [r"bootstrap", r"bootstrap\.min\.css", r"col-md-", r"col-xs-"], "category": "CSS Framework", "color": "purple"},
    "Tailwind CSS": {"patterns": [r"tailwind", r"tailwindcss"], "category": "CSS Framework", "color": "purple"},
    "Google Analytics": {"patterns": [r"google-analytics", r"ga\(", r"gtag"], "category": "Analytics", "color": "slate"},
    "Facebook Pixel": {"patterns": [r"fbq\(", r"facebook.*pixel"], "category": "Analytics", "color": "slate"},
    "Hotjar": {"patterns": [r"hotjar", r"hj\("], "category": "Analytics", "color": "slate"},
    "Mixpanel": {"patterns": [r"mixpanel"], "category": "Analytics", "color": "slate"},
    "Matomo": {"patterns": [r"matomo", r"piwik"], "category": "Analytics", "color": "slate"},
    "Intercom": {"patterns": [r"intercom"], "category": "Live Chat", "color": "green"},
    "Drift": {"patterns": [r"drift"], "category": "Live Chat", "color": "green"},
    "Zendesk": {"patterns": [r"zendesk"], "category": "Live Chat", "color": "green"},
    "Tawk.to": {"patterns": [r"tawk"], "category": "Live Chat", "color": "green"},
    "Stripe": {"patterns": [r"stripe\.com", r"pk_live_", r"sk_live_"], "category": "Payment", "color": "purple"},
    "PayPal": {"patterns": [r"paypal", r"paypalobjects"], "category": "Payment", "color": "purple"},
    "Google Tag Manager": {"patterns": [r"googletagmanager", r"gtm\.js"], "category": "Tag Manager", "color": "slate"},
    "Disqus": {"patterns": [r"disqus"], "category": "Comments", "color": "slate"},
    "Mailchimp": {"patterns": [r"mailchimp"], "category": "Email", "color": "orange"},
    "SendGrid": {"patterns": [r"sendgrid"], "category": "Email", "color": "orange"},
    "AWS": {"patterns": [r"amazonaws", r"aws"], "category": "Cloud", "color": "orange"},
    "Google Cloud": {"patterns": [r"googleapis", r"gstatic"], "category": "Cloud", "color": "orange"},
    "Azure": {"patterns": [r"azure", r"windows\.net"], "category": "Cloud", "color": "orange"},
    "Cloudflare": {"patterns": [r"cloudflare", r"cf-ray"], "category": "CDN", "color": "orange"},
    "Akamai": {"patterns": [r"akamai", r"akamaized"], "category": "CDN", "color": "orange"},
    "Fastly": {"patterns": [r"fastly"], "category": "CDN", "color": "orange"},
    "Recaptcha": {"patterns": [r"recaptcha", r"g-recaptcha"], "category": "Security", "color": "slate"},
    "hCaptcha": {"patterns": [r"hcaptcha"], "category": "Security", "color": "slate"},
    "Google Fonts": {"patterns": [r"fonts\.googleapis", r"fonts\.gstatic"], "category": "Fonts", "color": "slate"},
    "Font Awesome": {"patterns": [r"font-awesome", r"fontawesome", r"fa-"], "category": "Fonts", "color": "slate"},
    "YouTube": {"patterns": [r"youtube\.com"], "category": "Video", "color": "red"},
    "Vimeo": {"patterns": [r"vimeo"], "category": "Video", "color": "slate"},
    "Google Maps": {"patterns": [r"maps\.googleapis", r"maps\.google\.com"], "category": "Maps", "color": "slate"},
    "OpenStreetMap": {"patterns": [r"openstreetmap"], "category": "Maps", "color": "slate"},
    "TinyMCE": {"patterns": [r"tinymce"], "category": "Editor", "color": "slate"},
    "CKEditor": {"patterns": [r"ckeditor"], "category": "Editor", "color": "slate"},
    "Three.js": {"patterns": [r"three\.js"], "category": "3D Graphics", "color": "slate"},
    "D3.js": {"patterns": [r"d3\.js", r"d3\.min\.js"], "category": "Visualization", "color": "slate"},
    "Chart.js": {"patterns": [r"chart\.js", r"chart\.min\.js"], "category": "Visualization", "color": "slate"},
    "Socket.IO": {"patterns": [r"socket\.io"], "category": "Realtime", "color": "slate"},
    "GSAP": {"patterns": [r"gsap", "TweenMax"], "category": "Animation", "color": "slate"},
    "Swiper": {"patterns": [r"swiper"], "category": "Slider", "color": "slate"},
    "Alpine.js": {"patterns": [r"alpine\.js"], "category": "JavaScript Framework", "color": "cyan"},
    "Next.js": {"patterns": [r"__next", r"_next/static", r"next\.js", r"next/static"], "category": "Framework", "color": "orange"},
    "Nuxt.js": {"patterns": [r"__nuxt", r"_nuxt/", r"nuxt\.js"], "category": "Framework", "color": "orange"},
    "Gatsby": {"patterns": [r"gatsby", r"___gatsby"], "category": "Framework", "color": "orange"},
}

VERSION_PATTERNS = {
    "WordPress": [r"(?i)wordpress\s*(\d+\.\d+(?:\.\d+)?)", r"ver=(\d+\.\d+(?:\.\d+)?)"],
    "jQuery": [r"(?i)jquery[.-](\d+\.\d+(?:\.\d+)?)", r"jquery.*v?(\d+\.\d+(?:\.\d+)?)"],
    "Bootstrap": [r"(?i)bootstrap[.-](\d+\.\d+(?:\.\d+)?)", r"bootstrap.*v?(\d+\.\d+(?:\.\d+)?)"],
    "Angular": [r"(?i)angular[.-](\d+\.\d+(?:\.\d+)?)", r"ng-version=\"(\d+\.\d+(?:\.\d+)?)"],
    "React": [r"(?i)react[.-](\d+\.\d+(?:\.\d+)?)"],
    "Vue.js": [r"(?i)vue[.-](\d+\.\d+(?:\.\d+)?)"],
    "Laravel": [r"(?i)laravel[./](\d+\.\d+(?:\.\d+)?)"],
    "Drupal": [r"(?i)drupal[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Magento": [r"(?i)magento[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Shopify": [r"(?i)shopify[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Django": [r"(?i)django[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Next.js": [r"(?i)next[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Nginx": [r"(?i)nginx/(\d+\.\d+(?:\.\d+)?)"],
    "Apache": [r"(?i)apache/(\d+\.\d+(?:\.\d+)?)"],
    "IIS": [r"(?i)iis/(\d+\.\d+)"],
    "Node.js": [r"(?i)node[/.](\d+\.\d+(?:\.\d+)?)"],
    "PHP": [r"(?i)php/(\d+\.\d+(?:\.\d+)?)", r"x-powered-by.*php/(\d+\.\d+(?:\.\d+)?)"],
    "Python": [r"(?i)python/(\d+\.\d+(?:\.\d+)?)"],
    "Ruby": [r"(?i)ruby/(\d+\.\d+(?:\.\d+)?)"],
}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await safe_fetch(client, base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        html = resp.text[:100000] if hasattr(resp, 'text') else ""

        for header_key, (ftype, color) in TECH_SIGNATURES.items():
            val = headers.get(header_key.lower())
            if val:
                findings.append(make_finding(
                    entity=val[:200],
                    ftype=ftype,
                    source="WebTech",
                    confidence="High",
                    color=color,
                    threat_level="Informational",
                    raw_data=f"{header_key}: {val[:500]}"
                ))

        for header_key, patterns in HEADER_TECH_PATTERNS.items():
            val = headers.get(header_key.lower())
            if val:
                val_lower = val.lower()
                for pattern, tech_name, category, tech_color in patterns:
                    if re.search(pattern, val_lower):
                        findings.append(make_finding(
                            entity=tech_name,
                            ftype=f"Tech: {category} (Header)",
                            source="WebTech",
                            confidence="High",
                            color=tech_color,
                            threat_level="Informational",
                            raw_data=f"{header_key}: {val}"
                        ))
                        break

        server = (headers.get("server") or "").lower()
        if server:
            matched = False
            for sig, ftype in SERVER_SIGNATURES.items():
                if sig in server:
                    findings.append(make_finding(
                        entity=headers.get("server", "")[:200],
                        ftype=ftype,
                        source="WebTech",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        raw_data=headers.get("server", "")
                    ))
                    matched = True
                    break
            if not matched:
                findings.append(make_finding(
                    entity=headers.get("server", "")[:200],
                    ftype="Web Server",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

        ct = headers.get("content-type", "")
        if "php" in html.lower() or "php" in ct:
            findings.append(make_finding(
                entity="PHP detected",
                ftype="Tech: PHP",
                source="WebTech",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
            ))

        all_tech_patterns = {**HTML_TECH_PATTERNS, **EXTRA_HTML_TECH_PATTERNS}

        for tech_name, tech_info in all_tech_patterns.items():
            for pattern in tech_info["patterns"]:
                if re.search(pattern, html, re.I):
                    category = tech_info["category"]
                    color = tech_info["color"]

                    version = None
                    if tech_name in VERSION_PATTERNS:
                        for vpat in VERSION_PATTERNS[tech_name]:
                            vm = re.search(vpat, html, re.I)
                            if vm:
                                version = vm.group(1)
                                break

                    entity = tech_name
                    if version:
                        entity += f" v{version}"
                        await _check_eol(tech_name, version, findings)
                    confidence = "High" if version else "Medium"

                    findings.append(make_finding(
                        entity=entity,
                        ftype=f"{category}: {tech_name}",
                        source="WebTech",
                        confidence=confidence,
                        color=color,
                        threat_level="Informational",
                        raw_data=f"Pattern matched: {pattern}" + (f" | Version: {version}" if version else "")
                    ))
                    break

        if "csrf" in html.lower() or "csrf_token" in html.lower():
            findings.append(make_finding(
                entity="CSRF protection detected",
                ftype="Security: CSRF Protection",
                source="WebTech",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
            ))

        csp = headers.get("content-security-policy", "")
        if csp:
            directives = [d.strip() for d in csp.split(";") if d.strip()]
            for d in directives:
                if "unsafe-inline" in d or "unsafe-eval" in d:
                    findings.append(make_finding(
                        entity=f"CSP allows unsafe: {d[:80]}",
                        ftype="CSP Weakness",
                        source="WebTech",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=d[:500]
                    ))

        x_frame = headers.get("x-frame-options", "")
        if x_frame:
            findings.append(make_finding(
                entity=f"X-Frame-Options: {x_frame}",
                ftype="Security: Clickjacking Protection",
                source="WebTech",
                confidence="High",
                color="emerald" if x_frame.lower() in ("deny", "sameorigin") else "orange",
                threat_level="Informational",
            ))

        strict_transport = headers.get("strict-transport-security", "")
        if strict_transport:
            findings.append(make_finding(
                entity="HSTS enabled",
                ftype="Security: HSTS",
                source="WebTech",
                confidence="High",
                color="emerald",
                threat_level="Informational",
            ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"WebTech HTTP error: {str(e)[:100]}",
            ftype="WebTech Error",
            source="WebTech",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))

    try:
        cert_info = await get_ssl_cert_info(target)
        if cert_info and cert_info.get("cert"):
            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)

            if parsed.get("issuer"):
                org = parsed["issuer"].get("organizationName", "Unknown")
                cn = parsed["issuer"].get("commonName", "")
                findings.append(make_finding(
                    entity=f"Issuer: {org} ({cn})" if cn else f"Issuer: {org}",
                    ftype="SSL Certificate Authority",
                    source="WebTech",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Issuer: {parsed['issuer']}"
                ))

            if parsed.get("days_remaining") is not None:
                days = parsed["days_remaining"]
                color = "emerald" if days > 30 else ("orange" if days > 7 else "red")
                risk = "Informational" if days > 30 else ("Elevated Risk" if days > 7 else "High Risk")
                findings.append(make_finding(
                    entity=f"SSL expires in {days} days ({parsed.get('valid_to', '')})",
                    ftype="SSL Expiry",
                    source="WebTech",
                    confidence="High",
                    color=color,
                    threat_level=risk,
                    raw_data=f"Valid until: {parsed.get('valid_to')}"
                ))

            if parsed.get("is_expired"):
                findings.append(make_finding(
                    entity="SSL Certificate has EXPIRED",
                    ftype="SSL Expired",
                    source="WebTech",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Expired at: {parsed.get('valid_to')}",
                    tags=["security"]
                ))

            if parsed.get("subject_alt_names"):
                sans = parsed["subject_alt_names"]
                for san in sans[:10]:
                    findings.append(make_finding(
                        entity=san,
                        ftype="SSL SAN (Subject Alternative Name)",
                        source="WebTech",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                    ))
                if len(sans) > 10:
                    findings.append(make_finding(
                        entity=f"... and {len(sans)-10} more SANs",
                        ftype="SSL SAN Summary",
                        source="WebTech",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                    ))

            protocol = cert_info.get("protocol", "")
            if protocol:
                findings.append(make_finding(
                    entity=protocol,
                    ftype="SSL/TLS Protocol",
                    source="WebTech",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))

            cipher = cert_info.get("cipher")
            if cipher:
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                findings.append(make_finding(
                    entity=cipher_name,
                    ftype="SSL/TLS Cipher",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

    except Exception:
        pass

    return findings

EXTRA_HTML_TECH_PATTERNS = {
    "Hugo": {"patterns": [r"hugo"], "category": "Static Site Generator", "color": "orange"},
    "Jekyll": {"patterns": [r"jekyll"], "category": "Static Site Generator", "color": "orange"},
    "Gatsby": {"patterns": [r"gatsby", r"___gatsby"], "category": "Static Site Generator", "color": "orange"},
    "Next.js": {"patterns": [r"__next", r"_next/static", r"next\.js", "next/static"], "category": "Framework", "color": "orange"},
    "Nuxt.js": {"patterns": [r"__nuxt", r"_nuxt/", r"nuxt\.js"], "category": "Framework", "color": "orange"},
    "Sapper": {"patterns": [r"sapper"], "category": "Framework", "color": "orange"},
    "11ty": {"patterns": [r"11ty", r"eleventy"], "category": "Static Site Generator", "color": "orange"},
    "Hexo": {"patterns": [r"hexo"], "category": "Static Site Generator", "color": "orange"},
    "Ghost": {"patterns": [r"ghost"], "category": "CMS", "color": "blue"},
    "Strapi": {"patterns": [r"strapi"], "category": "Headless CMS", "color": "blue"},
    "Contentful": {"patterns": [r"contentful"], "category": "Headless CMS", "color": "blue"},
    "Sanity": {"patterns": [r"sanity"], "category": "Headless CMS", "color": "blue"},
    "Webflow": {"patterns": [r"webflow"], "category": "CMS", "color": "blue"},
    "Wix": {"patterns": [r"wix", r"_wix", r"wixstatic"], "category": "CMS", "color": "blue"},
    "Squarespace": {"patterns": [r"squarespace"], "category": "CMS", "color": "blue"},
    "Weebly": {"patterns": [r"weebly"], "category": "CMS", "color": "blue"},
    "Umbraco": {"patterns": [r"umbraco"], "category": "CMS", "color": "blue"},
    "Sitecore": {"patterns": [r"sitecore"], "category": "CMS", "color": "blue"},
    "Kentico": {"patterns": [r"kentico"], "category": "CMS", "color": "blue"},
    "OctoberCMS": {"patterns": [r"octobercms", r"october"], "category": "CMS", "color": "blue"},
    "Concrete5": {"patterns": [r"concrete5"], "category": "CMS", "color": "blue"},
    "CraftCMS": {"patterns": [r"craftcms", r"craft"], "category": "CMS", "color": "blue"},
    "PrestaShop": {"patterns": [r"prestashop"], "category": "E-commerce", "color": "purple"},
    "OpenCart": {"patterns": [r"opencart"], "category": "E-commerce", "color": "purple"},
    "BigCommerce": {"patterns": [r"bigcommerce"], "category": "E-commerce", "color": "purple"},
    "WooCommerce": {"patterns": [r"woocommerce", r"wc-api", r"woo-variation"], "category": "E-commerce", "color": "purple"},
    "Magento": {"patterns": [r"magento", r"mage/", "skin/frontend"], "category": "E-commerce", "color": "purple"},
    "Drupal Commerce": {"patterns": [r"drupal.*commerce", r"commerce"], "category": "E-commerce", "color": "purple"},
    "Shopify": {"patterns": [r"shopify", r"myshopify", r"cdn\.shopify\.com"], "category": "E-commerce", "color": "purple"},
    "Ecwid": {"patterns": [r"ecwid"], "category": "E-commerce", "color": "purple"},
    "Squarespace Commerce": {"patterns": [r"squarespace.*commerce"], "category": "E-commerce", "color": "purple"},
    "Symfony": {"patterns": [r"symfony", r"sf_"], "category": "Framework", "color": "orange"},
    "CodeIgniter": {"patterns": [r"codeigniter", r"ci_session"], "category": "Framework", "color": "orange"},
    "CakePHP": {"patterns": [r"cakephp", r"cake."], "category": "Framework", "color": "orange"},
    "Yii": {"patterns": [r"yii"], "category": "Framework", "color": "orange"},
    "Zend Framework": {"patterns": [r"zend"], "category": "Framework", "color": "orange"},
    "Spring": {"patterns": [r"spring"], "category": "Framework", "color": "orange"},
    "Flask": {"patterns": [r"flask"], "category": "Framework", "color": "orange"},
    "FastAPI": {"patterns": [r"fastapi"], "category": "Framework", "color": "orange"},
    "Express": {"patterns": [r"express"], "category": "Framework", "color": "orange"},
    "Koa": {"patterns": [r"koa"], "category": "Framework", "color": "orange"},
    "NestJS": {"patterns": [r"nestjs", r"@nestjs"], "category": "Framework", "color": "orange"},
    "AdonisJS": {"patterns": [r"adonis"], "category": "Framework", "color": "orange"},
    "SvelteKit": {"patterns": [r"sveltekit"], "category": "Framework", "color": "orange"},
    "Remix": {"patterns": [r"remix"], "category": "Framework", "color": "orange"},
    "Astro": {"patterns": [r"astro"], "category": "Static Site Generator", "color": "orange"},
    "LitElement": {"patterns": [r"lit-element", r"lit-html"], "category": "JavaScript Framework", "color": "cyan"},
    "Preact": {"patterns": [r"preact"], "category": "JavaScript Framework", "color": "cyan"},
    "Inferno": {"patterns": [r"inferno"], "category": "JavaScript Framework", "color": "cyan"},
    "Ember.js": {"patterns": [r"ember"], "category": "JavaScript Framework", "color": "cyan"},
    "Backbone.js": {"patterns": [r"backbone"], "category": "JavaScript Library", "color": "slate"},
    "Underscore.js": {"patterns": [r"underscore"], "category": "JavaScript Library", "color": "slate"},
    "Lodash": {"patterns": [r"lodash"], "category": "JavaScript Library", "color": "slate"},
    "Moment.js": {"patterns": [r"moment"], "category": "JavaScript Library", "color": "slate"},
    "Day.js": {"patterns": [r"dayjs"], "category": "JavaScript Library", "color": "slate"},
    "Axios": {"patterns": [r"axios"], "category": "JavaScript Library", "color": "slate"},
    "SuperAgent": {"patterns": [r"superagent"], "category": "JavaScript Library", "color": "slate"},
    "SWR": {"patterns": [r"swr"], "category": "JavaScript Library", "color": "slate"},
    "React Query": {"patterns": [r"react-query"], "category": "JavaScript Library", "color": "slate"},
    "Redux": {"patterns": [r"redux"], "category": "State Management", "color": "slate"},
    "MobX": {"patterns": [r"mobx"], "category": "State Management", "color": "slate"},
    "Zustand": {"patterns": [r"zustand"], "category": "State Management", "color": "slate"},
    "Recoil": {"patterns": [r"recoil"], "category": "State Management", "color": "slate"},
    "Pinia": {"patterns": [r"pinia"], "category": "State Management", "color": "slate"},
    "Vuex": {"patterns": [r"vuex"], "category": "State Management", "color": "slate"},
    "Material UI": {"patterns": [r"mui", r"@mui", r"material-ui"], "category": "CSS Framework", "color": "purple"},
    "Ant Design": {"patterns": [r"antd", r"ant-design"], "category": "CSS Framework", "color": "purple"},
    "Chakra UI": {"patterns": [r"chakra"], "category": "CSS Framework", "color": "purple"},
    "Semantic UI": {"patterns": [r"semantic-ui", r"semantic"], "category": "CSS Framework", "color": "purple"},
    "Bulma": {"patterns": [r"bulma"], "category": "CSS Framework", "color": "purple"},
    "Foundation": {"patterns": [r"foundation"], "category": "CSS Framework", "color": "purple"},
    "PureCSS": {"patterns": [r"purecss", r"pure\.css"], "category": "CSS Framework", "color": "purple"},
    "UIKit": {"patterns": [r"uikit"], "category": "CSS Framework", "color": "purple"},
    "Milligram": {"patterns": [r"milligram"], "category": "CSS Framework", "color": "purple"},
    "Skeleton": {"patterns": [r"skeleton"], "category": "CSS Framework", "color": "purple"},
    "PostCSS": {"patterns": [r"postcss"], "category": "CSS Tool", "color": "purple"},
    "Sass": {"patterns": [r"sass", r"scss"], "category": "CSS Preprocessor", "color": "purple"},
    "Less": {"patterns": [r"less\.css"], "category": "CSS Preprocessor", "color": "purple"},
    "HTMX": {"patterns": [r"htmx"], "category": "JavaScript Library", "color": "slate"},
    "Alpine.js": {"patterns": [r"alpine\.js"], "category": "JavaScript Framework", "color": "cyan"},
    "Turbo": {"patterns": [r"turbo"], "category": "JavaScript Library", "color": "slate"},
    "Stimulus": {"patterns": [r"stimulus"], "category": "JavaScript Framework", "color": "cyan"},
    "FullCalendar": {"patterns": [r"fullcalendar"], "category": "UI Library", "color": "slate"},
    "DataTables": {"patterns": [r"datatables"], "category": "UI Library", "color": "slate"},
    "Select2": {"patterns": [r"select2"], "category": "UI Library", "color": "slate"},
    "Flatpickr": {"patterns": [r"flatpickr"], "category": "UI Library", "color": "slate"},
    "Choices.js": {"patterns": [r"choices\.js"], "category": "UI Library", "color": "slate"},
    "Slick": {"patterns": [r"slick"], "category": "Slider", "color": "slate"},
    "Owl Carousel": {"patterns": [r"owlcarousel", r"owl-carousel"], "category": "Slider", "color": "slate"},
    "FancyBox": {"patterns": [r"fancybox"], "category": "Lightbox", "color": "slate"},
    "Lightbox": {"patterns": [r"lightbox"], "category": "Lightbox", "color": "slate"},
    "Magnific Popup": {"patterns": [r"magnific-popup"], "category": "Lightbox", "color": "slate"},
    "Isotope": {"patterns": [r"isotope"], "category": "Layout", "color": "slate"},
    "Masonry": {"patterns": [r"masonry"], "category": "Layout", "color": "slate"},
    "Parcel": {"patterns": [r"parcel"], "category": "Build Tool", "color": "slate"},
    "Webpack": {"patterns": [r"webpack"], "category": "Build Tool", "color": "slate"},
    "Vite": {"patterns": [r"vite"], "category": "Build Tool", "color": "slate"},
    "ESBuild": {"patterns": [r"esbuild"], "category": "Build Tool", "color": "slate"},
    "Rollup": {"patterns": [r"rollup"], "category": "Build Tool", "color": "slate"},
    "Gulp": {"patterns": [r"gulp"], "category": "Build Tool", "color": "slate"},
    "Grunt": {"patterns": [r"grunt"], "category": "Build Tool", "color": "slate"},
    "Babel": {"patterns": [r"babel"], "category": "Build Tool", "color": "slate"},
    "TypeScript": {"patterns": [r"typescript", r"\.ts\b"], "category": "Language", "color": "blue"},
    "CoffeeScript": {"patterns": [r"coffeescript"], "category": "Language", "color": "blue"},
    "Dart": {"patterns": [r"dart"], "category": "Language", "color": "blue"},
    "Swift": {"patterns": [r"swift"], "category": "Language", "color": "blue"},
    "Kotlin": {"patterns": [r"kotlin"], "category": "Language", "color": "blue"},
    "Rust": {"patterns": [r"rust"], "category": "Language", "color": "blue"},
    "Go": {"patterns": [r"golang"], "category": "Language", "color": "blue"},
    "Elixir": {"patterns": [r"elixir"], "category": "Language", "color": "blue"},
    "Phoenix": {"patterns": [r"phoenix"], "category": "Framework", "color": "orange"},
    "Haskell": {"patterns": [r"haskell"], "category": "Language", "color": "blue"},
    "Scala": {"patterns": [r"scala"], "category": "Language", "color": "blue"},
    "Clojure": {"patterns": [r"clojure"], "category": "Language", "color": "blue"},
    "MariaDB": {"patterns": [r"mariadb"], "category": "Database", "color": "blue"},
    "MySQL": {"patterns": [r"mysql"], "category": "Database", "color": "blue"},
    "PostgreSQL": {"patterns": [r"postgresql", r"pgsql"], "category": "Database", "color": "blue"},
    "MongoDB": {"patterns": [r"mongodb"], "category": "Database", "color": "blue"},
    "Redis": {"patterns": [r"redis"], "category": "Cache", "color": "blue"},
    "Memcached": {"patterns": [r"memcached"], "category": "Cache", "color": "blue"},
    "Elasticsearch": {"patterns": [r"elasticsearch"], "category": "Search", "color": "blue"},
    "Algolia": {"patterns": [r"algolia"], "category": "Search", "color": "blue"},
    "Meilisearch": {"patterns": [r"meilisearch"], "category": "Search", "color": "blue"},
    "Typesense": {"patterns": [r"typesense"], "category": "Search", "color": "blue"},
    "SOLR": {"patterns": [r"solr"], "category": "Search", "color": "blue"},
    "Sphinx": {"patterns": [r"sphinx"], "category": "Search", "color": "blue"},
    "Nginx": {"patterns": [r"nginx"], "category": "Web Server", "color": "orange"},
    "Apache": {"patterns": [r"apache"], "category": "Web Server", "color": "orange"},
    "IIS": {"patterns": [r"iis"], "category": "Web Server", "color": "orange"},
    "Caddy": {"patterns": [r"caddy"], "category": "Web Server", "color": "orange"},
    "Tomcat": {"patterns": [r"tomcat"], "category": "Application Server", "color": "orange"},
    "JBoss": {"patterns": [r"jboss"], "category": "Application Server", "color": "orange"},
    "WildFly": {"patterns": [r"wildfly"], "category": "Application Server", "color": "orange"},
    "GlassFish": {"patterns": [r"glassfish"], "category": "Application Server", "color": "orange"},
    "Jetty": {"patterns": [r"jetty"], "category": "Application Server", "color": "orange"},
    "Payara": {"patterns": [r"payara"], "category": "Application Server", "color": "orange"},
    "WebLogic": {"patterns": [r"weblogic"], "category": "Application Server", "color": "orange"},
    "WebSphere": {"patterns": [r"websphere"], "category": "Application Server", "color": "orange"},
    "Cloudflare": {"patterns": [r"cloudflare", r"cf-ray"], "category": "CDN", "color": "orange"},
    "CloudFront": {"patterns": [r"cloudfront"], "category": "CDN", "color": "orange"},
    "Akamai": {"patterns": [r"akamai", r"akamaized"], "category": "CDN", "color": "orange"},
    "Fastly": {"patterns": [r"fastly"], "category": "CDN", "color": "orange"},
    "Varnish": {"patterns": [r"varnish"], "category": "CDN", "color": "orange"},
    "KeyCDN": {"patterns": [r"keycdn"], "category": "CDN", "color": "orange"},
    "BunnyCDN": {"patterns": [r"bunnycdn", r"\.b-cdn\.net"], "category": "CDN", "color": "orange"},
    "StackPath": {"patterns": [r"stackpath"], "category": "CDN", "color": "orange"},
    "Sucuri": {"patterns": [r"sucuri"], "category": "CDN", "color": "orange"},
    "Incapsula": {"patterns": [r"incapsula"], "category": "CDN", "color": "orange"},
    "Imperva": {"patterns": [r"imperva"], "category": "CDN", "color": "orange"},
    "Azure Front Door": {"patterns": [r"azurefd"], "category": "CDN", "color": "orange"},
    "Google Cloud CDN": {"patterns": [r"gcp-cdn"], "category": "CDN", "color": "orange"},
    "Segment": {"patterns": [r"segment"], "category": "Analytics", "color": "slate"},
    "Amplitude": {"patterns": [r"amplitude"], "category": "Analytics", "color": "slate"},
    "Heap": {"patterns": [r"heap"], "category": "Analytics", "color": "slate"},
    "FullStory": {"patterns": [r"fullstory"], "category": "Analytics", "color": "slate"},
    "CrazyEgg": {"patterns": [r"crazyegg"], "category": "Analytics", "color": "slate"},
    "Mouseflow": {"patterns": [r"mouseflow"], "category": "Analytics", "color": "slate"},
    "Lucky Orange": {"patterns": [r"luckyorange"], "category": "Analytics", "color": "slate"},
    "Clicky": {"patterns": [r"clicky"], "category": "Analytics", "color": "slate"},
    "Piwik PRO": {"patterns": [r"piwik"], "category": "Analytics", "color": "slate"},
    "New Relic": {"patterns": [r"newrelic"], "category": "Monitoring", "color": "slate"},
    "Datadog": {"patterns": [r"datadog"], "category": "Monitoring", "color": "slate"},
    "Sentry": {"patterns": [r"sentry"], "category": "Error Tracking", "color": "red"},
    "Rollbar": {"patterns": [r"rollbar"], "category": "Error Tracking", "color": "red"},
    "Bugsnag": {"patterns": [r"bugsnag"], "category": "Error Tracking", "color": "red"},
    "LogRocket": {"patterns": [r"logrocket"], "category": "Session Replay", "color": "slate"},
    "Hotjar": {"patterns": [r"hotjar"], "category": "Session Replay", "color": "slate"},
    "Clarity": {"patterns": [r"clarity"], "category": "Session Replay", "color": "slate"},
    "PostHog": {"patterns": [r"posthog"], "category": "Product Analytics", "color": "slate"},
    "Mixpanel": {"patterns": [r"mixpanel"], "category": "Product Analytics", "color": "slate"},
    "Stripe": {"patterns": [r"stripe\.com", r"pk_live_", r"sk_live_"], "category": "Payment", "color": "purple"},
    "PayPal": {"patterns": [r"paypal", r"paypalobjects"], "category": "Payment", "color": "purple"},
    "Braintree": {"patterns": [r"braintree"], "category": "Payment", "color": "purple"},
    "Square": {"patterns": [r"square"], "category": "Payment", "color": "purple"},
    "Adyen": {"patterns": [r"adyen"], "category": "Payment", "color": "purple"},
    "Paddle": {"patterns": [r"paddle"], "category": "Payment", "color": "purple"},
    "Lemon Squeezy": {"patterns": [r"lemonsqueezy"], "category": "Payment", "color": "purple"},
    "Gumroad": {"patterns": [r"gumroad"], "category": "Payment", "color": "purple"},
    "Chargebee": {"patterns": [r"chargebee"], "category": "Billing", "color": "purple"},
    "Recurly": {"patterns": [r"recurly"], "category": "Billing", "color": "purple"},
    "Auth0": {"patterns": [r"auth0"], "category": "Authentication", "color": "green"},
    "Firebase Auth": {"patterns": [r"firebase.*auth", r"firebaseapp"], "category": "Authentication", "color": "green"},
    "Clerk": {"patterns": [r"clerk"], "category": "Authentication", "color": "green"},
    "Supabase": {"patterns": [r"supabase"], "category": "Backend", "color": "green"},
    "PocketBase": {"patterns": [r"pocketbase"], "category": "Backend", "color": "green"},
    "Appwrite": {"patterns": [r"appwrite"], "category": "Backend", "color": "green"},
    "Firebase": {"patterns": [r"firebase"], "category": "Backend", "color": "green"},
    "Hasura": {"patterns": [r"hasura"], "category": "GraphQL", "color": "purple"},
    "Apollo": {"patterns": [r"apollo"], "category": "GraphQL", "color": "purple"},
    "GraphQL Yoga": {"patterns": [r"graphql-yoga"], "category": "GraphQL", "color": "purple"},
    "Relay": {"patterns": [r"relay"], "category": "GraphQL", "color": "purple"},
    "Urql": {"patterns": [r"urql"], "category": "GraphQL", "color": "purple"},
    "Open Graph": {"patterns": [r"og:", r"og:title", r"og:description"], "category": "SEO", "color": "slate"},
    "Twitter Cards": {"patterns": [r"twitter:card", r"twitter:site"], "category": "SEO", "color": "slate"},
    "JSON-LD": {"patterns": [r"application/ld+json"], "category": "SEO", "color": "slate"},
    "Schema.org": {"patterns": [r"schema\.org"], "category": "SEO", "color": "slate"},
    "Yoast SEO": {"patterns": [r"yoast"], "category": "SEO", "color": "slate"},
    "Rank Math": {"patterns": [r"rank.math"], "category": "SEO", "color": "slate"},
    "All in One SEO": {"patterns": [r"all_in_one_seo"], "category": "SEO", "color": "slate"},
    "Cookiebot": {"patterns": [r"cookiebot"], "category": "Consent", "color": "slate"},
    "OneTrust": {"patterns": [r"onetrust"], "category": "Consent", "color": "slate"},
    "CookieYes": {"patterns": [r"cookieyes"], "category": "Consent", "color": "slate"},
    "Quantcast": {"patterns": [r"quantcast"], "category": "Consent", "color": "slate"},
    "Cloudflare Turnstile": {"patterns": [r"turnstile"], "category": "Security", "color": "slate"},
    "reCAPTCHA": {"patterns": [r"recaptcha", r"g-recaptcha"], "category": "Security", "color": "slate"},
    "hCaptcha": {"patterns": [r"hcaptcha"], "category": "Security", "color": "slate"},
    "Arkose Labs": {"patterns": [r"arkose"], "category": "Security", "color": "slate"},
    "FingerprintJS": {"patterns": [r"fingerprint"], "category": "Security", "color": "slate"},
    "Pusher": {"patterns": [r"pusher"], "category": "Realtime", "color": "slate"},
    "Ably": {"patterns": [r"ably"], "category": "Realtime", "color": "slate"},
    "Socket.IO": {"patterns": [r"socket\.io"], "category": "Realtime", "color": "slate"},
    "WebSocket": {"patterns": [r"websocket"], "category": "Realtime", "color": "slate"},
    "Twilio": {"patterns": [r"twilio"], "category": "Communications", "color": "slate"},
    "SendGrid": {"patterns": [r"sendgrid"], "category": "Email", "color": "orange"},
    "Mailgun": {"patterns": [r"mailgun"], "category": "Email", "color": "orange"},
    "Mailchimp": {"patterns": [r"mailchimp"], "category": "Email", "color": "orange"},
    "Postmark": {"patterns": [r"postmark"], "category": "Email", "color": "orange"},
    "SendInBlue": {"patterns": [r"sendinblue"], "category": "Email", "color": "orange"},
    "Mailjet": {"patterns": [r"mailjet"], "category": "Email", "color": "orange"},
    "Amazon SES": {"patterns": [r"amazon.*ses"], "category": "Email", "color": "orange"},
    "Mapbox": {"patterns": [r"mapbox"], "category": "Maps", "color": "slate"},
    "Leaflet": {"patterns": [r"leaflet"], "category": "Maps", "color": "slate"},
    "Google Maps": {"patterns": [r"maps\.googleapis", r"maps\.google\.com"], "category": "Maps", "color": "slate"},
    "MapQuest": {"patterns": [r"mapquest"], "category": "Maps", "color": "slate"},
    "Here Maps": {"patterns": [r"here\.com"], "category": "Maps", "color": "slate"},
    "Vimeo": {"patterns": [r"vimeo"], "category": "Video", "color": "slate"},
    "YouTube": {"patterns": [r"youtube\.com"], "category": "Video", "color": "red"},
    "Wistia": {"patterns": [r"wistia"], "category": "Video", "color": "slate"},
    "Brightcove": {"patterns": [r"brightcove"], "category": "Video", "color": "slate"},
    "JW Player": {"patterns": [r"jwplayer"], "category": "Video", "color": "slate"},
    "Video.js": {"patterns": [r"videojs", r"video\.js"], "category": "Video", "color": "slate"},
    "SoundCloud": {"patterns": [r"soundcloud"], "category": "Audio", "color": "slate"},
    "Spotify": {"patterns": [r"spotify"], "category": "Audio", "color": "slate"},
    "Calendly": {"patterns": [r"calendly"], "category": "Scheduling", "color": "slate"},
    "Cal.com": {"patterns": [r"cal\.com"], "category": "Scheduling", "color": "slate"},
    "Acuity": {"patterns": [r"acuity"], "category": "Scheduling", "color": "slate"},
    "Bookly": {"patterns": [r"bookly"], "category": "Scheduling", "color": "slate"},
    "Typeform": {"patterns": [r"typeform"], "category": "Forms", "color": "slate"},
    "JotForm": {"patterns": [r"jotform"], "category": "Forms", "color": "slate"},
    "Gravity Forms": {"patterns": [r"gravityforms"], "category": "Forms", "color": "slate"},
    "Contact Form 7": {"patterns": [r"contact-form-7"], "category": "Forms", "color": "slate"},
    "WPForms": {"patterns": [r"wpforms"], "category": "Forms", "color": "slate"},
    "Elementor": {"patterns": [r"elementor"], "category": "Page Builder", "color": "purple"},
    "Divi": {"patterns": [r"divi"], "category": "Page Builder", "color": "purple"},
    "Beaver Builder": {"patterns": [r"beaver"], "category": "Page Builder", "color": "purple"},
    "WPBakery": {"patterns": [r"wpbakery"], "category": "Page Builder", "color": "purple"},
    "Brizy": {"patterns": [r"brizy"], "category": "Page Builder", "color": "purple"},
    "Oxygen": {"patterns": [r"oxygen"], "category": "Page Builder", "color": "purple"},
    "Avada": {"patterns": [r"avada"], "category": "Theme", "color": "purple"},
    "Genesis": {"patterns": [r"genesis"], "category": "Theme Framework", "color": "purple"},
    "Thesis": {"patterns": [r"thesis"], "category": "Theme Framework", "color": "purple"},
    "AMP": {"patterns": [r"amp"], "category": "Mobile", "color": "slate"},
    "Prismic": {"patterns": [r"prismic"], "category": "Headless CMS", "color": "blue"},
    "DatoCMS": {"patterns": [r"datocms"], "category": "Headless CMS", "color": "blue"},
    "Storyblok": {"patterns": [r"storyblok"], "category": "Headless CMS", "color": "blue"},
    "Cloudinary": {"patterns": [r"cloudinary"], "category": "Media", "color": "slate"},
    "Imgix": {"patterns": [r"imgix"], "category": "Media", "color": "slate"},
    "ImageKit": {"patterns": [r"imagekit"], "category": "Media", "color": "slate"},
    "Cloudflare Images": {"patterns": [r"cf\.images"], "category": "Media", "color": "slate"},
    "Terraform": {"patterns": [r"terraform"], "category": "Infrastructure", "color": "slate"},
    "Docker": {"patterns": [r"docker"], "category": "Container", "color": "blue"},
    "Kubernetes": {"patterns": [r"kubernetes", r"k8s"], "category": "Container", "color": "blue"},
    "Podman": {"patterns": [r"podman"], "category": "Container", "color": "blue"},
    "Helm": {"patterns": [r"helm"], "category": "Container", "color": "blue"},
    "Vagrant": {"patterns": [r"vagrant"], "category": "Infrastructure", "color": "slate"},
    "Ansible": {"patterns": [r"ansible"], "category": "Infrastructure", "color": "slate"},
    "Puppet": {"patterns": [r"puppet"], "category": "Infrastructure", "color": "slate"},
    "Chef": {"patterns": [r"chef"], "category": "Infrastructure", "color": "slate"},
    "SaltStack": {"patterns": [r"salt"], "category": "Infrastructure", "color": "slate"},
    "Terraform Cloud": {"patterns": [r"terraform.*cloud"], "category": "Infrastructure", "color": "slate"},
    "Pulumi": {"patterns": [r"pulumi"], "category": "Infrastructure", "color": "slate"},
    "Serverless": {"patterns": [r"serverless"], "category": "Infrastructure", "color": "slate"},
    "Temporal": {"patterns": [r"temporal"], "category": "Workflow", "color": "slate"},
    "Airflow": {"patterns": [r"airflow"], "category": "Workflow", "color": "slate"},
    "n8n": {"patterns": [r"n8n"], "category": "Workflow", "color": "slate"},
    "Zapier": {"patterns": [r"zapier"], "category": "Integration", "color": "slate"},
    "Make": {"patterns": [r"make\.com"], "category": "Integration", "color": "slate"},
    "IFTTT": {"patterns": [r"ifttt"], "category": "Integration", "color": "slate"},
    "Webhook": {"patterns": [r"webhook"], "category": "Integration", "color": "slate"},
}

EOL_VERSIONS = {
    "WordPress": {"pattern": r"(?i)wordpress\s*(\d+\.\d+)", "eol": {"4": "2022-11-30", "5": "2024-01-16"}},
    "jQuery": {"pattern": r"(?i)jquery[.-](\d+)\.(\d+)", "eol": {"1": "2022-07-01", "2": "2022-07-01"}},
    "Bootstrap": {"pattern": r"(?i)bootstrap[.-](\d+)\.(\d+)", "eol": {"3": "2024-07-01", "4": "2026-01-01"}},
    "Angular": {"pattern": r"(?i)angular[.-](\d+)\.(\d+)", "eol": {"1": "2022-01-01", "2": "2022-01-01", "4": "2022-12-31", "5": "2022-12-31", "6": "2023-12-31", "7": "2024-12-31", "8": "2024-12-31", "9": "2024-12-31", "10": "2024-12-31", "11": "2024-12-31", "12": "2024-12-31"}},
    "PHP": {"pattern": r"(?i)php/(\d+\.\d+)", "eol": {"5.6": "2018-12-31", "7.0": "2019-01-01", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26"}},
    "Python": {"pattern": r"(?i)python/(\d+\.\d+)", "eol": {"2.7": "2020-01-01", "3.5": "2020-09-13", "3.6": "2021-12-23", "3.7": "2023-06-27"}},
    "Node.js": {"pattern": r"(?i)node[/.](\d+)\.", "eol": {"10": "2021-04-30", "12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11", "18": "2025-04-30"}},
    "Magento": {"pattern": r"(?i)magento[.-]?(\d+)\.(\d+)", "eol": {"1": "2020-06-30", "2.0": "2020-06-30", "2.1": "2022-12-31", "2.2": "2023-12-31"}},
    "Drupal": {"pattern": r"(?i)drupal[.-]?(\d+)\.", "eol": {"6": "2016-02-24", "7": "2025-01-05", "8": "2021-11-17"}},
}

EOL_WARNINGS = {k: v["eol"] for k, v in EOL_VERSIONS.items()}

async def _check_eol(tech_name: str, version: str, findings: list):
    try:
        if tech_name not in EOL_VERSIONS:
            return
        eol_map = EOL_VERSIONS[tech_name]["eol"]
        for ver_range, eol_date in eol_map.items():
            if version.startswith(ver_range):
                from datetime import datetime
                eol_dt = datetime.strptime(eol_date, "%Y-%m-%d")
                if eol_dt < datetime.now():
                    findings.append(make_finding(
                        entity=f"{tech_name} {version} reached EOL on {eol_date}",
                        ftype="End of Life Software",
                        source="WebTech",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        tags=["security", "eol", tech_name.lower().replace(" ", "_")],
                    ))
    except Exception:
        pass
