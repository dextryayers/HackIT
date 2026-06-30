import httpx
import ssl
import socket
import asyncio
import re
from models import IntelligenceFinding
from osint_common import get_ssl_cert_info, parse_cert_to_dict

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
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        html = resp.text[:100000] if hasattr(resp, 'text') else ""

        for header_key, (ftype, color) in TECH_SIGNATURES.items():
            val = headers.get(header_key.lower())
            if val:
                findings.append(IntelligenceFinding(
                    entity=val[:200],
                    type=ftype,
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
                        findings.append(IntelligenceFinding(
                            entity=tech_name,
                            type=f"Tech: {category} (Header)",
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
                    findings.append(IntelligenceFinding(
                        entity=headers.get("server", "")[:200],
                        type=ftype,
                        source="WebTech",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        raw_data=headers.get("server", "")
                    ))
                    matched = True
                    break
            if not matched:
                findings.append(IntelligenceFinding(
                    entity=headers.get("server", "")[:200],
                    type="Web Server",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

        ct = headers.get("content-type", "")
        if "php" in html.lower() or "php" in ct:
            findings.append(IntelligenceFinding(
                entity="PHP detected",
                type="Tech: PHP",
                source="WebTech",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
            ))

        for tech_name, tech_info in HTML_TECH_PATTERNS.items():
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
                    confidence = "High" if version else "Medium"

                    findings.append(IntelligenceFinding(
                        entity=entity,
                        type=f"{category}: {tech_name}",
                        source="WebTech",
                        confidence=confidence,
                        color=color,
                        threat_level="Informational",
                        raw_data=f"Pattern matched: {pattern}" + (f" | Version: {version}" if version else "")
                    ))
                    break

        if "csrf" in html.lower() or "csrf_token" in html.lower():
            findings.append(IntelligenceFinding(
                entity="CSRF protection detected",
                type="Security: CSRF Protection",
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
                    findings.append(IntelligenceFinding(
                        entity=f"CSP allows unsafe: {d[:80]}",
                        type="CSP Weakness",
                        source="WebTech",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=d[:500]
                    ))

        x_frame = headers.get("x-frame-options", "")
        if x_frame:
            findings.append(IntelligenceFinding(
                entity=f"X-Frame-Options: {x_frame}",
                type="Security: Clickjacking Protection",
                source="WebTech",
                confidence="High",
                color="emerald" if x_frame.lower() in ("deny", "sameorigin") else "orange",
                threat_level="Informational",
            ))

        strict_transport = headers.get("strict-transport-security", "")
        if strict_transport:
            findings.append(IntelligenceFinding(
                entity="HSTS enabled",
                type="Security: HSTS",
                source="WebTech",
                confidence="High",
                color="emerald",
                threat_level="Informational",
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"WebTech HTTP error: {str(e)[:100]}",
            type="WebTech Error",
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
                findings.append(IntelligenceFinding(
                    entity=f"Issuer: {org} ({cn})" if cn else f"Issuer: {org}",
                    type="SSL Certificate Authority",
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
                findings.append(IntelligenceFinding(
                    entity=f"SSL expires in {days} days ({parsed.get('valid_to', '')})",
                    type="SSL Expiry",
                    source="WebTech",
                    confidence="High",
                    color=color,
                    threat_level=risk,
                    raw_data=f"Valid until: {parsed.get('valid_to')}"
                ))

            if parsed.get("is_expired"):
                findings.append(IntelligenceFinding(
                    entity="SSL Certificate has EXPIRED",
                    type="SSL Expired",
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
                    findings.append(IntelligenceFinding(
                        entity=san,
                        type="SSL SAN (Subject Alternative Name)",
                        source="WebTech",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                    ))
                if len(sans) > 10:
                    findings.append(IntelligenceFinding(
                        entity=f"... and {len(sans)-10} more SANs",
                        type="SSL SAN Summary",
                        source="WebTech",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                    ))

            protocol = cert_info.get("protocol", "")
            if protocol:
                findings.append(IntelligenceFinding(
                    entity=protocol,
                    type="SSL/TLS Protocol",
                    source="WebTech",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))

            cipher = cert_info.get("cipher")
            if cipher:
                cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                findings.append(IntelligenceFinding(
                    entity=cipher_name,
                    type="SSL/TLS Cipher",
                    source="WebTech",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                ))

    except Exception:
        pass

    return findings
