import httpx
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

EXTENSION_MAP = {
    ".php": "PHP", ".phtml": "PHP", ".php3": "PHP", ".php4": "PHP", ".php5": "PHP", ".php7": "PHP", ".php8": "PHP",
    ".asp": "ASP Classic", ".aspx": "ASP.NET", ".asmx": "ASP.NET", ".ashx": "ASP.NET",
    ".jsp": "Java/JSP", ".jspx": "Java/JSP", ".do": "Java Struts", ".action": "Java Struts",
    ".py": "Python", ".rb": "Ruby", ".cfm": "ColdFusion", ".cfml": "ColdFusion",
    ".shtml": "Server-Side Includes", ".stm": "Server-Side Includes",
    ".pl": "Perl", ".cgi": "CGI/Perl", ".fcgi": "FastCGI",
    ".dhtml": "Dynamic HTML", ".shtm": "Server-Side Includes",
    ".njs": "Node.js (NJS)", ".jws": "Java Web Service",
    ".do": "Java", ".go": "Go (rare for web)",
}

COOKIE_MAP = {
    r"PHPSESSID": "PHP",
    r"ASP\.NET_SessionId": "ASP.NET",
    r"JSESSIONID": "Java/JSP",
    r"JSESSIONIDSSO": "Java/JSP",
    r"CFID|CFTOKEN": "ColdFusion",
    r"connect\.sid": "Node.js/Express",
    r"session": "Generic",
    r".+session": "Generic",
    r"rack\.session": "Ruby/Rack",
    r"_session_id": "Ruby on Rails",
    r"laravel_session": "PHP/Laravel",
    r"symfony": "PHP/Symfony",
    r"wordpress_logged_in": "PHP/WordPress",
    r"wp\-settings": "PHP/WordPress",
    r"drupal": "PHP/Drupal",
    r"joomla": "PHP/Joomla",
    r"magento": "PHP/Magento",
    r"ci_session": "PHP/CodeIgniter",
    r"cake_cookie": "PHP/CakePHP",
}

HEADER_MAP = {
    "x-powered-by": None,
    "x-runtime": "Ruby on Rails",
    "x-rack-cache": "Ruby/Rack",
    "x-rack-session": "Ruby/Rack",
    "x-rails-asset-id": "Ruby on Rails",
    "x-webpack-dev-server": "Node.js/Webpack",
    "x-express": "Node.js/Express",
    "x-nuxt": "Vue.js/Nuxt",
    "x-nextjs": "Next.js",
    "x-remix": "Remix",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-drupal-cache": "PHP/Drupal",
    "x-drupal-dynamic-cache": "PHP/Drupal",
    "x-generator": "CMS Generator",
    "x-varnish": "Varnish Cache",
    "x-cf-worker": "Cloudflare Workers",
}

URL_PATTERNS = {
    r"/wp-(content|includes|admin|json|api)": "PHP/WordPress",
    r"/administrator/": "PHP/Joomla",
    r"/joomla/": "PHP/Joomla",
    r"/sites/default/": "PHP/Drupal",
    r"/sites/all/": "PHP/Drupal",
    r"/magento/": "PHP/Magento",
    r"/skin/frontend/": "PHP/Magento",
    r"/media/wysiwyg/": "PHP/Magento",
    r"/assets/": "Ruby on Rails / Generic",
    r"/rails/": "Ruby on Rails",
    r"/app\.js": "JavaScript",
    r"/service-worker\.js": "JavaScript/PWA",
    r"/webpack": "Node.js/Webpack",
    r"/node_modules": "Node.js",
    r"/api/": "API backend",
    r"/graphql": "GraphQL API",
    r"/swagger": "API Documentation",
    r"/laravel/": "PHP/Laravel",
    r"/vendor/": "PHP Composer",
    r"/cgi-bin/": "CGI",
}

async def detect_language_from_urls(client: httpx.AsyncClient, base_url: str) -> list:
    detections = []
    try:
        resp = await client.get(base_url, timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
        html = resp.text

        found_extensions = set(re.findall(r'\.(php|phtml|php[34578]|asp|aspx|asmx|ashx|jsp|jspx|do|action|py|rb|cfm|cfml|shtml|pl|cgi|fcgi|go)\b', html, re.I))
        for ext in found_extensions:
            lang = EXTENSION_MAP.get(f".{ext.lower()}", "Unknown")
            if lang not in [d[0] for d in detections]:
                detections.append((lang, f"File extension .{ext}"))

        for pattern, lang in URL_PATTERNS.items():
            if re.search(pattern, html, re.I):
                if lang not in [d[0] for d in detections]:
                    detections.append((lang, f"URL pattern: {pattern}"))
    except Exception:
        pass
    return detections

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    all_languages = set()
    detection_sources = {}

    for proto in ["https", "http"]:
        try:
            resp = await client.get(f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            cookies = dict(resp.cookies)
            html = resp.text
            status = resp.status_code

            findings.append(IntelligenceFinding(
                entity=f"Initial fetch: HTTP {status} ({len(resp.content)} bytes)",
                type="Lang: Initial Fetch",
                source="LanguageDetector",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["language", "initial"]
            ))

            for hdr_name, lang in HEADER_MAP.items():
                if hdr_name in headers:
                    hdr_val = headers[hdr_name]
                    detected_lang = lang
                    if hdr_name == "x-powered-by":
                        if "PHP" in hdr_val:
                            detected_lang = "PHP"
                        elif "ASP.NET" in hdr_val:
                            detected_lang = "ASP.NET"
                        elif "Express" in hdr_val:
                            detected_lang = "Node.js/Express"
                        elif "Ruby" in hdr_val:
                            detected_lang = "Ruby"
                        elif "Python" in hdr_val:
                            detected_lang = "Python"
                        elif "Java" in hdr_val:
                            detected_lang = "Java"
                        else:
                            detected_lang = f"X-Powered-By: {hdr_val[:30]}"
                    elif hdr_name == "x-generator":
                        if "Drupal" in hdr_val:
                            detected_lang = "PHP/Drupal"
                        elif "WordPress" in hdr_val:
                            detected_lang = "PHP/WordPress"
                        elif "Joomla" in hdr_val:
                            detected_lang = "PHP/Joomla"
                        else:
                            detected_lang = f"Generator: {hdr_val[:30]}"

                    if detected_lang and detected_lang not in all_languages:
                        all_languages.add(detected_lang)
                        detection_sources[detected_lang] = f"Header: {hdr_name}"
                        findings.append(IntelligenceFinding(
                            entity=f"Language detected via header: {detected_lang} ({hdr_name}: {hdr_val[:60]})",
                            type="Lang: Header Detection",
                            source="LanguageDetector",
                            confidence="High",
                            color="purple",
                            threat_level="Informational",
                            raw_data=f"header={hdr_name}, value={hdr_val[:200]}, lang={detected_lang}",
                            tags=["language", "header", detected_lang.lower().replace("/", "-").replace(" ", "-")]
                        ))

            for cookie_name, cookie_val in cookies.items():
                for pattern, lang in COOKIE_MAP.items():
                    if re.search(pattern, cookie_name, re.I) or re.search(pattern, cookie_val, re.I):
                        if lang not in all_languages and lang != "Generic":
                            all_languages.add(lang)
                            detection_sources[lang] = f"Cookie: {cookie_name}"
                            findings.append(IntelligenceFinding(
                                entity=f"Language detected via cookie: {lang} ({cookie_name})",
                                type="Lang: Cookie Detection",
                                source="LanguageDetector",
                                confidence="High",
                                color="purple",
                                threat_level="Informational",
                                raw_data=f"cookie={cookie_name}, value={cookie_val[:50]}, lang={lang}",
                                tags=["language", "cookie", lang.lower().replace("/", "-").replace(" ", "-")]
                            ))

            ext_detections = await detect_language_from_urls(client, f"{proto}://{domain}")
            for lang, source in ext_detections:
                if lang not in all_languages:
                    all_languages.add(lang)
                    detection_sources[lang] = source
                    findings.append(IntelligenceFinding(
                        entity=f"Language detected via content: {lang} ({source})",
                        type="Lang: Content Detection",
                        source="LanguageDetector",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"lang={lang}, source={source}",
                        tags=["language", "content", lang.lower().replace("/", "-").replace(" ", "-")]
                    ))

            server_header = headers.get("server", "")
            if server_header:
                server_lang_map = {
                    "nginx": "nginx (often PHP/Python proxy)", "apache": "Apache (often PHP)",
                    "iis": "ASP.NET", "caddy": "Go/Caddy", "gunicorn": "Python/Gunicorn",
                    "uwsgi": "Python/uWSGI", "unicorn": "Ruby/Unicorn", "puma": "Ruby/Puma",
                    "passenger": "Ruby/Passenger", "jetty": "Java/Jetty", "tomcat": "Java/Tomcat",
                    "weblogic": "Java/WebLogic", "websphere": "Java/WebSphere",
                }
                for server_sig, lang in server_lang_map.items():
                    if server_sig in server_header.lower():
                        if lang not in all_languages:
                            all_languages.add(lang)
                            detection_sources[lang] = f"Server header: {server_header}"
                            findings.append(IntelligenceFinding(
                                entity=f"Language inferred from Server header: {lang} ({server_header})",
                                type="Lang: Server Inference",
                                source="LanguageDetector",
                                confidence="Medium",
                                color="purple",
                                threat_level="Informational",
                                raw_data=f"server={server_header}, inferred_lang={lang}",
                                tags=["language", "server", lang.lower().replace("/", "-").replace(" ", "-")]
                            ))

            break
        except Exception:
            continue

    if not all_languages:
        findings.append(IntelligenceFinding(
            entity=f"Could not determine programming language for {domain}",
            type="Lang: No Detection",
            source="LanguageDetector",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["language", "unknown"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Detected {len(all_languages)} language(s): {', '.join(all_languages)}",
            type="Lang: Detection Summary",
            source="LanguageDetector",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"languages={', '.join(all_languages)}, sources={detection_sources}",
            tags=["language", "summary"]
        ))

    return findings
