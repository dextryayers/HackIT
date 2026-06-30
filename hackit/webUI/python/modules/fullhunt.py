import httpx
import asyncio
import socket
import ssl
import json
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

FULLHUNT_BASE = "https://fullhunt.io"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

TECH_STACK_INDICATORS = {
    "cloudflare": "CDN: Cloudflare", "akamai": "CDN: Akamai", "fastly": "CDN: Fastly",
    "cloudfront": "CDN: AWS CloudFront", "incapsula": "CDN: Imperva",
    "nginx": "Web Server: Nginx", "apache": "Web Server: Apache",
    "iis": "Web Server: IIS", "lighttpd": "Web Server: Lighttpd",
    "openresty": "Web Server: OpenResty", "gunicorn": "Web Server: Gunicorn",
    "caddy": "Web Server: Caddy", "tomcat": "Tech: Tomcat",
    "jetty": "Tech: Jetty", "netty": "Tech: Netty",
    "node": "Tech: Node.js", "express": "Framework: Express.js",
    "next.js": "Framework: Next.js", "python": "Tech: Python",
    "django": "Framework: Django", "flask": "Framework: Flask",
    "fastapi": "Framework: FastAPI", "java": "Tech: Java",
    "spring": "Framework: Spring", "php": "Tech: PHP",
    "laravel": "Framework: Laravel", "wordpress": "CMS: WordPress",
    "drupal": "CMS: Drupal", "joomla": "CMS: Joomla", "magento": "CMS: Magento",
    "shopify": "E-Commerce: Shopify", "ruby": "Tech: Ruby",
    "rails": "Framework: Ruby on Rails", "go": "Tech: Golang",
    "rust": "Tech: Rust", "elixir": "Tech: Elixir",
    "react": "JS: React", "vue": "JS: Vue.js", "angular": "JS: Angular",
    "jquery": "JS: jQuery", "bootstrap": "CSS: Bootstrap",
    "tailwind": "CSS: Tailwind", "sass": "CSS: SASS/SCSS",
    "redis": "Cache: Redis", "memcached": "Cache: Memcached",
    "varnish": "Cache: Varnish", "haproxy": "LB: HAProxy",
    "mysql": "DB: MySQL", "postgresql": "DB: PostgreSQL",
    "mongodb": "DB: MongoDB", "mariadb": "DB: MariaDB",
    "elasticsearch": "DB: Elasticsearch", "cassandra": "DB: Cassandra",
    "graphql": "API: GraphQL", "rest": "API: REST",
    "swagger": "API: Swagger/OpenAPI",
    "google-analytics": "Analytics: Google Analytics",
    "gtm": "Analytics: Google Tag Manager",
    "facebook": "Analytics: Facebook", "hotjar": "Analytics: Hotjar",
    "segment": "Analytics: Segment", "amplitude": "Analytics: Amplitude",
    "mixpanel": "Analytics: Mixpanel", "intercom": "Widget: Intercom",
    "drift": "Widget: Drift", "hubspot": "Widget: HubSpot",
    "zendesk": "Widget: Zendesk", "crisp": "Widget: Crisp",
    "tawk": "Widget: Tawk.to", "livechat": "Widget: LiveChat",
    "stripe": "Payment: Stripe", "paypal": "Payment: PayPal",
    "braintree": "Payment: Braintree", "square": "Payment: Square",
    "auth0": "Auth: Auth0", "okta": "Auth: Okta", "firebase": "Auth: Firebase",
    "sentry": "Monitoring: Sentry", "datadog": "Monitoring: Datadog",
    "newrelic": "Monitoring: New Relic", "dynatrace": "Monitoring: Dynatrace",
    "hotjar": "Monitoring: Hotjar", "luckyorange": "Monitoring: LuckyOrange",
    "fullstory": "Monitoring: FullStory", "heap": "Monitoring: Heap",
    "azure": "Cloud: Azure", "aws": "Cloud: AWS", "gcp": "Cloud: GCP",
    "digitalocean": "Cloud: DigitalOcean", "heroku": "Cloud: Heroku",
}

ADDITIONAL_HTTP_HEADERS = [
    "x-frame-options", "x-xss-protection", "x-content-type-options",
    "strict-transport-security", "content-security-policy",
    "referrer-policy", "permissions-policy", "x-robots-tag",
]

async def resolve_ip(hostname: str) -> list:
    try:
        loop = asyncio.get_event_loop()
        addrinfo = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM))
        return list(set(a[4][0] for a in addrinfo[:5]))
    except:
        return []

async def resolve_ipv6(hostname: str) -> list:
    try:
        loop = asyncio.get_event_loop()
        addrinfo = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, 80, socket.AF_INET6, socket.SOCK_STREAM))
        return list(set(a[4][0] for a in addrinfo[:5]))
    except:
        return []

async def check_http_service(hostname: str, client: httpx.AsyncClient) -> dict:
    result = {}
    for scheme in ["https", "http"]:
        try:
            resp = await client.get(f"{scheme}://{hostname}", timeout=10.0, follow_redirects=True,
                                    headers={"User-Agent": UA})
            result[f"{scheme}_status"] = resp.status_code
            result[f"{scheme}_headers"] = dict(resp.headers)
            result[f"{scheme}_html"] = resp.text[:5000]
            result[f"{scheme}_history"] = [str(r.url) for r in resp.history]
            return result
        except:
            continue
    return result

async def get_ssl_info(hostname: str) -> dict:
    result = {}
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(8)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                result["issuer"] = dict(cert.get("issuer", []))
                result["subject"] = dict(cert.get("subject", []))
                result["sans"] = [v for _, v in cert.get("subjectAltName", [])]
                result["cipher"] = s.cipher()
                result["protocol"] = s.version()
                s.close()
                return result
            except:
                return {}
        return await loop.run_in_executor(None, fetch)
    except:
        return {}

async def probe_subdomain_http(subdomain: str, client: httpx.AsyncClient) -> dict:
    result = {"alive": False, "status": None, "title": "", "server": "", "tech": []}
    try:
        resp = await client.get(f"https://{subdomain}", timeout=8.0, follow_redirects=True,
                                headers={"User-Agent": UA})
        result["alive"] = True
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("server", "")
        result["content_type"] = resp.headers.get("content-type", "")
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.IGNORECASE)
        if title_match:
            result["title"] = title_match.group(1).strip()
        body_lower = resp.text.lower()
        for sig, tech_label in TECH_STACK_INDICATORS.items():
            if sig in body_lower:
                result["tech"].append(tech_label)
        for hdr in ["x-powered-by", "x-aspnet-version", "x-generator"]:
            val = resp.headers.get(hdr, "")
            if val:
                result["tech"].append(f"Header:{hdr}={val}")
    except:
        try:
            resp = await client.get(f"http://{subdomain}", timeout=8.0, follow_redirects=True,
                                    headers={"User-Agent": UA})
            result["alive"] = True
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("server", "")
        except:
            pass
    return result

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    api_endpoints = [
        {
            "url": f"{FULLHUNT_BASE}/api/v1/domain/{domain}/subdomains",
            "type": "Subdomains",
            "key_field": "subdomains",
            "alt_keys": ["hosts", "domains"],
        },
        {
            "url": f"{FULLHUNT_BASE}/api/v1/domain/{domain}/tech",
            "type": "Technologies",
            "key_field": "tech",
            "alt_keys": ["technologies", "stacks"],
        },
        {
            "url": f"{FULLHUNT_BASE}/api/v1/domain/{domain}/dns",
            "type": "DNS Records",
            "key_field": "dns",
            "alt_keys": ["records", "dns_records"],
        },
        {
            "url": f"{FULLHUNT_BASE}/api/v1/domain/{domain}/whois",
            "type": "WHOIS",
            "key_field": "whois",
            "alt_keys": ["whois_data", "data"],
        },
        {
            "url": f"{FULLHUNT_BASE}/api/v1/domain/{domain}/ips",
            "type": "IPs",
            "key_field": "ips",
            "alt_keys": ["ip_addresses", "addresses"],
        },
    ]

    api_data = {}
    for ep in api_endpoints:
        try:
            resp = await client.get(ep["url"], timeout=15.0,
                                    headers={"User-Agent": UA, "Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                items = data.get(ep["key_field"], [])
                if not items:
                    for alt in ep["alt_keys"]:
                        items = data.get(alt, [])
                        if items:
                            break
                api_data[ep["type"]] = items
        except:
            continue

    subdomains_found = set()
    for item in api_data.get("Subdomains", []):
        if isinstance(item, str):
            subdomains_found.add(item.lower())
        elif isinstance(item, dict):
            name = item.get("hostname", item.get("domain", item.get("name", "")))
            if name:
                subdomains_found.add(name.lower())

    if subdomains_found:
        findings.append(IntelligenceFinding(
            entity=f"{len(subdomains_found)} subdomains found via FullHunt API",
            type="FullHunt: Subdomain Discovery",
            source="FullHunt",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status=f"{len(subdomains_found)} subdomains",
            resolution=domain,
            tags=["fullhunt", "subdomains", "discovery"]
        ))

    for sub in sorted(subdomains_found)[:30]:
        ips = await resolve_ip(sub)
        ipv6s = await resolve_ipv6(sub)
        ip_str = f" [{', '.join(ips[:3])}]" if ips else ""
        findings.append(IntelligenceFinding(
            entity=f"{sub}{ip_str}",
            type="FullHunt: Subdomain",
            source="FullHunt",
            confidence="High" if ips else "Medium",
            color="emerald",
            threat_level="Informational",
            status="Resolved" if ips else "Unresolved",
            resolution=f"IPs: {', '.join(ips[:3])}" if ips else "DNS resolution failed",
            tags=["fullhunt", "subdomain"]
        ))

        if ips:
            for ip in ips[:2]:
                findings.append(IntelligenceFinding(
                    entity=f"{sub} -> {ip}",
                    type="FullHunt: Subdomain Resolution",
                    source="FullHunt",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Resolved",
                    resolution=ip,
                    raw_data=f"A record: {sub} = {ip}",
                    tags=["fullhunt", "dns", "a-record"]
                ))

        probe_result = await probe_subdomain_http(sub, client)
        if probe_result["alive"]:
            status_color = "emerald" if probe_result["status"] and probe_result["status"] < 400 else "red"
            findings.append(IntelligenceFinding(
                entity=f"HTTP Probe: {sub} (Status: {probe_result['status']})",
                type="FullHunt: Subdomain HTTP Probe",
                source="FullHunt",
                confidence="High",
                color=status_color,
                threat_level="Informational" if probe_result["status"] and probe_result["status"] < 400 else "Elevated Risk",
                status=f"HTTP {probe_result['status']}",
                resolution=sub,
                raw_data=f"Title: {probe_result.get('title', 'N/A')}, Server: {probe_result.get('server', 'N/A')}",
                tags=["fullhunt", "http-probe"]
            ))
            if probe_result.get("title"):
                findings.append(IntelligenceFinding(
                    entity=f"Page Title: {probe_result['title'][:200]}",
                    type="FullHunt: HTTP Probe Title",
                    source="FullHunt",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=sub,
                    tags=["fullhunt", "http-probe", "title"]
                ))
            if probe_result.get("tech"):
                for tech in probe_result["tech"][:5]:
                    findings.append(IntelligenceFinding(
                        entity=tech,
                        type="FullHunt: HTTP Probe Tech",
                        source="FullHunt",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        resolution=sub,
                        tags=["fullhunt", "http-probe", "technology"]
                    ))

    for tech_entry in api_data.get("Technologies", [])[:20]:
        if isinstance(tech_entry, str):
            findings.append(IntelligenceFinding(
                entity=tech_entry, type="FullHunt: Technology", source="FullHunt",
                confidence="Medium", color="orange", threat_level="Informational",
                status="Detected", tags=["fullhunt", "technology"]
            ))
            for key, tech_label in TECH_STACK_INDICATORS.items():
                if key in tech_entry.lower():
                    findings.append(IntelligenceFinding(
                        entity=tech_label, type="FullHunt: Tech Stack", source="FullHunt",
                        confidence="Medium", color="purple", threat_level="Informational",
                        status="Categorized", tags=["fullhunt", "technology"]
                    ))
        elif isinstance(tech_entry, dict):
            name = tech_entry.get("name", tech_entry.get("tech", ""))
            if name:
                findings.append(IntelligenceFinding(
                    entity=name, type="FullHunt: Technology", source="FullHunt",
                    confidence="Medium", color="orange", threat_level="Informational",
                    status="Detected", tags=["fullhunt", "technology"]
                ))
                version = tech_entry.get("version", "")
                if version:
                    findings.append(IntelligenceFinding(
                        entity=f"{name} v{version}", type="FullHunt: Tech Version",
                        source="FullHunt", confidence="Medium", color="slate",
                        threat_level="Informational", status="Versioned",
                        tags=["fullhunt", "technology"]
                    ))
                category = tech_entry.get("category", "")
                if category:
                    findings.append(IntelligenceFinding(
                        entity=f"{name} -> Category: {category}",
                        type="FullHunt: Tech Category",
                        source="FullHunt", confidence="Medium", color="slate",
                        threat_level="Informational", tags=["fullhunt", "technology"]
                    ))

    dns_items = api_data.get("DNS Records", [])
    if isinstance(dns_items, list):
        dns_type_count = {}
        for dns_entry in dns_items[:20]:
            if isinstance(dns_entry, dict):
                rtype = dns_entry.get("type", "Record")
                value = dns_entry.get("value", dns_entry.get("data", str(dns_entry)))
                dns_type_count[rtype] = dns_type_count.get(rtype, 0) + 1
                findings.append(IntelligenceFinding(
                    entity=str(value)[:200], type=f"FullHunt: DNS {rtype}",
                    source="FullHunt", confidence="High", color="blue",
                    threat_level="Informational", status="DNS Record",
                    tags=["fullhunt", "dns"]
                ))
        if dns_type_count:
            findings.append(IntelligenceFinding(
                entity=f"DNS Summary: {', '.join(f'{k}: {v}' for k, v in dns_type_count.items())}",
                type="FullHunt: DNS Summary",
                source="FullHunt",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["fullhunt", "dns", "summary"]
            ))

    whois_data = api_data.get("WHOIS", [])
    if whois_data:
        findings.append(IntelligenceFinding(
            entity=f"WHOIS data retrieved via FullHunt API",
            type="FullHunt: WHOIS",
            source="FullHunt",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Retrieved",
            raw_data=str(whois_data)[:1000],
            tags=["fullhunt", "whois"]
        ))

    ips_data = api_data.get("IPs", [])
    if ips_data:
        for ip_entry in ips_data[:10]:
            if isinstance(ip_entry, str):
                findings.append(IntelligenceFinding(
                    entity=ip_entry,
                    type="FullHunt: Associated IP",
                    source="FullHunt",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    status="IP Found",
                    tags=["fullhunt", "ip"]
                ))

    http_info = await check_http_service(domain, client)
    if http_info.get("https_status"):
        findings.append(IntelligenceFinding(
            entity=f"HTTPS {http_info['https_status']}",
            type="FullHunt: HTTP Service",
            source="FullHunt",
            confidence="High",
            color="emerald" if http_info["https_status"] < 400 else "red",
            threat_level="Informational",
            status="Online" if http_info["https_status"] < 400 else "Error",
            tags=["fullhunt", "http"]
        ))

        if http_info.get("https_history"):
            redirect_chain = " -> ".join(http_info["https_history"])
            findings.append(IntelligenceFinding(
                entity=f"Redirect chain: {redirect_chain}",
                type="FullHunt: HTTP Redirect Chain",
                source="FullHunt",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["fullhunt", "http", "redirect"]
            ))

        headers = http_info.get("https_headers", {})
        for hdr in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            val = headers.get(hdr, "")
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{hdr}: {val[:100]}",
                    type="FullHunt: HTTP Header",
                    source="FullHunt",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Header Detected",
                    tags=["fullhunt", "http-header"]
                ))

        for sec_hdr in ADDITIONAL_HTTP_HEADERS:
            val = headers.get(sec_hdr, "")
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{sec_hdr}: {val[:100]}",
                    type="FullHunt: Security Header",
                    source="FullHunt",
                    confidence="High",
                    color="emerald" if "deny" in val.lower() or val.lower() in ("sameorigin", "1; mode=block") else "orange",
                    threat_level="Informational",
                    status="Header Found",
                    tags=["fullhunt", "security-header"]
                ))

        html = http_info.get("https_html", "")
        html_lower = html.lower()
        for sig, tech_label in TECH_STACK_INDICATORS.items():
            if sig in html_lower:
                findings.append(IntelligenceFinding(
                    entity=tech_label, type="FullHunt: Tech from HTML",
                    source="FullHunt", confidence="Medium", color="purple",
                    threat_level="Informational", status="Detected in HTML",
                    tags=["fullhunt", "technology"]
                ))

        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(IntelligenceFinding(
                    entity="CSP allows unsafe-inline/eval",
                    type="FullHunt: CSP Weakness",
                    source="FullHunt", confidence="High", color="red",
                    threat_level="Elevated Risk",
                    status="Weak CSP",
                    tags=["fullhunt", "security"]
                ))
            if "default-src 'none'" in csp or "default-src 'self'" in csp:
                findings.append(IntelligenceFinding(
                    entity="CSP uses restrictive defaults",
                    type="FullHunt: CSP Good Practice",
                    source="FullHunt", confidence="High", color="emerald",
                    threat_level="Informational",
                    status="Good CSP",
                    tags=["fullhunt", "security"]
                ))

    ssl_info = await get_ssl_info(domain)
    if ssl_info:
        if ssl_info.get("issuer"):
            findings.append(IntelligenceFinding(
                entity=str(ssl_info["issuer"]),
                type="FullHunt: SSL Issuer",
                source="FullHunt", confidence="High", color="emerald",
                threat_level="Informational", status="SSL",
                tags=["fullhunt", "ssl"]
            ))
        if ssl_info.get("sans"):
            san_count = len(ssl_info["sans"])
            findings.append(IntelligenceFinding(
                entity=f"{san_count} SAN entries on live cert",
                type="FullHunt: SSL SAN Count",
                source="FullHunt", confidence="High", color="blue",
                threat_level="Informational", status=f"{san_count} SANs",
                tags=["fullhunt", "ssl"]
            ))
            for san in ssl_info["sans"][:5]:
                findings.append(IntelligenceFinding(
                    entity=san, type="FullHunt: SSL SAN",
                    source="FullHunt", confidence="High", color="blue",
                    threat_level="Informational", status="SAN",
                    tags=["fullhunt", "ssl"]
                ))
        if ssl_info.get("protocol"):
            protocol = ssl_info["protocol"]
            findings.append(IntelligenceFinding(
                entity=protocol,
                type="FullHunt: SSL/TLS Protocol",
                source="FullHunt", confidence="High",
                color="emerald" if "1.3" in protocol or "1.2" in protocol else "orange",
                threat_level="Informational",
                status="SSL",
                tags=["fullhunt", "ssl"]
            ))
        if ssl_info.get("cipher"):
            cipher_name = ssl_info["cipher"][0] if isinstance(ssl_info["cipher"], tuple) else str(ssl_info["cipher"])
            is_weak = any(w in cipher_name.upper() for w in ["RC4", "DES", "MD5", "SHA1", "EXPORT", "NULL"])
            findings.append(IntelligenceFinding(
                entity=cipher_name[:100],
                type="FullHunt: SSL/TLS Cipher",
                source="FullHunt", confidence="High",
                color="red" if is_weak else "slate",
                threat_level="Elevated Risk" if is_weak else "Informational",
                status="SSL",
                tags=["fullhunt", "ssl"]
            ))

    total_items = (len(subdomains_found) + len(api_data.get("Technologies", [])) +
                   len(dns_items if isinstance(dns_items, list) else []))

    findings.append(IntelligenceFinding(
        entity=f"FullHunt scan complete: {len(subdomains_found)} subdomains, "
               f"{len(api_data.get('Technologies', []))} technologies, "
               f"{len(dns_items if isinstance(dns_items, list) else [])} DNS records, "
               f"{'HTTPS online' if http_info.get('https_status') else 'HTTP offline'}",
        type="FullHunt Summary",
        source="FullHunt",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["fullhunt", "summary"]
    ))

    return findings
