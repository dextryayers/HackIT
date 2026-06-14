import httpx
import asyncio
import socket
import ssl
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
}

async def resolve_ip(hostname: str) -> list:
    try:
        loop = asyncio.get_event_loop()
        addrinfo = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM))
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
            result[f"{scheme}_html"] = resp.text[:3000]
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

    for sub in sorted(subdomains_found)[:30]:
        ips = await resolve_ip(sub)
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

    dns_items = api_data.get("DNS Records", [])
    if isinstance(dns_items, list):
        for dns_entry in dns_items[:15]:
            if isinstance(dns_entry, dict):
                rtype = dns_entry.get("type", "Record")
                value = dns_entry.get("value", dns_entry.get("data", str(dns_entry)))
                findings.append(IntelligenceFinding(
                    entity=str(value)[:200], type=f"FullHunt: DNS {rtype}",
                    source="FullHunt", confidence="High", color="blue",
                    threat_level="Informational", status="DNS Record",
                    tags=["fullhunt", "dns"]
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
        if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
            findings.append(IntelligenceFinding(
                entity="CSP allows unsafe-inline/eval",
                type="FullHunt: CSP Weakness",
                source="FullHunt", confidence="High", color="red",
                threat_level="Elevated Risk",
                status="Weak CSP",
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
            for san in ssl_info["sans"][:5]:
                findings.append(IntelligenceFinding(
                    entity=san, type="FullHunt: SSL SAN",
                    source="FullHunt", confidence="High", color="blue",
                    threat_level="Informational", status="SAN",
                    tags=["fullhunt", "ssl"]
                ))
        if ssl_info.get("protocol"):
            findings.append(IntelligenceFinding(
                entity=ssl_info["protocol"],
                type="FullHunt: SSL/TLS Protocol",
                source="FullHunt", confidence="High", color="slate",
                threat_level="Informational", status="SSL",
                tags=["fullhunt", "ssl"]
            ))
        if ssl_info.get("cipher"):
            findings.append(IntelligenceFinding(
                entity=ssl_info["cipher"][0] if isinstance(ssl_info["cipher"], tuple) else str(ssl_info["cipher"]),
                type="FullHunt: SSL/TLS Cipher",
                source="FullHunt", confidence="High", color="slate",
                threat_level="Informational", status="SSL",
                tags=["fullhunt", "ssl"]
            ))

    total_items = (len(subdomains_found) + len(api_data.get("Technologies", [])) +
                   len(dns_items if isinstance(dns_items, list) else []))
    findings.append(IntelligenceFinding(
        entity=f"FullHunt scan complete: {len(subdomains_found)} subdomains, "
               f"{len(api_data.get('Technologies', []))} technologies, {len(dns_items if isinstance(dns_items, list) else [])} DNS records",
        type="FullHunt Summary",
        source="FullHunt",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["fullhunt", "summary"]
    ))

    return findings
