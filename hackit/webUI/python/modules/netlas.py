import httpx
import json
import re
from module_common import safe_fetch, make_finding

NETLAS_BASE = "https://app.netlas.io/api"
NETLAS_KEY = ""
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

QUERY_TYPES = {
    "domain": {"endpoint": "/domains/", "query_field": "q", "query_template": "domain:{target}"},
    "host": {"endpoint": "/hosts/", "query_field": "q", "query_template": "host:{target}"},
    "ip": {"endpoint": "/hosts/", "query_field": "q", "query_template": "ip:{target}"},
    "cert": {"endpoint": "/certs/", "query_field": "q", "query_template": "domain:{target}"},
    "response": {"endpoint": "/responses/", "query_field": "q", "query_template": "domain:{target}"},
    "search": {"endpoint": "/search/", "query_field": "q", "query_template": "{target}"},
}

SERVICE_CATEGORIES = {
    "http": "Web Server",
    "https": "Web Server (SSL)",
    "ssh": "Remote Access",
    "ftp": "File Transfer",
    "smtp": "Mail Server",
    "dns": "DNS",
    "mysql": "Database",
    "postgresql": "Database",
    "mongodb": "Database",
    "redis": "Cache Store",
    "elasticsearch": "Search Engine",
    "memcached": "Cache Store",
    "rdp": "Remote Desktop",
    "telnet": "Remote Access",
    "sip": "VoIP",
    "imap": "Email",
    "pop3": "Email",
    "smb": "File Sharing",
    "nfs": "File Sharing",
    "vnc": "Remote Desktop",
}

TECH_INDICATORS = {
    "nginx/": "Nginx",
    "apache/": "Apache",
    "cloudflare": "Cloudflare",
    "iis/": "IIS",
    "lighttpd/": "Lighttpd",
    "openresty/": "OpenResty",
    "gunicorn/": "Gunicorn",
    "python/": "Python",
    "php/": "PHP",
    "java/": "Java",
    "node.js": "Node.js",
    "express": "Express.js",
    "next.js": "Next.js",
    "vue.js": "Vue.js",
    "react": "React",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "tomcat": "Tomcat",
    "jetty": "Jetty",
    "caddy": "Caddy",
    "traefik": "Traefik",
    "haproxy": "HAProxy",
    "envoy": "Envoy",
    "istio": "Istio",
    "varnish": "Varnish",
    "squid": "Squid Proxy",
    "ruby/": "Ruby",
    "perl/": "Perl",
    "go/": "Go",
    "rust/": "Rust",
    "laravel": "Laravel",
    "django": "Django",
    "flask": "Flask",
    "rails": "Ruby on Rails",
    "asp.net": "ASP.NET",
    "iis": "IIS",
}

async def netlas_search(target: str, query_type: str, config: dict, client: httpx.AsyncClient) -> list:
    results = []
    template = config["query_template"].format(target=target)
    params = {config["query_field"]: template, "size": 50}
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "X-API-Key": NETLAS_KEY,
    }
    try:
        resp = await safe_fetch(client, 
            f"{NETLAS_BASE}{config['endpoint']}",
            params=params,
            timeout=20.0,
            headers=headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", data.get("data", data.get("results", [])))
            total = data.get("total", data.get("count", len(items)))
            results.append({"type": "summary", "count": total, "query_type": query_type, "items": items[:40]})
            for item in items[:40]:
                results.append({"type": "item", "query_type": query_type, "data": item})
    except Exception as e:
        results.append({"type": "error", "query_type": query_type, "message": str(e)[:100]})
    return results

def extract_ip(item: dict) -> str:
    for key in ["ip", "ip_address", "address", "host_ip"]:
        val = item.get(key, "")
        if val:
            return str(val)
    return ""

def extract_port(item: dict) -> int:
    for key in ["port", "port_number"]:
        val = item.get(key, 0)
        if val:
            return int(val)
    return 0

def extract_service(item: dict) -> str:
    for key in ["service", "service_name", "protocol", "application_protocol"]:
        val = item.get(key, "")
        if val:
            return str(val).lower()
    return ""

def extract_host(item: dict) -> str:
    for key in ["domain", "host", "hostname", "name", "fqdn"]:
        val = item.get(key, "")
        if val:
            return str(val).lower()
    return ""

def detect_technology(banner: str) -> list:
    techs = []
    if not banner:
        return techs
    banner_lower = banner.lower()
    for indicator, tech_name in TECH_INDICATORS.items():
        if indicator in banner_lower:
            techs.append(tech_name)
    return techs

def detect_http_techs(item: dict) -> list:
    techs = []
    http_data = item.get("http", {})
    if isinstance(http_data, dict):
        server = http_data.get("server", "")
        if server:
            techs.append(f"Server: {server}")
        x_powered = http_data.get("x-powered-by", "")
        if x_powered:
            techs.append(f"Powered by: {x_powered}")
        via = http_data.get("via", "")
        if via:
            techs.append(f"Via: {via}")
        title = http_data.get("title", "")
        if title:
            techs.append(f"Title: {title}")
        x_generator = http_data.get("x-generator", "")
        if x_generator:
            techs.append(f"Generator: {x_generator}")
    headers = item.get("headers", {})
    if isinstance(headers, dict):
        for hdr in ["server", "x-powered-by", "x-generator", "x-aspnet-version", "x-aspnetmvc-version"]:
            val = headers.get(hdr, "")
            if val:
                techs.append(f"{hdr}: {val}")
    return techs

def extract_subdomains_from_cert(item: dict) -> list:
    subs = []
    try:
        ssl_data = item.get("ssl", item.get("tls", {}))
        if isinstance(ssl_data, dict):
            cert = ssl_data.get("cert", ssl_data.get("certificate", {}))
            if isinstance(cert, dict):
                for key in ["subject_alt_name", "san", "subject_alt_names"]:
                    val = cert.get(key, [])
                    if isinstance(val, list):
                        for v in val:
                            if isinstance(v, str) and v.count(".") >= 1:
                                subs.append(v.lower())
    except:
        pass
    return subs

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    ip_target = domain
    try:
        import socket
        ip_target = socket.gethostbyname(domain)
    except Exception:
        pass

    all_items = []
    all_subdomains = set()
    for qtype, config in QUERY_TYPES.items():
        results = await netlas_search(domain, qtype, config, client)
        for res in results:
            if res["type"] == "item":
                all_items.append(res)
            elif res["type"] == "summary":
                if res["count"] > 0:
                    findings.append(make_finding(
                        entity=f"{res['count']} results for {qtype} query on {domain}",
                        ftype=f"Netlas: {qtype.title()} Search Summary",
                        source="Netlas",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        status="Found",
                        raw_data=f"Query type: {qtype}, Total: {res['count']}",
                        tags=[f"netlas-{qtype}", "summary"],
                    ))

    seen_services = {}
    for res_item in all_items:
        item = res_item.get("data", {})
        if not isinstance(item, dict):
            continue

        ip = extract_ip(item)
        port = extract_port(item)
        service = extract_service(item)
        host = extract_host(item)
        banner = item.get("banner", item.get("data", ""))
        if isinstance(banner, bytes):
            banner = banner.decode("utf-8", errors="replace")

        dedup_key = f"{ip}:{port}:{service}"
        if dedup_key in seen_services:
            continue
        seen_services[dedup_key] = True

        entity = host or ip or domain
        if port:
            entity += f":{port}"
        if service:
            entity += f" ({service})"

        cat = SERVICE_CATEGORIES.get(service, "Unknown Service")
        raw = json.dumps(item)[:1000]

        tags = ["netlas"]
        if service:
            tags.append(f"service-{service}")

        findings.append(make_finding(
            entity=entity[:200],
            ftype=f"Netlas: {cat}",
            source="Netlas",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            status="Discovered",
            resolution=ip if ip else None,
            raw_data=raw,
            tags=tags,
        ))

        techs = detect_technology(str(banner)) + detect_http_techs(item)
        for tech in set(techs):
            findings.append(make_finding(
                entity=tech[:200],
                ftype="Netlas: Technology Detection",
                source="Netlas",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                raw_data=f"Technology detected on {entity}: {tech}",
                tags=["technology"],
            ))

        ssl_data = item.get("ssl", item.get("tls", {}))
        if isinstance(ssl_data, dict):
            cert = ssl_data.get("cert", ssl_data.get("certificate", {}))
            if isinstance(cert, dict):
                issuer = cert.get("issuer", cert.get("issuer_dn", ""))
                if issuer:
                    findings.append(make_finding(
                        entity=str(issuer)[:200],
                        ftype="Netlas: SSL Certificate Issuer",
                        source="Netlas",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"SSL cert issuer on {entity}: {issuer}",
                        tags=["ssl"],
                    ))
                validity = cert.get("validity", cert.get("valid_to", ""))
                if validity:
                    findings.append(make_finding(
                        entity=str(validity)[:200],
                        ftype="Netlas: SSL Certificate Expiry",
                        source="Netlas",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        raw_data=f"SSL cert validity on {entity}: {validity}",
                        tags=["ssl"],
                    ))
                sans = cert.get("subject_alt_name", cert.get("san", []))
                if isinstance(sans, list):
                    for san in sans[:5]:
                        findings.append(make_finding(
                            entity=str(san)[:200],
                            ftype="Netlas: SSL SAN",
                            source="Netlas",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            tags=["ssl", "san"],
                        ))
                subs_from_cert = extract_subdomains_from_cert(item)
                for sub in subs_from_cert:
                    if sub not in all_subdomains:
                        all_subdomains.add(sub)
                        findings.append(make_finding(
                            entity=sub,
                            ftype="Netlas: Subdomain from Certificate",
                            source="Netlas",
                            confidence="Medium",
                            color="blue",
                            threat_level="Informational",
                            raw_data=f"Subdomain extracted from cert: {sub}",
                            tags=["subdomain", "ssl"],
                        ))

        http_resp = item.get("http", item.get("response", {}))
        if isinstance(http_resp, dict):
            status_code = http_resp.get("status_code", http_resp.get("code", 0))
            if status_code:
                findings.append(make_finding(
                    entity=f"HTTP {status_code} on {entity}",
                    ftype="Netlas: HTTP Status",
                    source="Netlas",
                    confidence="High",
                    color="emerald" if 200 <= int(status_code) < 400 else "orange",
                    threat_level="Informational",
                    raw_data=f"HTTP response code: {status_code} on {entity}",
                    tags=["http"],
                ))
            location = http_resp.get("location", http_resp.get("redirect", ""))
            if location:
                findings.append(make_finding(
                    entity=str(location)[:200],
                    ftype="Netlas: HTTP Redirect",
                    source="Netlas",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Redirects to: {location}",
                    tags=["http", "redirect"],
                ))
            content_type = http_resp.get("content_type", http_resp.get("mime_type", ""))
            if content_type:
                findings.append(make_finding(
                    entity=f"Content-Type: {content_type}",
                    ftype="Netlas: HTTP Content Type",
                    source="Netlas",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Content type on {entity}: {content_type}",
                    tags=["http", "content-type"],
                ))

        geo = item.get("geo", item.get("geolocation", {}))
        if isinstance(geo, dict):
            country = geo.get("country", geo.get("country_name", ""))
            city = geo.get("city", "")
            org = geo.get("org", geo.get("organization", geo.get("asn_description", "")))
            if country:
                asn = geo.get("asn", geo.get("as_number", ""))
                loc_str = f"{city}, {country}" if city else country
                if org:
                    loc_str += f" ({org})"
                if asn:
                    loc_str += f" [AS{asn}]"
                findings.append(make_finding(
                    entity=loc_str[:200],
                    ftype="Netlas: Geolocation",
                    source="Netlas",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=ip,
                    raw_data=f"Geo for {entity}: {loc_str}",
                    tags=["geolocation"],
                ))

    # Summary: endpoint coverage
    endpoints_queried = list(QUERY_TYPES.keys())
    total_items = len(all_items)
    findings.append(make_finding(
        entity=f"Netlas scan: {total_items} items from {len(endpoints_queried)} endpoints",
        ftype="Netlas: Scan Summary",
        source="Netlas",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Endpoints: {', '.join(endpoints_queried)}, Items: {total_items}, Subdomains: {len(all_subdomains)}",
        tags=["netlas-summary"],
    ))

    if not findings:
        findings.append(make_finding(
            entity=f"No Netlas results found for {domain}",
            ftype="Netlas: Empty",
            source="Netlas",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="No Results",
            tags=["empty"],
        ))

    return findings
