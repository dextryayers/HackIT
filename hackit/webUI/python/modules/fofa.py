import httpx
import asyncio
import re
import socket
import ssl
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from osint_common import get_ssl_cert_info, parse_cert_to_dict

FOFA_BASE = "https://en.fofa.info"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

PORT_PROTOCOLS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

TECH_SIGNATURES = {
    "nginx": "Nginx", "apache": "Apache", "iis": "IIS", "lighttpd": "Lighttpd",
    "tomcat": "Tomcat", "jetty": "Jetty", "caddy": "Caddy", "openresty": "OpenResty",
    "gunicorn": "Gunicorn", "node.js": "Node.js", "express": "Express",
    "php": "PHP", "python": "Python", "java": "Java", "ruby": "Ruby",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly",
    "react": "React", "vue": "Vue.js", "angular": "Angular", "jquery": "jQuery",
    "bootstrap": "Bootstrap", "tailwind": "Tailwind",
}

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PORT_RE = re.compile(r'(?::(\d{1,5}))(?:\s|$|/)')
HOST_RE = re.compile(r'([\w.-]+\.\w+)')

async def fetch_fofa_search(domain: str, client: httpx.AsyncClient, page: int = 1) -> str:
    query = f'domain="{domain}"'
    encoded = quote(query)
    url = f"{FOFA_BASE}/result?qbase64={encoded}&page={page}"
    try:
        resp = await client.get(url, headers={"User-Agent": UA, "Accept": "text/html"}, timeout=15.0)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    try:
        url2 = f"{FOFA_BASE}/result?q={quote(domain)}&page={page}"
        resp = await client.get(url2, headers={"User-Agent": UA, "Accept": "text/html"}, timeout=15.0)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return ""

def parse_fofa_results(html: str, domain: str) -> dict:
    ips = set()
    hosts = set()
    ports = set()
    countries = set()
    services = []
    banners = []

    for ip_match in IP_RE.finditer(html):
        ip = ip_match.group()
        ips.add(ip)

    host_pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
    for m in host_pattern.finditer(html):
        hosts.add(m.group(1).lower())

    for port_match in PORT_RE.finditer(html):
        try:
            p = int(port_match.group(1))
            if 1 <= p <= 65535:
                ports.add(p)
        except:
            pass

    country_matches = re.findall(r'(?i)(?:country|location|region)[=:]\s*([A-Za-z\s]{2,20}?)(?:\s|$|<|,)', html)
    for c in country_matches:
        c = c.strip()
        if len(c) >= 2 and not re.match(r'^\d+$', c):
            countries.add(c)

    proto_section = re.findall(r'(?:protocol|service)[=:]\s*([\w/-]+)', html, re.IGNORECASE)
    services.extend(proto_section)

    banner_section = re.findall(r'(?:banner|title|header)[=:]\s*(.{20,200}?)(?:<|$)', html, re.IGNORECASE)
    banners.extend(b.strip() for b in banner_section if b.strip())

    result_count = 0
    count_match = re.search(r'(\d[\d,]*)\s*(?:result|total|matches)', html, re.IGNORECASE)
    if count_match:
        result_count = int(count_match.group(1).replace(",", ""))

    return {
        "ips": ips,
        "hosts": hosts,
        "ports": ports,
        "countries": countries,
        "services": services,
        "banners": banners,
        "result_count": result_count,
    }

async def attempt_banner_grab(ip: str, port: int) -> str:
    try:
        loop = asyncio.get_event_loop()
        def grab():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((ip, port))
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=ip)
                s.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                data = s.recv(2048)
                s.close()
                return data.decode("utf-8", errors="ignore")[:500]
            except:
                return ""
        return await loop.run_in_executor(None, grab)
    except:
        return ""

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = await fetch_fofa_search(domain, client)
    if not html:
        findings.append(IntelligenceFinding(
            entity=f"FOFA search returned no results for {domain}",
            type="FOFA Status", source="FOFA",
            confidence="Low", color="slate", threat_level="Informational",
            status="No Data", tags=["fofa"]
        ))
        return findings

    results = parse_fofa_results(html, domain)

    for ip in sorted(results["ips"])[:20]:
        findings.append(IntelligenceFinding(
            entity=ip, type="FOFA: IP Address", source="FOFA",
            confidence="Medium", color="slate", threat_level="Informational",
            status="Discovered", resolution=f"IP associated with {domain}",
            tags=["fofa", "ip"]
        ))

    for host in sorted(results["hosts"])[:20]:
        findings.append(IntelligenceFinding(
            entity=host, type="FOFA: Host", source="FOFA",
            confidence="Medium", color="emerald", threat_level="Informational",
            status="Subdomain", resolution=f"Sub-host of {domain}",
            tags=["fofa", "host"]
        ))

    recognized_services = 0
    for port in sorted(results["ports"])[:20]:
        proto = PORT_PROTOCOLS.get(port, "Unknown")
        findings.append(IntelligenceFinding(
            entity=f"Port {port}/{proto}", type="FOFA: Service/Port", source="FOFA",
            confidence="Medium", color="blue", threat_level="Informational",
            status="Open", resolution=f"Port {port} detected via FOFA",
            tags=["fofa", "port", f"port-{port}"]
        ))
        recognized_services += 1

    for country in sorted(results["countries"])[:10]:
        findings.append(IntelligenceFinding(
            entity=country, type="FOFA: Country/Location", source="FOFA",
            confidence="Medium", color="slate", threat_level="Informational",
            status="Geo", tags=["fofa", "geo"]
        ))

    for svc in results["services"][:10]:
        findings.append(IntelligenceFinding(
            entity=svc, type="FOFA: Protocol/Service", source="FOFA",
            confidence="Medium", color="orange", threat_level="Informational",
            status="Protocol Detected",
            tags=["fofa", "protocol"]
        ))

    techs_found = set()
    for banner in results["banners"]:
        low_banner = banner.lower()
        for sig, tech_name in TECH_SIGNATURES.items():
            if sig in low_banner:
                techs_found.add(tech_name)
    for tech in sorted(techs_found)[:10]:
        findings.append(IntelligenceFinding(
            entity=tech, type="FOFA: Technology Fingerprint", source="FOFA",
            confidence="Medium", color="orange", threat_level="Informational",
            status="Detected", tags=["fofa", "technology"]
        ))

    for ip in sorted(results["ips"])[:5]:
        for port in [443, 80, 8080, 8443]:
            banner = await attempt_banner_grab(ip, port)
            if banner:
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port} banner", type="FOFA: Banner Grab", source="FOFA",
                    confidence="Medium", color="slate", threat_level="Informational",
                    status="Banner", resolution=banner[:200],
                    tags=["fofa", "banner"]
                ))
                break

    try:
        cert_info = await get_ssl_cert_info(domain)
        if cert_info and cert_info.get("cert"):
            parsed = parse_cert_to_dict(cert_info["cert"])
            if parsed.get("issuer"):
                findings.append(IntelligenceFinding(
                    entity=parsed["issuer"].get("organizationName", "Unknown"),
                    type="FOFA: SSL Certificate", source="FOFA",
                    confidence="High", color="emerald", threat_level="Informational",
                    status="SSL", tags=["fofa", "ssl"]
                ))
            if parsed.get("days_remaining") is not None:
                days = parsed["days_remaining"]
                color = "emerald" if days > 30 else "orange"
                findings.append(IntelligenceFinding(
                    entity=f"SSL expires in {days} days",
                    type="FOFA: SSL Expiry", source="FOFA",
                    confidence="High", color=color, threat_level="Informational",
                    status="SSL Valid" if days > 0 else "Expired",
                    tags=["fofa", "ssl"]
                ))
    except:
        pass

    html_techs = set()
    html_lower = html.lower()
    for sig, tech in TECH_SIGNATURES.items():
        if sig in html_lower:
            html_techs.add(tech)
    for tech in sorted(html_techs - techs_found)[:10]:
        findings.append(IntelligenceFinding(
            entity=tech, type="FOFA: Technology from HTML", source="FOFA",
            confidence="Medium", color="orange", threat_level="Informational",
            status="Detected", tags=["fofa", "technology"]
        ))

    summary_parts = []
    if results["result_count"]:
        summary_parts.append(f"{results['result_count']} total results")
    summary_parts.append(f"{len(results['ips'])} IPs")
    summary_parts.append(f"{len(results['hosts'])} hosts")
    summary_parts.append(f"{len(results['ports'])} ports")
    summary_parts.append(f"{len(techs_found | html_techs)} technologies")

    findings.append(IntelligenceFinding(
        entity="FOFA scan complete: " + ", ".join(summary_parts),
        type="FOFA Summary",
        source="FOFA",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["fofa", "summary"]
    ))

    return findings
