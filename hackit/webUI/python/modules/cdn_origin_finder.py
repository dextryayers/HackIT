import httpx
import asyncio
import re
import json
import socket
import struct
import hashlib
import ssl
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Optional, Set
from datetime import datetime

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

CDN_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "cf-connecting-ip", "cf-worker"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache", "via", "x-amz-cf-*"],
    "akamai": ["x-akamai-", "akamai-", "x-akamai-transformed", "x-akamai-server"],
    "fastly": ["x-served-by", "x-cache", "x-cache-hits", "x-timer", "fastly-", "x-fastly-"],
    "azure_cdn": ["x-azure-", "azurecdn", "x-azure-ref"],
    "gcp_cdn": ["x-cloud-trace-context", "via", "x-goog-"],
    "stackpath": ["x-stackpath-"],
    "keycdn": ["x-keycdn-", "keycdn-"],
    "cdn77": ["x-cdn77-", "cdn77-"],
    "bunnycdn": ["x-bunny-", "bunnycdn-"],
    "cachefly": ["x-cachefly-"],
    "section.io": ["x-section-io-"],
    "belugacdn": ["x-beluga-"],
    "ovh_cdn": ["x-ovh-", "ovh-"],
    "cdnvideo": ["x-cdnvideo-"],
    "g core (cdn)": ["x-gcore-", "gcore-"],
    "quantil": ["x-ql-"],
    "chinacache": ["x-chinacache-"],
    "edgecast": ["x-edgecast-", "edgecast-"],
    "incapsula": ["x-incapsula-", "incapsula-"],
    "sucuri": ["x-sucuri-", "sucuri-"],
    "arvancloud": ["x-arvan-", "arvan-"],
    "myracloud": ["x-myra-", "myra-"],
}

CNAME_CDN_PATTERNS = {
    "cloudflare": [".cloudflare.", "cfcdn", ".cloudflare-ip", ".cloudflare.net"],
    "cloudfront": [".cloudfront.net"],
    "akamai": [".akamai", "akamaiedge", "akamaihd", ".akamaized.net", ".akamai.net"],
    "fastly": [".fastly.net", ".fastlylb.net", ".fastly-edge.com"],
    "azure_cdn": [".azureedge.net", ".azurefd.net", ".trafficmanager.net", ".azure.com"],
    "gcp_cdn": [".cdn.google", ".gcpcdn", ".googleusercontent.com"],
    "aws_cdn": [".awsglobalaccelerator", ".elb.amazonaws.com"],
    "keycdn": [".kxcdn.com"],
    "bunnycdn": [".bunnycdn.com", ".b-cdn.net", ".bunny.net"],
    "stackpath": [".stackpathcdn.com"],
    "cdn77": [".cdn77.net", ".cdn77.org"],
    "cachefly": [".cachefly.net"],
    "ovh_cdn": [".ovh.net", ".ovh.com"],
    "section.io": [".section.io"],
    "belugacdn": [".belugacdn.com"],
    "cdnvideo": [".cdnvideo.ru"],
    "gcore": [".gdagent.com", ".gcorelabs.com", ".gcore.lu"],
    "quantil": [".quantil.com"],
    "chinacache": [".chinacache.com"],
    "cdn.net": [".cdn.net"],
    "edgecast": [".edgecastcdn.net", ".edgecast.com"],
    "incapsula": [".incapsula.com"],
    "sucuri": [".sucuri.net"],
    "arvancloud": [".arvancloud.com", ".arvancloud.ir"],
    "myracloud": [".myracloud.com"],
    "ddos-guard": [".ddos-guard.net"],
    "rabbitloader": [".rabbitloader.com"],
    "reblaze": [".reblaze.com"],
    "x4b": [".x4b.net"],
}

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cpanel", "direct", "test",
    "portal", "support", "dev", "staging", "api", "app", "web",
    "email", "mx", "pop3", "imap", "webdisk", "mysql",
    "autodiscover", "localhost", "host", "hosting", "redirect",
    "forum", "wiki", "news", "cdn", "static", "media", "img",
    "download", "dns", "dns1", "dns2", "ftp", "ssh", "git",
    "jenkins", "jira", "monitor", "status", "stats", "m", "mobile",
    "remote", "gateway", "proxy", "owa", "exchange",
    "origin", "origin-www", "origin-server", "origin-backend",
    "backend", "backup", "beta", "dev-api", "dev-www",
    "direct", "direct-www", "edge", "lb", "loadbalancer",
    "node", "nodes", "primary", "secondary", "replica",
    "prod", "production", "production-www", "staging-www",
    "test-www", "uat", "qa", "quality", "preprod",
    "assets", "img", "img1", "img2", "static1", "static2",
    "css", "js", "files", "uploads", "storage",
    "db", "database", "sql", "mysql", "redis",
    "rabbitmq", "mq", "queue", "worker", "job",
    "websocket", "ws", "wss", "socket",
    "analytics", "logs", "monitor", "metrics", "stats",
    "gitlab", "github", "bitbucket",
    "s3", "bucket", "storage",
    "shop", "store", "cart", "checkout",
    "auth", "login", "sso", "oauth",
]

ALT_PORTS = [80, 443, 8080, 8443, 4443, 2053, 2083, 2087, 2096, 8880, 8888, 9000, 9001, 7443, 9443, 11443, 12443]

def detect_cdn_from_headers(headers: Dict) -> List[str]:
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for cdn_name, patterns in CDN_HEADERS.items():
        for pattern in patterns:
            if pattern.endswith("*"):
                prefix = pattern.rstrip("*")
                if any(hk.startswith(prefix.lower()) for hk in headers_lower):
                    detected.append(cdn_name)
                    break
            else:
                if any(pattern.lower() in hk for hk in headers_lower):
                    detected.append(cdn_name)
                    break
    return detected

def detect_cdn_from_cname(cname: str) -> str:
    cname_lower = cname.lower()
    for cdn_name, patterns in CNAME_CDN_PATTERNS.items():
        for pattern in patterns:
            if pattern in cname_lower:
                return cdn_name
    return "Unknown/Generic CDN"

def is_cloudflare_ip(ip: str) -> bool:
    cf_ranges = [
        ("103.21.244.0", "103.21.247.255"),
        ("103.22.200.0", "103.22.203.255"),
        ("103.31.4.0", "103.31.7.255"),
        ("141.101.64.0", "141.101.127.255"),
        ("108.162.192.0", "108.162.255.255"),
        ("190.93.240.0", "190.93.255.255"),
        ("188.114.96.0", "188.114.127.255"),
        ("197.234.240.0", "197.234.255.255"),
        ("198.41.128.0", "198.41.255.255"),
        ("162.158.0.0", "162.159.255.255"),
        ("104.16.0.0", "104.31.255.255"),
        ("172.64.0.0", "172.71.255.255"),
        ("131.0.72.0", "131.0.75.255"),
    ]
    try:
        ip_num = struct.unpack("!I", socket.inet_aton(ip))[0]
        for start, end in cf_ranges:
            s = struct.unpack("!I", socket.inet_aton(start))[0]
            e = struct.unpack("!I", socket.inet_aton(end))[0]
            if s <= ip_num <= e:
                return True
    except Exception:
        pass
    return False

def is_cdn_ip(ip: str) -> bool:
    if is_cloudflare_ip(ip):
        return True
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        cdn_domains = ["cloudfront.net", "akamai", "fastly.net", "azureedge.net",
                       "azurefd.net", "cdn.google", "gcpcdn", "stackpathcdn.com",
                       "bunnycdn.com", "kxcdn.com", "cdn77.net", "cachefly.net",
                       "edgecastcdn.net", "incapsula.com", "keycdn.com",
                       "sucuri.net", "arvancloud.com", "myracloud.com",
                       "ddos-guard.net", "ovh.net"]
        for cdn_domain in cdn_domains:
            if cdn_domain in hostname:
                return True
    except Exception:
        pass
    return False

async def resolve_dns(hostname: str, rtype: str = "A") -> List[str]:
    results = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(hostname, rtype)
        for rdata in answers:
            results.append(str(rdata))
    except Exception:
        pass
    return results

async def resolve_dns_cname(hostname: str) -> List[str]:
    results = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            results.append(str(rdata).rstrip("."))
    except Exception:
        pass
    return results

async def get_historical_dns(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    records = []
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/history/dns"
        headers = {"User-Agent": UA, "Accept": "application/json", "APIKEY": "demo"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("records", [])[:50]:
                if record.get("type") == "A":
                    records.append({
                        "ip": record.get("value", ""),
                        "first_seen": record.get("first_seen", ""),
                        "last_seen": record.get("last_seen", ""),
                        "source": "SecurityTrails",
                        "type": "historical_a",
                    })
    except Exception:
        pass
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"User-Agent": UA, "Accept": "application/json", "APIKEY": "demo"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = data.get("subdomains", [])
            for sub in subdomains[:50]:
                fqdn = f"{sub}.{domain}"
                ips = await resolve_dns(fqdn, "A")
                for ip in ips:
                    records.append({
                        "ip": ip,
                        "hostname": fqdn,
                        "source": "SecurityTrails Subdomains",
                        "type": "subdomain_a",
                    })
    except Exception:
        pass
    return records

async def get_crtsh_certs(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    records = []
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:200]:
                name_value = entry.get("name_value", "")
                for name in name_value.split('\n'):
                    name = name.strip().lstrip('*.').rstrip('.')
                    if name and name != domain and name.endswith(f".{domain}"):
                        ips = await resolve_dns(name, "A")
                        for ip in ips:
                            records.append({
                                "ip": ip,
                                "hostname": name,
                                "source": "CRT.sh SSL SAN",
                                "type": "ssl_san",
                            })
    except Exception:
        pass
    return records

async def get_wayback_machine(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=20&fl=original,statuscode,timestamp"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[1:]:
                original = entry[0] if len(entry) > 0 else ""
                if original:
                    parsed = urlparse(original)
                    if parsed.hostname and parsed.hostname != domain:
                        try:
                            ip = socket.gethostbyname(parsed.hostname)
                            if not is_cdn_ip(ip):
                                ips.append(ip)
                        except Exception:
                            pass
    except Exception:
        pass
    return ips

async def get_securitytrails_history(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {"User-Agent": UA, "APIKEY": "demo"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("records", []):
                ip = record.get("value", "")
                if ip and not is_cdn_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips

async def check_ssl_sans(client: httpx.AsyncClient, domain: str) -> List[str]:
    sans = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        wrapped = ctx.wrap_socket(sock, server_hostname=domain)
        wrapped.connect((domain, 443))
        cert = wrapped.getpeercert()
        if cert:
            for san_entry in cert.get("subjectAltName", []):
                if san_entry[0] == "DNS":
                    sans.append(san_entry[1].lower())
        wrapped.close()
    except Exception:
        pass
    return sans

async def try_subdomain_bruteforce(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    for sub in COMMON_SUBDOMAINS:
        hostname = f"{sub}.{domain}"
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            try:
                cnames = resolver.resolve(hostname, "CNAME")
                for cname in cnames:
                    cname_str = str(cname).rstrip('.')
                    cdn_detected = detect_cdn_from_cname(cname_str)
                    if cdn_detected == "Unknown/Generic CDN":
                        a_records = resolver.resolve(cname_str, "A")
                        for a in a_records:
                            ip = str(a)
                            if not is_cdn_ip(ip):
                                results.append({
                                    "ip": ip,
                                    "hostname": hostname,
                                    "cname": cname_str,
                                    "source": "Subdomain CNAME",
                                    "type": "origin_cname",
                                })
                    else:
                        results.append({
                            "ip": "",
                            "hostname": hostname,
                            "cname": cname_str,
                            "cdn": cdn_detected,
                            "source": "Subdomain CNAME (CDN)",
                            "type": "cdn_cname",
                        })
            except Exception:
                pass
            try:
                a_records = resolver.resolve(hostname, "A")
                for a in a_records:
                    ip = str(a)
                    if not is_cdn_ip(ip):
                        results.append({
                            "ip": ip,
                            "hostname": hostname,
                            "source": "Subdomain A record",
                            "type": "origin_a",
                        })
            except Exception:
                pass
        except Exception:
            pass
    return results

async def shodan_favicon_search(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        fav_url = f"https://{domain}/favicon.ico"
        resp = await client.get(fav_url, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            fav_hash = hashlib.md5(resp.content).hexdigest()
            url = f"https://www.shodan.io/search?query=http.favicon.hash:{fav_hash}"
            headers = {"User-Agent": UA}
            search_resp = await client.get(url, headers=headers, timeout=20.0)
            if search_resp.status_code == 200:
                found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', search_resp.text)
                for found_ip in set(found_ips):
                    if not is_cdn_ip(found_ip):
                        ips.append(found_ip)
    except Exception:
        pass
    return ips

async def shodan_hostname_search(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://www.shodan.io/search?query=hostname%3A{quote(domain)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', resp.text)
            for ip in set(found_ips):
                if not is_cdn_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips

async def censys_search(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://search.censys.io/search?resource=hosts&q={quote(domain)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', resp.text)
            for ip in set(found_ips):
                if not is_cdn_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips

async def shodan_cert_search(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://www.shodan.io/search?query=ssl.cert.subject.cn%3A{quote(domain)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', resp.text)
            for ip in set(found_ips):
                if not is_cdn_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    return ips

async def compare_headers(client: httpx.AsyncClient, domain: str, ip: str) -> Dict:
    result = {"origin_indicators": [], "is_origin": False}
    try:
        domain_resp = await client.get(f"https://{domain}", headers={"User-Agent": UA}, timeout=15.0, follow_redirects=False)
        domain_headers = {k.lower(): v for k, v in dict(domain_resp.headers).items()}
        ip_headers = {}
        for port in [80, 443, 8080, 8443]:
            try:
                proto = "https" if port in [443, 8443] else "http"
                ip_resp = await client.get(f"{proto}://{ip}:{port}", headers={"User-Agent": UA, "Host": domain}, timeout=10.0, follow_redirects=False)
                ip_headers = {k.lower(): v for k, v in dict(ip_resp.headers).items()}
                break
            except Exception:
                continue
        if ip_headers:
            cdn_found = detect_cdn_from_headers(domain_headers)
            ip_cdn_found = detect_cdn_from_headers(ip_headers)
            if cdn_found and not ip_cdn_found:
                result["is_origin"] = True
                result["origin_indicators"].append(f"CDN headers present on domain ({', '.join(cdn_found)}) but not on direct IP")
            domain_server = domain_headers.get("server", "").lower()
            ip_server = ip_headers.get("server", "").lower()
            if domain_server != ip_server and "cloudflare" not in domain_server:
                result["origin_indicators"].append(f"Server header differs: domain='{domain_server}' vs IP='{ip_server}'")
            if ip_headers.get("x-powered-by") and not domain_headers.get("x-powered-by"):
                result["origin_indicators"].append(f"X-Powered-By header visible on IP but not domain")
            if ip_headers.get("set-cookie") and not domain_headers.get("set-cookie"):
                result["origin_indicators"].append("Set-Cookie header present on direct IP")
    except Exception:
        pass
    return result

async def scan_alt_ports(client: httpx.AsyncClient, ip: str) -> List[Dict]:
    results = []
    for port in ALT_PORTS[:8]:
        try:
            proto = "https" if port in [443, 8443, 4443, 2083, 2087, 2096, 7443] else "http"
            resp = await client.get(
                f"{proto}://{ip}:{port}",
                headers={"User-Agent": UA},
                timeout=5.0,
                follow_redirects=False,
            )
            server = resp.headers.get("server", "")
            if server and "cloudflare" not in server.lower():
                results.append({
                    "port": port,
                    "status": resp.status_code,
                    "server": server,
                    "content_type": resp.headers.get("content-type", ""),
                })
        except Exception:
            continue
    return results

async def scan_ip_range(client: httpx.AsyncClient, base_ip: str) -> List[str]:
    origins = []
    try:
        parts = base_ip.split('.')
        if len(parts) == 4:
            base_prefix = '.'.join(parts[:3])
            tasks = []
            for last_octet in range(1, 5):
                test_ip = f"{base_prefix}.{last_octet}"
                if test_ip == base_ip:
                    continue
                tasks.append(check_host_banner(client, test_ip))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, str):
                    origins.append(r)
    except Exception:
        pass
    return origins

async def check_host_banner(client: httpx.AsyncClient, ip: str) -> Optional[str]:
    try:
        resp = await client.get(f"http://{ip}:80", headers={"User-Agent": UA}, timeout=5.0, follow_redirects=False)
        server = resp.headers.get("server", "")
        if server and not is_cdn_ip(ip):
            return ip
    except Exception:
        pass
    return None

async def rtt_proximity_check(client: httpx.AsyncClient, domain: str, edge_ips: List[str]) -> List[str]:
    origins = []
    try:
        import time
        base_rtt = None
        for _ in range(2):
            t1 = time.time()
            try:
                resp = await client.get(f"https://{domain}", headers={"User-Agent": UA}, timeout=10.0)
                t2 = time.time()
                rtt = (t2 - t1) * 1000
                if base_rtt is None or rtt < base_rtt:
                    base_rtt = rtt
            except Exception:
                pass
        if base_rtt and edge_ips:
            for edge_ip in edge_ips[:5]:
                parts = edge_ip.rsplit('.', 2)
                if len(parts) == 3:
                    prefix = parts[0]
                    for last_octet in [1, 254]:
                        test_ip = f"{prefix}.{last_octet}"
                        if test_ip == edge_ip:
                            continue
                        t1 = time.time()
                        try:
                            resp = await client.get(f"http://{test_ip}:80", headers={"User-Agent": UA}, timeout=3.0)
                            t2 = time.time()
                            test_rtt = (t2 - t1) * 1000
                            if test_rtt < base_rtt * 0.3:
                                origins.append(test_ip)
                        except Exception:
                            pass
    except Exception:
        pass
    return origins

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    detected_cdns = []
    edge_ips = []

    try:
        resp = await client.get(f"https://{domain}", headers={"User-Agent": UA}, timeout=15.0, follow_redirects=True)
        headers = dict(resp.headers)
        detected = detect_cdn_from_headers(headers)
        detected_cdns = detected
        if detected:
            for cdn in detected:
                findings.append(IntelligenceFinding(
                    entity=f"CDN detected: {cdn.capitalize()}",
                    type=f"CDN: {cdn.capitalize()}",
                    source="CDNOriginFinder",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    tags=["cdn", cdn.lower().replace(" ", "-"), "detected"]
                ))
    except Exception:
        pass

    historical = await get_historical_dns(client, domain)
    for record in historical:
        ip = record.get("ip", "")
        if not ip:
            continue
        if not is_cdn_ip(ip):
            source = record.get("source", "Historical DNS")
            hostname = record.get("hostname", "")
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type=f"CDN: Pre-CDN IP",
                source=f"CDNOriginFinder/{source}",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Historical Record",
                resolution=f"Hostname: {hostname}" if hostname else None,
                raw_data=f"IP: {ip}\nSource: {source}\nFirst: {record.get('first_seen', 'N/A')} Last: {record.get('last_seen', 'N/A')}",
                tags=["cdn-bypass", "origin-ip", "historical-dns"]
            ))

    certs = await get_crtsh_certs(client, domain)
    for record in certs:
        ip = record.get("ip", "")
        hostname = record.get("hostname", "")
        if ip and not is_cdn_ip(ip):
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: SSL SAN Origin",
                source="CDNOriginFinder/CRT.sh",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="From SSL Certificate SAN",
                resolution=f"Hostname: {hostname}",
                raw_data=f"IP: {ip}\nSSL SAN Hostname: {hostname}",
                tags=["cdn-bypass", "origin-ip", "ssl-san"]
            ))

    wayback_ips = await get_wayback_machine(client, domain)
    for ip in wayback_ips:
        if ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: Wayback Historical IP",
                source="CDNOriginFinder/Wayback",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"Found via Wayback Machine history",
                tags=["cdn-bypass", "origin-ip", "wayback"]
            ))

    sec_trails_ips = await get_securitytrails_history(client, domain)
    for ip in sec_trails_ips:
        if ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: SecurityTrails Historical A",
                source="CDNOriginFinder/SecurityTrails",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["cdn-bypass", "origin-ip", "securitytrails"]
            ))

    shodan_ips = await shodan_favicon_search(client, domain)
    for ip in shodan_ips:
        findings.append(IntelligenceFinding(
            entity=f"Origin IP: {ip}",
            type="CDN: Favicon Hash Match",
            source="CDNOriginFinder/Shodan",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            raw_data=f"Matched via favicon.ico hash on Shodan",
            tags=["cdn-bypass", "origin-ip", "favicon"]
        ))

    shodan_host_ips = await shodan_hostname_search(client, domain)
    for ip in shodan_host_ips:
        if ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: Shodan Hostname Search",
                source="CDNOriginFinder/Shodan",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                raw_data=f"Found via Shodan hostname search",
                tags=["cdn-bypass", "origin-ip", "shodan"]
            ))

    shodan_cert_ips = await shodan_cert_search(client, domain)
    for ip in shodan_cert_ips:
        if ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: Shodan Certificate Search",
                source="CDNOriginFinder/Shodan",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                raw_data=f"Found via Shodan SSL cert search",
                tags=["cdn-bypass", "origin-ip", "shodan-cert"]
            ))

    censys_ips = await censys_search(client, domain)
    for ip in censys_ips:
        if ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
            findings.append(IntelligenceFinding(
                entity=f"Origin IP: {ip}",
                type="CDN: Censys Search",
                source="CDNOriginFinder/Censys",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                raw_data=f"Found via Censys host search",
                tags=["cdn-bypass", "origin-ip", "censys"]
            ))

    subdomain_results = await try_subdomain_bruteforce(client, domain)
    for sr in subdomain_results:
        if sr.get("type") == "origin_a" or sr.get("type") == "origin_cname":
            ip = sr.get("ip", "")
            hostname = sr.get("hostname", "")
            if ip and not is_cdn_ip(ip) and ip not in [f.entity.replace("Origin IP: ", "") for f in findings if f.type.startswith("CDN:")]:
                findings.append(IntelligenceFinding(
                    entity=f"Origin IP: {ip}",
                    type="CDN: Subdomain Discovery",
                    source=f"CDNOriginFinder/{sr.get('source', 'Subdomain Brute')}",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    resolution=f"Subdomain: {hostname}",
                    raw_data=f"IP: {ip}\nSubdomain: {hostname}\nCNAME: {sr.get('cname', 'N/A')}",
                    tags=["cdn-bypass", "origin-ip", "subdomain"]
                ))
        elif sr.get("type") == "cdn_cname":
            hostname = sr.get("hostname", "")
            cname = sr.get("cname", "")
            cdn = sr.get("cdn", "Unknown")
            findings.append(IntelligenceFinding(
                entity=f"CDN CNAME: {hostname} -> {cname}",
                type=f"CDN: CNAME ({cdn})",
                source="CDNOriginFinder/Subdomain CNAME",
                confidence="High",
                color="blue",
                threat_level="Informational",
                tags=["cdn", "cname", cdn.lower().replace(" ", "-")]
            ))

    sans = await check_ssl_sans(client, domain)
    for san in sans:
        if san != domain and san != f"*.{domain.split('.')[-2]}.{domain.split('.')[-1]}" if len(domain.split('.')) >= 2 else True:
            findings.append(IntelligenceFinding(
                entity=f"SSL SAN: {san}",
                type="CDN: SSL SAN Discovery",
                source="CDNOriginFinder/SSL SAN",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["cdn", "ssl-san", "discovery"]
            ))

    all_origin_ips = set()
    for f in findings:
        if "Origin IP" in f.entity:
            ip = f.entity.replace("Origin IP: ", "")
            all_origin_ips.add(ip)

    for ip in list(all_origin_ips)[:10]:
        header_comp = await compare_headers(client, domain, ip)
        if header_comp.get("is_origin"):
            for f in findings:
                if f.entity == f"Origin IP: {ip}":
                    f.confidence = "High"
                    f.color = "red"
                    f.threat_level = "High Risk"
                    f.resolution = f"Confirmed via header comparison: {'; '.join(header_comp.get('origin_indicators', []))}"[:300]

        alt_port_results = await scan_alt_ports(client, ip)
        for apr in alt_port_results:
            findings.append(IntelligenceFinding(
                entity=f"Origin service on {ip}:{apr['port']}",
                type=f"CDN: Origin Port ({apr['server'][:30]})",
                source="CDNOriginFinder/Alt Port",
                confidence="High" if apr.get("server") else "Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"IP: {ip}:{apr['port']}\nServer: {apr.get('server', 'N/A')}\nStatus: {apr.get('status')}\nContent-Type: {apr.get('content_type', 'N/A')}",
                tags=["cdn-bypass", "origin-port", "alt-port"]
            ))

    dns_resolved = await resolve_dns(domain, "A")
    for ip in dns_resolved:
        edge_ips.append(ip)

    if detected_cdns and len(all_origin_ips) == 0:
        for cdn in detected_cdns:
            findings.append(IntelligenceFinding(
                entity=f"No origin IP found behind {cdn}",
                type=f"CDN: Origin Not Found",
                source="CDNOriginFinder",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["cdn-bypass", "origin-not-found"]
            ))

    if findings:
        origin_count = sum(1 for f in findings if "Origin IP" in f.entity and f.confidence == "High")
        medium_origin = sum(1 for f in findings if "Origin IP" in f.entity and f.confidence == "Medium")
        low_origin = sum(1 for f in findings if "Origin IP" in f.entity and f.confidence == "Low")
        cdn_names = list(set(detected_cdns))
        findings.append(IntelligenceFinding(
            entity=f"CDN Origin Scan: {origin_count + medium_origin + low_origin} candidates ({origin_count} high, {medium_origin} medium, {low_origin} low)",
            type="CDN: Summary",
            source="CDNOriginFinder",
            confidence="Medium",
            color="red" if origin_count > 0 else "orange",
            threat_level="High Risk" if origin_count > 0 else "Elevated Risk",
            raw_data=f"CDNs detected: {', '.join(cdn_names) if cdn_names else 'None'} | High: {origin_count} | Medium: {medium_origin} | Low: {low_origin} | Alt ports: {sum(1 for f in findings if f.type.startswith('CDN: Origin Port'))} | Subdomains: {sum(1 for f in findings if f.type == 'CDN: CNAME')}",
            tags=["summary", "cdn", "origin-finder"]
        ))

    return findings
