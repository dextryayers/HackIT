import httpx
import asyncio
import re
import json
import socket
import struct
import hashlib
import time
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Optional, Set, Any, Tuple
from datetime import datetime

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cpanel", "whm", "direct",
    "test", "portal", "support", "dev", "staging", "api", "app",
    "web", "mail2", "email", "mx", "pop3", "imap", "webdisk",
    "cpcalendars", "cpcontacts", "mysql", "autodiscover",
    "cpanel", "webmail", "localhost", "host", "hosting",
    "redirect", "forum", "wiki", "news", "shop", "store",
    "cdn", "static", "media", "img", "video", "download",
    "dns", "dns1", "dns2", "dns3", "dns4",
    "ns", "ns1", "ns2", "ns3", "ns4",
    "ftp", "ssh", "git", "jenkins", "jira", "confluence",
    "monitor", "status", "stats", "analytics", "tracking",
    "m", "mobile", "iphone", "android", "play",
    "remote", "remote2", "gateway", "proxy", "webproxy",
    "owa", "exchange", "rpc", "lyncdiscover", "sip",
    "vpn", "vpn2", "vpn3", "vpn4", "openvpn", "wireguard",
    "ssh", "ssh2", "sftp", "rdp", "teamviewer", "anydesk",
    "jenkins", "gitlab", "bitbucket", "gitea", "sonarqube",
    "jira", "confluence", "trello", "slack", "discord",
    "grafana", "prometheus", "kibana", "elastic", "logstash",
    "k8s", "kubernetes", "docker", "swarm", "nomad",
    "rancher", "openshift", "minikube", "microk8s",
    "redis", "memcached", "rabbitmq", "kafka", "nats",
    "mysql", "mariadb", "postgres", "mongodb", "couchdb",
    "phpmyadmin", "adminer", "pgadmin", "phpPgAdmin",
    "php", "php7", "php8", "python", "node", "ruby",
    "go", "golang", "rust", "dotnet", "aspnet",
    "api", "api2", "api3", "api-v1", "api-v2", "rest", "graphql",
    "swagger", "docs", "developer", "developers", "devportal",
    "stage", "staging", "stage-api", "sandbox", "demo", "test",
    "uat", "qa", "quality", "integration", "beta", "alpha",
    "prod", "production", "live", "release", "preprod",
    "backup", "backup2", "backup3", "primary", "secondary",
    "master", "slave", "replica", "replication", "cluster",
    "node1", "node2", "node3", "worker1", "worker2",
    "web1", "web2", "web3", "web4", "web5",
    "app1", "app2", "app3", "app4", "app5",
    "db1", "db2", "db3", "db-master", "db-slave",
    "cache1", "cache2", "cache3", "memcache", "varnish",
    "lb1", "lb2", "loadbalancer", "load-balancer", "haproxy",
    "nginx", "apache", "tomcat", "jboss", "jetty", "wildfly",
    "cacti", "nagios", "zabbix", "icinga", "checkmk",
    "sentry", "rollbar", "bugsnag", "datadog", "newrelic",
    "s3", "storage", "filestore", "files", "uploads",
    "assets", "assets1", "assets2", "res", "resources",
    "img", "img1", "img2", "images", "static", "static1",
    "css", "js", "fonts", "icons", "svg",
    "stream", "streaming", "live", "livecast", "hls",
    "rtmp", "wowza", "flash", "websocket", "socket",
    "wss", "ws", "mqtt", "coap", "amqp",
    "webhook", "hooks", "callback", "notify", "notification",
    "auth", "login", "signin", "signup", "register", "oauth",
    "saml", "sso", "openid", "ldap", "radius",
    "iam", "identity", "keycloak", "cas", "shibboleth",
    "billing", "payment", "invoice", "checkout", "cart",
    "shop", "store", "product", "products", "catalog",
    "community", "forums", "board", "chat", "livechat",
    "help", "support", "helpdesk", "ticket", "zendesk",
    "docs", "wiki", "kb", "knowledgebase", "faq",
    "partners", "partner", "affiliate", "affiliates", "referral",
    "recruit", "jobs", "careers", "career", "apply",
    "corp", "corporate", "company", "about", "contact",
    "news", "press", "blog", "insights", "research",
    "events", "webinar", "meetup", "conference", "summit",
    "status", "uptime", "health", "healthcheck", "ping",
    "license", "licensing", "activation", "verify", "validation",
]

CNAME_PATTERNS = {
    "cloudflare": [".cloudflare.", "cfcdn", "cloudflare-ip"],
    "cloudfront": [".cloudfront.net"],
    "akamai": [".akamai", "akamaiedge", "akamaihd"],
    "fastly": [".fastly.net"],
    "azure_cdn": [".azureedge.net", ".azurefd.net"],
    "gcp_cdn": [".cdn.google", "gcpcdn"],
    "aws_cdn": [".awsglobalaccelerator"],
    "keycdn": [".keycdn.com", ".kxcdn.com"],
    "stackpath": [".stackpathcdn.com"],
    "bunnycdn": [".bunnycdn.com", ".b-cdn.net"],
    "cachefly": [".cachefly.net"],
    "section": [".section.io"],
    "belugacdn": [".belugacdn.com"],
}

ORIGIN_HEADER_PATTERNS = [
    "x-origin-server", "x-backend-server", "x-forwarded-server",
    "x-real-ip", "x-originating-ip", "x-origin-ip",
    "x-amz-cf-pop", "x-azure-ref", "via", "age",
    "x-backend-host", "x-origin-host", "x-proxied-for",
    "x-forwarded-host", "x-original-host", "x-real-host",
]

ORIGIN_ERROR_SIGNATURES = {
    "nginx": ["nginx/", "nginx"],
    "apache": ["apache", "Apache", "httpd"],
    "iis": ["iis", "IIS", "Microsoft-IIS"],
    "tomcat": ["tomcat", "Tomcat", "Apache-Coyote"],
    "jetty": ["jetty", "Jetty"],
    "gunicorn": ["gunicorn", "Gunicorn"],
    "uwsgi": ["uWSGI", "uwsgi"],
    "nodejs": ["Node.js", "node.js", "Express"],
    "python": ["Python", "WSGIServer", "TwistedWeb"],
    "ruby": ["WEBrick", "Phusion", "Passenger"],
    "java": ["Java", "GlassFish", "JBoss", "WildFly", "WebLogic"],
    "caddy": ["Caddy"],
    "traefik": ["Traefik"],
    "envoy": ["envoy"],
    "lighttpd": ["lighttpd", "lighttp"],
    "cowboy": ["Cowboy"],
    "openresty": ["OpenResty"],
}

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
            start_num = struct.unpack("!I", socket.inet_aton(start))[0]
            end_num = struct.unpack("!I", socket.inet_aton(end))[0]
            if start_num <= ip_num <= end_num:
                return True
    except Exception:
        pass
    return False


def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def int_to_ip(num: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", num))


def compute_favicon_hash_md5(resp_bytes: bytes) -> Optional[str]:
    if len(resp_bytes) < 100:
        return None
    return hashlib.md5(resp_bytes).hexdigest()


def compute_favicon_hash_mmh3(resp_bytes: bytes) -> Optional[str]:
    if len(resp_bytes) < 100:
        return None
    mmh3 = hashlib.murmur3_32(resp_bytes)
    return format(mmh3 & 0xFFFFFFFF, '08x')


def compute_tls_fingerprint(server_name: str, issuer: str, valid_from: str, valid_to: str, san_count: int) -> str:
    raw = f"{server_name}|{issuer}|{valid_from}|{valid_to}|{san_count}"
    return hashlib.md5(raw.encode()).hexdigest()


async def resolve_dns(hostname: str, record_type: str = "A") -> List[str]:
    results = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(hostname, record_type)
        for rdata in answers:
            results.append(str(rdata))
    except Exception:
        pass
    return results


async def check_http_on_port(client: httpx.AsyncClient, hostname: str, port: int) -> Optional[Dict]:
    try:
        url = f"http://{hostname}:{port}"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=10.0, follow_redirects=False)
        headers = dict(resp.headers)
        server = headers.get("server", "")
        if server and "cloudflare" not in server.lower():
            return {
                "ip": "",
                "server": server,
                "status": resp.status_code,
                "headers": headers,
            }
    except Exception:
        pass

    try:
        url = f"https://{hostname}:{port}"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=10.0, follow_redirects=False)
        headers = dict(resp.headers)
        server = headers.get("server", "")
        if server and "cloudflare" not in server.lower():
            return {
                "ip": "",
                "server": server,
                "status": resp.status_code,
                "headers": headers,
            }
    except Exception:
        pass
    return None


async def search_crtsh_certs(client: httpx.AsyncClient, domain: str, page: int = 1) -> List[str]:
    names = []
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json&page={page}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            if not data:
                return names
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for n in name.split('\n'):
                        n = n.strip().lstrip('*.').rstrip('.')
                        if n and n not in names:
                            names.append(n)
    except Exception:
        pass
    return names


async def search_crtsh_certs_paginated(client: httpx.AsyncClient, domain: str) -> List[str]:
    all_names = []
    for page in range(1, 6):
        page_names = await search_crtsh_certs(client, domain, page)
        if not page_names:
            break
        for n in page_names:
            if n not in all_names:
                all_names.append(n)
    return all_names


async def search_securitytrails(client: httpx.AsyncClient, domain: str) -> Dict:
    result = {"a_records": [], "mx_records": [], "ns_records": [], "subdomains": [], "soa_records": [], "txt_records": []}
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json", "APIKEY": "demo"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("current_dns", {}).get("a", []):
                if isinstance(record, dict):
                    result["a_records"].append(record.get("ip", ""))
                elif isinstance(record, str):
                    result["a_records"].append(record)
            for record in data.get("current_dns", {}).get("mx", []):
                if isinstance(record, dict):
                    result["mx_records"].append(record.get("host", ""))
                elif isinstance(record, str):
                    result["mx_records"].append(record)
            for record in data.get("current_dns", {}).get("ns", []):
                if isinstance(record, dict):
                    result["ns_records"].append(record.get("nameserver", ""))
                elif isinstance(record, str):
                    result["ns_records"].append(record)
            for record in data.get("current_dns", {}).get("soa", []):
                if isinstance(record, dict):
                    result["soa_records"].append(record.get("email", ""))
            for record in data.get("current_dns", {}).get("txt", []):
                if isinstance(record, dict):
                    result["txt_records"].append(record.get("value", ""))
                elif isinstance(record, str):
                    result["txt_records"].append(record)

        sub_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        resp2 = await client.get(sub_url, headers=headers, timeout=20.0)
        if resp2.status_code == 200:
            sub_data = resp2.json()
            result["subdomains"] = sub_data.get("subdomains", [])

        tags_url = f"https://api.securitytrails.com/v1/domain/{domain}/tags"
        resp3 = await client.get(tags_url, headers=headers, timeout=20.0)
        if resp3.status_code == 200:
            result["tags"] = resp3.json().get("tags", [])

        associated_url = f"https://api.securitytrails.com/v1/domain/{domain}/associated"
        resp4 = await client.get(associated_url, headers=headers, timeout=20.0)
        if resp4.status_code == 200:
            result["associated"] = resp4.json().get("associated_domains", [])
    except Exception:
        pass
    return result


async def search_dnsdumpster(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = "https://dnsdumpster.com/"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=15.0)
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.text)

        headers = {
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://dnsdumpster.com/",
        }
        data = {"csrfmiddlewaretoken": csrf_match.group(1) if csrf_match else "", "targetip": domain}

        resp2 = await client.post(url, headers=headers, data=data, timeout=30.0)
        if resp2.status_code == 200:
            html = resp2.text
            ip_matches = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', html)
            for ip in set(ip_matches):
                if not is_cloudflare_ip(ip):
                    results.append({"ip": ip, "source": "DNSDumpster", "type": "potential_origin"})

            mx_ips = re.findall(r'MX\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', html)
            for ip in set(mx_ips):
                if not is_cloudflare_ip(ip):
                    results.append({"ip": ip, "source": "DNSDumpster MX", "type": "mail_server"})

            ns_ips = re.findall(r'NS\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', html)
            for ip in set(ns_ips):
                if not is_cloudflare_ip(ip):
                    results.append({"ip": ip, "source": "DNSDumpster NS", "type": "nameserver"})
    except Exception:
        pass
    return results


async def check_cname_resolution(client: httpx.AsyncClient, hostname: str) -> Optional[Dict]:
    try:
        cnames = await resolve_dns(hostname, "CNAME")
        if cnames:
            cname = cnames[0].rstrip('.')
            cname_ips = await resolve_dns(cname, "A")
            if cname_ips:
                detected_cdn = "Unknown"
                for cdn_name, patterns in CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in cname.lower():
                            detected_cdn = cdn_name
                            break
                return {
                    "cname": cname,
                    "ip": cname_ips[0] if cname_ips else "",
                    "cdn": detected_cdn,
                    "is_cdn": detected_cdn != "Unknown",
                }
    except Exception:
        pass
    return None


async def check_shodan_favicon(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        favicon_url = f"https://{domain}/favicon.ico"
        resp = await client.get(favicon_url, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            fav_hash = hashlib.md5(resp.content).hexdigest()
            shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash:{fav_hash}"
            headers = {"User-Agent": UA}
            shodan_resp = await client.get(shodan_url, headers=headers, timeout=20.0)
            if shodan_resp.status_code == 200:
                found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', shodan_resp.text)
                for found_ip in set(found_ips):
                    if not is_cloudflare_ip(found_ip) and found_ip not in ips:
                        ips.append(found_ip)
    except Exception:
        pass
    return ips


async def search_shodan_direct(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        queries = [
            f"hostname:{domain}",
            f"ssl.cert.subject.cn:{domain}",
            f"org:Cloudflare port:80 http.title:'{domain.split('.')[0]}'",
        ]
        for query in queries:
            try:
                shodan_url = f"https://www.shodan.io/search?query={quote(query)}"
                resp = await client.get(shodan_url, headers={"User-Agent": UA}, timeout=20.0)
                if resp.status_code == 200:
                    found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', resp.text)
                    for found_ip in set(found_ips):
                        if not is_cloudflare_ip(found_ip):
                            results.append({"ip": found_ip, "source": f"Shodan direct query: {query}", "confidence": "Medium"})
            except Exception:
                continue
    except Exception:
        pass
    return results


async def search_fofa_favicon(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        favicon_url = f"https://{domain}/favicon.ico"
        resp = await client.get(favicon_url, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            mmh3_hash = compute_favicon_hash_mmh3(resp.content)
            if mmh3_hash:
                fofa_url = f"https://fofa.info/result?qbase64={quote(mmh3_hash)}"
                fofa_resp = await client.get(fofa_url, headers={"User-Agent": UA}, timeout=20.0)
                if fofa_resp.status_code == 200:
                    found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', fofa_resp.text)
                    for found_ip in set(found_ips):
                        if not is_cloudflare_ip(found_ip):
                            results.append({"ip": found_ip, "source": "FOFA favicon hash", "confidence": "Medium"})

            md5_hash = compute_favicon_hash_md5(resp.content)
            if md5_hash:
                fofa_md5_url = f"https://fofa.info/result?qbase64={quote(md5_hash)}"
                fofa_md5_resp = await client.get(fofa_md5_url, headers={"User-Agent": UA}, timeout=20.0)
                if fofa_md5_resp.status_code == 200:
                    found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', fofa_md5_resp.text)
                    for found_ip in set(found_ips):
                        if not is_cloudflare_ip(found_ip) and found_ip not in [r["ip"] for r in results]:
                            results.append({"ip": found_ip, "source": "FOFA favicon hash (MD5)", "confidence": "Medium"})
    except Exception:
        pass
    return results


async def search_censys_certificate(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        sha256_fp = None
        try:
            import ssl as ssl_mod
            import socket as sock_mod
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            with ctx.wrap_socket(sock_mod.socket(sock_mod.AF_INET), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert(binary_form=True)
                sha256_fp = hashlib.sha256(cert).hexdigest()
        except Exception:
            pass

        if sha256_fp:
            censys_url = f"https://search.censys.io/certificates?q=sha256:{sha256_fp}"
            censys_resp = await client.get(censys_url, headers={"User-Agent": UA}, timeout=20.0)
            if censys_resp.status_code == 200:
                found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', censys_resp.text)
                for found_ip in set(found_ips):
                    if not is_cloudflare_ip(found_ip):
                        results.append({"ip": found_ip, "source": "Censys certificate search", "confidence": "High"})

        censys_query_url = f"https://search.censys.io/search?resource=hosts&q=services.tls.certificates.leaf_data.subject.common_name:%22{quote(domain)}%22"
        censys_resp2 = await client.get(censys_query_url, headers={"User-Agent": UA}, timeout=20.0)
        if censys_resp2.status_code == 200:
            found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', censys_resp2.text)
            for found_ip in set(found_ips):
                if not is_cloudflare_ip(found_ip) and found_ip not in [r["ip"] for r in results]:
                    results.append({"ip": found_ip, "source": "Censys hostname search", "confidence": "Medium"})
    except Exception:
        pass
    return results


async def search_zoomeye_favicon(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        favicon_url = f"https://{domain}/favicon.ico"
        resp = await client.get(favicon_url, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            mmh3_hash = compute_favicon_hash_mmh3(resp.content)
            if mmh3_hash:
                zoomeye_url = f"https://www.zoomeye.org/searchResult?q={quote(f'app:"{domain}"')}"
                zoomeye_resp = await client.get(zoomeye_url, headers={"User-Agent": UA}, timeout=20.0)
                if zoomeye_resp.status_code == 200:
                    found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', zoomeye_resp.text)
                    for found_ip in set(found_ips):
                        if not is_cloudflare_ip(found_ip):
                            results.append({"ip": found_ip, "source": "ZoomEye search", "confidence": "Medium"})
    except Exception:
        pass
    return results


async def search_virustotal_passive_dns(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                ip = attrs.get("ip_address", "")
                if ip and not is_cloudflare_ip(ip):
                    results.append({
                        "ip": ip,
                        "source": "VirusTotal passive DNS",
                        "confidence": "High",
                        "date": attrs.get("date", ""),
                    })
    except Exception:
        pass
    return results


async def search_alienvault_otx(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                ip = entry.get("address", "")
                if ip and not is_cloudflare_ip(ip):
                    results.append({
                        "ip": ip,
                        "source": "AlienVault OTX passive DNS",
                        "confidence": "High",
                        "hostname": entry.get("hostname", ""),
                        "first_seen": entry.get("first_seen", ""),
                        "last_seen": entry.get("last_seen", ""),
                    })
    except Exception:
        pass
    return results


async def search_urlscan(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for result_item in data.get("results", []):
                page = result_item.get("page", {})
                ip = page.get("ip", "")
                if ip and not is_cloudflare_ip(ip):
                    results.append({
                        "ip": ip,
                        "source": "URLScan.io",
                        "confidence": "Medium",
                        "url": page.get("url", ""),
                        "server": page.get("server", ""),
                        "asn": page.get("asn", ""),
                        "country": page.get("country", ""),
                    })
    except Exception:
        pass
    return results


async def search_securitytrails_history(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        urls = [
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            f"https://api.securitytrails.com/v1/history/{domain}/dns/aaaa",
        ]
        for url in urls:
            try:
                headers = {"User-Agent": UA, "Accept": "application/json", "APIKEY": "demo"}
                resp = await client.get(url, headers=headers, timeout=20.0)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("records", []):
                        ip = record.get("ip", "") if "ip" in record else record.get("value", "")
                        if ip and not is_cloudflare_ip(ip):
                            results.append({
                                "ip": ip,
                                "source": "SecurityTrails history",
                                "confidence": "High",
                                "first_seen": record.get("first_seen", ""),
                                "last_seen": record.get("last_seen", ""),
                                "organizations": record.get("organizations", []),
                            })
            except Exception:
                continue
    except Exception:
        pass
    return results


async def search_subdomain_center(client: httpx.AsyncClient, domain: str) -> List[str]:
    subs = []
    try:
        url = f"https://subdomaincenter.com/api/subdomain/{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        sub = entry.get("subdomain", "")
                        if sub:
                            subs.append(sub)
                    elif isinstance(entry, str):
                        subs.append(entry)
    except Exception:
        pass
    return subs


async def search_threatminer(client: httpx.AsyncClient, domain: str) -> List[str]:
    subs = []
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status_code") == "200":
                for entry in data.get("results", []):
                    if isinstance(entry, str):
                        subs.append(entry)
    except Exception:
        pass
    return subs


async def search_anubisdb(client: httpx.AsyncClient, domain: str) -> List[str]:
    subs = []
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, str) and entry.endswith(f".{domain}"):
                        sub = entry.replace(f".{domain}", "")
                        if sub and sub not in subs:
                            subs.append(entry)
    except Exception:
        pass
    return subs


async def search_riddler(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = f"https://riddler.io/search?q=pld:{domain}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', resp.text)
            for found_ip in set(found_ips):
                if not is_cloudflare_ip(found_ip):
                    results.append({"ip": found_ip, "source": "Riddler.io search", "confidence": "Medium"})
    except Exception:
        pass
    return results


async def rtt_analysis(hostname: str) -> List[str]:
    potential_origins = []
    try:
        import ping3
        resolved = await resolve_dns(hostname)
        if resolved:
            base_rtt = ping3.ping(hostname, timeout=3)
            if base_rtt:
                for last_octet in range(1, 255):
                    base_parts = resolved[0].rsplit('.', 1)
                    test_ip = f"{base_parts[0]}.{last_octet}"
                    if test_ip != resolved[0]:
                        rtt = ping3.ping(test_ip, timeout=1)
                        if rtt and rtt < base_rtt * 0.5:
                            potential_origins.append(test_ip)
    except Exception:
        pass
    return potential_origins


async def search_hackertarget_reverse_ip(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://api.hackertarget.com/reverseip/?q={domain}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                if line.strip() and not line.startswith("Host"):
                    ips.append(line.strip())
    except Exception:
        pass
    return ips


async def test_alternative_ports(client: httpx.AsyncClient, ip: str) -> List[Dict]:
    results = []
    alt_ports = [80, 443, 8080, 8443, 4443, 2053, 2083, 2087, 2096, 8880, 8888]
    for port in alt_ports:
        try:
            if port == 443 or port in [8443, 4443, 2083, 2087, 2096]:
                url = f"https://{ip}:{port}"
            else:
                url = f"http://{ip}:{port}"
            resp = await client.get(url, headers={"User-Agent": UA}, timeout=5.0, follow_redirects=False)
            headers = dict(resp.headers)
            server = headers.get("server", "")
            if server and "cloudflare" not in server.lower():
                results.append({
                    "port": port,
                    "server": server,
                    "status": resp.status_code,
                    "headers": {k: v for k, v in headers.items() if k.lower() in ("server", "x-powered-by", "cf-ray")},
                })
        except Exception:
            continue
    return results


async def check_origin_headers(headers: Dict[str, str]) -> Dict:
    origin_info = {}
    for header_lower in ORIGIN_HEADER_PATTERNS:
        for key, value in headers.items():
            if key.lower() == header_lower:
                origin_info[key] = value
    return origin_info


async def analyze_error_page(client: httpx.AsyncClient, ip: str, domain: str, port: int = 80) -> Optional[Dict]:
    try:
        scheme = "https" if port in [443, 8443, 4443, 2083, 2087, 2096] else "http"
        url = f"{scheme}://{ip}:{port}"
        resp = await client.get(
            url,
            headers={"User-Agent": UA, "Host": domain},
            timeout=8.0,
            follow_redirects=False,
        )
        server = resp.headers.get("server", "").lower()
        body_lower = resp.text.lower()

        detected_origin_servers = []
        for server_name, signatures in ORIGIN_ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in server or sig.lower() in body_lower[:500]:
                    detected_origin_servers.append(server_name)
                    break

        default_pages = ["default page", "it works", "welcome to", "index of /", "under construction",
                         "nginx", "apache2", "iis", "tomcat", "jboss", "wildfly"]

        is_default_page = False
        for dp in default_pages:
            if dp in body_lower[:300]:
                is_default_page = True
                break

        is_cf_page = "cloudflare" in server or "cloudflare-nginx" in server or "cf-ray" in resp.headers

        return {
            "ip": ip,
            "port": port,
            "status": resp.status_code,
            "server": resp.headers.get("server", ""),
            "body_start": resp.text[:300] if resp.text else "",
            "detected_origin_servers": detected_origin_servers,
            "is_default_page": is_default_page,
            "is_cloudflare_error_page": is_cf_page,
            "headers": dict(resp.headers),
        }
    except Exception:
        return None


async def extract_certificate_info(hostname: str) -> Optional[Dict]:
    try:
        import ssl as ssl_mod
        import socket as sock_mod
        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        with ctx.wrap_socket(sock_mod.socket(sock_mod.AF_INET), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            binary_cert = s.getpeercert(binary_form=True)
            if cert:
                sans = []
                for ext in cert.get("subjectAltName", []):
                    if ext[0] == "DNS":
                        sans.append(ext[1])
                return {
                    "subject": dict(cert.get("subject", [[["", ""]]])[0]),
                    "issuer": dict(cert.get("issuer", [[["", ""]]])[0]),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "serialNumber": cert.get("serialNumber", ""),
                    "san": sans,
                    "sha256": hashlib.sha256(binary_cert).hexdigest() if binary_cert else "",
                    "is_self_signed": dict(cert.get("issuer", [[["", ""]]])[0]) == dict(cert.get("subject", [[["", ""]]])[0]),
                }
    except Exception:
        pass
    return None


async def check_cdn_misconfiguration(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        resolved_ips = await resolve_dns(domain, "A")
        cnames = await resolve_dns(domain, "CNAME")

        detected_cdns = []
        if cnames:
            for cname in cnames:
                for cdn_name, patterns in CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in cname.lower():
                            detected_cdns.append(cdn_name)

        try:
            resp = await client.get(
                f"https://{domain}",
                headers={"User-Agent": UA},
                timeout=10.0,
                follow_redirects=False,
            )
            headers = dict(resp.headers)
            cf_ray = headers.get("cf-ray", "")
            cf_cache = headers.get("cf-cache-status", "")
            server = headers.get("server", "")
            if "cloudflare" in server.lower() or cf_ray or cf_cache:
                detected_cdns.append("cloudflare")

            cloudfront_pop = headers.get("x-amz-cf-pop", "")
            if cloudfront_pop:
                detected_cdns.append("cloudfront")

            x_azure_ref = headers.get("x-azure-ref", "")
            if x_azure_ref:
                detected_cdns.append("azure_cdn")

            x_akamai = headers.get("x-akamai-", "")
            if x_akamai or "akamai" in server.lower():
                detected_cdns.append("akamai")
        except Exception:
            pass

        detected_cdns = list(set(detected_cdns))
        if len(detected_cdns) > 1:
            results.append({
                "type": "multi_cdn",
                "cdns": detected_cdns,
                "source": "CDN header analysis",
                "detail": f"Multiple CDNs detected: {', '.join(detected_cdns)}",
            })

        origin_headers = {}
        try:
            resolved_ips = await resolve_dns(domain, "A")
            for ip in resolved_ips[:3]:
                if not is_cloudflare_ip(ip):
                    continue
                try:
                    resp_direct = await client.get(
                        f"https://{ip}",
                        headers={"User-Agent": UA, "Host": domain},
                        timeout=8.0,
                        follow_redirects=False,
                    )
                    direct_headers = dict(resp_direct.headers)
                    for h in ORIGIN_HEADER_PATTERNS:
                        for key, value in direct_headers.items():
                            if key.lower() == h:
                                origin_headers[key] = value
                except Exception:
                    pass
        except Exception:
            pass

        if origin_headers:
            results.append({
                "type": "leaked_origin_header",
                "headers": origin_headers,
                "source": "Direct IP access header analysis",
                "detail": f"Origin headers leaked: {json.dumps(origin_headers)}",
            })

    except Exception:
        pass
    return results


async def detect_rate_limiting(client: httpx.AsyncClient, domain: str) -> Dict:
    result = {
        "is_rate_limited": False,
        "is_challenge_page": False,
        "details": "",
    }
    try:
        resp = await client.get(
            f"https://{domain}",
            headers={"User-Agent": UA},
            timeout=10.0,
            follow_redirects=True,
        )
        body = resp.text.lower()
        status = resp.status_code

        if status == 429:
            result["is_rate_limited"] = True
            result["details"] = "HTTP 429 Too Many Requests"

        if status == 503:
            result["is_rate_limited"] = True
            result["details"] = "HTTP 503 Service Unavailable"

        challenge_indicators = [
            "just a moment", "checking your browser", "cf-browser-verification",
            "challenge-form", "challenge-running", "javascript challenge",
            "attention required", "cloudflare ray id", "403 forbidden",
            "enable javascript", "your browser", "verifying you are human",
        ]
        for indicator in challenge_indicators:
            if indicator in body:
                result["is_challenge_page"] = True
                result["details"] = f"Challenge page detected: '{indicator}'"
                break

        rate_limit_indicators = [
            "rate limit", "rate_limit", "too many requests",
            "slow down", "try again later", "timeout",
        ]
        for indicator in rate_limit_indicators:
            if indicator in body:
                result["is_rate_limited"] = True
                result["details"] = f"Rate limit detected: '{indicator}'"
                break

    except Exception:
        pass
    return result


async def fingerprint_origin(client: httpx.AsyncClient, ip: str, domain: str) -> Optional[Dict]:
    fp = {
        "ip": ip,
        "http": {},
        "https": {},
        "tls_cert": None,
        "response_similarity": 0.0,
    }
    try:
        resp_http = await client.get(
            f"http://{ip}",
            headers={"User-Agent": UA, "Host": domain},
            timeout=8.0,
            follow_redirects=False,
        )
        body_snippet = resp_http.text[:200] if resp_http.text else ""
        fp["http"] = {
            "status": resp_http.status_code,
            "server": resp_http.headers.get("server", ""),
            "headers": dict(resp_http.headers),
            "body_hash": hashlib.md5((resp_http.text or "").encode()).hexdigest(),
            "content_length": len(resp_http.content),
            "body_snippet": body_snippet,
        }
    except Exception:
        pass

    try:
        resp_https = await client.get(
            f"https://{ip}",
            headers={"User-Agent": UA, "Host": domain},
            timeout=8.0,
            follow_redirects=False,
            verify=False,
        )
        body_snippet = resp_https.text[:200] if resp_https.text else ""
        fp["https"] = {
            "status": resp_https.status_code,
            "server": resp_https.headers.get("server", ""),
            "headers": dict(resp_https.headers),
            "body_hash": hashlib.md5((resp_https.text or "").encode()).hexdigest(),
            "content_length": len(resp_https.content),
            "body_snippet": body_snippet,
        }
    except Exception:
        pass

    cert_info = await extract_certificate_info(ip)
    if cert_info:
        fp["tls_cert"] = cert_info

    return fp


def compute_origin_confidence(
    candidate: Dict,
    domain: str,
    cert_info: Optional[Dict] = None,
    target_cert: Optional[Dict] = None,
    fingerprints: Optional[Dict] = None,
    common_ips: Optional[List[str]] = None,
) -> int:
    score = 0
    ip = candidate.get("ip", "")
    source = candidate.get("source", "").lower()

    reliability_map = {
        "securitytrails": 70,
        "virustotal": 75,
        "alienvault": 70,
        "urlscan": 55,
        "hackertarget": 40,
        "dnsdumpster": 50,
        "crtsh": 65,
        "fofa": 50,
        "censys": 75,
        "zoomeye": 45,
        "shodan": 60,
        "cname": 80,
        "subdomain": 60,
        "ssl san": 65,
        "alientvault": 70,
        "riddler": 40,
        "favicon": 45,
    }
    for key, rel_score in reliability_map.items():
        if key in source:
            score += rel_score
            break
    else:
        score += 30

    if candidate.get("confidence") == "High":
        score += 20
    elif candidate.get("confidence") == "Medium":
        score += 10

    if candidate.get("historical") or "history" in source:
        score += 15
    if candidate.get("date") or candidate.get("first_seen"):
        score += 10

    if cert_info and target_cert:
        common_sans = set(cert_info.get("san", [])) & set(target_cert.get("san", []))
        if common_sans:
            score += 20
        if cert_info.get("issuer") == target_cert.get("issuer"):
            score += 15
        if cert_info.get("is_self_signed"):
            score -= 15
        if cert_info.get("sha256") == target_cert.get("sha256"):
            score += 30

    if fingerprints:
        fp = fingerprints.get(ip, {})
        if fp.get("http", {}).get("body_hash"):
            for other_ip, other_fp in fingerprints.items():
                if other_ip != ip and other_fp.get("http", {}).get("body_hash") == fp["http"]["body_hash"]:
                    score += 10
                    break

    if common_ips and ip in common_ips:
        score += 25

    return min(100, max(0, score))


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    is_cloudflare_detected = False
    origin_candidates = []
    rate_limit_info = {}

    try:
        resp = await client.get(f"https://{domain}", headers={"User-Agent": UA}, timeout=15.0, follow_redirects=True)
        headers = dict(resp.headers)
        cf_ray = headers.get("cf-ray", "")
        cf_cache = headers.get("cf-cache-status", "")
        server = headers.get("server", "")
        if "cloudflare" in server.lower() or cf_ray or cf_cache:
            is_cloudflare_detected = True
            findings.append(IntelligenceFinding(
                entity="Cloudflare detected via response headers",
                type="CDN: Cloudflare Detected",
                source="CloudflareResolver",
                confidence="High",
                color="blue",
                threat_level="Informational",
                tags=["cloudflare", "cdn", "detected"]
            ))
    except Exception:
        pass

    rate_limit_info = await detect_rate_limiting(client, domain)
    if rate_limit_info.get("is_challenge_page") or rate_limit_info.get("is_rate_limited"):
        findings.append(IntelligenceFinding(
            entity=f"Cloudflare security: {rate_limit_info.get('details', 'Unknown')}",
            type="CDN: Cloudflare Security Detection",
            source="CloudflareResolver",
            confidence="High",
            color="yellow",
            threat_level="Informational",
            raw_data=f"Rate limited: {rate_limit_info.get('is_rate_limited')}\nChallenge page: {rate_limit_info.get('is_challenge_page')}\nDetails: {rate_limit_info.get('details', '')}",
            tags=["cloudflare", "security", "rate-limit", "challenge"]
        ))

    crtsh_names = await search_crtsh_certs_paginated(client, domain)
    subdomain_candidates = set()
    for name in crtsh_names:
        if name.endswith(f".{domain}") and name != domain:
            sub = name.replace(f".{domain}", "")
            subdomain_candidates.add(f"{sub}.{domain}")
    subdomain_candidates.update([f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS])

    st_data = await search_securitytrails(client, domain)
    historical_ips = st_data.get("a_records", [])
    for ip in set(historical_ips):
        if not is_cloudflare_ip(ip):
            origin_candidates.append({"ip": ip, "source": "SecurityTrails (historical)", "confidence": "Medium"})

    st_history = await search_securitytrails_history(client, domain)
    for entry in st_history:
        ip = entry["ip"]
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": entry["source"], "confidence": "High", "historical": True, "first_seen": entry.get("first_seen", ""), "last_seen": entry.get("last_seen", "")})

    dnsdumpster_ips = await search_dnsdumpster(client, domain)
    for entry in dnsdumpster_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": "Medium"})

    vt_ips = await search_virustotal_passive_dns(client, domain)
    for entry in vt_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"], "date": entry.get("date", "")})

    otx_ips = await search_alienvault_otx(client, domain)
    for entry in otx_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"], "first_seen": entry.get("first_seen", ""), "last_seen": entry.get("last_seen", "")})

    urlscan_ips = await search_urlscan(client, domain)
    for entry in urlscan_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"], "url": entry.get("url", ""), "server": entry.get("server", ""), "asn": entry.get("asn", ""), "country": entry.get("country", "")})

    subdomain_center_subs = await search_subdomain_center(client, domain)
    for sub in subdomain_center_subs:
        subdomain_candidates.add(sub if sub.startswith(sub.replace(f".{domain}", "")) else f"{sub}.{domain}")

    threatminer_subs = await search_threatminer(client, domain)
    for sub in threatminer_subs:
        subdomain_candidates.add(sub)

    anubis_subs = await search_anubisdb(client, domain)
    for sub in anubis_subs:
        subdomain_candidates.add(sub)

    riddler_ips = await search_riddler(client, domain)
    for entry in riddler_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"]})

    for subdomain in list(subdomain_candidates)[:50]:
        cname_info = await check_cname_resolution(client, subdomain)
        if cname_info and not cname_info["is_cdn"] and cname_info.get("ip"):
            if not is_cloudflare_ip(cname_info["ip"]):
                origin_candidates.append({
                    "ip": cname_info["ip"],
                    "source": f"CNAME resolution ({subdomain} -> {cname_info['cname']})",
                    "confidence": "High",
                })

        sub_ips = await resolve_dns(subdomain, "A")
        for sip in sub_ips:
            if not is_cloudflare_ip(sip) and sip not in [c["ip"] for c in origin_candidates]:
                origin_candidates.append({
                    "ip": sip,
                    "source": f"Subdomain DNS A record ({subdomain})",
                    "confidence": "Medium",
                })

    fav_ips = await check_shodan_favicon(client, domain)
    for ip in fav_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "Favicon hash match (Shodan)", "confidence": "Medium"})

    fofa_ips = await search_fofa_favicon(client, domain)
    for entry in fofa_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"]})

    censys_ips = await search_censys_certificate(client, domain)
    for entry in censys_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"]})

    zoomeye_ips = await search_zoomeye_favicon(client, domain)
    for entry in zoomeye_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"]})

    shodan_direct_ips = await search_shodan_direct(client, domain)
    for entry in shodan_direct_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": entry["confidence"]})

    hackertarget_ips = await search_hackertarget_reverse_ip(client, domain)
    for ip in hackertarget_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "HackerTarget reverse IP", "confidence": "Low"})

    ssl_san_ips = []
    for cert_name in crtsh_names[:50]:
        if cert_name != domain:
            cert_ips = await resolve_dns(cert_name, "A")
            for ip in cert_ips:
                if not is_cloudflare_ip(ip) and ip not in ssl_san_ips:
                    ssl_san_ips.append(ip)
    for ip in ssl_san_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "SSL SAN DNS resolution", "confidence": "Medium"})

    cdn_misconfigs = await check_cdn_misconfiguration(client, domain)
    for entry in cdn_misconfigs:
        if entry["type"] == "multi_cdn":
            findings.append(IntelligenceFinding(
                entity=f"Multi-CDN detected: {', '.join(entry['cdns'])}",
                type="CDN: Multi-CDN Detection",
                source="CloudflareResolver",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                raw_data=entry["detail"],
                tags=["cdn", "multi-cdn", "misconfiguration"]
            ))
        elif entry["type"] == "leaked_origin_header":
            findings.append(IntelligenceFinding(
                entity=f"Origin IP leaked via headers: {', '.join(entry['headers'].keys())}",
                type="CDN: Origin Header Leaked",
                source="CloudflareResolver",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data=entry["detail"],
                tags=["cdn", "origin-leaked", "header"]
            ))
            for header_key, header_val in entry["headers"].items():
                ip_match = re.search(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', header_val)
                if ip_match:
                    leaked_ip = ip_match.group(0)
                    if not is_cloudflare_ip(leaked_ip) and leaked_ip not in [c["ip"] for c in origin_candidates]:
                        origin_candidates.append({"ip": leaked_ip, "source": f"Leaked from header: {header_key}", "confidence": "High"})

    target_cert = await extract_certificate_info(domain)

    fingerprints = {}
    error_page_analyses = []
    for candidate in origin_candidates:
        ip = candidate["ip"]
        fp = await fingerprint_origin(client, ip, domain)
        if fp:
            fingerprints[ip] = fp

    for candidate in origin_candidates:
        ip = candidate["ip"]
        error_analysis = await analyze_error_page(client, ip, domain, 443)
        if error_analysis:
            error_page_analyses.append(error_analysis)
        error_analysis_80 = await analyze_error_page(client, ip, domain, 80)
        if error_analysis_80:
            error_page_analyses.append(error_analysis_80)

    for analysis in error_page_analyses:
        if analysis.get("detected_origin_servers") and not analysis.get("is_cloudflare_error_page"):
            ip = analysis["ip"]
            if ip not in [c["ip"] for c in origin_candidates]:
                origin_candidates.append({"ip": ip, "source": f"Error page analysis ({','.join(analysis['detected_origin_servers'])})", "confidence": "Medium"})

    new_candidates = []
    for candidate in origin_candidates:
        ip = candidate["ip"]
        orig_headers = {}
        for port in [80, 443, 8080, 8443]:
            try:
                scheme = "https" if port in [443, 8443] else "http"
                resp = await client.get(
                    f"{scheme}://{ip}:{port}",
                    headers={"User-Agent": UA, "Host": domain},
                    timeout=5.0,
                    follow_redirects=False,
                )
                header_info = await check_origin_headers(dict(resp.headers))
                if header_info:
                    orig_headers.update(header_info)
            except Exception:
                pass

        if orig_headers:
            candidate["origin_headers"] = orig_headers
            candidate["source"] += f" [origin headers: {','.join(orig_headers.keys())}]"
            candidate["confidence"] = "High"

        cert_info = fingerprints.get(ip, {}).get("tls_cert")
        confidence_score = compute_origin_confidence(
            candidate, domain, cert_info, target_cert,
            fingerprints, [c["ip"] for c in origin_candidates]
        )
        candidate["score"] = confidence_score

        if confidence_score >= 80:
            candidate["confidence"] = "High"
        elif confidence_score >= 50:
            candidate["confidence"] = "Medium"
        else:
            candidate["confidence"] = "Low"

    origin_candidates.sort(key=lambda x: x.get("score", 0), reverse=True)

    seen_ips = set()
    for candidate in origin_candidates:
        ip = candidate["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        alt_port_results = await test_alternative_ports(client, ip)
        alt_port_info = ""
        if alt_port_results:
            alt_port_info = " | Alt ports: " + ", ".join(f"{r['port']}:{r['server']}" for r in alt_port_results[:3])

        confidence = candidate.get("confidence", "Medium")
        source_info = candidate.get("source", "Unknown")
        score = candidate.get("score", 0)

        tags = ["cloudflare-resolver", "origin-ip"]
        if alt_port_results:
            tags.append("alt-port-access")
        if candidate.get("origin_headers"):
            tags.append("origin-header-leak")

        raw_data = f"IP: {ip}\nSource: {source_info}\nConfidence: {confidence}\nConfidence Score: {score}/100"
        if alt_port_results:
            for r in alt_port_results:
                raw_data += f"\nAlt port {r['port']}: {r['server']} (HTTP {r['status']})"
        if candidate.get("origin_headers"):
            raw_data += f"\nOrigin Headers: {json.dumps(candidate['origin_headers'])}"

        fp = fingerprints.get(ip, {})
        if fp.get("tls_cert"):
            cert = fp["tls_cert"]
            raw_data += f"\nTLS: SAN={','.join(cert.get('san', [])[:5])}, Issuer={cert.get('issuer', {})}"

        if fp.get("http", {}).get("body_snippet"):
            raw_data += f"\nHTTP Body (first 200 chars): {fp['http']['body_snippet']}"

        findings.append(IntelligenceFinding(
            entity=f"Origin IP: {ip}",
            type="CDN: Origin IP Candidate",
            source=f"CloudflareResolver/{source_info.split('(')[0].strip()}",
            confidence=confidence,
            color="red" if confidence == "High" else ("orange" if confidence == "Medium" else "slate"),
            threat_level="High Risk" if confidence == "High" else ("Elevated Risk" if confidence == "Medium" else "Informational"),
            status="Potential Origin" if confidence in ("High", "Medium") else "Low Confidence",
            resolution=f"Confidence: {confidence} (Score: {score}/100){alt_port_info}",
            raw_data=raw_data,
            tags=tags,
        ))

    if fingerprints and len(fingerprints) > 1:
        body_hashes = {}
        for ip, fp in fingerprints.items():
            bh = fp.get("http", {}).get("body_hash") or fp.get("https", {}).get("body_hash")
            if bh:
                body_hashes.setdefault(bh, []).append(ip)

        cluster_info = []
        for bh, ips in body_hashes.items():
            if len(ips) > 1:
                cluster_info.append(f"Cluster: {', '.join(ips)} (same response body)")

        if cluster_info:
            findings.append(IntelligenceFinding(
                entity=f"Origin server clusters: {len(cluster_info)} groups found",
                type="CDN: Origin Fingerprint Clusters",
                source="CloudflareResolver",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                raw_data="\n".join(cluster_info),
                tags=["cloudflare", "fingerprint", "cluster"]
            ))

    if target_cert:
        findings.append(IntelligenceFinding(
            entity=f"Target TLS Certificate: {len(target_cert.get('san', []))} SANs, Issuer: {target_cert.get('issuer', {}).get('organizationName', 'Unknown')}",
            type="CDN: Target Certificate Analysis",
            source="CloudflareResolver",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=json.dumps({k: v for k, v in target_cert.items() if k != 'sha256'}, indent=2),
            tags=["cloudflare", "tls", "certificate"]
        ))

    if is_cloudflare_detected and findings:
        high_conf = [f for f in findings if f.confidence == "High" and "Origin IP" in f.type]
        med_conf = [f for f in findings if f.confidence == "Medium" and "Origin IP" in f.type]
        low_conf = [f for f in findings if f.confidence == "Low" and "Origin IP" in f.type]

        total_origins = len(high_conf) + len(med_conf) + len(low_conf)
        avg_score = 0
        if origin_candidates:
            avg_score = sum(c.get("score", 0) for c in origin_candidates) / len(origin_candidates)

        summary_lines = [
            f"Origin IP candidates found: {len(high_conf)} high, {len(med_conf)} medium, {len(low_conf)} low confidence",
            f"Total candidates: {total_origins}",
            f"Average confidence score: {avg_score:.1f}/100",
            f"High confidence IPs: {', '.join([f.entity.replace('Origin IP: ', '') for f in high_conf]) if high_conf else 'None'}",
            f"Medium confidence IPs: {', '.join([f.entity.replace('Origin IP: ', '') for f in med_conf[:5]]) if med_conf else 'None'}",
            f"Fingerprinted origins: {len(fingerprints)}",
            f"Certificate matches: {sum(1 for c in origin_candidates if c.get('score', 0) >= 80)} high-score candidates",
        ]

        findings.append(IntelligenceFinding(
            entity=f"Cloudflare Origin Resolution: {len(high_conf)} high-confidence origins (avg score: {avg_score:.0f}/100)",
            type="CDN: Origin Resolution Summary",
            source="CloudflareResolver",
            confidence="Medium",
            color="red" if high_conf else "orange",
            threat_level="High Risk" if high_conf else "Elevated Risk",
            raw_data="\n".join(summary_lines),
            tags=["summary", "cloudflare", "origin-resolution"]
        ))
    elif is_cloudflare_detected and not findings:
        findings.append(IntelligenceFinding(
            entity="Cloudflare detected but no origin IP found. Target likely fully proxied.",
            type="CDN: Origin Resolution",
            source="CloudflareResolver",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["cloudflare", "origin-not-found"]
        ))

    return findings
