import httpx
import re
import json
import socket
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "pop", "imap", "admin", "cpanel", "whm", "autodiscover",
    "m", "mobile", "api", "dev", "staging", "test", "app", "portal",
    "vpn", "ssh", "ftp", "sftp", "secure", "cloud", "my", "shop",
    "support", "help", "status", "docs", "wiki", "forum", "community",
    "cdn", "static", "assets", "media", "img", "css", "js",
    "download", "uploads", "files", "storage", "backup", "db",
    "mysql", "database", "redis", "mq", "rabbitmq", "kafka",
    "jenkins", "jira", "confluence", "git", "svn", "bitbucket",
    "monitor", "grafana", "prometheus", "kibana", "elastic",
    "logs", "analytics", "metrics", "dashboard", "report",
    "web", "www2", "www3", "en", "es", "fr", "de", "it", "pt", "ru",
    "corp", "internal", "intranet", "hr", "payroll", "erp", "crm",
    "owa", "exchange", "outlook", "ews", "autodiscover",
]

EXPOSED_PANEL_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/phpPgAdmin",
    "/adminer", "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/manager/html", "/jmx-console", "/web-console", "/actuator",
    "/swagger-ui", "/api/docs", "/graphql", "/console",
    "/.git", "/.env", "/.svn", "/.DS_Store", "/backup", "/dump",
]

EXPOSED_DB_PATTERNS = {
    "MongoDB": [re.compile(r'mongodb|mongo', re.I), 27017],
    "Redis": [re.compile(r'redis', re.I), 6379],
    "Elasticsearch": [re.compile(r'elasticsearch|elastic', re.I), 9200],
    "MySQL": [re.compile(r'mysql|mariadb', re.I), 3306],
    "PostgreSQL": [re.compile(r'postgres|postgresql', re.I), 5432],
    "Memcached": [re.compile(r'memcached', re.I), 11211],
    "Cassandra": [re.compile(r'cassandra', re.I), 9042],
    "CouchDB": [re.compile(r'couchdb', re.I), 5984],
    "Neo4j": [re.compile(r'neo4j|neo4j', re.I), 7474],
    "InfluxDB": [re.compile(r'influxdb|influx', re.I), 8086],
}

THIRD_PARTY_SERVICES = {
    "Google Analytics": ["google-analytics", "googletagmanager", "gtag"],
    "Cloudflare": ["cloudflare", "cf-"],
    "AWS": ["aws", "amazonaws", "s3.amazonaws", "cloudfront"],
    "Azure": ["azure", "azureedge", "azurewebsites"],
    "GCP": ["gcp", "googlecloud", "appspot", "googleapis"],
    "Fastly": ["fastly", "fastlylb"],
    "Akamai": ["akamai", "akamaiedge", "akamaitech"],
    "New Relic": ["newrelic", "nr-data"],
    "Stripe": ["stripe", "stripe.com"],
    "PayPal": ["paypal", "paypalobjects"],
}

async def check_subdomains(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for sub in COMMON_SUBDOMAINS[:40]:
            domain = f"{sub}.{target}"
            try:
                socket.gethostbyname(domain)
                results.append({"subdomain": domain})
            except:
                pass
    except:
        pass
    return results

async def check_exposed_paths(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            base = f"https://{target}"
        else:
            base = target
        for path in EXPOSED_PANEL_PATHS:
            try:
                url = f"{base}{path}"
                resp = await client.get(url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"},
                    follow_redirects=False)
                if resp.status_code in [200, 201, 202, 204, 301, 302, 403]:
                    results.append({"path": path, "status": resp.status_code, "url": url})
            except:
                pass
    except:
        pass
    return results

async def scan_open_ports(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                        1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
                        6379, 8080, 8443, 9090, 9200, 9443, 10000, 11211, 27017]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target.split(":")[0], port))
                if result == 0:
                    service = socket.getservbyport(port, "tcp") if port in [21,22,23,25,53,80,110,143,443,993,995] else "unknown"
                    results.append({"port": port, "service": service, "state": "open"})
                sock.close()
            except:
                pass
    except:
        pass
    return results

async def check_dns_records(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await client.get(f"https://dns.google/resolve?name={target}&type=ANY",
            timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            for answer in data.get("Answer", []):
                results.append({
                    "type": answer.get("type", ""),
                    "name": answer.get("name", ""),
                    "data": answer.get("data", ""),
                    "ttl": answer.get("TTL", 0),
                })
    except:
        pass
    return results

async def check_shadow_it(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        shadow_services = [
            "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
            "github.io", "gitlab.io", "firebaseapp.com", "azurewebsites.net",
            "s3.amazonaws.com", "s3-website", "cloudfront.net",
        ]
        for svc in shadow_services:
            domain = f"{target.replace('.','-')}.{svc}"
            try:
                socket.gethostbyname(domain)
                results.append({"domain": domain, "service": svc, "exists": True})
            except:
                pass
    except:
        pass
    return results

async def check_third_party_risk(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            url = f"https://{target}"
        else:
            url = target
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            text = resp.text
            for service, indicators in THIRD_PARTY_SERVICES.items():
                for ind in indicators:
                    if ind in text:
                        results.append({"service": service, "indicator": ind})
                        break
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    subdomain_results = await check_subdomains(client, query)
    for r in subdomain_results:
        findings.append(IntelligenceFinding(
            entity=f"Subdomain discovered: {r['subdomain']}",
            type="Subdomain Discovery",
            source="Attack Surface Scanner",
            confidence="High",
            color="yellow",
            category="Attack Surface",
            threat_level="Elevated Risk",
            status="Subdomain Found",
            resolution=query,
            tags=["subdomain", "discovery", "attack-surface"]
        ))

    exposed_path_results = await check_exposed_paths(client, query)
    for r in exposed_path_results:
        findings.append(IntelligenceFinding(
            entity=f"Exposed path: {r['path']} (HTTP {r['status']}) - {r['url']}",
            type="Exposed Path Detection",
            source="Attack Surface Scanner",
            confidence="Medium",
            color="red" if r['status'] == 200 else "yellow",
            category="Attack Surface",
            threat_level="High Risk" if r['status'] == 200 else "Elevated Risk",
            status="Path Accessible",
            resolution=query,
            tags=["exposed-path", "attack-surface", f"status-{r['status']}"]
        ))

    port_results = await scan_open_ports(client, query)
    for r in port_results:
        findings.append(IntelligenceFinding(
            entity=f"Open port: {r['port']}/{r['service']} ({r['state']})",
            type="Open Port Detection",
            source="Attack Surface Scanner",
            confidence="High",
            color="yellow" if r['port'] in [21,23,25,445,3389,3306,5432,6379,27017] else "slate",
            category="Attack Surface",
            threat_level="Elevated Risk" if r['port'] in [21,23,25,445,3389,3306,5432,6379,27017] else "Informational",
            status="Port Open",
            resolution=query,
            tags=["port", f"port-{r['port']}", r['service'], "open"]
        ))

    dns_results = await check_dns_records(client, query)
    dns_types_found = set()
    for r in dns_results:
        rtype = r.get("type", "")
        if isinstance(rtype, int):
            type_names = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 99: "SPF"}
            rtype = type_names.get(rtype, str(rtype))
        if rtype not in dns_types_found:
            dns_types_found.add(rtype)
            findings.append(IntelligenceFinding(
                entity=f"DNS record type: {rtype} - {r.get('name', '')} -> {r.get('data', '')}",
                type="DNS Record Discovery",
                source="Attack Surface Scanner",
                confidence="High",
                color="slate",
                category="Attack Surface",
                threat_level="Informational",
                status="Record Found",
                resolution=query,
                tags=["dns", f"record-{rtype}", "discovery"]
            ))

    shadow_it_results = await check_shadow_it(client, query)
    for r in shadow_it_results:
        findings.append(IntelligenceFinding(
            entity=f"Shadow IT detected: {r['domain']} (hosted on {r['service']})",
            type="Shadow IT Detection",
            source="Attack Surface Scanner",
            confidence="Medium",
            color="red",
            category="Attack Surface",
            threat_level="High Risk",
            status="Unauthorized Service",
            resolution=query,
            tags=["shadow-it", "unauthorized", r['service'].split(".")[0]]
        ))

    third_party_results = await check_third_party_risk(client, query)
    for r in third_party_results:
        findings.append(IntelligenceFinding(
            entity=f"Third-party dependency: {r['service']} (indicator: {r['indicator']})",
            type="Third-Party Risk",
            source="Attack Surface Scanner",
            confidence="Medium",
            color="yellow",
            category="Attack Surface",
            threat_level="Elevated Risk",
            status="Dependency Found",
            resolution=query,
            tags=["third-party", "dependency", r['service'].lower().replace(" ", "-")]
        ))

    exposed_db_results = []
    for db_name, (patterns, port) in EXPOSED_DB_PATTERNS.items():
        for p in patterns:
            if p.search(query):
                exposed_db_results.append({"database": db_name, "port": port})
                break
    for r in exposed_db_results:
        findings.append(IntelligenceFinding(
            entity=f"Exposed database indicator: {r['database']} (port {r['port']})",
            type="Exposed Database Detection",
            source="Attack Surface Scanner",
            confidence="Low",
            color="red",
            category="Attack Surface",
            threat_level="Critical",
            status="Database Indicator",
            resolution=query,
            tags=["database", "exposed", r['database'].lower()]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Attack surface scan complete for {query}: discovered {len(subdomain_results)} subdomains, {len(port_results)} open ports, {len(exposed_path_results)} exposed paths",
        type="Attack Surface Scan Summary",
        source="Attack Surface Scanner",
        confidence="Medium",
        color="slate",
        category="Attack Surface",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["attack-surface", "summary", "scan"]
    ))

    return findings
