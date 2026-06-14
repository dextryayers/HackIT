import httpx
import re
import socket
import asyncio
import ssl
from models import IntelligenceFinding
from urllib.parse import urlparse

SHODAN_API_BASE = "https://api.shodan.io"
SHODAN_HOST_ENDPOINT = f"{SHODAN_API_BASE}/shodan/host/{{target}}"
SHODAN_SEARCH_ENDPOINT = f"{SHODAN_API_BASE}/shodan/host/search"
SHODAN_DOMAIN_ENDPOINT = f"{SHODAN_API_BASE}/dns/domain/{{domain}}"
SHODAN_MYIP_ENDPOINT = f"{SHODAN_API_BASE}/tools/myip"
SHODAN_PROTOCOLS_ENDPOINT = f"{SHODAN_API_BASE}/shodan/protocols"
SHODAN_PORTS_ENDPOINT = f"{SHODAN_API_BASE}/shodan/ports"
SHODAN_QUOTA_ENDPOINT = f"{SHODAN_API_BASE}/api-info"
SHODAN_RESOLVE_ENDPOINT = f"{SHODAN_API_BASE}/dns/resolve"
SHODAN_REVERSE_ENDPOINT = f"{SHODAN_API_BASE}/dns/reverse"
SHODAN_EXPLOITS_SEARCH = f"{SHODAN_API_BASE}/shodan/exploit/search"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

CVSS_LEVELS = [
    (9.0, "Critical", "red"),
    (7.0, "High", "orange"),
    (4.0, "Medium", "yellow"),
    (0.1, "Low", "slate"),
    (0.0, "None", "emerald"),
]

def _cvss_severity(score: float) -> tuple[str, str]:
    for threshold, label, color in CVSS_LEVELS:
        if score >= threshold:
            return label, color
    return "None", "emerald"

async def _shodan_api(url: str, client: httpx.AsyncClient, params: dict = None) -> dict | None:
    try:
        resp = await client.get(url, params=params, timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 403:
            return {"error": "API key required or quota exceeded"}
    except Exception:
        pass
    return None

async def _resolve_dns(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

async def _get_ssl_info(hostname: str, port: int = 443) -> dict | None:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=context, server_hostname=hostname),
            timeout=8.0
        )
        cert = writer.get_extra_info("ssl_object").getpeercert()
        writer.close()
        if cert:
            return cert
    except Exception:
        pass
    return None

def _extract_cve_from_text(text: str) -> list[str]:
    return re.findall(r'CVE-\d{4}-\d{4,7}', text)

def _score_open_port(port: int, service: str) -> tuple[str, str]:
    sensitive_ports = {21: ("FTP", "orange"), 22: ("SSH", "orange"), 23: ("Telnet", "red"),
                       25: ("SMTP", "orange"), 53: ("DNS", "slate"), 80: ("HTTP", "slate"),
                       110: ("POP3", "orange"), 143: ("IMAP", "orange"), 443: ("HTTPS", "emerald"),
                       445: ("SMB", "red"), 1433: ("MSSQL", "red"), 1521: ("Oracle", "red"),
                       2049: ("NFS", "red"), 3306: ("MySQL", "red"), 3389: ("RDP", "red"),
                       5432: ("PostgreSQL", "red"), 5900: ("VNC", "red"), 6379: ("Redis", "red"),
                       8080: ("HTTP-Alt", "orange"), 8443: ("HTTPS-Alt", "slate"),
                       27017: ("MongoDB", "red"), 9200: ("Elasticsearch", "red")}
    service_lower = (service or "").lower()
    for sp, (sname, scolor) in sensitive_ports.items():
        if port == sp:
            return sname, scolor
    if any(kw in service_lower for kw in ["database", "sql", "db", "storage", "backup"]):
        return f"Port {port}", "red"
    if any(kw in service_lower for kw in ["http", "web", "proxy"]):
        return f"Port {port}", "slate"
    return f"Port {port}", "blue"

def _parse_banner_info(service_data: dict) -> dict:
    info = {}
    product = service_data.get("product", "")
    version = service_data.get("version", "")
    info_str = service_data.get("info", "")
    transport = service_data.get("transport", "tcp")
    devicetype = service_data.get("devicetype", "")
    os = service_data.get("os", "")
    if product:
        info["product"] = product
    if version:
        info["version"] = version
    if info_str:
        info["info"] = info_str[:200]
    if transport:
        info["transport"] = transport
    if devicetype:
        info["device_type"] = devicetype
    if os:
        info["os"] = os
    return info

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if raw_target.startswith("http"):
        raw_target = urlparse(raw_target).netloc
    raw_target = raw_target.strip().lower()

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw_target))
    target_for_api = raw_target if is_ip else None

    if not is_ip:
        resolved = await _resolve_dns(raw_target)
        if resolved:
            target_for_api = resolved
            findings.append(IntelligenceFinding(
                entity=f"{raw_target} resolves to {resolved}",
                type="Shodan DNS Resolution",
                source="Shodan",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Resolved",
                resolution=resolved,
                raw_data=f"Domain {raw_target} -> IP {resolved}",
                tags=["dns", "resolution", raw_target.replace('.', '_')]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"Could not resolve {raw_target}",
                type="Shodan Resolution Error",
                source="Shodan",
                confidence="Low",
                color="red",
                threat_level="Informational",
                status="Failed",
                tags=["error"]
            ))
            return findings

    host_data = await _shodan_api(SHODAN_HOST_ENDPOINT.format(target=target_for_api), client)
    if host_data and isinstance(host_data, dict) and "error" not in host_data:
        ip = host_data.get("ip_str", target_for_api)
        ports = host_data.get("ports", [])
        hostnames = host_data.get("hostnames", [])
        vulns = host_data.get("vulns", [])
        os = host_data.get("os", "")
        data_list = host_data.get("data", [])
        city = host_data.get("city", "")
        country_code = host_data.get("country_code", "")
        country_name = host_data.get("country_name", "")
        isp = host_data.get("isp", "")
        org = host_data.get("org", "")
        asn = host_data.get("asn", "")
        latitude = host_data.get("latitude")
        longitude = host_data.get("longitude")
        last_update = host_data.get("last_update", "")
        tags = host_data.get("tags", [])

        if city or country_code:
            geo_str = f"{city}, {country_name or country_code}" if city else (country_name or country_code)
            findings.append(IntelligenceFinding(
                entity=geo_str,
                type="Shodan Geo Location",
                source="Shodan",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="GeoLocated",
                raw_data=f"Location: {geo_str} (lat: {latitude}, lon: {longitude})",
                tags=["geo", "location"]
            ))
        if isp:
            findings.append(IntelligenceFinding(
                entity=isp[:200],
                type="Shodan ISP",
                source="Shodan",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Identified",
                raw_data=f"ISP: {isp}",
                tags=["isp", "network"]
            ))
        if org:
            findings.append(IntelligenceFinding(
                entity=org[:200],
                type="Shodan Organization",
                source="Shodan",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Identified",
                raw_data=f"Organization: {org}",
                tags=["org"]
            ))
        if asn:
            findings.append(IntelligenceFinding(
                entity=str(asn),
                type="Shodan ASN",
                source="Shodan",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Confirmed",
                raw_data=f"ASN: {asn}",
                tags=["asn"]
            ))
        if os:
            findings.append(IntelligenceFinding(
                entity=os[:200],
                type="Shodan OS Detection",
                source="Shodan",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                raw_data=f"OS: {os}",
                tags=["os", "fingerprint"]
            ))
        for tag in tags[:10]:
            findings.append(IntelligenceFinding(
                entity=str(tag)[:100],
                type="Shodan Host Tag",
                source="Shodan",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Categorized",
                raw_data=f"Tag: {tag}",
                tags=["tag", str(tag).lower()]
            ))
        for hostname in hostnames[:10]:
            findings.append(IntelligenceFinding(
                entity=hostname,
                type="Shodan Hostname",
                source="Shodan",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Associated",
                resolution=ip,
                raw_data=f"Hostname: {hostname} on {ip}",
                tags=["hostname", "reverse_dns"]
            ))
        for port in sorted(ports)[:25]:
            sname, scolor = _score_open_port(port, "")
            findings.append(IntelligenceFinding(
                entity=f"{ip}:{port}",
                type=f"Shodan Open Port ({sname})",
                source="Shodan",
                confidence="High",
                color=scolor,
                threat_level="Standard Target" if scolor == "red" else "Informational",
                status="Open",
                resolution=f"tcp/{port}",
                raw_data=f"Open port: {ip}:{port} ({sname})",
                tags=["port", f"port_{port}", "open"]
            ))
        for vuln in vulns[:15]:
            findings.append(IntelligenceFinding(
                entity=vuln,
                type="Shodan Vulnerability",
                source="Shodan",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Detected",
                resolution=ip,
                raw_data=f"Vulnerability: {vuln} on {ip}",
                tags=["vulnerability", vuln.lower().replace('-', '_'), "cve"]
            ))
        for service_data in data_list[:20]:
            if not isinstance(service_data, dict):
                continue
            port = service_data.get("port", 0)
            transport = service_data.get("transport", "tcp")
            product = service_data.get("product", "")
            version = service_data.get("version", "")
            info = service_data.get("info", "")
            banner_data = _parse_banner_info(service_data)
            service_name = service_data.get("_shodan", {}).get("module", service_data.get("module", ""))
            if product or version:
                service_str = f"{product} {version}" if version else product
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port} - {service_str[:200]}",
                    type="Shodan Service Detection",
                    source="Shodan",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"Service on {ip}:{port}: {product} {version} (transport: {transport})",
                    tags=["service", str(product).lower().replace(' ', '_') if product else "unknown"]
                ))
            if info and len(info) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port} banner info: {info[:200]}",
                    type="Shodan Banner Info",
                    source="Shodan",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Captured",
                    resolution=ip,
                    raw_data=f"Banner on {ip}:{port}: {info[:500]}",
                    tags=["banner", "info"]
                ))
            if service_data.get("ssl"):
                ssl_data = service_data["ssl"]
                cert_data = ssl_data.get("cert", {})
                if cert_data:
                    issuer = cert_data.get("issuer", {})
                    subject = cert_data.get("subject", {})
                    if issuer:
                        findings.append(IntelligenceFinding(
                            entity=f"SSL Issuer on port {port}: {issuer}",
                            type="Shodan SSL Certificate",
                            source="Shodan",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            status="Verified",
                            resolution=ip,
                            raw_data=f"SSL issuer: {issuer}",
                            tags=["ssl", "certificate"]
                        ))
                    sans = cert_data.get("extensions", {}).get("subject_alt_name", [])
                    for san in sans[:5]:
                        san_clean = san.replace("DNS:", "").strip()
                        if san_clean:
                            findings.append(IntelligenceFinding(
                                entity=san_clean,
                                type="Shodan SSL SAN",
                                source="Shodan",
                                confidence="High",
                                color="blue",
                                threat_level="Informational",
                                status="Extracted",
                                resolution=ip,
                                raw_data=f"SSL SAN on port {port}: {san_clean}",
                                tags=["ssl", "san"]
                            ))

    search_query = f"hostname:{raw_target}" if not is_ip else f"ip:{raw_target}"
    search_params = {"query": search_query, "limit": 20}
    search_data = await _shodan_api(SHODAN_SEARCH_ENDPOINT, client, search_params)
    if search_data and isinstance(search_data, dict) and "error" not in search_data:
        matches = search_data.get("matches", [])
        total = search_data.get("total", 0)
        for match in matches[:15]:
            if isinstance(match, dict):
                match_ip = match.get("ip_str", "")
                match_port = match.get("port", 0)
                match_hostname = match.get("hostnames", [])
                match_product = match.get("product", "")
                match_os = match.get("os", "")
                match_city = match.get("city", "")
                match_country = match.get("country_code", "")
                if match_hostname:
                    for hn in match_hostname[:3]:
                        findings.append(IntelligenceFinding(
                            entity=f"{hn} ({match_ip}:{match_port})",
                            type="Shodan Search Result",
                            source="Shodan",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            status="Discovered",
                            resolution=match_ip,
                            raw_data=f"Search result: {hn} = {match_ip}:{match_port} [{match_product}]",
                            tags=["search", "discovered"]
                        ))
        if total > 0:
            findings.append(IntelligenceFinding(
                entity=f"Shodan search returned {total} total results for {raw_target}",
                type="Shodan Search Summary",
                source="Shodan",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Complete",
                raw_data=f"Total Shodan search results: {total}",
                tags=["search_summary"]
            ))

    quota_data = await _shodan_api(SHODAN_QUOTA_ENDPOINT, client)
    if quota_data and isinstance(quota_data, dict) and "error" not in quota_data:
        query_credits = quota_data.get("query_credits", 0)
        scan_credits = quota_data.get("scan_credits", 0)
        if query_credits is not None:
            findings.append(IntelligenceFinding(
                entity=f"Shodan API quota: {query_credits} query credits remaining",
                type="Shodan API Info",
                source="Shodan",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Info",
                raw_data=f"Query credits: {query_credits}, Scan credits: {scan_credits}",
                tags=["api", "quota"]
            ))

    if findings:
        type_counts = {}
        for f in findings:
            t = f.type
            type_counts[t] = type_counts.get(t, 0) + 1
        summary_str = "; ".join([f"{k}: {v}" for k, v in sorted(type_counts.items(), key=lambda x: -x[1])[:6]])
        findings.append(IntelligenceFinding(
            entity=f"Shodan scan complete: {len(findings)} findings for {raw_target}",
            type="Shodan Summary",
            source="Shodan",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=target_for_api or "",
            raw_data=summary_str,
            tags=["summary", raw_target.replace('.', '_')]
        ))

    return findings
