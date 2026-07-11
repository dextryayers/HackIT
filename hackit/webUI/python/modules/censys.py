import httpx
import socket
import asyncio
import re
from typing import List
from osint_common import normalize_target
from models import IntelligenceFinding
from module_common import safe_fetch, make_finding

CENSYS_V2_HOSTS = "https://search.censys.io/api/v2/hosts"
CENSYS_V2_CERTS = "https://search.censys.io/api/v2/certificates/search"
CENSYS_V2_SUBDOMAINS = "https://search.censys.io/api/v2/domains"
CENSYS_V1_CERTS = "https://www.censys.io/api/v1/view/certificates"
CENSYS_V2_SEARCH = "https://search.censys.io/api/v2"

RISK_PORT_CATEGORIES = {
    "web": {80, 443, 8080, 8443, 3000, 5000, 8000, 8888},
    "database": {3306, 5432, 27017, 6379, 1433, 1521, 9042, 5984, 9200, 9300},
    "remote_access": {22, 23, 3389, 5900, 5800, 2222, 3390},
    "mail": {25, 110, 143, 465, 587, 993, 995},
    "file_sharing": {21, 445, 139, 2049, 111, 2049},
    "management": {2082, 2083, 2086, 2087, 9090, 10000, 8834, 4848, 9443},
    "message_queue": {5672, 61616, 1883, 8883, 15672},
    "container": {2375, 2376, 8443, 10250, 10255},
}

TLS_WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON", "aNULL", "eNULL", "DES-CBC3", "RC4-MD5"}

async def query_hosts(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
        except:
            return []
        resp = await safe_fetch(client, f"{CENSYS_V2_HOSTS}/{ip}", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 403:
            return []
        if resp.status_code == 200:
            return [resp.json().get("result", {})]
        return []
    except:
        return []

async def query_certificates(target: str, client: httpx.AsyncClient, page_size: int = 50) -> List[dict]:
    try:
        resp = await safe_fetch(client, f"{CENSYS_V2_CERTS}?q=names:{target}&per_page={page_size}",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("hits", data.get("result", {}).get("hits", []))
        return []
    except:
        return []

async def query_subdomains(target: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await safe_fetch(client, f"{CENSYS_V2_SUBDOMAINS}/{target}/subdomains",
            timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            return data.get("subdomains", [])
        return []
    except:
        return []

async def query_host_search(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"{CENSYS_V2_HOSTS}/search",
            params={"q": target, "per_page": 20},
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            results.extend(data.get("result", {}).get("hits", []))
    except:
        pass
    return results

def classify_port_risk(port: int, service: str) -> tuple:
    for category, ports in RISK_PORT_CATEGORIES.items():
        if port in ports:
            if category == "database":
                return "High Risk" if port in {3306, 5432, 27017, 6379, 9200, 9300} else "Elevated Risk"
            if category == "remote_access":
                return "Elevated Risk" if port in {22, 443} else "High Risk"
            if category == "management":
                return "Elevated Risk"
            if category == "message_queue":
                return "Elevated Risk"
            if category == "container":
                return "High Risk"
            return "Standard Target"
    return "Low Profile"

def analyze_tls_security(cipher_str: str, protocol: str) -> List[dict]:
    issues = []
    if protocol in TLS_WEAK_VERSIONS:
        issues.append({
            "entity": f"Weak TLS version: {protocol}",
            "type": "TLS Weak Protocol",
            "color": "red",
            "threat": "High Risk"
        })
    if cipher_str:
        for weak in WEAK_CIPHERS:
            if weak.lower() in cipher_str.lower() or weak in cipher_str.upper():
                issues.append({
                    "entity": f"Weak cipher: {cipher_str[:80]}",
                    "type": "Weak Cipher Suite",
                    "color": "red",
                    "threat": "High Risk"
                })
                break
    return issues

def extract_location_info(result: dict) -> List[dict]:
    locs = []
    loc = result.get("location", {})
    if isinstance(loc, dict):
        country = loc.get("country", "")
        city = loc.get("city", "")
        timezone = loc.get("timezone", "")
        latitude = loc.get("latitude")
        longitude = loc.get("longitude")
        if country:
            locs.append(make_finding(country, "Censys Country", "Censys",
                confidence="High", color="slate", threat_level="Informational",
                resolution=country))
        if city:
            locs.append(make_finding(city, "Censys City", "Censys",
                confidence="High", color="slate", threat_level="Informational",
                resolution=f"{city}, {country}" if country else city))
        if timezone:
            locs.append(make_finding(timezone, "Censys Timezone", "Censys",
                confidence="High", color="slate", threat_level="Informational"))
        if latitude and longitude:
            locs.append(make_finding(f"{latitude}, {longitude}", "Censys Coordinates", "Censys",
                confidence="High", color="slate", threat_level="Informational",
                resolution=f"https://www.google.com/maps?q={latitude},{longitude}"))
    return locs

def extract_asn_info(result: dict) -> List[dict]:
    entries = []
    asn_obj = result.get("autonomous_system", {})
    if isinstance(asn_obj, dict):
        asn = asn_obj.get("asn", "")
        asn_name = asn_obj.get("name", "")
        bgp_prefix = asn_obj.get("bgp_prefix", "")
        if asn:
            entries.append(make_finding(f"AS{asn} ({asn_name})", "Censys ASN", "Censys",
                confidence="High", color="slate", threat_level="Informational",
                resolution=bgp_prefix,
                raw_data=f"AS{asn}: {asn_name}, Prefix: {bgp_prefix}"))
        if asn_name:
            org = asn_obj.get("organization", "")
            if org and org != asn_name:
                entries.append(make_finding(org, "Censys Organization", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))
    return entries

def extract_services(ip: str, result: dict) -> List[dict]:
    entries = []
    services = result.get("services", [])
    seen_ports = set()
    for svc in services:
        port = svc.get("port", 0)
        if port in seen_ports:
            continue
        seen_ports.add(port)
        service_name = svc.get("service_name", svc.get("name", ""))
        transport = svc.get("transport_protocol", "")
        software = svc.get("software", [])
        cert_info = svc.get("certificate", {})
        http = svc.get("http", {})

        entity_str = f"{ip}:{port} ({service_name})" if service_name else f"{ip}:{port}"
        try:
            svc_name_by_port = socket.getservbyport(port)
            if not service_name:
                service_name = svc_name_by_port
        except:
            pass

        risk, threat = classify_port_risk(port, service_name)
        color_map = {"High Risk": "red", "Elevated Risk": "orange", "Standard Target": "yellow", "Low Profile": "slate"}

        raw_parts = [f"port={port}", f"service={service_name}", f"transport={transport}"]
        if software:
            for sw in software:
                if isinstance(sw, dict):
                    product = sw.get("product", "")
                    version = sw.get("version", "")
                    if product:
                        raw_parts.append(f"software={product} {version}".strip())

        entries.append(make_finding(entity_str, "Censys Service", "Censys",
            confidence="High", color=color_map.get(risk, "slate"),
            threat_level=threat, status="Open",
            resolution=ip,
            raw_data="; ".join(raw_parts),
            tags=[service_name.lower(), str(port)]))

        if software:
            for sw in software[:3]:
                if isinstance(sw, dict):
                    product = sw.get("product", "")
                    version = sw.get("version", "")
                    category = sw.get("category", "")
                    if product:
                        sw_entity = f"{product} {version}".strip()
                        entries.append(make_finding(sw_entity, "Censys Software", "Censys",
                            confidence="High", color="orange", threat_level="Informational",
                            resolution=f"{ip}:{port}",
                            raw_data=f"Port {port}: {sw_entity} ({category})" if category else f"Port {port}: {sw_entity}",
                            tags=[product.lower() if product else "unknown"]))

        if http:
            http_title = http.get("title", "")
            http_server = http.get("server", "")
            http_status = http.get("response_code", "")
            if http_title:
                entries.append(make_finding(http_title[:200], "HTTP Title", "Censys",
                    confidence="High", color="blue", threat_level="Informational",
                    resolution=f"{ip}:{port}",
                    raw_data=f"Title: {http_title[:200]}"))
            if http_server:
                entries.append(make_finding(http_server[:200], "HTTP Server Header", "Censys",
                    confidence="High", color="orange", threat_level="Informational",
                    resolution=f"{ip}:{port}",
                    raw_data=f"Server: {http_server[:200]}"))
            if http_status:
                entries.append(make_finding(f"HTTP {http_status} on {ip}:{port}", "HTTP Status", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))

        if cert_info and isinstance(cert_info, dict):
            cert_parsed = parse_censys_cert(cert_info)
            entries.extend(cert_parsed)

    if services:
        entries.append(make_finding(f"{len(seen_ports)} services on {ip}", "Censys Service Summary", "Censys",
            confidence="High", color="purple", threat_level="Informational",
            raw_data=f"Ports: {', '.join(map(str, sorted(seen_ports)))}",
            tags=["service-summary"]))

    return entries

def parse_censys_cert(cert_info: dict) -> List[dict]:
    entries = []
    issuer = cert_info.get("issuer", {})
    subject = cert_info.get("subject", {})
    fingerprint = cert_info.get("fingerprint", {}).get("sha256", "")
    serial = cert_info.get("serial_number", "")
    validity = cert_info.get("validity", {})
    not_before = validity.get("start", "")
    not_after = validity.get("end", "")

    if issuer:
        issuer_str = "; ".join(f"{k}={v}" for k, v in issuer.items() if v)
        if issuer_str:
            entries.append(make_finding(issuer_str[:200], "Censys Cert Issuer", "Censys",
                confidence="High", color="emerald", threat_level="Informational",
                raw_data=issuer_str[:1000]))
    if subject:
        subject_str = "; ".join(f"{k}={v}" for k, v in subject.items() if v)
        if subject_str:
            entries.append(make_finding(subject_str[:200], "Censys Cert Subject", "Censys",
                confidence="High", color="emerald", threat_level="Informational"))
    if fingerprint:
        entries.append(make_finding(fingerprint[:64], "Censys Cert Fingerprint (SHA256)", "Censys",
            confidence="High", color="slate", threat_level="Informational"))
    if serial:
        entries.append(make_finding(serial, "Censys Cert Serial", "Censys",
            confidence="High", color="slate", threat_level="Informational"))
    if not_before and not_after:
        entries.append(make_finding(f"Valid: {not_before} to {not_after}", "Censys Cert Validity", "Censys",
            confidence="High", color="emerald", threat_level="Informational",
            raw_data=f"From: {not_before}, To: {not_after}"))
    return entries

def extract_vulnerability_indicators(ip: str, result: dict) -> List[dict]:
    entries = []
    labels = result.get("labels", [])
    if labels and isinstance(labels, list):
        for label in labels[:15]:
            entries.append(make_finding(label, "Censys Label/Tag", "Censys",
                confidence="Medium", color="orange", threat_level="Elevated Risk",
                resolution=ip, raw_data=f"Label: {label}", tags=["censys-label"]))

    services = result.get("services", [])
    for svc in services:
        cve_list = svc.get("cves", []) if isinstance(svc, dict) else []
        if cve_list:
            for cve in cve_list[:5]:
                entries.append(make_finding(cve, "Censys Vulnerability Indicator", "Censys",
                    confidence="Medium", color="red", threat_level="High Risk",
                    resolution=ip,
                    raw_data=f"CVE: {cve} on {ip}:{svc.get('port', '')}",
                    tags=["cve", "vulnerability"]))

    return entries

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    host_results = await query_hosts(normalized, client)
    for result in host_results:
        if not isinstance(result, dict):
            continue
        ip = result.get("ip", result.get("host", ""))
        if not ip:
            continue

        findings.append(make_finding(ip, "Censys IP Address", "Censys",
            confidence="High", color="slate", threat_level="Informational",
            status="Found", resolution=normalized,
            raw_data=f"Target: {normalized} resolved to {ip}",
            tags=["ip-address"]))

        findings.extend(extract_location_info(result))
        findings.extend(extract_asn_info(result))
        findings.extend(extract_services(ip, result))
        findings.extend(extract_vulnerability_indicators(ip, result))

        os_info = result.get("operating_system", {})
        if isinstance(os_info, dict):
            os_name = os_info.get("name", "")
            if os_name:
                findings.append(make_finding(os_name, "Censys OS Detection", "Censys",
                    confidence="Medium", color="orange", threat_level="Informational",
                    resolution=ip, raw_data=f"OS: {os_name}",
                    tags=[os_name.lower().replace(" ", "-")]))

        transport_ports = {}
        services = result.get("services", [])
        for svc in services:
            transport = svc.get("transport_protocol", "")
            port = svc.get("port", 0)
            if transport:
                if transport not in transport_ports:
                    transport_ports[transport] = []
                transport_ports[transport].append(str(port))
        for transport, ports in transport_ports.items():
            findings.append(make_finding(f"{transport.upper()}: {', '.join(ports[:10])}",
                f"Censys {transport.upper()} Ports", "Censys",
                confidence="High", color="slate", threat_level="Informational",
                resolution=ip, raw_data=f"Transport: {transport} on ports: {', '.join(ports)}"))

        if services:
            tls_services = [s for s in services if s.get("service_name", "").lower() in {"https", "tls", "ssl"} or s.get("transport_protocol") == "tcp" and s.get("port") in {443, 8443, 465, 993, 995, 636}]
            for tls_svc in tls_services[:5]:
                tls_info = tls_svc.get("tls", {}) or tls_svc.get("ssl", {})
                if isinstance(tls_info, dict):
                    version = tls_info.get("version", "")
                    cipher_info = tls_info.get("cipher", {})
                    cipher_name = ""
                    if isinstance(cipher_info, dict):
                        cipher_name = cipher_info.get("name", "")
                    elif isinstance(cipher_info, str):
                        cipher_name = cipher_info
                    if version:
                        findings.append(make_finding(f"TLS {version} on port {tls_svc.get('port')}",
                            "Censys TLS Version", "Censys",
                            confidence="High", color="emerald" if version not in TLS_WEAK_VERSIONS else "red",
                            threat_level="Informational" if version not in TLS_WEAK_VERSIONS else "High Risk",
                            resolution=ip,
                            raw_data=f"Port {tls_svc.get('port')}: {version}",
                            tags=["tls"]))
                    if cipher_name:
                        findings.append(make_finding(cipher_name, "Censys TLS Cipher", "Censys",
                            confidence="High", color="slate", threat_level="Informational",
                            resolution=ip, raw_data=f"Cipher: {cipher_name}"))
                    tls_issues = analyze_tls_security(cipher_name, version)
                    for issue in tls_issues:
                        findings.append(make_finding(issue["entity"], issue["type"], "Censys",
                            confidence="High", color=issue["color"], threat_level=issue["threat"],
                            resolution=ip, tags=["tls-weakness"]))

    cert_hits = await query_certificates(normalized, client)
    if cert_hits:
        seen_cns = set()
        for hit in cert_hits[:30]:
            if not isinstance(hit, dict):
                continue
            names = hit.get("names", [])
            cn = hit.get("common_name", "")
            if isinstance(names, list):
                for name in names:
                    if isinstance(name, str) and name.endswith(normalized) and name not in seen_cns:
                        seen_cns.add(name)
                        findings.append(make_finding(name, "Censys Cert SAN Discovery", "Censys",
                            confidence="High", color="emerald", threat_level="Informational",
                            status="Found", resolution=normalized,
                            tags=["subdomain", "cert-discovery"]))
            if cn and cn not in seen_cns and isinstance(cn, str):
                seen_cns.add(cn)
                findings.append(make_finding(cn, "Censys Cert Common Name", "Censys",
                    confidence="High", color="emerald", threat_level="Informational",
                    resolution=normalized, tags=["cert-cn"]))

            issuer_name = hit.get("issuer", {}).get("common_name", "") if isinstance(hit.get("issuer"), dict) else ""
            if issuer_name:
                findings.append(make_finding(issuer_name, "Censys Cert Issuer CN", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))

            fingerprint = hit.get("fingerprint", {}).get("sha256", "")
            if fingerprint:
                findings.append(make_finding(fingerprint[:64], "Censys Cert Fingerprint", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))

            # Certificate validity period
            validity = hit.get("validity", {})
            if isinstance(validity, dict):
                valid_from = validity.get("start", "")
                valid_to = validity.get("end", "")
                if valid_from and valid_to:
                    findings.append(make_finding(f"Valid: {valid_from[:10]} to {valid_to[:10]}", "Censys Cert Validity Period", "Censys",
                        confidence="High", color="emerald", threat_level="Informational",
                        raw_data=f"From: {valid_from}, To: {valid_to}"))

            # Signature algorithm
            sig_algo = hit.get("signature_algorithm", {}).get("name", hit.get("sig_alg", ""))
            if sig_algo:
                findings.append(make_finding(f"Sig Algorithm: {sig_algo}", "Censys Cert Signature Algorithm", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))

            # Key type
            key_algo = hit.get("key_algorithm", {}).get("name", "")
            key_size = hit.get("key_size", hit.get("key_length", 0))
            if key_algo:
                key_str = f"{key_algo} {key_size}" if key_size else key_algo
                findings.append(make_finding(key_str, "Censys Cert Key Algorithm", "Censys",
                    confidence="High", color="slate", threat_level="Informational"))

        if seen_cns:
            findings.append(make_finding(f"{len(seen_cns)} unique names from Censys certs",
                "Censys Cert Summary", "Censys",
                confidence="High", color="purple", threat_level="Informational",
                raw_data=f"Names: {', '.join(sorted(seen_cns)[:15])}",
                tags=["cert-summary"]))

    subdomain_hits = await query_subdomains(normalized, client)
    if subdomain_hits:
        seen_subs = set()
        for entry in subdomain_hits[:50]:
            if isinstance(entry, dict):
                name = entry.get("name", "")
            elif isinstance(entry, str):
                name = entry
            else:
                continue
            if name and name not in seen_subs:
                full_name = f"{name}.{normalized}"
                seen_subs.add(name)
                findings.append(make_finding(full_name, "Censys Subdomain Discovery", "Censys",
                    confidence="High", color="blue", threat_level="Informational",
                    status="Found", resolution=normalized,
                    raw_data=f"Subdomain: {full_name}",
                    tags=["subdomain"]))
        if seen_subs:
            findings.append(make_finding(f"{len(seen_subs)} subdomains from Censys",
                "Censys Subdomain Summary", "Censys",
                confidence="High", color="purple", threat_level="Informational",
                tags=["subdomain-summary"]))

    # Additional host search
    host_search_hits = await query_host_search(normalized, client)
    for hit in host_search_hits[:10]:
        hit_ip = hit.get("ip", "")
        if hit_ip:
            findings.append(make_finding(f"{hit_ip}", "Censys Host Search Result", "Censys",
                confidence="Medium", color="slate", threat_level="Informational",
                resolution=normalized, tags=["host-search"]))

    if not host_results and not cert_hits and not subdomain_hits and not host_search_hits:
        findings.append(make_finding(normalized, "Censys No Results", "Censys",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found",
            resolution=normalized,
            raw_data="No data returned from any Censys API endpoint",
            tags=["empty"]))

    return findings
