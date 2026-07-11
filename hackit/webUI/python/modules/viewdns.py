import httpx
import re
import json
import ssl
import socket
import asyncio
from datetime import datetime
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

VIEWDNS_BASE = "https://viewdns.info"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

SPAM_DB_CHECK_URLS = [
    "https://www.spamhaus.org/lookup/",
    "https://check.spammy.net/",
]

SPAM_DATABASES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "all.s5h.net",
    "http.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "web.dnsbl.sorbs.net",
    "zombie.dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "db.wpbl.info",
    "ix.dnsbl.manitu.net",
    "tor.dnsbl.sectoor.de",
    "rbl-plus.mail-abuse.org",
    "dnsbl.inps.de",
    "bogons.cymru.com",
    "hostkarma.junkemailfilter.com",
    "multi.surbl.org",
    "dsn.rfc-ignorant.org",
    "dnsbl.njabl.org",
    "access.worldhosts.info",
    "blackholes.mail-abuse.org",
    "combined.njabl.org",
    "dnsbl.dronebl.org",
    "dnsbl.kempt.net",
    "dnsbl.rv-soft.info",
    "dnsbl.rymsho.ru",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "ips.backscatterer.org",
    "korea.services.net",
    "netblock.pedantic.org",
    "no-more-funn.moensted.dk",
    "psbl.surriel.com",
    "rbl.ipv6-world.net",
    "spam.abuse.ch",
    "spam.spamrats.com",
    "spamrbl.imp.ch",
    "torexit.danwin.se",
    "ubl.unsubscore.com",
    "virbl.bit.nl",
    "whois.rfc-ignorant.org",
    "wormrbl.imp.ch",
    "zen.spamhaus.org",
]

SSL_CIPHER_PREFERENCE = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
]

def extract_table_rows(html: str):
    rows = []
    for m in re.finditer(r'<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>', html, re.DOTALL):
        col1 = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        col2 = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        if col1 and col2:
            rows.append((col1, col2))
    return rows

def extract_single_cell_rows(html: str):
    items = []
    for m in re.finditer(r'<tr>\s*<td>(.*?)</td>\s*</tr>', html, re.DOTALL):
        cell = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        if cell:
            items.append(cell)
    return items

async def check_spam_database(ip: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        loop = asyncio.get_event_loop()
        for spam_db in SPAM_DATABASES[:15]:
            try:
                reversed_ip = ".".join(reversed(ip.split(".")))
                query = f"{reversed_ip}.{spam_db}"
                await loop.run_in_executor(
                    None, lambda: resolve_ip(query)
                )
                results.append(spam_db)
            except socket.gaierror:
                pass
    except Exception:
        pass
    return results

async def get_ssl_certificate_info(hostname: str) -> dict:
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
                cipher = s.cipher()
                version = s.version()
                s.close()
                return {
                    "issuer": dict(cert.get("issuer", [])),
                    "subject": dict(cert.get("subject", [])),
                    "sans": [v for _, v in cert.get("subjectAltName", [])],
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "cipher": cipher,
                    "protocol": version,
                    "serial": cert.get("serialNumber", ""),
                }
            except:
                return {}
        result = await loop.run_in_executor(None, fetch)
    except Exception:
        pass
    return result

async def check_http_security_headers(url: str, client: httpx.AsyncClient) -> dict:
    result = {}
    try:
        resp = await safe_fetch(client, url, timeout=10.0, follow_redirects=True,
                                headers={"User-Agent": USER_AGENT})
        headers = resp.headers
        result["status"] = resp.status_code
        result["content_type"] = headers.get("content-type", "")
        result["server"] = headers.get("server", "")
        result["x_powered_by"] = headers.get("x-powered-by", "")
        result["x_frame_options"] = headers.get("x-frame-options", "")
        result["x_xss_protection"] = headers.get("x-xss-protection", "")
        result["x_content_type_options"] = headers.get("x-content-type-options", "")
        result["strict_transport_security"] = headers.get("strict-transport-security", "")
        result["content_security_policy"] = headers.get("content-security-policy", "")
        result["referrer_policy"] = headers.get("referrer-policy", "")
        result["permissions_policy"] = headers.get("permissions-policy", "")
        result["set_cookie"] = headers.get("set-cookie", "")
        result["x_robots_tag"] = headers.get("x-robots-tag", "")
    except Exception:
        pass
    return result

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    resolved_ip = ""

    try:
        ip_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/reverseip/?host={domain}&t=1",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if ip_resp.status_code == 200:
            ip_hosts = extract_table_rows(ip_resp.text)
            ip_matches = re.findall(r'<b>\s*(\d+\.\d+\.\d+\.\d+)\s*</b>', ip_resp.text)
            resolved_ip = ip_matches[0] if ip_matches else ""

            for hostname, ip_addr in ip_hosts[:30]:
                if hostname and ip_addr:
                    findings.append(make_finding(
                        entity=hostname[:200],
                        ftype="ViewDNS Reverse IP",
                        source="ViewDNS",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        status="Resolved",
                        resolution=ip_addr.strip(),
                        raw_data=f"Host: {hostname} | IP: {ip_addr.strip()}",
                        tags=["reverse-ip", "hostname"]
                    ))

            if resolved_ip:
                findings.append(make_finding(
                    entity=resolved_ip,
                    ftype="Resolved IP Address",
                    source="ViewDNS",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Resolved",
                    resolution=resolved_ip,
                    raw_data=f"IP for {domain}: {resolved_ip}",
                    tags=["dns", "resolution"]
                ))

            total_hosts = re.search(r'There\s+are\s+(\d[\d,]*)\s+domains', ip_resp.text)
            if total_hosts:
                findings.append(make_finding(
                    entity=f"{total_hosts.group(1)} domains hosted on same IP",
                    type="Reverse IP Summary",
                    source="ViewDNS",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    resolution=resolved_ip,
                    tags=["reverse-ip", "summary"]
                ))
    except Exception:
        pass

    try:
        whois_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/whois/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if whois_resp.status_code == 200:
            whois_text = whois_resp.text
            whois_lines = []
            for line in whois_text.split("\n"):
                line_stripped = line.strip()
                if ":" in line_stripped and len(line_stripped) < 300:
                    key, _, val = line_stripped.partition(":")
                    key_stripped = key.strip()
                    val_stripped = val.strip()
                    if key_stripped and val_stripped:
                        whois_lines.append(f"{key_stripped}: {val_stripped}")
                        if any(k in key_stripped.lower() for k in ["registrar", "registrant", "creation", "expir", "updated", "name server", "dnssec", "status"]):
                            findings.append(make_finding(
                                entity=f"{key_stripped}: {val_stripped[:180]}",
                                ftype=f"WHOIS: {key_stripped}",
                                source="ViewDNS",
                                confidence="High",
                                color="slate",
                                threat_level="Informational",
                                raw_data=f"{key_stripped}: {val_stripped}",
                                tags=["whois", "domain-info"]
                            ))

            if whois_lines:
                findings.append(make_finding(
                    entity=f"WHOIS data retrieved for {domain}",
                    ftype="WHOIS Summary",
                    source="ViewDNS",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data="\n".join(whois_lines[:30]),
                    tags=["whois", "domain-info", "summary"]
                ))

            email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', whois_text)
            if email_match:
                findings.append(make_finding(
                    entity=email_match.group(0),
                    type="WHOIS Contact Email",
                    source="ViewDNS",
                    confidence="Medium",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Email: {email_match.group(0)}",
                    tags=["whois", "contact", "email"]
                ))
    except Exception:
        pass

    try:
        dns_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/dnsrecord/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if dns_resp.status_code == 200:
            dns_rows = extract_table_rows(dns_resp.text)
            seen_records = set()

            dns_record_count = {"A": 0, "AAAA": 0, "MX": 0, "NS": 0, "CNAME": 0, "TXT": 0, "SOA": 0, "SRV": 0, "CAA": 0}

            for rectype, value in dns_rows[:50]:
                record_key = f"{rectype}:{value}"
                if record_key not in seen_records:
                    seen_records.add(record_key)
                    record_color = "emerald"
                    if rectype.upper() in ("A", "AAAA"):
                        record_color = "blue"
                    elif rectype.upper() in ("MX", "TXT", "NS"):
                        record_color = "purple"
                    elif rectype.upper() == "CNAME":
                        record_color = "orange"
                    elif rectype.upper() == "SOA":
                        record_color = "yellow"

                    rt = rectype.upper()
                    if rt in dns_record_count:
                        dns_record_count[rt] += 1

                    findings.append(make_finding(
                        entity=f"{rt}: {value[:180]}",
                        ftype=f"DNS Record: {rt}",
                        source="ViewDNS",
                        confidence="High",
                        color=record_color,
                        threat_level="Informational",
                        raw_data=f"Type: {rt} | Value: {value}",
                        tags=["dns", f"dns-{rectype.lower()}"]
                    ))

            active_counts = {k: v for k, v in dns_record_count.items() if v > 0}
            if active_counts:
                findings.append(make_finding(
                    entity=f"DNS record summary: {', '.join(f'{k}: {v}' for k, v in active_counts.items())}",
                    type="DNS Record Summary",
                    source="ViewDNS",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    tags=["dns", "summary"]
                ))
    except Exception:
        pass

    try:
        ip_loc_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/ipinfo/?ip={resolved_ip if resolved_ip else domain}&t=1",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if ip_loc_resp.status_code == 200 and resolved_ip:
            loc_rows = extract_table_rows(ip_loc_resp.text)
            location_data = {}
            for key, value in loc_rows[:15]:
                if key.lower() in ("country", "city", "region", "isp", "organization", "latitude", "longitude", "asn"):
                    location_data[key] = value
                    findings.append(make_finding(
                        entity=f"{key}: {value[:180]}",
                        ftype=f"IP Location: {key}",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=resolved_ip,
                        raw_data=f"{key}: {value}",
                        tags=["geo", "ip-location"]
                    ))
            if location_data:
                findings.append(make_finding(
                    entity=f"Geo-location summary: {location_data.get('city', '?')}, {location_data.get('region', '?')}, {location_data.get('country', '?')}",
                    type="Geo-Location Summary",
                    source="ViewDNS",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    resolution=resolved_ip,
                    tags=["geo", "summary"]
                ))
    except Exception:
        pass

    try:
        rev_dns_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/reversedns/?ip={resolved_ip if resolved_ip else domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if rev_dns_resp.status_code == 200:
            ptr_pattern = re.compile(r'<tr><td[^>]*>(\d+\.\d+\.\d+\.\d+)</td><td[^>]*>([^<]+)</td></tr>')
            ptr_count = 0
            for m in ptr_pattern.finditer(rev_dns_resp.text):
                rev_ip = m.group(1).strip()
                rev_host = m.group(2).strip()
                if rev_host:
                    ptr_count += 1
                    findings.append(make_finding(
                        entity=f"{rev_ip} -> {rev_host}",
                        ftype="Reverse DNS (PTR)",
                        source="ViewDNS",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        resolution=rev_ip,
                        raw_data=f"PTR: {rev_ip} resolves to {rev_host}",
                        tags=["dns", "reverse-dns"]
                    ))
            if ptr_count > 0:
                findings.append(make_finding(
                    entity=f"{ptr_count} PTR records found for IP range",
                    ftype="Reverse DNS Summary",
                    source="ViewDNS",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    tags=["dns", "reverse-dns", "summary"]
                ))
    except Exception:
        pass

    try:
        ns_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/nameserver/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if ns_resp.status_code == 200:
            ns_matches = re.findall(r'<td[^>]*>([\w.-]+\.)</td>', ns_resp.text)
            ns_list = []
            for ns in ns_matches[:10]:
                ns_clean = ns.strip().rstrip(".")
                if ns_clean and ns_clean != domain and ns_clean not in ns_list:
                    ns_list.append(ns_clean)
                    findings.append(make_finding(
                        entity=ns_clean,
                        ftype="Nameserver",
                        source="ViewDNS",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"Nameserver: {ns_clean}",
                        tags=["dns", "nameserver"]
                    ))
            if ns_list:
                findings.append(make_finding(
                    entity=f"Nameservers: {', '.join(ns_list)}",
                    type="Nameserver Summary",
                    source="ViewDNS",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    tags=["dns", "nameserver", "summary"]
                ))
    except Exception:
        pass

    try:
        port_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/portscan/?host={domain}",
            timeout=25.0,
            headers={"User-Agent": USER_AGENT}
        )
        if port_resp.status_code == 200:
            port_rows = extract_single_cell_rows(port_resp.text)
            port_pattern = re.compile(r'(\d+)\s*[-:]\s*(open|filtered|closed)?', re.IGNORECASE)
            open_ports = []
            filtered_ports = []
            closed_ports = []

            for item in port_rows:
                pm = port_pattern.search(item)
                if pm:
                    port_num = pm.group(1)
                    status_val = pm.group(2) if pm.group(2) else "unknown"
                    if status_val.lower() == "open":
                        open_ports.append(port_num)
                    elif status_val.lower() == "filtered":
                        filtered_ports.append(port_num)
                    elif status_val.lower() == "closed":
                        closed_ports.append(port_num)

                    findings.append(make_finding(
                        entity=f"Port {port_num} ({status_val})",
                        type="ViewDNS Port Scan",
                        source="ViewDNS",
                        confidence="Low",
                        color="orange" if "open" in status_val.lower() else "slate",
                        threat_level="Elevated Risk" if status_val.lower() == "open" else "Informational",
                        raw_data=item[:200],
                        tags=["port-scan"]
                    ))

            findings.append(make_finding(
                entity=f"Port scan summary: {len(open_ports)} open, {len(filtered_ports)} filtered, {len(closed_ports)} closed",
                type="Port Scan Summary",
                source="ViewDNS",
                confidence="Medium",
                color="orange" if open_ports else "emerald",
                threat_level="Elevated Risk" if open_ports else "Informational",
                raw_data=f"Open: {', '.join(open_ports)} | Filtered: {', '.join(filtered_ports)}",
                tags=["port-scan", "summary"]
            ))
    except Exception:
        pass

    try:
        host_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/domainhistory/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if host_resp.status_code == 200:
            host_rows = extract_table_rows(host_resp.text)
            unique_ips = set()
            for date_val, ip_val in host_rows[:20]:
                if date_val and ip_val:
                    unique_ips.add(ip_val.strip())
                    findings.append(make_finding(
                        entity=f"{date_val}: {ip_val}",
                        ftype="Hosting History",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=ip_val.strip(),
                        raw_data=f"Date: {date_val} | IP: {ip_val}",
                        tags=["history", "hosting"]
                    ))
            if len(host_rows) > 10:
                findings.append(make_finding(
                    entity=f"... and {len(host_rows) - 10} more historical records ({len(unique_ips)} unique IPs)",
                    type="Hosting History Summary",
                    source="ViewDNS",
                    confidence="Low",
                    color="purple",
                    threat_level="Informational",
                    tags=["history", "summary"]
                ))
    except Exception:
        pass

    try:
        rdns_resp = await safe_fetch(client, 
            f"{VIEWDNS_BASE}/reversednsip/?ip={resolved_ip if resolved_ip else domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if rdns_resp.status_code == 200:
            rdns_pattern = re.compile(r'<b>\s*([\w.-]+\.[\w.-]+)\s*</b>')
            rdns_hosts = rdns_pattern.findall(rdns_resp.text)
            rdns_unique = set()
            for rdns_host in rdns_hosts[:15]:
                rdns_clean = rdns_host.strip().lower()
                if rdns_clean and rdns_clean not in rdns_unique:
                    rdns_unique.add(rdns_clean)
                    findings.append(make_finding(
                        entity=rdns_clean,
                        ftype="Reverse IP Hostnames",
                        source="ViewDNS",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"Reverse-host: {rdns_clean}",
                        tags=["reverse-ip", "hostname"]
                    ))
            if rdns_unique:
                findings.append(make_finding(
                    entity=f"{len(rdns_unique)} unique hostnames on same IP",
                    type="Reverse IP Hostnames Summary",
                    source="ViewDNS",
                    confidence="Low",
                    color="purple",
                    threat_level="Informational",
                    tags=["reverse-ip", "summary"]
                ))
    except Exception:
        pass

    try:
        spam_results = await check_spam_database(resolved_ip if resolved_ip else domain, client)
        if spam_results:
            for spam_db in spam_results:
                findings.append(make_finding(
                    entity=f"LISTED in {spam_db}",
                    ftype="Spam Database Check",
                    source="ViewDNS",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Blacklisted",
                    resolution=resolved_ip,
                    raw_data=f"Spam DB: {spam_db}",
                    tags=["spam", "blacklist", "reputation"]
                ))
            findings.append(make_finding(
                entity=f"Listed in {len(spam_results)}/{len(SPAM_DATABASES)} spam databases checked",
                type="Spam Database Summary",
                source="ViewDNS",
                confidence="High",
                color="red" if len(spam_results) > 3 else "orange",
                threat_level="High Risk" if len(spam_results) > 3 else "Elevated Risk",
                resolution=resolved_ip,
                raw_data=f"Spam DB listings: {', '.join(spam_results)}",
                tags=["spam", "blacklist", "summary"]
            ))
        else:
            findings.append(make_finding(
                entity=f"Not listed in any spam database checked",
                ftype="Spam Database Check",
                source="ViewDNS",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Clean",
                resolution=resolved_ip,
                tags=["spam", "blacklist", "clean"]
            ))
    except Exception:
        pass

    try:
        ssl_info = await get_ssl_certificate_info(domain)
        if ssl_info:
            if ssl_info.get("issuer"):
                issuer_str = str(ssl_info["issuer"])
                findings.append(make_finding(
                    entity=issuer_str[:200],
                    ftype="SSL Certificate Issuer",
                    source="ViewDNS",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["ssl", "certificate"]
                ))
            if ssl_info.get("protocol"):
                findings.append(make_finding(
                    entity=ssl_info["protocol"],
                    ftype="SSL/TLS Protocol",
                    source="ViewDNS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["ssl", "protocol"]
                ))
            if ssl_info.get("cipher"):
                cipher_name = ssl_info["cipher"][0] if isinstance(ssl_info["cipher"], tuple) else str(ssl_info["cipher"])
                findings.append(make_finding(
                    entity=cipher_name[:100],
                    ftype="SSL/TLS Cipher",
                    source="ViewDNS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["ssl", "cipher"]
                ))
            if ssl_info.get("sans"):
                for san in ssl_info["sans"][:5]:
                    findings.append(make_finding(
                        entity=san,
                        ftype="SSL Subject Alternative Name",
                        source="ViewDNS",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        resolution=domain,
                        tags=["ssl", "san"]
                    ))
    except Exception:
        pass

    try:
        sec_headers = await check_http_security_headers(f"https://{domain}", client)
        if sec_headers:
            if sec_headers.get("strict_transport_security"):
                findings.append(make_finding(
                    entity=f"HSTS: {sec_headers['strict_transport_security'][:100]}",
                    ftype="HTTP Security Header: HSTS",
                    source="ViewDNS",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["security", "http-header", "hsts"]
                ))
            if sec_headers.get("x_frame_options"):
                findings.append(make_finding(
                    entity=f"X-Frame-Options: {sec_headers['x_frame_options']}",
                    ftype="HTTP Security Header: X-Frame-Options",
                    source="ViewDNS",
                    confidence="High",
                    color="emerald" if sec_headers["x_frame_options"].upper() in ("DENY", "SAMEORIGIN") else "orange",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["security", "http-header"]
                ))
            if sec_headers.get("content_security_policy"):
                csp_issues = []
                csp = sec_headers["content_security_policy"]
                if "unsafe-inline" in csp:
                    csp_issues.append("unsafe-inline")
                if "unsafe-eval" in csp:
                    csp_issues.append("unsafe-eval")
                if csp_issues:
                    findings.append(make_finding(
                        entity=f"CSP allows: {', '.join(csp_issues)}",
                        type="HTTP Security: CSP Weakness",
                        source="ViewDNS",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        resolution=domain,
                        tags=["security", "csp", "weakness"]
                    ))
            if sec_headers.get("server"):
                findings.append(make_finding(
                    entity=f"Server: {sec_headers['server'][:100]}",
                    ftype="HTTP Server Header",
                    source="ViewDNS",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=domain,
                    tags=["http", "server"]
                ))
            status = sec_headers.get("status")
            if status:
                findings.append(make_finding(
                    entity=f"HTTP Status: {status}",
                    ftype="HTTP Response Status",
                    source="ViewDNS",
                    confidence="High",
                    color="emerald" if status < 400 else "red",
                    threat_level="Informational" if status < 400 else "Error",
                    resolution=domain,
                    tags=["http", "status"]
                ))
    except Exception:
        pass

    return findings
