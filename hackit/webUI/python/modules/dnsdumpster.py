import httpx
import re
import socket
import asyncio
import json
from typing import List, Optional, Dict
from urllib.parse import urlparse
from models import IntelligenceFinding
from osint_common import normalize_target, make_finding, resolve_dns

DNSDUMPSTER_URL = "https://dnsdumpster.com"
HACKERTARGET_URL = "https://api.hackertarget.com"

RECORD_COLORS = {
    "A": "blue",
    "AAAA": "blue",
    "MX": "orange",
    "NS": "purple",
    "TXT": "emerald",
    "CNAME": "cyan",
    "SOA": "slate",
    "SRV": "yellow",
    "PTR": "emerald",
}

SERVICE_GUESS = {
    "mail": "Mail Server",
    "smtp": "SMTP Server",
    "pop": "POP3 Server",
    "imap": "IMAP Server",
    "webmail": "Webmail",
    "cpanel": "cPanel",
    "ftp": "FTP Server",
    "ssh": "SSH",
    "vpn": "VPN Server",
    "remote": "Remote Access",
    "api": "API Server",
    "dev": "Development Server",
    "test": "Test Server",
    "stage": "Staging Server",
    "blog": "Blog",
    "wiki": "Wiki",
    "docs": "Documentation",
    "cdn": "CDN",
    "static": "Static Assets",
    "assets": "Assets Server",
    "img": "Image Server",
    "media": "Media Server",
    "video": "Video Server",
    "download": "Download Server",
    "support": "Support Portal",
    "help": "Help Desk",
    "status": "Status Page",
    "monitor": "Monitoring",
    "ns1": "Primary Nameserver",
    "ns2": "Secondary Nameserver",
    "ns3": "Tertiary Nameserver",
    "ns4": "Quaternary Nameserver",
    "dns": "DNS Server",
    "ntp": "NTP Server",
    "ldap": "LDAP Server",
    "radius": "RADIUS Server",
    "sip": "SIP Server",
}

async def fetch_dnsdumpster_csrf(client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await client.get(DNSDUMPSTER_URL, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            match = re.search(r'name="_csrf"[^>]*value="([^"]+)"', resp.text)
            if match:
                return match.group(1)
        return None
    except:
        return None

async def query_dnsdumpster(target: str, csrf: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        post_resp = await client.post(
            DNSDUMPSTER_URL,
            data={"_csrf": csrf, "targetip": target, "user": "free"},
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Referer": DNSDUMPSTER_URL,
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )
        if post_resp.status_code == 200:
            return post_resp.text
        return None
    except:
        return None

async def query_hackertarget_dns(target: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await client.get(f"{HACKERTARGET_URL}/dnslookup/?q={target}", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and "error" not in resp.text.lower():
            return resp.text
        return None
    except:
        return None

async def query_reverse_dns(ip: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0] if socket.gethostbyaddr(ip) else "")
        return hostname
    except:
        return None

def parse_dnsdumpster_html(html: str, target: str) -> Dict[str, List[dict]]:
    results: Dict[str, List[dict]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "SRV": [], "subdomains": []}
    if not html:
        return results

    subdomain_pattern = re.compile(rf'([\w.-]+\.{re.escape(target)})', re.IGNORECASE)
    subdomains = set()
    for match in subdomain_pattern.finditer(html):
        sub = match.group(1).lower()
        if sub != target:
            subdomains.add(sub)

    results["subdomains"] = [{"name": s, "type": "subdomain"} for s in sorted(subdomains)]

    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for sub in subdomains:
        sub_html_section = re.search(rf'{re.escape(sub)}[^<]*', html)
        if sub_html_section:
            ips = ip_pattern.findall(sub_html_section.group())
            for ip in ips:
                results["A"].append({"name": sub, "value": ip})
        for ip_match in ip_pattern.finditer(html):
            ip = ip_match.group(0)
            context_start = max(0, ip_match.start() - 200)
            context = html[context_start:ip_match.end() + 100]
            if sub in context.lower():
                results["A"].append({"name": sub, "value": ip})

    table_pattern = re.compile(r'<tr[^>]*>(.*?)</tr>', re.DOTALL)
    for table_match in table_pattern.finditer(html):
        row = table_match.group(1)
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(cells) >= 3:
            domain_cell = re.sub(r'<[^>]+>', '', cells[0]).strip()
            ip_cell = re.sub(r'<[^>]+>', '', cells[1]).strip()
            type_cell = re.sub(r'<[^>]+>', '', cells[2]).strip() if len(cells) > 2 else ""
            if domain_cell and ip_cell:
                rr_type = "A"
                if "MX" in type_cell.upper():
                    rr_type = "MX"
                elif "NS" in type_cell.upper():
                    rr_type = "NS"
                elif "TXT" in type_cell.upper():
                    rr_type = "TXT"
                elif "CNAME" in type_cell.upper():
                    rr_type = "CNAME"
                elif "SOA" in type_cell.upper():
                    rr_type = "SOA"
                if target.lower() in domain_cell.lower() or target.lower() in ip_cell.lower():
                    results[rr_type].append({"name": domain_cell, "value": ip_cell})

    return results

def guess_service(hostname: str) -> str:
    host_lower = hostname.lower().split(".")[0]
    for prefix, service in SERVICE_GUESS.items():
        if host_lower == prefix or host_lower.startswith(prefix):
            return service
    return ""

def classify_dns_finding(subdomain: str, ip: str = "", record_type: str = "A") -> tuple:
    service = guess_service(subdomain)
    if service in {"Mail Server", "SMTP Server", "IMAP Server", "POP3 Server", "Webmail"}:
        return ("orange", "Standard Target", [record_type.lower(), "mail"])
    if service in {"Primary Nameserver", "Secondary Nameserver", "DNS Server"}:
        return ("purple", "Standard Target", [record_type.lower(), "dns"])
    if service in {"VPN Server", "Remote Access", "SSH"}:
        return ("red", "Elevated Risk", [record_type.lower(), "remote-access"])
    if service in {"Development Server", "Test Server", "Staging Server"}:
        return ("yellow", "Informational", [record_type.lower(), "development"])
    if service in {"cPanel", "Management"}:
        return ("orange", "Elevated Risk", [record_type.lower(), "management"])
    return ("blue", "Informational", [record_type.lower()])

def resolve_subdomain_ip(subdomain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    csrf = await fetch_dnsdumpster_csrf(client)
    dnsdumpster_html = None
    if csrf:
        dnsdumpster_html = await query_dnsdumpster(normalized, csrf, client)

    hackertarget_dns = await query_hackertarget_dns(normalized, client)

    parsed_data = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "SRV": [], "subdomains": []}

    if dnsdumpster_html:
        parsed_data = parse_dnsdumpster_html(dnsdumpster_html, normalized)

    if hackertarget_dns:
        for line in hackertarget_dns.split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = re.split(r'\s+', line, maxsplit=3)
            if len(parts) >= 3:
                host_part = parts[0].lower()
                ttl_part = parts[1]
                rr_part = parts[2].upper()
                value_part = parts[3] if len(parts) > 3 else ""
                if normalized in host_part or normalized in value_part:
                    if rr_part in parsed_data:
                        parsed_data[rr_part].append({"name": host_part, "value": value_part, "ttl": ttl_part})

    all_subdomains = set()
    for rr_type, records in parsed_data.items():
        if rr_type == "subdomains":
            for sd in records:
                all_subdomains.add(sd["name"])
        else:
            for rec in records:
                name = rec.get("name", "").lower().rstrip(".")
                if name and name != normalized and name.endswith("." + normalized):
                    all_subdomains.add(name)

    if all_subdomains:
        for subdomain in sorted(all_subdomains)[:50]:
            ip = resolve_subdomain_ip(subdomain)
            service = guess_service(subdomain)
            color, threat_level, tags = classify_dns_finding(subdomain, ip or "")

            findings.append(make_finding(
                subdomain, "DNSDumpster Subdomain", "DNSDumpster",
                confidence="High", color=color,
                threat_level=threat_level,
                status="Found", resolution=ip or "Unresolved",
                raw_data=f"Subdomain: {subdomain}, Service: {service}" if service else f"Subdomain: {subdomain}",
                tags=["subdomain"] + tags))

            if ip:
                findings.append(make_finding(
                    f"{subdomain} -> {ip}", "DNS Resolution", "DNSDumpster",
                    confidence="High", color="slate", threat_level="Informational",
                    resolution=ip, status="Resolved",
                    raw_data=f"DNS A record: {subdomain} = {ip}",
                    tags=["dns-resolution", rr_type.lower() if rr_type else "a"]))

        findings.append(make_finding(
            f"{len(all_subdomains)} subdomains discovered on {normalized}",
            "DNSDumpster Subdomain Summary", "DNSDumpster",
            confidence="High", color="purple", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Total subdomains: {len(all_subdomains)}",
            tags=["subdomain-summary"]))

    for rr_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        records = parsed_data.get(rr_type, [])
        if not records:
            continue
        seen_values = set()
        for rec in records:
            name = rec.get("name", "").lower().rstrip(".")
            value = rec.get("value", "")
            ttl = rec.get("ttl", "")

            if value in seen_values:
                continue
            seen_values.add(value)

            color = RECORD_COLORS.get(rr_type, "slate")
            service_info = ""
            if rr_type == "MX":
                service_info = "Mail Exchange"
                value_clean = value.rstrip(".")
                priority_match = re.search(r'\b(\d+)\b', value[:10]) if " " in value else None
                if priority_match:
                    priority = priority_match.group(1)
                    findings.append(make_finding(
                        f"MX: {value_clean} (priority {priority})",
                        "DNS MX Record", "DNSDumpster",
                        confidence="High", color=color, threat_level="Standard Target",
                        resolution=value_clean,
                        raw_data=f"MX: {value_clean}, Priority: {priority}",
                        tags=["mx", "dns"]))
                    continue
            elif rr_type == "NS":
                service_info = "Nameserver"
                value_clean = value.rstrip(".")
                findings.append(make_finding(
                    f"NS: {value_clean}", "DNS NS Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    resolution=value_clean,
                    raw_data=f"Nameserver: {value_clean}",
                    tags=["ns", "dns"]))
                continue
            elif rr_type == "TXT":
                txt_preview = value[:120]
                service_info = "Text Record"
                if "v=spf1" in value:
                    findings.append(make_finding(
                        f"SPF: {txt_preview}", "DNS SPF Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        raw_data=f"SPF: {txt_preview}",
                        tags=["spf", "email-security"]))
                    continue
                elif "dkim" in name.lower():
                    findings.append(make_finding(
                        f"DKIM: {name}: {txt_preview}", "DNS DKIM Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        tags=["dkim", "email-security"]))
                    continue
                elif "_dmarc" in name.lower():
                    findings.append(make_finding(
                        f"DMARC: {txt_preview}", "DNS DMARC Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        tags=["dmarc", "email-security"]))
                    continue
                else:
                    findings.append(make_finding(
                        f"TXT: {name} -> {txt_preview}", "DNS TXT Record", "DNSDumpster",
                        confidence="High", color=color, threat_level="Informational",
                        raw_data=f"TXT: {value[:500]}",
                        tags=["txt", "dns"]))
                    continue
            elif rr_type == "CNAME":
                value_clean = value.rstrip(".")
                findings.append(make_finding(
                    f"CNAME: {name} -> {value_clean}", "DNS CNAME Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    resolution=value_clean,
                    raw_data=f"CNAME: {name} -> {value_clean}",
                    tags=["cname", "dns"]))
                continue
            elif rr_type == "SOA":
                findings.append(make_finding(
                    value[:200], "DNS SOA Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    raw_data=f"SOA: {value[:500]}",
                    tags=["soa", "dns"]))
                continue

            if rr_type in {"A", "AAAA"}:
                color_rec, threat, tags_rec = classify_dns_finding(name, value, rr_type)
                findings.append(make_finding(
                    f"{rr_type}: {name} -> {value}", f"DNS {rr_type} Record", "DNSDumpster",
                    confidence="High", color=color_rec, threat_level=threat,
                    resolution=value,
                    raw_data=f"{rr_type}: {name} = {value}",
                    tags=[rr_type.lower(), "dns"] + tags_rec))

    if hackertarget_dns:
        findings.append(make_finding(
            "HackerTarget DNS Lookup used as supplementary source",
            "DNS Supplementary Source", "DNSDumpster",
            confidence="High", color="slate", threat_level="Informational",
            resolution=normalized, tags=["supplementary"]))

    record_summary = {}
    for rr_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        count = len(parsed_data.get(rr_type, []))
        if count > 0:
            record_summary[rr_type] = count

    if record_summary:
        summary_parts = [f"{k}: {v}" for k, v in sorted(record_summary.items())]
        total_records = sum(record_summary.values())
        findings.append(make_finding(
            f"DNS Records: {', '.join(summary_parts)} (Total: {total_records})",
            "DNS Record Summary", "DNSDumpster",
            confidence="High", color="purple", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Total DNS records: {total_records}, Subdomains: {len(all_subdomains)}",
            tags=["dns-summary"]))

    if all_subdomains:
        graph_nodes = [{"id": normalized, "type": "root"}]
        graph_edges = []
        for sub in sorted(all_subdomains)[:30]:
            graph_nodes.append({"id": sub, "type": "subdomain"})
            graph_edges.append({"source": normalized, "target": sub, "type": "dns"})
        findings.append(make_finding(
            json.dumps({"nodes": graph_nodes, "edges": graph_edges})[:2000],
            "DNS Graph Visualization Data", "DNSDumpster",
            confidence="High", color="slate", threat_level="Informational",
            resolution=normalized,
            tags=["visualization", "dns-graph"]))

    if not all_subdomains and not record_summary:
        findings.append(make_finding(
            normalized, "DNSDumpster No Results", "DNSDumpster",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found", resolution=normalized,
            raw_data="No DNS records found from DNSDumpster",
            tags=["empty"]))

    return findings
