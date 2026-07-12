import httpx
import re
import socket
import asyncio
import json
import time
import base64
from typing import List, Optional, Dict
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

DNSDUMPSTER_URL = "https://dnsdumpster.com"
HACKERTARGET_URL = "https://api.hackertarget.com"
DNSLYTICS_URL = "https://www.dnslytics.com"
YOUGETSIGNAL_URL = "https://www.yougetsignal.com"

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

async def fetch_with_retry(client: httpx.AsyncClient, url: str, max_retries: int = 3, **kwargs) -> Optional[httpx.Response]:
    for attempt in range(max_retries):
        try:
            resp = await safe_fetch(client, url, **kwargs)
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                wait = 2 ** attempt
                await asyncio.sleep(wait)
                continue
            else:
                return resp
        except:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            return None
    return None

async def post_with_retry(client: httpx.AsyncClient, url: str, data: dict, max_retries: int = 3, **kwargs) -> Optional[httpx.Response]:
    for attempt in range(max_retries):
        try:
            resp = await safe_fetch(client, url, data=data, **kwargs)
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                wait = 2 ** attempt
                await asyncio.sleep(wait)
                continue
            else:
                return resp
        except:
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            return None
    return None

async def fetch_dnsdumpster_csrf(client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await fetch_with_retry(client, DNSDUMPSTER_URL, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp:
            match = re.search(r'name="_csrf"[^>]*value="([^"]+)"', resp.text)
            if match:
                return match.group(1)
        return None
    except:
        return None

async def query_dnsdumpster(target: str, csrf: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        post_resp = await post_with_retry(client,
            DNSDUMPSTER_URL,
            data={"_csrf": csrf, "targetip": target, "user": "free"},
            timeout=35.0,
            max_retries=3,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Referer": DNSDUMPSTER_URL,
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )
        if post_resp:
            return post_resp.text
        return None
    except:
        return None

async def query_dnsdumpster_fallback(target: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await fetch_with_retry(client,
            f"{DNSDUMPSTER_URL}/dns/?q={target}",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp and "error" not in resp.text.lower():
            return resp.text
    except:
        pass
    return None

async def query_hackertarget_dns(target: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await fetch_with_retry(client,
            f"{HACKERTARGET_URL}/dnslookup/?q={target}",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp and resp.status_code == 200 and "error" not in resp.text.lower():
            return resp.text
        return None
    except:
        return None

async def query_dnslytics(target: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await fetch_with_retry(client,
            f"{DNSLYTICS_URL}/domain/{target}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp:
            subdomains = re.findall(rf'([\w.-]+\.{re.escape(target)})', resp.text, re.IGNORECASE)
            if subdomains:
                return "\n".join(set(subdomains))
    except:
        pass
    return None

async def query_yougetsignal(target: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{YOUGETSIGNAL_URL}/what-is-my-ip-address/",
        }
        resp = await safe_fetch(client, 
            f"{YOUGETSIGNAL_URL}/tools/web-sites-on-web-server/php/ip-check.php",
            data={"remoteAddress": target, "checktype": "domain"},
            timeout=20.0,
            headers=headers
        )
        if resp.status_code == 200:
            json_data = resp.json()
            if "domain" in json_data:
                domains = json_data.get("domain", [])
                return "\n".join(d.get("", "") for d in domains[:30])
    except:
        pass
    return None

async def query_reverse_dns(ip: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0] if socket.gethostbyaddr(ip) else "")
        return hostname
    except:
        return None

def parse_dnsdumpster_html(html: str, target: str) -> Dict[str, List[dict]]:
    results: Dict[str, List[dict]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "SRV": [], "PTR": [], "subdomains": []}
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

    # Extract hostmap image reference
    img_pattern = re.compile(r'<img[^>]*src="([^"]*hostmap[^"]*)"[^>]*>', re.IGNORECASE)
    for match in img_pattern.finditer(html):
        img_src = match.group(1)
        if img_src.startswith("/"):
            img_src = f"https://dnsdumpster.com{img_src}"
        results["hostmap"] = img_src

    # Extract SRV records
    srv_pattern = re.compile(r'_(\w+)\._(tcp|udp)\.' + re.escape(target), re.IGNORECASE)
    for match in srv_pattern.finditer(html):
        results["SRV"].append({"name": match.group(0), "value": f"_{match.group(1)}._({match.group(2)})"})

    return results

def parse_hackertarget_output(text: str, target: str) -> Dict[str, List[dict]]:
    results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": []}
    if not text:
        return results
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = re.split(r'\s+', line, maxsplit=3)
        if len(parts) >= 3:
            host_part = parts[0].lower()
            ttl_part = parts[1]
            rr_part = parts[2].upper()
            value_part = parts[3] if len(parts) > 3 else ""
            if target in host_part or target in value_part:
                if rr_part in results:
                    results[rr_part].append({"name": host_part, "value": value_part, "ttl": ttl_part, "source": "hackertarget"})
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

    # 1. Primary: DNSDumpster with retry
    csrf = await fetch_dnsdumpster_csrf(client)
    dnsdumpster_html = None
    if csrf:
        dnsdumpster_html = await query_dnsdumpster(normalized, csrf, client)

    # 2. Fallback: try direct DNSDumpster query URL if POST fails
    if not dnsdumpster_html:
        dnsdumpster_html = await query_dnsdumpster_fallback(normalized, client)
        if dnsdumpster_html:
            findings.append(make_finding(
                "DNSDumpster fallback query used (POST failed, used GET)",
                "DNSDumpster Query Mode",
                "DNSDumpster",
                confidence="Medium", color="yellow", threat_level="Informational",
                raw_data="Fell back to GET-based DNSDumpster query",
                tags=["dnsdumpster", "fallback"]
            ))

    # 3. Secondary: HackerTarget
    hackertarget_dns = await query_hackertarget_dns(normalized, client)

    # 4. Tertiary: DNSLyrics
    dnslytics_data = await query_dnslytics(normalized, client)

    # 5. Quaternary: YouGetSignal (if available)
    yougetsignal_data = None
    try:
        yougetsignal_data = await query_yougetsignal(normalized, client)
    except:
        pass

    parsed_data = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": [], "SRV": [], "PTR": [], "subdomains": []}
    hostmap_url = None

    # Parse DNSDumpster HTML
    if dnsdumpster_html:
        parsed = parse_dnsdumpster_html(dnsdumpster_html, normalized)
        for key in parsed:
            if key == "hostmap":
                hostmap_url = parsed[key]
            elif key in parsed_data:
                parsed_data[key].extend(parsed[key])

        if hostmap_url:
            findings.append(make_finding(
                f"Hostmap available: {hostmap_url}",
                "DNSDumpster Hostmap Image",
                "DNSDumpster",
                confidence="Medium", color="slate", threat_level="Informational",
                raw_data=f"DNS hostmap image URL: {hostmap_url}",
                tags=["hostmap", "visualization", "dnsdumpster"]
            ))

    # Parse HackerTarget
    if hackertarget_dns:
        ht_data = parse_hackertarget_output(hackertarget_dns, normalized)
        for key in ht_data:
            if key in parsed_data:
                parsed_data[key].extend(ht_data[key])

    # Merge DNSLyrics data as subdomains
    if dnslytics_data:
        for line in dnslytics_data.strip().split("\n"):
            line = line.strip().lower()
            if line.endswith("." + normalized) and line not in [s["name"] for s in parsed_data["subdomains"]]:
                parsed_data["subdomains"].append({"name": line, "type": "subdomain", "source": "dnslytics"})

    if yougetsignal_data:
        for line in yougetsignal_data.strip().split("\n"):
            line = line.strip().lower()
            if line.endswith("." + normalized) and line not in [s["name"] for s in parsed_data["subdomains"]]:
                parsed_data["subdomains"].append({"name": line, "type": "subdomain", "source": "yougetsignal"})

    # Collect all unique subdomains
    all_subdomains = set()
    subdomain_sources = defaultdict(set)
    for rr_type, records in parsed_data.items():
        if rr_type == "subdomains":
            for sd in records:
                all_subdomains.add(sd["name"])
                source = sd.get("source", "dnsdumpster")
                subdomain_sources[sd["name"]].add(source)
        else:
            for rec in records:
                name = rec.get("name", "").lower().rstrip(".")
                if name and name != normalized and name.endswith("." + normalized):
                    all_subdomains.add(name)
                    source = rec.get("source", "dnsdumpster")
                    subdomain_sources[name].add(source)

    # Per-subdomain findings
    if all_subdomains:
        for subdomain in sorted(all_subdomains)[:60]:
            try:
                ip = resolve_subdomain_ip(subdomain)
                service = guess_service(subdomain)
                color, threat_level, tags = classify_dns_finding(subdomain, ip or "")
                sources_list = list(subdomain_sources.get(subdomain, ["dnsdumpster"]))

                findings.append(make_finding(
                    subdomain,
                    f"Subdomain ({', '.join(sources_list)})",
                    "DNSDumpster",
                    confidence="High", color=color,
                    threat_level=threat_level,
                    status="Found", resolution=ip or "Unresolved",
                    raw_data=f"Subdomain: {subdomain}, Service: {service}, Sources: {', '.join(sources_list)}" if service else f"Subdomain: {subdomain}, Sources: {', '.join(sources_list)}",
                    tags=["subdomain"] + tags + sources_list))

                if ip:
                    findings.append(make_finding(
                        f"{subdomain} -> {ip}", "DNS Resolution", "DNSDumpster",
                        confidence="High", color="slate", threat_level="Informational",
                        resolution=ip, status="Resolved",
                        raw_data=f"DNS A record: {subdomain} = {ip}",
                        tags=["dns-resolution", "a-record"]))
            except:
                pass

        # Source breakdown
        source_counts = defaultdict(int)
        for sources in subdomain_sources.values():
            for s in sources:
                source_counts[s] += 1
        for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            findings.append(make_finding(
                f"{src}: {count} subdomains",
                "Subdomain Source Breakdown",
                "DNSDumpster",
                confidence="High", color="blue", threat_level="Informational",
                raw_data=f"Source '{src}' contributed {count} subdomains",
                tags=["source-stats", src]
            ))

        findings.append(make_finding(
            f"{len(all_subdomains)} subdomains discovered on {normalized}",
            "DNSDumpster Subdomain Summary",
            "DNSDumpster",
            confidence="High", color="purple", threat_level="Informational",
            resolution=normalized,
            raw_data=f"Total subdomains: {len(all_subdomains)}, Sources: {len(subdomain_sources)}",
            tags=["subdomain-summary"]))

    # Record-type findings
    for rr_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR"]:
        records = parsed_data.get(rr_type, [])
        if not records:
            continue
        seen_values = set()
        for rec in records:
            name = rec.get("name", "").lower().rstrip(".")
            value = rec.get("value", "")
            ttl = rec.get("ttl", "")
            source = rec.get("source", "dnsdumpster")

            if value in seen_values:
                continue
            seen_values.add(value)

            color = RECORD_COLORS.get(rr_type, "slate")

            if rr_type == "MX":
                value_clean = value.rstrip(".")
                priority_match = re.search(r'\b(\d+)\b', value[:10]) if " " in value else None
                if priority_match:
                    priority = priority_match.group(1)
                    findings.append(make_finding(
                        f"MX: {value_clean} (priority {priority}) [{source}]",
                        "DNS MX Record", "DNSDumpster",
                        confidence="High", color=color, threat_level="Standard Target",
                        resolution=value_clean,
                        raw_data=f"MX: {value_clean}, Priority: {priority}, Source: {source}",
                        tags=["mx", "dns"]))
                    continue
            elif rr_type == "NS":
                value_clean = value.rstrip(".")
                findings.append(make_finding(
                    f"NS: {value_clean} [{source}]", "DNS NS Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    resolution=value_clean,
                    raw_data=f"Nameserver: {value_clean}, Source: {source}",
                    tags=["ns", "dns"]))
                continue
            elif rr_type == "TXT":
                txt_preview = value[:120]
                if "v=spf1" in value:
                    findings.append(make_finding(
                        f"SPF: {txt_preview} [{source}]", "DNS SPF Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        raw_data=f"SPF: {txt_preview[:500]}",
                        tags=["spf", "email-security"]))
                    continue
                elif "dkim" in name.lower():
                    findings.append(make_finding(
                        f"DKIM: {name}: {txt_preview} [{source}]", "DNS DKIM Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        tags=["dkim", "email-security"]))
                    continue
                elif "_dmarc" in name.lower():
                    findings.append(make_finding(
                        f"DMARC: {txt_preview} [{source}]", "DNS DMARC Record", "DNSDumpster",
                        confidence="High", color="emerald", threat_level="Informational",
                        tags=["dmarc", "email-security"]))
                    continue
                else:
                    findings.append(make_finding(
                        f"TXT: {name} -> {txt_preview} [{source}]", "DNS TXT Record", "DNSDumpster",
                        confidence="High", color=color, threat_level="Informational",
                        raw_data=f"TXT: {value[:500]}",
                        tags=["txt", "dns"]))
                    continue
            elif rr_type == "CNAME":
                value_clean = value.rstrip(".")
                findings.append(make_finding(
                    f"CNAME: {name} -> {value_clean} [{source}]", "DNS CNAME Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    resolution=value_clean,
                    raw_data=f"CNAME: {name} -> {value_clean}, Source: {source}",
                    tags=["cname", "dns"]))
                continue
            elif rr_type == "SOA":
                findings.append(make_finding(
                    f"SOA: {value[:200]} [{source}]", "DNS SOA Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    raw_data=f"SOA: {value[:500]}",
                    tags=["soa", "dns"]))
                continue
            elif rr_type == "SRV":
                findings.append(make_finding(
                    f"SRV: {name} -> {value} [{source}]", "DNS SRV Record", "DNSDumpster",
                    confidence="High", color=color, threat_level="Informational",
                    raw_data=f"SRV: {name} = {value}",
                    tags=["srv", "dns"]))
                continue

            if rr_type in {"A", "AAAA"}:
                color_rec, threat, tags_rec = classify_dns_finding(name, value, rr_type)
                findings.append(make_finding(
                    f"{rr_type}: {name} -> {value} [{source}]", f"DNS {rr_type} Record", "DNSDumpster",
                    confidence="High", color=color_rec, threat_level=threat,
                    resolution=value,
                    raw_data=f"{rr_type}: {name} = {value}, Source: {source}",
                    tags=[rr_type.lower(), "dns"] + tags_rec))

    # IP-to-subdomain mapping (reverse mapping)
    ip_subdomains_map = defaultdict(list)
    for rec in parsed_data.get("A", []):
        ip = rec.get("value", "")
        name = rec.get("name", "").lower().rstrip(".")
        if ip and name:
            ip_subdomains_map[ip].append(name)
    for rec in parsed_data.get("AAAA", []):
        ip = rec.get("value", "")
        name = rec.get("name", "").lower().rstrip(".")
        if ip and name:
            ip_subdomains_map[ip].append(name)

    if len(ip_subdomains_map) > 0:
        for ip, subs in sorted(ip_subdomains_map.items(), key=lambda x: -len(x[1]))[:5]:
            if len(subs) > 1:
                findings.append(make_finding(
                    f"IP {ip} hosts {len(subs)} subdomains: {', '.join(subs[:5])}",
                    "IP-to-Subdomain Mapping",
                    "DNSDumpster",
                    confidence="High", color="blue", threat_level="Informational",
                    resolution=ip,
                    raw_data=f"IP {ip} has {len(subs)} associated subdomains",
                    tags=["ip-mapping", "co-hosting"]))

    # Secondary source usage notification
    if hackertarget_dns:
        findings.append(make_finding(
            "HackerTarget DNS Lookup used as supplementary source",
            "Supplementary Source: HackerTarget",
            "DNSDumpster",
            confidence="High", color="slate", threat_level="Informational",
            resolution=normalized, tags=["supplementary", "hackertarget"]))

    if dnslytics_data:
        findings.append(make_finding(
            "DNSLyrics used as supplementary subdomain source",
            "Supplementary Source: DNSLyrics",
            "DNSDumpster",
            confidence="Low", color="slate", threat_level="Informational",
            resolution=normalized, tags=["supplementary", "dnslytics"]))

    if yougetsignal_data:
        findings.append(make_finding(
            "YouGetSignal used as supplementary subdomain source",
            "Supplementary Source: YouGetSignal",
            "DNSDumpster",
            confidence="Low", color="slate", threat_level="Informational",
            resolution=normalized, tags=["supplementary", "yougetsignal"]))

    # Record summary
    record_summary = {}
    for rr_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR"]:
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

    # Visualization graph data
    if all_subdomains:
        graph_nodes = [{"id": normalized, "type": "root", "ip": "", "color": "blue"}]
        graph_edges = []
        ip_nodes = set()

        sub_count = 0
        for sub in sorted(all_subdomains)[:40]:
            ip = resolve_subdomain_ip(sub)
            graph_nodes.append({"id": sub, "type": "subdomain", "ip": ip or "", "color": "green"})
            graph_edges.append({"source": normalized, "target": sub, "type": "dns"})
            if ip:
                ip_node = f"IP:{ip}"
                if ip_node not in ip_nodes:
                    ip_nodes.add(ip_node)
                    graph_nodes.append({"id": ip_node, "type": "ip", "ip": ip, "color": "red"})
                graph_edges.append({"source": sub, "target": ip_node, "type": "resolve"})

        findings.append(make_finding(
            json.dumps({"nodes": graph_nodes, "edges": graph_edges, "total": len(all_subdomains)})[:3000],
            "DNS Graph Visualization Data", "DNSDumpster",
            confidence="High", color="slate", threat_level="Informational",
            resolution=normalized,
            tags=["visualization", "dns-graph"]))

    # Empty result handling
    if not all_subdomains and not record_summary:
        findings.append(make_finding(
            normalized, "DNSDumpster No Results", "DNSDumpster",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found", resolution=normalized,
            raw_data="No DNS records found from DNSDumpster or fallback sources",
            tags=["empty"]))

    return findings
