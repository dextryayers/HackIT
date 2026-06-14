import httpx
import re
import json
from datetime import datetime
from models import IntelligenceFinding

VIEWDNS_BASE = "https://viewdns.info"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

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

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        ip_resp = await client.get(
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
                    findings.append(IntelligenceFinding(
                        entity=hostname[:200],
                        type="ViewDNS Reverse IP",
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
                findings.append(IntelligenceFinding(
                    entity=resolved_ip,
                    type="Resolved IP Address",
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
                findings.append(IntelligenceFinding(
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
        whois_resp = await client.get(
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
                            findings.append(IntelligenceFinding(
                                entity=f"{key_stripped}: {val_stripped[:180]}",
                                type=f"WHOIS: {key_stripped}",
                                source="ViewDNS",
                                confidence="High",
                                color="slate",
                                threat_level="Informational",
                                raw_data=f"{key_stripped}: {val_stripped}",
                                tags=["whois", "domain-info"]
                            ))

            if whois_lines:
                findings.append(IntelligenceFinding(
                    entity=f"WHOIS data retrieved for {domain}",
                    type="WHOIS Summary",
                    source="ViewDNS",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data="\n".join(whois_lines[:30]),
                    tags=["whois", "domain-info", "summary"]
                ))

            email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', whois_text)
            if email_match:
                findings.append(IntelligenceFinding(
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
        dns_resp = await client.get(
            f"{VIEWDNS_BASE}/dnsrecord/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if dns_resp.status_code == 200:
            dns_rows = extract_table_rows(dns_resp.text)
            seen_records = set()
            for rectype, value in dns_rows[:40]:
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

                    findings.append(IntelligenceFinding(
                        entity=f"{rectype.upper()}: {value[:180]}",
                        type=f"DNS Record: {rectype.upper()}",
                        source="ViewDNS",
                        confidence="High",
                        color=record_color,
                        threat_level="Informational",
                        raw_data=f"Type: {rectype.upper()} | Value: {value}",
                        tags=["dns", f"dns-{rectype.lower()}"]
                    ))
    except Exception:
        pass

    try:
        ip_loc_resp = await client.get(
            f"{VIEWDNS_BASE}/ipinfo/?ip={resolved_ip if resolved_ip else domain}&t=1",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if ip_loc_resp.status_code == 200 and resolved_ip:
            loc_rows = extract_table_rows(ip_loc_resp.text)
            for key, value in loc_rows[:15]:
                if key.lower() in ("country", "city", "region", "isp", "organization", "latitude", "longitude", "asn"):
                    findings.append(IntelligenceFinding(
                        entity=f"{key}: {value[:180]}",
                        type=f"IP Location: {key}",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=resolved_ip,
                        raw_data=f"{key}: {value}",
                        tags=["geo", "ip-location"]
                    ))
    except Exception:
        pass

    try:
        rev_dns_resp = await client.get(
            f"{VIEWDNS_BASE}/reversedns/?ip={resolved_ip if resolved_ip else domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if rev_dns_resp.status_code == 200:
            ptr_pattern = re.compile(r'<tr><td[^>]*>(\d+\.\d+\.\d+\.\d+)</td><td[^>]*>([^<]+)</td></tr>')
            for m in ptr_pattern.finditer(rev_dns_resp.text):
                rev_ip = m.group(1).strip()
                rev_host = m.group(2).strip()
                if rev_host:
                    findings.append(IntelligenceFinding(
                        entity=f"{rev_ip} -> {rev_host}",
                        type="Reverse DNS (PTR)",
                        source="ViewDNS",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        resolution=rev_ip,
                        raw_data=f"PTR: {rev_ip} resolves to {rev_host}",
                        tags=["dns", "reverse-dns"]
                    ))
    except Exception:
        pass

    try:
        ns_resp = await client.get(
            f"{VIEWDNS_BASE}/nameserver/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if ns_resp.status_code == 200:
            ns_matches = re.findall(r'<td[^>]*>([\w.-]+\.)</td>', ns_resp.text)
            for ns in ns_matches[:8]:
                ns_clean = ns.strip().rstrip(".")
                if ns_clean and ns_clean != domain:
                    findings.append(IntelligenceFinding(
                        entity=ns_clean,
                        type="Nameserver",
                        source="ViewDNS",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        raw_data=f"Nameserver: {ns_clean}",
                        tags=["dns", "nameserver"]
                    ))
    except Exception:
        pass

    try:
        port_resp = await client.get(
            f"{VIEWDNS_BASE}/portscan/?host={domain}",
            timeout=25.0,
            headers={"User-Agent": USER_AGENT}
        )
        if port_resp.status_code == 200:
            port_rows = extract_single_cell_rows(port_resp.text)
            port_pattern = re.compile(r'(\d+)\s*[-:]\s*(open|filtered|closed)?', re.IGNORECASE)
            for item in port_rows:
                pm = port_pattern.search(item)
                if pm:
                    port_num = pm.group(1)
                    status_val = pm.group(2) if pm.group(2) else "unknown"
                    findings.append(IntelligenceFinding(
                        entity=f"Port {port_num} ({status_val})",
                        type="ViewDNS Port Scan",
                        source="ViewDNS",
                        confidence="Low",
                        color="orange" if "open" in status_val.lower() else "slate",
                        threat_level="Elevated Risk" if status_val.lower() == "open" else "Informational",
                        raw_data=item[:200],
                        tags=["port-scan"]
                    ))
    except Exception:
        pass

    try:
        host_resp = await client.get(
            f"{VIEWDNS_BASE}/domainhistory/?domain={domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if host_resp.status_code == 200:
            host_rows = extract_table_rows(host_resp.text)
            for date_val, ip_val in host_rows[:10]:
                if date_val and ip_val:
                    findings.append(IntelligenceFinding(
                        entity=f"{date_val}: {ip_val}",
                        type="Hosting History",
                        source="ViewDNS",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=ip_val.strip(),
                        raw_data=f"Date: {date_val} | IP: {ip_val}",
                        tags=["history", "hosting"]
                    ))
            if len(host_rows) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"... and {len(host_rows) - 10} more historical records",
                    type="Hosting History Summary",
                    source="ViewDNS",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["history", "summary"]
                ))
    except Exception:
        pass

    try:
        rdns_resp = await client.get(
            f"{VIEWDNS_BASE}/reversednsip/?ip={resolved_ip if resolved_ip else domain}",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if rdns_resp.status_code == 200:
            rdns_pattern = re.compile(r'<b>\s*([\w.-]+\.[\w.-]+)\s*</b>')
            rdns_hosts = rdns_pattern.findall(rdns_resp.text)
            for rdns_host in rdns_hosts[:5]:
                rdns_clean = rdns_host.strip()
                if rdns_clean and rdns_clean != domain:
                    findings.append(IntelligenceFinding(
                        entity=rdns_clean,
                        type="Reverse IP Hostnames",
                        source="ViewDNS",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"Reverse-host: {rdns_clean}",
                        tags=["reverse-ip", "hostname"]
                    ))
    except Exception:
        pass

    return findings
