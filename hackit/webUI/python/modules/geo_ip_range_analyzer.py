import re
import socket
import ipaddress
from module_common import safe_fetch_json, make_finding, is_ip, resolve_ip

COMMON_PORTS_SERVICES = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

NETWORK_CLASSES = {
    "A": (1, 126, "255.0.0.0", "Large networks (/8)"),
    "B": (128, 191, "255.255.0.0", "Medium networks (/16)"),
    "C": (192, 223, "255.255.255.0", "Small networks (/24)"),
    "D": (224, 239, "N/A", "Multicast"),
    "E": (240, 255, "N/A", "Experimental"),
}

ASN_QUERY_URLS = [
    "https://ipinfo.io/{}/json",
    "https://ipapi.co/{}/json/",
    "https://rdap.arin.net/registry/ip/{}",
    "https://rdap.db.ripe.net/ip/{}",
]

async def _resolve_target(target: str) -> tuple:
    if is_ip(target):
        return target, True
    ip = resolve_ip(target)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

def _ip_to_int(ip_str: str) -> int:
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def _int_to_ip(int_val: int) -> str:
    return f"{(int_val >> 24) & 255}.{(int_val >> 16) & 255}.{(int_val >> 8) & 255}.{int_val & 255}"

async def _analyze_network_class(ip: str) -> list:
    findings = []
    try:
        first_octet = int(ip.split(".")[0])
        for cls, (start, end, mask, desc) in NETWORK_CLASSES.items():
            if start <= first_octet <= end:
                findings.append(make_finding(
                    entity=f"Class {cls} Network ({desc})",
                    ftype="Network Class",
                    source="IPRangeAnalyzer",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"Network Class {cls}: {start}-{end}. Subnet mask: {mask}. {desc}",
                    tags=["network", f"class-{cls.lower()}"]
                ))
                break
    except Exception:
        pass
    return findings

async def _calculate_cidr(ip: str) -> list:
    findings = []
    try:
        ip_int = _ip_to_int(ip)
        cidr_24_start = _int_to_ip(ip_int & 0xFFFFFF00)
        cidr_24_end = _int_to_ip(ip_int | 0x000000FF)
        subnet_mask = "255.255.255.0"
        wildcard = "0.0.0.255"
        usable_hosts = 254
        network_bits = 24
        findings.append(make_finding(
            entity=f"CIDR: {cidr_24_start}/24",
            ftype="CIDR Range (/24)",
            source="IPRangeAnalyzer",
            confidence="High",
            color="blue",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Calculated",
            resolution=cidr_24_start,
            raw_data=f"CIDR: {cidr_24_start}/24 ({cidr_24_start} - {cidr_24_end}). Subnet: {subnet_mask}. Usable hosts: {usable_hosts}. Wildcard: {wildcard}. Network bits: {network_bits}",
            tags=["network", "cidr", "ipv4"]
        ))
        findings.append(make_finding(
            entity=f"Network Range: {cidr_24_start} - {cidr_24_end}",
            ftype="Network Range",
            source="IPRangeAnalyzer",
            confidence="High",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Calculated",
            raw_data=f"Full /24 range: {cidr_24_start} to {cidr_24_end}",
            tags=["network", "range"]
        ))
        findings.append(make_finding(
            entity=f"Usable hosts: {usable_hosts}",
            ftype="Usable Host Count",
            source="IPRangeAnalyzer",
            confidence="High",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Calculated",
            raw_data=f"/24 subnet has {usable_hosts} usable host addresses",
            tags=["network", "subnet"]
        ))
    except Exception:
        pass
    return findings

async def _reverse_dns_subnet(ip: str) -> list:
    findings = []
    try:
        ip_int = _ip_to_int(ip)
        host_suffix = ip_int & 0xFF
        active_hosts = []
        try:
            ptr = socket.gethostbyaddr(ip)
            active_hosts.append((ip, ptr[0]))
        except Exception:
            pass
        if active_hosts:
            for h_ip, h_name in active_hosts:
                findings.append(make_finding(
                    entity=f"PTR: {h_name} ({h_ip})",
                    ftype="Reverse DNS",
                    source="IPRangeAnalyzer",
                    confidence="High",
                    color="purple",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Resolved",
                    resolution=h_ip,
                    raw_data=f"Reverse DNS: {h_ip} -> {h_name}",
                    tags=["dns", "reverse-dns"]
                ))
        findings.append(make_finding(
            entity=f"Host suffix in /24: .{host_suffix}",
            ftype="Host Position in Subnet",
            source="IPRangeAnalyzer",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Calculated",
            raw_data=f"Target IP is host .{host_suffix} in /24 subnet",
            tags=["network", "subnet"]
        ))
    except Exception:
        pass
    return findings

async def _query_asn_info(ip: str, client) -> list:
    findings = []
    for url_tmpl in ASN_QUERY_URLS:
        url = url_tmpl.format(ip)
        data = await safe_fetch_json(client, url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if data:
            org = data.get("org", "") or data.get("organization", "") or ""
            asn = data.get("asn", "") or data.get("as", "") or ""
            if org:
                findings.append(make_finding(
                    entity=f"ASN/Org: {org}",
                    ftype="ASN Information",
                    source="IPRangeAnalyzer",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"Organization: {org}, ASN: {asn}",
                    tags=["network", "asn", "bgp"]
                ))
            if asn:
                findings.append(make_finding(
                    entity=f"AS{asn}",
                    ftype="Autonomous System Number",
                    source="IPRangeAnalyzer",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"ASN: {asn}",
                    tags=["network", "asn"]
                ))
            break
    return findings

async def _estimate_neighbor_asns(ip: str, client) -> list:
    findings = []
    data = await safe_fetch_json(client, f"https://ipinfo.io/{ip}/json",
        headers={"User-Agent": "Mozilla/5.0"})
    if data:
        org = data.get("org", "")
        if org:
            findings.append(make_finding(
                entity=f"Neighbor estimation: {org} owns nearby IPs",
                ftype="Neighboring ASN Estimate",
                source="IPRangeAnalyzer",
                confidence="Medium",
                color="slate",
                category="Geo / Network OSINT",
                threat_level="Informational",
                status="Estimated",
                resolution=ip,
                raw_data=f"Organization likely owns adjacent subnets: {org}",
                tags=["network", "bgp", "neighbors"]
            ))
    return findings

async def crawl(target: str, client) -> list:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip_flag = await _resolve_target(target)
    if ip is None:
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", ftype="DNS Error", source="IPRangeAnalyzer", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip_flag)[:200], tags=["error"]))
        return findings

    if not is_ip_flag:
        findings.append(make_finding(entity=f"{target} -> {ip}", ftype="DNS Resolution", source="IPRangeAnalyzer", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _analyze_network_class(ip))
    findings.extend(await _calculate_cidr(ip))
    findings.extend(await _reverse_dns_subnet(ip))
    findings.extend(await _query_asn_info(ip, client))
    findings.extend(await _estimate_neighbor_asns(ip, client))

    findings.append(make_finding(entity=f"Target: {ip}", ftype="IP Target", source="IPRangeAnalyzer", confidence="High", color="slate", category="Geo / Network OSINT", tags=["target"]))
    findings.append(make_finding(entity=f"Total subnet findings: {len(findings)}", ftype="IP Range Summary", source="IPRangeAnalyzer", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["summary"]))

    return findings
