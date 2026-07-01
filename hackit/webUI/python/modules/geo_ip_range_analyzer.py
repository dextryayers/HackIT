import httpx
import asyncio
import re
import socket
import ipaddress
from models import IntelligenceFinding

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
    try:
        socket.inet_aton(target)
        return target, True
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, False
    except Exception as e:
        return None, str(e)

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
                findings.append(IntelligenceFinding(
                    entity=f"Class {cls} Network ({desc})",
                    type="Network Class",
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
        findings.append(IntelligenceFinding(
            entity=f"CIDR: {cidr_24_start}/24",
            type="CIDR Range (/24)",
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
        findings.append(IntelligenceFinding(
            entity=f"Network Range: {cidr_24_start} - {cidr_24_end}",
            type="Network Range",
            source="IPRangeAnalyzer",
            confidence="High",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Calculated",
            raw_data=f"Full /24 range: {cidr_24_start} to {cidr_24_end}",
            tags=["network", "range"]
        ))
        findings.append(IntelligenceFinding(
            entity=f"Usable hosts: {usable_hosts}",
            type="Usable Host Count",
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
        cidr_start = ip_int & 0xFFFFFF00
        host_suffix = ip_int & 0xFF
        active_hosts = []
        try:
            ptr = socket.gethostbyaddr(ip)
            active_hosts.append((ip, ptr[0]))
        except Exception:
            pass
        if active_hosts:
            for h_ip, h_name in active_hosts:
                findings.append(IntelligenceFinding(
                    entity=f"PTR: {h_name} ({h_ip})",
                    type="Reverse DNS",
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
        findings.append(IntelligenceFinding(
            entity=f"Host suffix in /24: .{host_suffix}",
            type="Host Position in Subnet",
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

async def _query_asn_info(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    for url_tmpl in ASN_QUERY_URLS:
        url = url_tmpl.format(ip)
        try:
            resp = await client.get(url, timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                org = data.get("org", "") or data.get("organization", "") or ""
                asn = data.get("asn", "") or data.get("as", "") or ""
                if org:
                    findings.append(IntelligenceFinding(
                        entity=f"ASN/Org: {org}",
                        type="ASN Information",
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
                    findings.append(IntelligenceFinding(
                        entity=f"AS{asn}",
                        type="Autonomous System Number",
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
        except Exception:
            continue
    return findings

async def _estimate_neighbor_asns(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        url = f"https://ipinfo.io/{ip}/json"
        resp = await client.get(url, timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            if org:
                findings.append(IntelligenceFinding(
                    entity=f"Neighbor estimation: {org} owns nearby IPs",
                    type="Neighboring ASN Estimate",
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
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="IPRangeAnalyzer", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="IPRangeAnalyzer", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _analyze_network_class(ip))
    findings.extend(await _calculate_cidr(ip))
    findings.extend(await _reverse_dns_subnet(ip))
    findings.extend(await _query_asn_info(ip, client))
    findings.extend(await _estimate_neighbor_asns(ip, client))

    findings.append(IntelligenceFinding(entity=f"Target: {ip}", type="IP Target", source="IPRangeAnalyzer", confidence="High", color="slate", category="Geo / Network OSINT", tags=["target"]))
    findings.append(IntelligenceFinding(entity=f"Total subnet findings: {len(findings)}", type="IP Range Summary", source="IPRangeAnalyzer", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["summary"]))

    return findings
