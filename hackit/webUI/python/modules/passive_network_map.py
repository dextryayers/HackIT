import httpx
import re
import json
import asyncio
import socket
from urllib.parse import urlparse
from models import IntelligenceFinding

ASN_DATABASE = {
    "15169": "Google", "16509": "Amazon", "8075": "Microsoft",
    "13335": "Cloudflare", "54113": "Fastly", "20940": "Akamai",
    "16625": "Akamai", "14618": "Amazon", "3": "MIT",
    "714": "Apple", "32934": "Facebook", "36040": "Facebook",
    "36351": "SoftLayer/IBM", "36375": "UMich",
}

PEERING_LANS = {
    "Equinix": ["Equinix", "Equinix IX", "Equinix IXP"],
    "AMS-IX": ["AMS-IX", "Amsterdam IX"],
    "DE-CIX": ["DE-CIX", "Deutsche IX"],
    "LINX": ["LINX", "London IX"],
    "IXP": ["Internet Exchange"],
}

async def _resolve_and_get_asn(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    ip = None
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
    except Exception:
        return findings
    if ip:
        findings.append(IntelligenceFinding(
            entity=ip,
            type="Network Map - Resolved IP",
            source="Passive Network Map",
            confidence="High", color="blue",
            status="Resolved",
            tags=["network", "ip"]
        ))
    try:
        geo_resp = await client.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if geo_resp.status_code == 200:
            geo = geo_resp.json()
            asn = geo.get("asn", "")
            org = geo.get("org", "")
            country = geo.get("country_name", "")
            if asn:
                findings.append(IntelligenceFinding(
                    entity=asn,
                    type="Network Map - ASN Number",
                    source="ipapi.co",
                    confidence="High", color="slate",
                    status="Identified",
                    tags=["network", "asn"]
                ))
                if asn in ASN_DATABASE:
                    findings.append(IntelligenceFinding(
                        entity=f"AS{asn} -> {ASN_DATABASE[asn]}",
                        type="Network Map - ASN Owner",
                        source="ipapi.co",
                        confidence="High", color="orange",
                        status=f"Owner: {ASN_DATABASE[asn]}",
                        tags=["network", "asn-owner"]
                    ))
            if org:
                findings.append(IntelligenceFinding(
                    entity=org[:200],
                    type="Network Map - ISP/Organization",
                    source="ipapi.co",
                    confidence="High", color="slate",
                    tags=["network", "isp"]
                ))
    except Exception:
        pass
    try:
        rdap_resp = await client.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if rdap_resp.status_code == 200:
            rdap = rdap_resp.json()
            entities = rdap.get("entities", [])
            for entity in entities:
                if isinstance(entity, dict):
                    vcard = entity.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 3 and item[0] == "fn":
                                name = str(item[3])
                                findings.append(IntelligenceFinding(
                                    entity=name[:200],
                                    type="Network Map - RDAP Org Name",
                                    source="ARIN RDAP",
                                    confidence="High", color="slate",
                                    tags=["network", "rdap"]
                                ))
            net_ranges = rdap.get("arin_ranges", rdap.get("startAddress", ""))
            if rdap.get("startAddress") and rdap.get("endAddress"):
                findings.append(IntelligenceFinding(
                    entity=f"Range: {rdap['startAddress']} - {rdap['endAddress']}",
                    type="Network Map - IP Range",
                    source="ARIN RDAP",
                    confidence="High", color="slate",
                    tags=["network", "ip-range"]
                ))
    except Exception:
        pass
    try:
        bgp_resp = await client.get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if bgp_resp.status_code == 200:
            bgp_text = bgp_resp.text
            lines = bgp_text.strip().split("\n")
            for line in lines:
                if ":" in line:
                    parts = line.split(":", 1)
                    findings.append(IntelligenceFinding(
                        entity=parts[1].strip()[:200],
                        type=f"Network Map - BGP: {parts[0].strip()}",
                        source="HackerTarget",
                        confidence="High", color="slate",
                        tags=["network", "bgp"]
                    ))
    except Exception:
        pass
    return findings

async def _map_dns_infrastructure(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    record_types = {
        "NS": 2, "MX": 15, "SOA": 6,
    }
    servers_by_type = {}
    for rtype_name, rtype_num in record_types.items():
        try:
            resp = await client.get(
                f"https://dns.google/resolve?name={domain}&type={rtype_name}",
                timeout=10.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                for ans in answers:
                    if ans.get("type") == rtype_num:
                        val = ans.get("data", "").rstrip(".")
                        if rtype_name not in servers_by_type:
                            servers_by_type[rtype_name] = []
                        servers_by_type[rtype_name].append(val)
        except Exception:
            pass
    for rtype, servers in servers_by_type.items():
        for server in servers[:5]:
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(server))
                findings.append(IntelligenceFinding(
                    entity=f"{rtype}: {server} -> {ip}",
                    type=f"Network Map - {rtype} Server Location",
                    source="Passive Network Map",
                    confidence="High", color="slate",
                    status="Resolved",
                    raw_data=f"{rtype} server {server} resolves to {ip}",
                    tags=["network", rtype.lower()]
                ))
                geo_resp = await client.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=8.0,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if geo_resp.status_code == 200:
                    geo = geo_resp.json()
                    country = geo.get("country_name", "")
                    if country:
                        findings.append(IntelligenceFinding(
                            entity=f"{server} located in {country}",
                            type=f"Network Map - {rtype} Geographic Distribution",
                            source="Passive Network Map",
                            confidence="High", color="slate",
                            raw_data=f"{rtype} server {server} in {country}",
                            tags=["network", "geo", rtype.lower()]
                        ))
            except Exception:
                pass
    return findings

async def _check_reverse_dns_patterns(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/reverseip/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            host_patterns = {}
            for line in lines:
                if "," in line:
                    host = line.split(",")[0].strip()
                    parts = host.split(".")
                    if len(parts) >= 3:
                        pattern = ".".join(parts[-3:])
                        host_patterns[pattern] = host_patterns.get(pattern, 0) + 1
            for pattern, count in sorted(host_patterns.items(), key=lambda x: -x[1])[:10]:
                if count > 1:
                    findings.append(IntelligenceFinding(
                        entity=f"Pattern: *.{pattern} ({count} hosts)",
                        type="Network Map - Namespace/Naming Pattern",
                        source="Passive Network Map",
                        confidence="Medium",
                        color="slate",
                        raw_data=f"Reverse DNS naming pattern: {pattern} with {count} hosts",
                        tags=["network", "reverse-dns", "pattern"]
                    ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    asn_findings = await _resolve_and_get_asn(domain, client)
    findings.extend(asn_findings)

    dns_findings = await _map_dns_infrastructure(domain, client)
    findings.extend(dns_findings)

    rdns_findings = await _check_reverse_dns_patterns(domain, client)
    findings.extend(rdns_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Network Map complete: {len(findings)} findings",
            type="Network Map - Summary",
            source="Passive Network Map",
            confidence="High", color="purple",
            status="Complete",
            tags=["network", "summary"]
        ))

    return findings
