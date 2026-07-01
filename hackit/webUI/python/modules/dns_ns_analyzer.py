import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.rdatatype
import socket
import time
import re
from collections import defaultdict
from models import IntelligenceFinding

async def resolve_rtype(domain: str, rtype: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, rtype))
        return [str(r) for r in answers]
    except:
        return []

async def resolve_a(host: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, 53, socket.AF_INET))
        return list(set(a[4][0] for a in answers))
    except:
        return []

async def test_zone_transfer(ns: str, domain: str):
    loop = asyncio.get_event_loop()
    try:
        ns_ip = await resolve_a(ns)
        if not ns_ip:
            return False
        zt = await loop.run_in_executor(None, lambda: dns.zone.from_xfr(dns.query.xfr(ns_ip[0], domain, timeout=5)))
        return bool(zt)
    except:
        return False

async def get_ns_version(ns: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(ns, 'TXT'))
        for a in answers:
            txt = str(a).lower()
            if 'version' in txt or 'bind' in txt or 'nsd' in txt or 'powerdns' in txt:
                return txt
    except:
        pass
    try:
        query = dns.message.make_query('version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        ns_ips = await resolve_a(ns)
        if ns_ips:
            response = await loop.run_in_executor(None, lambda: dns.query.udp(query, ns_ips[0], timeout=5))
            for rr in response.answer:
                for r in rr:
                    return str(r)
    except:
        pass
    return ""

async def check_recursion(ns: str):
    loop = asyncio.get_event_loop()
    try:
        ns_ips = await resolve_a(ns)
        if not ns_ips:
            return False
        test_domain = "google.com"
        query = dns.message.make_query(test_domain, dns.rdatatype.A)
        response = await loop.run_in_executor(None, lambda: dns.query.udp(query, ns_ips[0], timeout=5))
        if response.answer:
            return True
    except:
        pass
    return False

async def measure_ns_latency(ns: str):
    loop = asyncio.get_event_loop()
    latencies = []
    for _ in range(3):
        try:
            start = time.monotonic()
            ns_ips = await resolve_a(ns)
            if ns_ips:
                query = dns.message.make_query('.', dns.rdatatype.NS)
                await loop.run_in_executor(None, lambda: dns.query.udp(query, ns_ips[0], timeout=5))
                latencies.append(time.monotonic() - start)
        except:
            pass
    return round(sum(latencies) / len(latencies), 3) if latencies else None

async def detect_ns_software(ns: str):
    loop = asyncio.get_event_loop()
    try:
        ns_ips = await resolve_a(ns)
        if not ns_ips:
            return ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ns_ips[0], 53))
        banner = ""
        try:
            reader = asyncio.StreamReader(loop=loop)
            transport, _ = await loop.connect_accepted_socket(lambda: reader, sock)
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner = banner.decode('utf-8', errors='ignore')
        except:
            pass
        sock.close()
        if 'bind' in banner.lower():
            return f"ISC BIND ({banner.strip()})"
        if 'nsd' in banner.lower():
            return f"NLnet Labs NSD ({banner.strip()})"
        if 'powerdns' in banner.lower():
            return f"PowerDNS ({banner.strip()})"
        if 'unbound' in banner.lower():
            return f"NLnet Labs Unbound ({banner.strip()})"
        if 'knot' in banner.lower():
            return f"Knot DNS ({banner.strip()})"
        if 'microsoft' in banner.lower() or 'windows' in banner.lower():
            return f"Microsoft DNS ({banner.strip()})"
        return f"Unknown ({banner.strip()[:50]})" if banner.strip() else "Unknown"
    except:
        return ""

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    ns_list = await resolve_rtype(domain, 'NS')
    if not ns_list:
        findings.append(IntelligenceFinding(
            entity=f"No NS records found for {domain}",
            type="Nameserver Analysis",
            source="DNS NS Analyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="No NS",
            tags=["ns", "missing"]
        ))
        return findings

    for ns in ns_list:
        ns = ns.rstrip('.')
        ns_ips = await resolve_a(ns)
        ips_str = ', '.join(ns_ips) if ns_ips else "Unresolvable"
        findings.append(IntelligenceFinding(
            entity=f"{ns} ({ips_str})",
            type="Nameserver Record",
            source="DNS NS Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Active",
            resolution=ips_str,
            raw_data=f"NS: {ns} | IPs: {ips_str}",
            tags=["ns", "nameserver"]
        ))

        if ns_ips:
            for ip in ns_ips:
                try:
                    ptr = await resolve_rtype(ip, 'PTR')
                    if ptr:
                        findings.append(IntelligenceFinding(
                            entity=f"PTR: {ip} -> {', '.join(ptr)}",
                            type="NS PTR Record (rDNS)",
                            source="DNS NS Analyzer",
                            confidence="High",
                            color="blue",
                            threat_level="Informational",
                            status="PTR Found",
                            resolution=ip,
                            tags=["ns", "ptr", "rdns"]
                        ))
                except:
                    pass

        zt_result = await test_zone_transfer(ns, domain)
        if zt_result:
            findings.append(IntelligenceFinding(
                entity=f"Zone transfer (AXFR) ALLOWED on {ns} - CRITICAL!",
                type="NS Zone Transfer Vulnerability",
                source="DNS NS Analyzer",
                confidence="Certain",
                color="red",
                threat_level="High Risk",
                status="Vulnerable",
                raw_data=f"Zone transfer succeeded on {ns} ({ns_ips[0] if ns_ips else '?'}). Entire DNS zone exposed!",
                tags=["ns", "zone-transfer", "vulnerability", "critical"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"Zone transfer (AXFR) blocked on {ns}",
                type="NS Zone Transfer Secure",
                source="DNS NS Analyzer",
                confidence="High",
                color="green",
                threat_level="Informational",
                status="Secure",
                tags=["ns", "zone-transfer", "secure"]
            ))

        version_info = await get_ns_version(ns)
        if version_info:
            findings.append(IntelligenceFinding(
                entity=f"{ns} version: {version_info}",
                type="NS Version Disclosure",
                source="DNS NS Analyzer",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="Version Exposed",
                raw_data=f"NS {ns} exposes version: {version_info}",
                tags=["ns", "version", "disclosure"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"{ns}: version hidden",
                type="NS Version Hiding",
                source="DNS NS Analyzer",
                confidence="Medium",
                color="green",
                threat_level="Informational",
                status="Version Hidden",
                tags=["ns", "version", "hidden"]
            ))

        rec_open = await check_recursion(ns)
        if rec_open:
            findings.append(IntelligenceFinding(
                entity=f"Recursion ENABLED on {ns} - open resolver!",
                type="NS Open Recursion",
                source="DNS NS Analyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Open Resolver",
                raw_data=f"{ns} allows recursive queries - can be used in DNS amplification attacks",
                tags=["ns", "recursion", "open-resolver", "abuse"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"Recursion disabled on {ns}",
                type="NS Recursion Status",
                source="DNS NS Analyzer",
                confidence="High",
                color="green",
                threat_level="Informational",
                status="Recursion Disabled",
                tags=["ns", "recursion", "secure"]
            ))

        latency = await measure_ns_latency(ns)
        if latency:
            lcolor = "green" if latency < 0.05 else "orange" if latency < 0.2 else "red"
            findings.append(IntelligenceFinding(
                entity=f"{ns}: {latency}s avg response time",
                type="NS Response Latency",
                source="DNS NS Analyzer",
                confidence="High",
                color=lcolor,
                threat_level="Informational",
                status="Measured",
                raw_data=f"NS: {ns} | Average Latency: {latency}s",
                tags=["ns", "latency", "performance"]
            ))

        software = await detect_ns_software(ns)
        if software and software != "Unknown":
            findings.append(IntelligenceFinding(
                entity=f"{ns}: {software}",
                type="NS Software Detection",
                source="DNS NS Analyzer",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Detected",
                tags=["ns", "software"]
            ))

        try:
            dnskey = await resolve_rtype(ns, 'DNSKEY')
            if dnskey:
                findings.append(IntelligenceFinding(
                    entity=f"DNSSEC enabled on nameserver {ns}",
                    type="NS DNSSEC Status",
                    source="DNS NS Analyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="DNSSEC Active",
                    tags=["ns", "dnssec"]
                ))
        except:
            pass

    if len(ns_list) >= 2:
        findings.append(IntelligenceFinding(
            entity=f"{len(ns_list)} nameservers provide redundancy",
            type="NS Redundancy Analysis",
            source="DNS NS Analyzer",
            confidence="High",
            color="green" if len(ns_list) >= 2 else "orange",
            threat_level="Informational",
            status=f"{len(ns_list)} NS",
            tags=["ns", "redundancy"]
        ))

    glue_tested = False
    for ns in ns_list:
        ns_clean = ns.rstrip('.')
        if ns_clean.endswith(domain):
            glue_tested = True
            findings.append(IntelligenceFinding(
                entity=f"{ns_clean} is in-zone (glue record may be needed)",
                type="NS Glue Record Check",
                source="DNS NS Analyzer",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="In-Zone NS",
                tags=["ns", "glue"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"Analyzed {len(ns_list)} nameservers for {domain}",
        type="NS Analysis Summary",
        source="DNS NS Analyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Nameservers: {', '.join(ns.rstrip('.') for ns in ns_list)}",
        tags=["ns", "summary"]
    ))

    return findings
