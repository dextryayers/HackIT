import asyncio
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import httpx
import json
import time
from models import IntelligenceFinding
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DS', 'TLSA', 'NAPTR', 'LOC', 'HINFO', 'RP', 'SSHFP', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'SVCB', 'HTTPS', 'ZONEMD', 'OPENPGPKEY']

MULTI_RESOLVERS = [
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Quad9", "ip": "9.9.9.9"},
    {"name": "OpenDNS", "ip": "208.67.222.222"},
    {"name": "Comodo", "ip": "8.26.56.26"},
]

DOH_ENDPOINTS = [
    {"name": "Cloudflare DoH", "url": "https://cloudflare-dns.com/dns-query"},
    {"name": "Google DoH", "url": "https://dns.google/dns-query"},
    {"name": "Quad9 DoH", "url": "https://dns.quad9.net/dns-query"},
]

async def resolve_with_resolver(domain: str, rtype: str, resolver_ip: str = None, timeout_sec: float = 5.0):
    try:
        res = dns.resolver.Resolver()
        if resolver_ip:
            res.nameservers = [resolver_ip]
        res.timeout = timeout_sec
        res.lifetime = timeout_sec
        answers = res.resolve(domain, rtype)
        return [str(r) for r in answers]
    except:
        return []

async def resolve_doh(domain: str, rtype: str, doh_url: str, client: httpx.AsyncClient) -> list:
    try:
        rtype_num = dns.rdatatype.from_text(rtype)
        msg = dns.message.make_query(domain, rtype_num)
        wire = msg.to_wire()
        resp = await client.post(
            doh_url,
            content=wire,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": "Mozilla/5.0"
            },
            timeout=10.0
        )
        if resp.status_code == 200:
            response = dns.message.from_wire(resp.content)
            return [str(r) for r in response.answer] if response.answer else []
    except:
        pass
    return []

async def resolve_any(domain: str, loop) -> list:
    results = []
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'ANY'))
        for rdata in answers:
            results.append(str(rdata))
    except:
        pass
    return results

async def compare_resolvers(domain: str, rtype: str, loop) -> dict:
    results = {}
    for resolver in MULTI_RESOLVERS:
        try:
            start = time.monotonic()
            answers = await loop.run_in_executor(None, lambda ip=resolver["ip"]: resolve_with_resolver(domain, rtype, ip))
            elapsed = time.monotonic() - start
            results[resolver["name"]] = {
                "ips": answers,
                "time": round(elapsed, 3),
                "ip_addr": resolver["ip"]
            }
        except:
            results[resolver["name"]] = {"ips": [], "time": None, "ip_addr": resolver["ip"]}
    return results

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    loop = asyncio.get_event_loop()

    # 1. Multi-resolver comparison for A records
    resolver_comparison = await compare_resolvers(domain, 'A', loop)
    resolver_signatures = {}
    resolver_times = {}
    for resolver_name, data in resolver_comparison.items():
        resolver_signatures[resolver_name] = sorted(data["ips"])
        resolver_times[resolver_name] = data["time"]

        if data["ips"]:
            for ip in data["ips"]:
                findings.append(IntelligenceFinding(
                    entity=f"A record via {resolver_name}: {ip}",
                    type=f"DNS A Record ({resolver_name})",
                    source="DNS Full Enumeration",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    resolution=ip,
                    raw_data=f"{resolver_name} ({data['ip_addr']}) resolved {domain} -> {ip} in {data['time']}s",
                    tags=["dns", "a-record", "multi-resolver", resolver_name.lower()]
                ))

    # 2. Resolver inconsistency detection
    all_ips = set()
    for name, ips in resolver_signatures.items():
        all_ips.update(ips)

    if len(resolver_signatures) >= 2:
        for name, ips in resolver_signatures.items():
            if ips and set(ips) != all_ips:
                findings.append(IntelligenceFinding(
                    entity=f"Resolver inconsistency: {name} returns {ips}, others see {all_ips - set(ips)}",
                    type="DNS Resolver Inconsistency",
                    source="DNS Full Enumeration",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    raw_data=f"{name} returns {ips} while other resolvers return {all_ips - set(ips)}. Possible geo-balancing or DNS poisoning!",
                    tags=["dns", "inconsistency", "geo-dns", resolver_name.lower()]
                ))

        all_match = all(set(ips) == all_ips for ips in resolver_signatures.values() if ips)
        if all_match and all_ips:
            findings.append(IntelligenceFinding(
                entity=f"All {len(resolver_comparison)} resolvers agree: {domain} -> {', '.join(sorted(all_ips))}",
                type="DNS Resolver Consensus",
                source="DNS Full Enumeration",
                confidence="Certain",
                color="green",
                threat_level="Informational",
                raw_data=f"Resolver consensus achieved across {len(resolver_comparison)} providers",
                tags=["dns", "consensus"]
            ))

    # 3. Resolver speed benchmark
    if any(t is not None for t in resolver_times.values()):
        valid_times = {k: v for k, v in resolver_times.items() if v is not None}
        if valid_times:
            fastest = min(valid_times, key=valid_times.get)
            slowest = max(valid_times, key=valid_times.get)
            findings.append(IntelligenceFinding(
                entity=f"Fastest resolver: {fastest} ({valid_times[fastest]}s), Slowest: {slowest} ({valid_times[slowest]}s)",
                type="DNS Resolver Speed Benchmark",
                source="DNS Full Enumeration",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Resolver speeds: {valid_times}",
                tags=["dns", "benchmark", "performance"]
            ))

    # 4. Standard record enumeration (multi-resolver for each type)
    for rtype in RECORD_TYPES:
        try:
            primary_answers = await loop.run_in_executor(None, lambda rt=rtype: dns.resolver.resolve(domain, rt))
            for rdata in primary_answers:
                value = str(rdata)
                color = "blue"
                ftype = f"DNS {rtype}"
                threat = "Informational"

                if rtype == "A": color = "emerald"
                elif rtype == "AAAA": color = "purple"
                elif rtype == "MX": color = "slate"
                elif rtype == "NS": color = "slate"
                elif rtype == "TXT":
                    color = "orange"
                    if value.startswith("v=spf1"): ftype = "SPF Record"
                    elif value.startswith("v=DMARC1"): ftype = "DMARC Record"
                elif rtype == "SOA": color = "indigo"
                elif rtype == "CAA": color = "yellow"
                elif rtype == "DS": color = "emerald"; ftype = "DNSSEC DS"
                elif rtype == "TLSA": color = "emerald"; ftype = "DANE TLSA"
                elif rtype == "SSHFP": color = "cyan"; ftype = "SSH Fingerprint"
                elif rtype in ("DNSKEY", "RRSIG", "NSEC", "NSEC3"):
                    color = "emerald"
                    threat = "Informational"

                findings.append(IntelligenceFinding(
                    entity=value[:300],
                    type=ftype,
                    source="DNS Full Enumeration",
                    confidence="High",
                    color=color,
                    threat_level=threat,
                    resolution=f"{rtype} record",
                    raw_data=value[:2000],
                    tags=["dns", rtype.lower()]
                ))

                # Verify with secondary resolver
                if rtype in ("A", "AAAA", "MX", "NS"):
                    for sec_resolver in ["1.1.1.1", "8.8.8.8"][:1]:
                        sec_answers = await resolve_with_resolver(domain, rtype, sec_resolver)
                        if sec_answers and value not in sec_answers:
                            findings.append(IntelligenceFinding(
                                entity=f"{rtype} mismatch: Primary {value} vs {sec_resolver} gives {sec_answers}",
                                type=f"DNS {rtype} Resolver Discrepancy",
                                source="DNS Full Enumeration",
                                confidence="Low",
                                color="yellow",
                                threat_level="Informational",
                                raw_data=f"Discrepancy for {rtype} record of {domain}",
                                tags=["dns", "discrepancy", rtype.lower()]
                            ))
        except:
            pass

    # 5. DoH (DNS over HTTPS) queries for blocked domains
    if client:
        for doh in DOH_ENDPOINTS[:2]:
            doh_results = await resolve_doh(domain, "A", doh["url"], client)
            if doh_results:
                for result in doh_results:
                    findings.append(IntelligenceFinding(
                        entity=f"DoH via {doh['name']}: {result}",
                        type="DNS over HTTPS (DoH) Result",
                        source="DNS Full Enumeration",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        resolution=str(result)[:200],
                        raw_data=f"DoH query to {doh['name']} resolved: {result}",
                        tags=["doh", "dns-over-https", doh["name"].lower().replace(" ", "-")]
                    ))

    # 6. ANY query
    any_results = await resolve_any(domain, loop)
    if any_results:
        findings.append(IntelligenceFinding(
            entity=f"ANY query returned {len(any_results)} records for {domain}",
            type="DNS ANY Query",
            source="DNS Full Enumeration",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data="\n".join(any_results[:5]),
            tags=["dns", "any-query"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"ANY query returned NO results for {domain}",
            type="DNS ANY Query (Filtered)",
            source="DNS Full Enumeration",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            raw_data="ANY query blocked or filtered - common with modern DNS servers",
            tags=["dns", "any-query", "filtered"]
        ))

    # 7. DNSSEC validation status
    dnssec_valid = False
    try:
        dnskey_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'DNSKEY'))
        if dnskey_answers:
            dnssec_valid = True
            findings.append(IntelligenceFinding(
                entity=f"DNSSEC enabled: {len(dnskey_answers)} DNSKEY records",
                type="DNSSEC Validation",
                source="DNS Full Enumeration",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="DNSSEC Valid",
                raw_data=f"DNSSEC is configured with {len(dnskey_answers)} DNSKEY records",
                tags=["dnssec", "valid"]
            ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"DNSSEC NOT enabled for {domain}",
            type="DNSSEC Validation",
            source="DNS Full Enumeration",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            status="DNSSEC Missing",
            raw_data="DNSSEC validation failed - domain may be vulnerable to DNS spoofing",
            tags=["dnssec", "missing"]
        ))

    # 8. CAA records for CA authorization
    try:
        caa_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'CAA'))
        for caa in caa_answers:
            findings.append(IntelligenceFinding(
                entity=f"CAA: {str(caa)}",
                type="CAA Record (CA Authorization)",
                source="DNS Full Enumeration",
                confidence="High",
                color="yellow",
                threat_level="Informational",
                raw_data=f"CAA: {str(caa)}",
                tags=["dns", "caa", "certificate"]
            ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"No CAA records for {domain}",
            type="CAA Record Status",
            source="DNS Full Enumeration",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data="No CAA records found - any CA can issue certificates",
            tags=["dns", "caa", "missing"]
        ))

    # 9. IPv6 resolution check
    try:
        aaaa_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'AAAA'))
        if aaaa_answers:
            findings.append(IntelligenceFinding(
                entity=f"{domain} has IPv6: {len(aaaa_answers)} AAAA records",
                type="IPv6 DNS Availability",
                source="DNS Full Enumeration",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"AAAA records: {', '.join(str(a) for a in aaaa_answers)}",
                tags=["dns", "ipv6", "aaaa"]
            ))
    except:
        pass

    # 10. DMARC query
    dmarc_selectors = ["_dmarc"]
    for sel in dmarc_selectors:
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{sel}.{domain}", "TXT"))
            for r in answers:
                findings.append(IntelligenceFinding(
                    entity=str(r)[:300],
                    type="DMARC Policy",
                    source="DNS Full Enumeration",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=str(r)[:2000],
                    tags=["dns", "dmarc", "email-security"]
                ))
        except:
            findings.append(IntelligenceFinding(
                entity=f"No DMARC record for {domain}",
                type="DMARC Status",
                source="DNS Full Enumeration",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data="Missing DMARC record leaves domain open to email spoofing",
                tags=["dmarc", "missing"]
            ))

    # 11. DKIM discovery
    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx', 'selector1', 'selector2', 's1', 's2']:
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT"))
            for r in answers:
                findings.append(IntelligenceFinding(
                    entity=f"{selector}._domainkey.{domain}",
                    type="DKIM Public Key",
                    source="DNS Full Enumeration",
                    confidence="High",
                    color="emerald",
                    resolution=str(r)[:200],
                    threat_level="Informational",
                    raw_data=str(r)[:2000],
                    tags=["dns", "dkim", "email-security"]
                ))
        except:
            pass

    # 12. Wildcard detection
    try:
        wc_test = f"xwcz-{abs(hash(domain)) % 99999}.{domain}"
        wild = await loop.run_in_executor(None, lambda: dns.resolver.resolve(wc_test, "A"))
        findings.append(IntelligenceFinding(
            entity=f"*.{domain} -> {str(wild[0])}",
            type="Wildcard DNS Detected",
            source="DNS Full Enumeration",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Wildcard resolves to {str(wild[0])}",
            tags=["dns", "wildcard"]
        ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"No wildcard DNS for {domain}",
            type="Wildcard DNS Check",
            source="DNS Full Enumeration",
            confidence="High",
            color="green",
            threat_level="Informational",
            raw_data="Random subdomain did not resolve - no wildcard",
            tags=["dns", "wildcard", "clean"]
        ))

    # 13. MX resolution chain
    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "MX"))
        mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
        for mx in mx_hosts:
            for ip_type in ['A', 'AAAA']:
                try:
                    ips = await loop.run_in_executor(None, lambda: dns.resolver.resolve(mx, ip_type))
                    for ip in ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{mx} -> {str(ip)}",
                            type="MX Server IP",
                            source="DNS Full Enumeration",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"MX {mx} resolves to {str(ip)}",
                            tags=["dns", "mx", "ip"]
                        ))
                except:
                    pass
    except:
        pass

    # 14. NS resolution chain
    try:
        ns_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "NS"))
        ns_hosts = [str(r).rstrip('.') for r in ns_records]
        for ns in ns_hosts:
            for ip_type in ['A', 'AAAA']:
                try:
                    ips = await loop.run_in_executor(None, lambda: dns.resolver.resolve(ns, ip_type))
                    for ip in ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{ns} -> {str(ip)}",
                            type="Nameserver IP",
                            source="DNS Full Enumeration",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"NS {ns} resolves to {str(ip)}",
                            tags=["dns", "ns", "ip"]
                        ))
                except:
                    pass
    except:
        pass

    # 15. SOA primary analysis
    try:
        soa = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, "SOA"))
        for r in soa:
            mname = str(r.mname).rstrip('.')
            rname = str(r.rname).rstrip('.')
            findings.append(IntelligenceFinding(
                entity=f"Primary NS: {mname}, Admin: {rname}",
                type="Primary Nameserver (SOA)",
                source="DNS Full Enumeration",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"SOA MNAME: {mname}, RNAME: {rname}",
                tags=["dns", "soa", "authority"]
            ))
            findings.append(IntelligenceFinding(
                entity=f"Serial: {r.serial}, Refresh: {r.refresh}, Retry: {r.retry}, Expire: {r.expire}, MinTTL: {r.minimum}",
                type="SOA Timing Parameters",
                source="DNS Full Enumeration",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"Serial={r.serial}, Refresh={r.refresh}, Retry={r.retry}, Expire={r.expire}, MinTTL={r.minimum}",
                tags=["dns", "soa", "timing"]
            ))
    except:
        pass

    # 16. Summary
    record_count = len([f for f in findings if f.type.startswith("DNS ")])
    findings.append(IntelligenceFinding(
        entity=f"{record_count} DNS records enumerated for {domain}",
        type="DNS Enumeration Summary",
        source="DNS Full Enumeration",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"Total records found: {record_count}",
        tags=["dns", "summary"]
    ))

    return findings
