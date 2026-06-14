import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.name
import time
from collections import defaultdict
from models import IntelligenceFinding

ALL_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR', 'CAA',
    'SSHFP', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'LOC', 'HINFO', 'RP',
    'NAPTR', 'CERT', 'SMIMEA', 'TLSA', 'URI', 'SVCB', 'HTTPS', 'DNAME', 'TKEY',
    'TSIG', 'ZONEMD', 'OPENPGPKEY',
]

RESOLVERS_TO_TEST = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
    "8.8.4.4", "1.0.0.1", "149.112.112.112", "208.67.220.220",
    "64.6.64.6", "77.88.8.8", "74.82.42.42",
]

RECORD_METADATA = {
    "A": {"color": "blue", "desc": "IPv4 Address"},
    "AAAA": {"color": "blue", "desc": "IPv6 Address"},
    "CNAME": {"color": "purple", "desc": "Canonical Name"},
    "MX": {"color": "slate", "desc": "Mail Exchange"},
    "NS": {"color": "slate", "desc": "Nameserver"},
    "TXT": {"color": "emerald", "desc": "Text Record"},
    "SOA": {"color": "purple", "desc": "Start of Authority"},
    "SRV": {"color": "cyan", "desc": "Service Record"},
    "PTR": {"color": "blue", "desc": "Pointer Record"},
    "CAA": {"color": "orange", "desc": "Certification Authority Authorization"},
    "SSHFP": {"color": "orange", "desc": "SSH Fingerprint"},
    "DNSKEY": {"color": "emerald", "desc": "DNSSEC Public Key"},
    "DS": {"color": "emerald", "desc": "DNSSEC Delegation Signer"},
    "NSEC": {"color": "emerald", "desc": "Next Secure (DNSSEC)"},
    "NSEC3": {"color": "emerald", "desc": "NSEC3 (DNSSEC)"},
    "RRSIG": {"color": "emerald", "desc": "Resource Record Signature (DNSSEC)"},
    "LOC": {"color": "orange", "desc": "Location Record"},
    "HINFO": {"color": "orange", "desc": "Host Information"},
    "RP": {"color": "slate", "desc": "Responsible Person"},
    "NAPTR": {"color": "purple", "desc": "Naming Authority Pointer"},
    "CERT": {"color": "orange", "desc": "Certificate Record"},
    "SMIMEA": {"color": "emerald", "desc": "S/MIME Cert Association"},
    "TLSA": {"color": "emerald", "desc": "TLSA (DANE)"},
    "URI": {"color": "purple", "desc": "URI Record"},
    "SVCB": {"color": "purple", "desc": "Service Binding"},
    "HTTPS": {"color": "purple", "desc": "HTTPS Service Binding"},
    "DNAME": {"color": "purple", "desc": "Delegation Name"},
    "OPENPGPKEY": {"color": "orange", "desc": "OpenPGP Key"},
    "ZONEMD": {"color": "orange", "desc": "Zone Message Digest"},
}

SECURITY_RECORDS = {"CAA", "SSHFP", "DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG", "TLSA", "SMIMEA", "OPENPGPKEY"}
DNSSEC_RECORDS = {"DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG"}

async def resolve_with_timeout(loop, domain, rtype, resolver=None, timeout_sec=5.0):
    start = time.monotonic()
    try:
        res = dns.resolver.Resolver()
        if resolver:
            res.nameservers = [resolver]
        res.timeout = timeout_sec
        res.lifetime = timeout_sec
        answers = await loop.run_in_executor(None, lambda: res.resolve(domain, rtype))
        elapsed = time.monotonic() - start
        return answers, elapsed
    except Exception:
        elapsed = time.monotonic() - start
        return None, elapsed

async def check_dnssec(loop, domain):
    status = {"valid": False, "algo": None, "keys": 0, "rrsigs": 0}
    try:
        dnskey = await resolve_with_timeout(loop, domain, "DNSKEY")
        if dnskey[0]:
            status["keys"] = len(dnskey[0])
            for key in dnskey[0]:
                if hasattr(key, "algorithm"):
                    status["algo"] = key.algorithm
    except:
        pass
    try:
        rrsig = await resolve_with_timeout(loop, domain, "RRSIG")
        if rrsig[0]:
            status["rrsigs"] = len(rrsig[0])
            status["valid"] = True
    except:
        pass
    return status

async def check_any_query(loop, domain):
    results = []
    try:
        answers = await resolve_with_timeout(loop, domain, "ANY")
        if answers[0]:
            for rdata in answers[0]:
                results.append(str(rdata))
    except:
        pass
    return results

async def benchmark_resolvers(loop, domain):
    bench_results = {}
    for resolver_ip in RESOLVERS_TO_TEST[:5]:
        try:
            _, elapsed = await resolve_with_timeout(loop, domain, "A", resolver=resolver_ip)
            bench_results[resolver_ip] = round(elapsed, 3)
        except:
            bench_results[resolver_ip] = None
    return bench_results

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    loop = asyncio.get_event_loop()

    dnssec_status = await check_dnssec(loop, domain)

    resolver_bench = await benchmark_resolvers(loop, domain)

    security_records_found = set()
    all_records_found = set()

    for rtype in ALL_RECORD_TYPES:
        try:
            result = await resolve_with_timeout(loop, domain, rtype)
            answers, elapsed = result

            if answers:
                all_records_found.add(rtype)
                values = [str(r) for r in answers]
                meta = RECORD_METADATA.get(rtype, {"color": "slate", "desc": rtype})
                color = meta["color"]
                desc = meta["desc"]

                threat_level = "Informational"
                if rtype in SECURITY_RECORDS:
                    security_records_found.add(rtype)
                if rtype in DNSSEC_RECORDS:
                    color = "emerald"
                    threat_level = "Informational"

                is_dnssec_rtype = rtype in DNSSEC_RECORDS

                for value in values[:3]:
                    finding_type = f"DNS {rtype} Record"
                    if rtype == "TXT":
                        lower_val = value.lower()
                        if lower_val.startswith("v=spf1"):
                            finding_type = "SPF Record"
                            color = "emerald"
                        elif "v=dkim1" in lower_val:
                            finding_type = "DKIM Record"
                            color = "emerald"
                        elif lower_val.startswith("v=dmarc1"):
                            finding_type = "DMARC Record"
                            color = "emerald"
                    elif rtype == "MX":
                        finding_type = "MX Record"
                    elif rtype == "NS":
                        finding_type = "Nameserver Record"
                    elif rtype == "SOA":
                        finding_type = "SOA Record"
                    elif rtype == "CAA":
                        finding_type = "CAA Record"
                    elif rtype == "DNSKEY":
                        finding_type = "DNSKEY (DNSSEC)"
                    elif rtype == "DS":
                        finding_type = "DS Record (DNSSEC)"

                    findings.append(IntelligenceFinding(
                        entity=value[:300],
                        type=finding_type,
                        source="DNS Resolver",
                        confidence="High",
                        color=color,
                        category="DNS Intelligence",
                        threat_level=threat_level,
                        status=f"{rtype} Resolved",
                        resolution=f"{rtype} record for {domain}",
                        raw_data=f"Type: {rtype} | Value: {value[:2000]}",
                        tags=["dns", rtype.lower(), "dnssec"] if is_dnssec_rtype else ["dns", rtype.lower()]
                    ))

                if len(values) > 3:
                    findings.append(IntelligenceFinding(
                        entity=f"{len(values)} total {rtype} records for {domain}",
                        type=f"DNS {rtype} Record Count",
                        source="DNS Resolver",
                        confidence="High",
                        color=color,
                        category="DNS Intelligence",
                        threat_level="Informational",
                        status=f"{len(values)} records",
                        tags=["dns", rtype.lower(), "count"]
                    ))

        except Exception:
            pass

    if security_records_found:
        findings.append(IntelligenceFinding(
            entity=f"Security records: {', '.join(sorted(security_records_found))}",
            type="DNS Security Records Summary",
            source="DNS Resolver",
            confidence="High",
            color="emerald",
            category="DNS Intelligence",
            threat_level="Informational",
            status="Security Records Found",
            tags=["dns", "security"]
        ))

    if dnssec_status["valid"]:
        findings.append(IntelligenceFinding(
            entity=f"DNSSEC Validated | {dnssec_status['keys']} DNSKEY(s), "
                   f"{dnssec_status['rrsigs']} RRSIG(s)",
            type="DNSSEC Status",
            source="DNS Resolver",
            confidence="High",
            color="emerald",
            category="DNS Intelligence",
            threat_level="Informational",
            status="DNSSEC Enabled",
            raw_data=f"Algorithm: {dnssec_status.get('algo', '?')}",
            tags=["dns", "dnssec", "security"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Domain {domain} does NOT have DNSSEC",
            type="DNSSEC Status",
            source="DNS Resolver",
            confidence="High",
            color="orange",
            category="DNS Intelligence",
            threat_level="Elevated Risk",
            status="DNSSEC Missing",
            tags=["dns", "dnssec", "security"]
        ))

    any_results = await check_any_query(loop, domain)
    if any_results:
        findings.append(IntelligenceFinding(
            entity=f"ANY query returned {len(any_results)} records",
            type="DNS ANY Query",
            source="DNS Resolver",
            confidence="Medium",
            color="slate",
            category="DNS Intelligence",
            threat_level="Informational",
            status="ANY Resolved",
            raw_data="\n".join(any_results[:5]),
            tags=["dns", "any-query"]
        ))

    if resolver_bench:
        fastest = min((ip for ip, t in resolver_bench.items() if t is not None),
                       key=lambda ip: resolver_bench[ip], default=None)
        slowest = max((ip for ip, t in resolver_bench.items() if t is not None),
                       key=lambda ip: resolver_bench[ip], default=None)
        if fastest and slowest:
            findings.append(IntelligenceFinding(
                entity=f"Fastest: {fastest} ({resolver_bench[fastest]}s) | "
                       f"Slowest: {slowest} ({resolver_bench[slowest]}s)",
                type="Resolver Speed Benchmark",
                source="DNS Resolver",
                confidence="High",
                color="slate",
                category="DNS Intelligence",
                threat_level="Informational",
                status="Benchmarked",
                raw_data=str(resolver_bench),
                tags=["dns", "benchmark"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"{len(all_records_found)}/{len(ALL_RECORD_TYPES)} record types resolved for {domain}",
        type="DNS Resolution Summary",
        source="DNS Resolver",
        confidence="High",
        color="blue",
        category="DNS Intelligence",
        threat_level="Informational",
        status=f"{len(all_records_found)} types resolved",
        tags=["dns", "summary"]
    ))

    dmarc_selectors = ["_dmarc"]
    for sel in dmarc_selectors:
        try:
            answers = await resolve_with_timeout(loop, f"{sel}.{domain}", "TXT")
            if answers[0]:
                for rdata in answers[0]:
                    value = str(rdata)
                    findings.append(IntelligenceFinding(
                        entity=value[:300],
                        type="DMARC Record",
                        source="DNS Resolver",
                        confidence="High",
                        color="emerald",
                        category="DNS Intelligence",
                        threat_level="Informational",
                        resolution=f"{sel}.{domain}",
                        status="DMARC Found",
                        raw_data=value[:2000],
                        tags=["dns", "dmarc", "email-security"]
                    ))
        except:
            pass

    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx',
                      'selector1', 'selector2', 'protonmail', 'zoho',
                      'mailgun', 'sendgrid', 'mandrill', 'sparkpost']:
        try:
            answers = await resolve_with_timeout(loop, f"{selector}._domainkey.{domain}", "TXT")
            if answers[0]:
                for rdata in answers[0]:
                    findings.append(IntelligenceFinding(
                        entity=f"{selector}._domainkey.{domain}",
                        type="DKIM Record",
                        source="DNS Resolver",
                        confidence="High",
                        color="emerald",
                        category="DNS Intelligence",
                        threat_level="Informational",
                        resolution=str(rdata)[:300],
                        status="DKIM Found",
                        raw_data=str(rdata)[:2000],
                        tags=["dns", "dkim", "email-security"]
                    ))
        except:
            pass

    try:
        wild_val = f"wildcard-test-{abs(hash(domain)) % 100000}.{domain}"
        wild = await resolve_with_timeout(loop, wild_val, "A")
        if wild[0]:
            findings.append(IntelligenceFinding(
                entity=f"*.{domain} resolves (wildcard DNS active)",
                type="Wildcard DNS Detection",
                source="DNS Resolver",
                confidence="High",
                color="orange",
                category="DNS Intelligence",
                threat_level="Elevated Risk",
                status="Wildcard Active",
                resolution=str(wild[0][0]),
                raw_data=f"Random subdomain {wild_val} resolves to {str(wild[0][0])}",
                tags=["dns", "wildcard"]
            ))
    except:
        pass

    try:
        mx_result = await resolve_with_timeout(loop, domain, "MX")
        if mx_result[0]:
            mx_hosts = [str(r.exchange).rstrip('.') for r in mx_result[0]]
            for mx in mx_hosts[:3]:
                try:
                    mx_a = await resolve_with_timeout(loop, mx, "A")
                    if mx_a[0]:
                        for ip in mx_a[0]:
                            findings.append(IntelligenceFinding(
                                entity=f"{mx} ({str(ip)})",
                                type="MX Server Resolution",
                                source="DNS Resolver",
                                confidence="High",
                                color="slate",
                                category="DNS Intelligence",
                                threat_level="Informational",
                                resolution=str(ip),
                                status="MX IP Resolved",
                                tags=["dns", "mx"]
                            ))
                except:
                    pass
    except:
        pass

    return findings
