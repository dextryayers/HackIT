import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.name
import dns.message
import dns.rdatatype
import dns.edns
import time
import random
import struct
from collections import defaultdict
from models import IntelligenceFinding

ALL_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR', 'CAA',
    'SSHFP', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'LOC', 'HINFO', 'RP',
    'NAPTR', 'CERT', 'SMIMEA', 'TLSA', 'URI', 'SVCB', 'HTTPS', 'DNAME', 'TKEY',
    'TSIG', 'ZONEMD', 'OPENPGPKEY',
]

RESOLVERS_TO_TEST = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Comodo", "8.26.56.26"),
    ("Yandex", "77.88.8.8"),
    ("Verisign", "64.6.64.6"),
    ("AdGuard", "94.140.14.14"),
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
    "CAA": {"color": "orange", "desc": "CA Authorization"},
    "SSHFP": {"color": "orange", "desc": "SSH Fingerprint"},
    "DNSKEY": {"color": "emerald", "desc": "DNSSEC Public Key"},
    "DS": {"color": "emerald", "desc": "DNSSEC Delegation Signer"},
    "NSEC": {"color": "emerald", "desc": "Next Secure (DNSSEC)"},
    "NSEC3": {"color": "emerald", "desc": "NSEC3 (DNSSEC)"},
    "RRSIG": {"color": "emerald", "desc": "Resource Record Signature"},
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

BULK_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
    "blog", "app", "webmail", "remote", "portal", "ssh", "git", "jenkins",
    "jira", "confluence", "mysql", "db", "ns1", "ns2", "cloud", "test",
    "stage", "demo", "beta", "nginx", "smtp", "imap", "pop3",
    "autodiscover", "m", "mobile", "chat", "forum", "help", "support",
    "docs", "wiki", "status", "tracker", "monitor", "dashboard",
    "analytics", "metrics", "logs", "sync", "static", "assets",
    "media", "img", "upload", "download", "files", "backup", "cpanel",
    "whm", "server", "redis", "mongo", "postgres", "elastic",
    "kibana", "grafana", "prometheus", "alertmanager", "consul",
    "k8s", "kubernetes", "docker", "registry", "nexus", "artifactory",
    "gitlab", "bitbucket", "npm", "lms", "erp", "crm", "hr",
    "owa", "exchange", "lync", "skype", "teams", "zoom",
    "radius", "ldap", "kerberos", "ntp", "dhcp", "dns",
    "proxy", "squid", "webproxy", "gateway", "firewall",
    "ws", "wss", "websocket", "socket", "stream",
    "mx", "mail2", "mail1", "email", "sip", "voip",
    "auth", "login", "signin", "register", "sso", "oauth",
    "password", "reset", "account", "profile", "settings",
    "admin-console", "admin-panel", "manage", "management",
    "oracle", "sap", "salesforce", "zendesk", "servicenow",
    "sharepoint", "slack", "discord", "office", "office365",
    "outlook", "calendar", "drive", "hq", "headquarters",
    "us", "uk", "eu", "asia", "china", "japan", "india",
    "data", "database", "db1", "db2", "db3",
    "search", "solr", "lucene", "sphinx", "algolia",
    "notification", "notify", "alert", "alarm",
    "streaming", "video", "audio", "media-server",
    "load", "load-balancer", "lb", "balancer",
    "health", "healthcheck", "heartbeat",
    "monitoring", "watchdog", "sentry",
    "inventory", "asset", "cmdb", "discovery",
    "deploy", "deployment", "release", "rollback", "canary",
    "blue", "green", "bluegreen", "feature", "flag",
    "compliance", "audit", "risk", "control",
    "version", "update", "upgrade", "migrate",
    "batch", "job", "task", "worker", "scheduler",
    "trigger", "hook", "webhook", "callback",
    "cache", "varnish", "memcache",
    "storage", "s3", "bucket", "minio",
    "ssl", "tls", "cert", "certificate", "acme",
    "firewall", "fw", "waf", "ids", "ips",
    "openvpn", "wireguard", "ipsec", "rdp", "citrix",
    "vdi", "vmware", "vcenter", "esxi", "openstack",
    "iaas", "paas", "saas", "serverless", "lambda",
]

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
    for name, ip in RESOLVERS_TO_TEST[:6]:
        try:
            _, elapsed = await resolve_with_timeout(loop, domain, "A", resolver=ip)
            bench_results[name] = {"ip": ip, "time": round(elapsed, 3) if elapsed else None}
        except:
            bench_results[name] = {"ip": ip, "time": None}
    return bench_results

async def check_edns0_support(loop, domain) -> dict:
    result = {"supported": False, "udp_size": 0, "extended_rcode": None, "dnssec_ok": False}
    try:
        res = dns.resolver.Resolver()
        res.use_edns(0, dns.flags.DO, 4096)
        res.timeout = 5.0
        res.lifetime = 5.0
        answers = await loop.run_in_executor(None, lambda: res.resolve(domain, 'A'))
        if answers:
            result["supported"] = True
            result["udp_size"] = 4096
            result["extended_rcode"] = 0
            result["dnssec_ok"] = True
    except:
        try:
            res = dns.resolver.Resolver()
            res.use_edns(0, 0, 512)
            res.timeout = 5.0
            res.lifetime = 5.0
            answers = await loop.run_in_executor(None, lambda: res.resolve(domain, 'A'))
            if answers:
                result["supported"] = True
                result["udp_size"] = 512
        except:
            pass
    return result

async def check_dns_amplification(loop, domain) -> dict:
    result = {"factor": 0, "request_size": 0, "response_size": 0, "amplifiable": False}
    for rtype in ["ANY", "DNSSEC", "TXT", "NS"]:
        try:
            msg = dns.message.make_query(domain, dns.rdatatype.from_text(rtype if rtype != "DNSSEC" else "DNSKEY"))
            wire = msg.to_wire()
            req_size = len(wire)

            res = dns.resolver.Resolver()
            res.timeout = 5.0
            res.lifetime = 5.0
            answers = await loop.run_in_executor(None, lambda rt=rtype if rtype != "DNSSEC" else "DNSKEY": res.resolve(domain, rt))

            resp = None
            try:
                resp = answers.response
                resp_wire = resp.to_wire()
                resp_size = len(resp_wire)
            except:
                resp_size = sum(len(str(r)) for r in answers) if answers else 0

            if req_size > 0 and resp_size > req_size:
                factor = resp_size / req_size
                if factor > result["factor"]:
                    result = {
                        "factor": round(factor, 1),
                        "request_size": req_size,
                        "response_size": resp_size,
                        "amplifiable": factor > 3,
                        "record_type": rtype
                    }
        except:
            pass
    return result

async def bulk_resolve(loop, domain, record_types, max_concurrent=20):
    results = defaultdict(list)
    sem = asyncio.Semaphore(max_concurrent)

    async def resolve_one(sub):
        async with sem:
            for rtype in record_types:
                try:
                    answers, _ = await resolve_with_timeout(loop, f"{sub}.{domain}", rtype, timeout_sec=3.0)
                    if answers:
                        for r in answers:
                            results[(sub, rtype)].append(str(r))
                except:
                    pass

    tasks = [resolve_one(sub) for sub in BULK_SUBDOMAINS]
    await asyncio.gather(*tasks)
    return results

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    loop = asyncio.get_event_loop()

    # 1. DNSSEC status
    dnssec_status = await check_dnssec(loop, domain)

    # 2. Resolver benchmark
    resolver_bench = await benchmark_resolvers(loop, domain)

    # 3. EDNS0 support check
    edns0_status = await check_edns0_support(loop, domain)

    # 4. DNS amplification factor
    amp_result = await check_dns_amplification(loop, domain)

    security_records_found = set()
    all_records_found = set()

    # 5. Standard record enumeration
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
                        threat_level=threat_level,
                        status=f"{rtype} Resolved",
                        resolution=f"{rtype} record for {domain}",
                        raw_data=f"Type: {rtype} | Value: {value[:2000]} | Resolved in {elapsed:.3f}s" if elapsed else f"Type: {rtype} | Value: {value[:2000]}",
                        tags=["dns", rtype.lower(), "dnssec"] if is_dnssec_rtype else ["dns", rtype.lower()]
                    ))

                if len(values) > 3:
                    findings.append(IntelligenceFinding(
                        entity=f"{len(values)} total {rtype} records for {domain}",
                        type=f"DNS {rtype} Record Count",
                        source="DNS Resolver",
                        confidence="High",
                        color=color,
                        threat_level="Informational",
                        status=f"{len(values)} records",
                        tags=["dns", rtype.lower(), "count"]
                    ))
        except:
            pass

    # 6. Security records summary
    if security_records_found:
        findings.append(IntelligenceFinding(
            entity=f"Security records: {', '.join(sorted(security_records_found))}",
            type="DNS Security Records Summary",
            source="DNS Resolver",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Security Records Found",
            tags=["dns", "security"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No DNS security records (CAA, SSHFP, DANE, DNSSEC) found for {domain}",
            type="DNS Security Records Summary",
            source="DNS Resolver",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="No Security Records",
            tags=["dns", "security", "missing"]
        ))

    # 7. DNSSEC findings
    if dnssec_status["valid"]:
        findings.append(IntelligenceFinding(
            entity=f"DNSSEC Validated | {dnssec_status['keys']} DNSKEY(s), {dnssec_status['rrsigs']} RRSIG(s)",
            type="DNSSEC Status",
            source="DNS Resolver",
            confidence="High",
            color="emerald",
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
            threat_level="Elevated Risk",
            status="DNSSEC Missing",
            tags=["dns", "dnssec", "security"]
        ))

    # 8. EDNS0 findings
    if edns0_status["supported"]:
        findings.append(IntelligenceFinding(
            entity=f"EDNS0 supported (UDP size: {edns0_status['udp_size']}, DNSSEC OK: {edns0_status['dnssec_ok']})",
            type="EDNS0 Support",
            source="DNS Resolver",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="EDNS0 Supported",
            raw_data=f"EDNS0: udp_size={edns0_status['udp_size']}, extended_rcode={edns0_status['extended_rcode']}, do_bit={edns0_status['dnssec_ok']}",
            tags=["dns", "edns0", "performance"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"EDNS0 NOT supported by {domain}'s DNS servers",
            type="EDNS0 Support",
            source="DNS Resolver",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            status="No EDNS0",
            tags=["dns", "edns0", "limitation"]
        ))

    # 9. DNS amplification findings
    if amp_result["request_size"] > 0:
        color_amp = "red" if amp_result["amplifiable"] else "green"
        threat_amp = "Elevated Risk" if amp_result["amplifiable"] else "Informational"
        findings.append(IntelligenceFinding(
            entity=f"DNS amplification factor: {amp_result['factor']}x ({amp_result['record_type']})",
            type="DNS Amplification Check",
            source="DNS Resolver",
            confidence="High",
            color=color_amp,
            threat_level=threat_amp,
            status="Amplifiable" if amp_result["amplifiable"] else "Not Amplifiable",
            raw_data=f"Request: {amp_result['request_size']}B | Response: {amp_result['response_size']}B | Factor: {amp_result['factor']}x via {amp_result.get('record_type', '?')}",
            tags=["dns", "amplification", "dos-risk"]
        ))

    # 10. ANY query
    any_results = await check_any_query(loop, domain)
    if any_results:
        findings.append(IntelligenceFinding(
            entity=f"ANY query returned {len(any_results)} records",
            type="DNS ANY Query",
            source="DNS Resolver",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="ANY Resolved",
            raw_data="\n".join(any_results[:5]),
            tags=["dns", "any-query"]
        ))

    # 11. Resolver benchmark results
    if resolver_bench:
        valid_bench = {k: v for k, v in resolver_bench.items() if v["time"] is not None}
        if valid_bench:
            fastest = min(valid_bench, key=lambda k: valid_bench[k]["time"])
            slowest = max(valid_bench, key=lambda k: valid_bench[k]["time"])
            avg_time = sum(v["time"] for v in valid_bench.values()) / len(valid_bench)
            findings.append(IntelligenceFinding(
                entity=f"Fastest: {fastest} ({valid_bench[fastest]['time']}s) | Slowest: {slowest} ({valid_bench[slowest]['time']}s) | Avg: {avg_time:.3f}s",
                type="Resolver Speed Benchmark",
                source="DNS Resolver",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Benchmarked",
                raw_data=str({k: v["time"] for k, v in valid_bench.items()}),
                tags=["dns", "benchmark", "performance"]
            ))

        for name, data in resolver_bench.items():
            if data["time"] is not None:
                findings.append(IntelligenceFinding(
                    entity=f"{name} ({data['ip']}): {data['time']}s",
                    type="Resolver Timing Detail",
                    source="DNS Resolver",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"Resolver {name} @ {data['ip']} responded in {data['time']}s",
                    tags=["dns", "resolver", name.lower(), "timing"]
                ))

    # 12. Response timing analysis for all resolved records
    timing_findings = []
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            _, elapsed = await resolve_with_timeout(loop, domain, rtype)
            if elapsed is not None:
                timing_findings.append((rtype, elapsed))
        except:
            pass

    if timing_findings:
        fastest_rec = min(timing_findings, key=lambda x: x[1])
        slowest_rec = max(timing_findings, key=lambda x: x[1])
        findings.append(IntelligenceFinding(
            entity=f"Fastest record type: {fastest_rec[0]} ({fastest_rec[1]:.3f}s), Slowest: {slowest_rec[0]} ({slowest_rec[1]:.3f}s)",
            type="DNS Response Timing Analysis",
            source="DNS Resolver",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"Record type timings: {', '.join(f'{rt}: {t:.3f}s' for rt, t in timing_findings)}",
            tags=["dns", "timing", "performance"]
        ))

    # 13. Bulk subdomain resolution
    bulk_record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    bulk_results = await bulk_resolve(loop, domain, bulk_record_types)

    # Group by subdomain
    subdomain_data = defaultdict(lambda: defaultdict(list))
    for (sub, rtype), values in bulk_results.items():
        for v in values:
            subdomain_data[sub][rtype].append(v)

    if subdomain_data:
        for sub, records in sorted(subdomain_data.items()):
            record_types_found = list(records.keys())
            ip_list = records.get("A", [])
            ip = ip_list[0] if ip_list else ""
            cname_list = records.get("CNAME", [])

            raw_parts = [f"{rt}: {', '.join(recs[:2])}" for rt, recs in records.items()]
            findings.append(IntelligenceFinding(
                entity=f"{sub}.{domain}",
                type="Bulk Resolved Subdomain",
                source="DNS Resolver",
                confidence="High",
                color="emerald" if ip_list else "purple" if "AAAA" in records else "slate",
                threat_level="Informational",
                status=f"Resolved ({', '.join(record_types_found)})",
                resolution=ip,
                raw_data=" | ".join(raw_parts),
                tags=["bulk", "subdomain", "dns"] + record_types_found
            ))

    if subdomain_data:
        findings.append(IntelligenceFinding(
            entity=f"Bulk resolved {len(subdomain_data)}/{len(BULK_SUBDOMAINS)} common subdomains for {domain}",
            type="Bulk Resolution Summary",
            source="DNS Resolver",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"{len(subdomain_data)} subdomains resolved from {len(BULK_SUBDOMAINS)} common prefixes",
            tags=["dns", "bulk", "summary"]
        ))

    # 14. Summary
    total_records = len([f for f in findings if f.type.startswith("DNS ")])
    findings.append(IntelligenceFinding(
        entity=f"{len(all_records_found)}/{len(ALL_RECORD_TYPES)} record types resolved | {total_records} total records",
        type="DNS Resolution Summary",
        source="DNS Resolver",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status=f"{len(all_records_found)} types resolved",
        tags=["dns", "summary"]
    ))

    # 15. DMARC/DKIM
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
                        threat_level="Informational",
                        resolution=f"{sel}.{domain}",
                        status="DMARC Found",
                        raw_data=value[:2000],
                        tags=["dns", "dmarc", "email-security"]
                    ))
        except:
            findings.append(IntelligenceFinding(
                entity=f"No DMARC record for {domain}",
                type="DMARC Status",
                source="DNS Resolver",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="No DMARC",
                tags=["dns", "dmarc", "missing"]
            ))

    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx',
                      'selector1', 'selector2', 'protonmail', 'zoho',
                      'mailgun', 'sendgrid', 'mandrill', 'sparkpost',
                      'postmark', 'amazonses', 'smtp', 'email']:
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
                        threat_level="Informational",
                        resolution=str(rdata)[:300],
                        status="DKIM Found",
                        raw_data=str(rdata)[:2000],
                        tags=["dns", "dkim", "email-security"]
                    ))
        except:
            pass

    # 16. Wildcard detection
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
                threat_level="Elevated Risk",
                status="Wildcard Active",
                resolution=str(wild[0][0]),
                raw_data=f"Random subdomain {wild_val} resolves to {str(wild[0][0])}",
                tags=["dns", "wildcard"]
            ))
    except:
        pass

    # 17. MX resolution
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
