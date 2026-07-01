import asyncio
import dns.resolver
import random
import string
from collections import defaultdict
from models import IntelligenceFinding

PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("AdGuard", "94.140.14.14"),
    ("Verisign", "64.6.64.6"),
]

async def resolve_with_resolver(domain: str, resolver_ip: str = None):
    loop = asyncio.get_event_loop()
    try:
        res = dns.resolver.Resolver()
        if resolver_ip:
            res.nameservers = [resolver_ip]
        res.timeout = 3.0
        res.lifetime = 3.0
        answers = res.resolve(domain, 'A')
        return [str(r) for r in answers]
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    random_subs = []
    for _ in range(25):
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10, 20)))
        random_subs.append(f"{rand_str}.{domain}")

    loop = asyncio.get_event_loop()
    wildcard_ips_per_resolver = defaultdict(set)
    wildcard_found = False

    for name, ip in PUBLIC_RESOLVERS:
        for rs in random_subs:
            ips = await resolve_with_resolver(rs, ip)
            if ips:
                for ip_addr in ips:
                    wildcard_ips_per_resolver[name].add(ip_addr)

    if any(wildcard_ips_per_resolver.values()):
        wildcard_found = True
        for name, ips in wildcard_ips_per_resolver.items():
            if ips:
                findings.append(IntelligenceFinding(
                    entity=f"Wildcard detected via {name}: {', '.join(ips)}",
                    type="Wildcard DNS Detection",
                    source="DNS Wildcard Detector",
                    confidence="Certain",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Wildcard Active",
                    raw_data=f"Resolver: {name} | Random subs resolve to: {', '.join(ips)}",
                    tags=["wildcard", name.lower(), "detected"]
                ))

        all_ips = set()
        for ips in wildcard_ips_per_resolver.values():
            all_ips.update(ips)
        findings.append(IntelligenceFinding(
            entity=f"Wildcard resolves to {len(all_ips)} unique IP(s): {', '.join(all_ips)}",
            type="Wildcard IP Analysis",
            source="DNS Wildcard Detector",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="Wildcard IPs",
            tags=["wildcard", "ip-analysis"]
        ))

        resolver_consistency = {}
        for name, ips in wildcard_ips_per_resolver.items():
            resolver_consistency[name] = ips == all_ips if ips else False
        consistent = all(v for v in resolver_consistency.values() if isinstance(v, bool))
        if not consistent:
            findings.append(IntelligenceFinding(
                entity=f"Wildcard responses differ across resolvers - possible geo-wildcard",
                type="Wildcard Resolver Inconsistency",
                source="DNS Wildcard Detector",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                status="Inconsistent",
                tags=["wildcard", "inconsistency"]
            ))

    long_prefix_subs = []
    for length in [30, 40, 50]:
        for _ in range(3):
            long_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
            long_prefix_subs.append(f"{long_str}.{domain}")

    long_resolved = []
    for rs in long_prefix_subs:
        ips = await resolve_with_resolver(rs)
        if ips:
            long_resolved.append((rs, ips))

    if long_resolved and wildcard_found:
        long_ips = set()
        for _, ips in long_resolved:
            long_ips.update(ips)
        if long_ips != all_ips:
            findings.append(IntelligenceFinding(
                entity=f"Long prefix bypass: {len(long_resolved)}/{len(long_prefix_subs)} resolved differently",
                type="Wildcard Bypass Attempt",
                source="DNS Wildcard Detector",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                status="Partial Bypass",
                tags=["wildcard", "bypass"]
            ))
        findings.append(IntelligenceFinding(
            entity=f"Long prefix ({length}+ chars) wildcard test: {len(long_resolved)} resolved",
            type="Wildcard Long Prefix Test",
            source="DNS Wildcard Detector",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Tested",
            tags=["wildcard", "long-prefix"]
        ))

    if not wildcard_found:
        findings.append(IntelligenceFinding(
            entity=f"No wildcard DNS detected for {domain}",
            type="Wildcard DNS Status",
            source="DNS Wildcard Detector",
            confidence="High",
            color="green",
            threat_level="Informational",
            status="No Wildcard",
            raw_data=f"Tested {len(random_subs)} random non-existent subdomains across {len(PUBLIC_RESOLVERS)} resolvers",
            tags=["wildcard", "clean"]
        ))

    cd_ips = set()
    for _ in range(5):
        cd_str = f"cdn-test-{''.join(random.choices(string.ascii_lowercase, k=8))}.{domain}"
        ips = await resolve_with_resolver(cd_str)
        if ips:
            cd_ips.update(ips)

    admin_ips = set()
    for _ in range(5):
        admin_str = f"admin-test-{''.join(random.choices(string.ascii_lowercase, k=8))}.{domain}"
        ips = await resolve_with_resolver(admin_str)
        if ips:
            admin_ips.update(ips)

    if cd_ips and admin_ips and cd_ips != admin_ips:
        findings.append(IntelligenceFinding(
            entity=f"Different wildcard IPs for 'cdn-*' vs 'admin-*' patterns - CDN/hosting routing",
            type="Wildcard Pattern Analysis",
            source="DNS Wildcard Detector",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Pattern Detected",
            raw_data=f"cdn-prefix IPs: {', '.join(cd_ips)} | admin-prefix IPs: {', '.join(admin_ips)}",
            tags=["wildcard", "pattern"]
        ))

    if wildcard_found:
        findings.append(IntelligenceFinding(
            entity=f"Wildcard DNS ACTIVE for {domain} - subdomain enumeration will have false positives",
            type="Wildcard Impact Assessment",
            source="DNS Wildcard Detector",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Active",
            raw_data=f"Wildcard IPs: {', '.join(all_ips)} | Resolvers detecting: {', '.join(wildcard_ips_per_resolver.keys())}",
            tags=["wildcard", "impact"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Wildcard detection complete for {domain}",
        type="Wildcard Detection Summary",
        source="DNS Wildcard Detector",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["wildcard", "summary"]
    ))

    return findings
