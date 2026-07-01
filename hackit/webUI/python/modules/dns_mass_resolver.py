import asyncio
import dns.resolver
import dns.message
import dns.rdatatype
import time
from collections import defaultdict
from models import IntelligenceFinding

RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Google-2", "8.8.4.4"),
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare-2", "1.0.0.1"),
    ("Quad9", "9.9.9.9"),
    ("Quad9-2", "149.112.112.112"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS-2", "208.67.220.220"),
    ("Comodo", "8.26.56.26"),
    ("Comodo-2", "8.20.247.20"),
    ("Verisign", "64.6.64.6"),
    ("Verisign-2", "64.6.65.6"),
    ("AdGuard", "94.140.14.14"),
    ("AdGuard-2", "94.140.15.15"),
    ("SafeSurfer", "104.155.237.5"),
    ("CleanBrowsing", "185.228.168.9"),
    ("Neustar", "156.154.70.1"),
    ("Yandex", "77.88.8.8"),
    ("DNS.WATCH", "84.200.69.80"),
    ("UncensoredDNS", "91.239.100.100"),
]

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']

async def resolve_single(domain: str, rtype: str, resolver_ip: str, timeout_sec: float = 4.0):
    start = time.monotonic()
    try:
        res = dns.resolver.Resolver()
        res.nameservers = [resolver_ip]
        res.timeout = timeout_sec
        res.lifetime = timeout_sec
        answers = res.resolve(domain, rtype)
        elapsed = time.monotonic() - start
        values = [str(r) for r in answers]
        return values, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        return [], elapsed

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    loop = asyncio.get_event_loop()
    rtype_summary = defaultdict(lambda: defaultdict(list))
    resolver_latency = defaultdict(list)

    for rtype in RECORD_TYPES:
        tasks = []
        for name, ip in RESOLVERS:
            tasks.append(resolve_single(domain, rtype, ip))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (name, ip), result in zip(RESOLVERS, results):
            if isinstance(result, tuple):
                values, elapsed = result
                if values:
                    rtype_summary[rtype][name] = values
                    resolver_latency[name].append(elapsed)
                    findings.append(IntelligenceFinding(
                        entity=f"{rtype}: {', '.join(values[:3])}",
                        type=f"DNS {rtype} via {name}",
                        source="DNS Mass Resolver",
                        confidence="High",
                        color="blue" if rtype == 'A' else "slate",
                        threat_level="Informational",
                        status="Resolved",
                        resolution=values[0] if rtype in ('A', 'AAAA') else ip,
                        raw_data=f"Resolver: {name} ({ip}) | Type: {rtype} | Values: {', '.join(values[:5])} | Time: {elapsed:.3f}s",
                        tags=["dns", "mass-resolver", name.lower().replace(" ", "-"), rtype.lower()]
                    ))

    for rtype, resolver_data in rtype_summary.items():
        all_values = set()
        for vals in resolver_data.values():
            all_values.update(vals)
        if len(resolver_data) >= 2:
            agreement_count = 0
            for vals in resolver_data.values():
                if set(vals) == all_values:
                    agreement_count += 1
            pct = round(agreement_count / len(resolver_data) * 100)
            color = "green" if pct >= 90 else "orange" if pct >= 50 else "red"
            findings.append(IntelligenceFinding(
                entity=f"{rtype}: {agreement_count}/{len(resolver_data)} resolvers agree ({pct}%)",
                type="DNS Resolver Consensus",
                source="DNS Mass Resolver",
                confidence="High",
                color=color,
                threat_level="Informational" if pct >= 90 else "Standard Target",
                status=f"{pct}% Agreement",
                raw_data=f"Record: {rtype} | Agreeing: {agreement_count}/{len(resolver_data)} | Values: {', '.join(sorted(all_values)[:3])}",
                tags=["dns", "consensus", rtype.lower()]
            ))

            discrepancies = {name: vals for name, vals in resolver_data.items() if set(vals) != all_values}
            for dname, dvals in discrepancies.items():
                findings.append(IntelligenceFinding(
                    entity=f"{dname} returns different {rtype}: {', '.join(dvals[:3])} vs expected {', '.join(sorted(all_values)[:3])}",
                    type="DNS Resolver Discrepancy",
                    source="DNS Mass Resolver",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Discrepancy",
                    raw_data=f"Resolver: {dname} | Type: {rtype} | Got: {dvals} | Expected: {all_values}",
                    tags=["dns", "discrepancy", "inconsistency", rtype.lower()]
                ))

    for resolver_name, latencies in resolver_latency.items():
        if latencies:
            avg_lat = round(sum(latencies) / len(latencies), 3)
            min_lat = round(min(latencies), 3)
            max_lat = round(max(latencies), 3)
            findings.append(IntelligenceFinding(
                entity=f"{resolver_name}: avg {avg_lat}s, min {min_lat}s, max {max_lat}s",
                type="Resolver Latency Analysis",
                source="DNS Mass Resolver",
                confidence="High",
                color="green" if avg_lat < 0.1 else "orange" if avg_lat < 0.5 else "red",
                threat_level="Informational",
                status="Measured",
                raw_data=f"Resolver: {resolver_name} | Avg: {avg_lat}s | Min: {min_lat}s | Max: {max_lat}s | Samples: {len(latencies)}",
                tags=["dns", "latency", "performance", resolver_name.lower().replace(" ", "-")]
            ))

    if resolver_latency:
        valid_avg = {name: round(sum(lats) / len(lats), 3) for name, lats in resolver_latency.items() if lats}
        if valid_avg:
            fastest = min(valid_avg, key=valid_avg.get)
            slowest = max(valid_avg, key=valid_avg.get)
            findings.append(IntelligenceFinding(
                entity=f"Fastest: {fastest} ({valid_avg[fastest]}s) | Slowest: {slowest} ({valid_avg[slowest]}s)",
                type="Resolver Speed Ranking",
                source="DNS Mass Resolver",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Ranked",
                raw_data=f"Rankings: {', '.join(sorted(valid_avg, key=valid_avg.get)[:5])}",
                tags=["dns", "speed", "ranking"]
            ))

    total_queries = sum(len(types) for types in rtype_summary.values())
    findings.append(IntelligenceFinding(
        entity=f"Completed {len(RECORD_TYPES)} record types across {len(RESOLVERS)} resolvers ({total_queries} resolver-record pairs)",
        type="Mass Resolution Summary",
        source="DNS Mass Resolver",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Target: {domain} | Resolvers: {len(RESOLVERS)} | Record Types: {len(RECORD_TYPES)} | Successful: {total_queries}",
        tags=["dns", "summary", "mass-resolver"]
    ))

    return findings
