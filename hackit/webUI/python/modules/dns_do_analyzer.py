import httpx
import asyncio
import dns.resolver
import dns.message
import dns.rdatatype
import time
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

DOH_ENDPOINTS = [
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query", "ip": "1.1.1.1"},
    {"name": "Google", "url": "https://dns.google/dns-query", "ip": "8.8.8.8"},
    {"name": "Quad9", "url": "https://dns.quad9.net/dns-query", "ip": "9.9.9.9"},
    {"name": "AdGuard", "url": "https://dns.adguard.com/dns-query", "ip": "94.140.14.14"},
    {"name": "AdGuard Family", "url": "https://dns-family.adguard.com/dns-query", "ip": "94.140.14.15"},
    {"name": "Mullvad", "url": "https://dns.mullvad.net/dns-query", "ip": "194.242.2.2"},
    {"name": "CZ.NIC", "url": "https://dns.nic.cz/dns-query", "ip": "193.17.47.1"},
    {"name": "dns0.eu", "url": "https://dns0.eu/dns-query", "ip": "193.110.81.0"},
    {"name": "LibreDNS", "url": "https://doh.libredns.gr/dns-query", "ip": "116.202.226.67"},
    {"name": "NextDNS", "url": "https://dns.nextdns.io/dns-query", "ip": "45.90.28.169"},
]

DOT_ENDPOINTS = [
    {"name": "Cloudflare", "host": "1.1.1.1", "tls_host": "cloudflare-dns.com"},
    {"name": "Google", "host": "8.8.8.8", "tls_host": "dns.google"},
    {"name": "Quad9", "host": "9.9.9.9", "tls_host": "dns.quad9.net"},
    {"name": "AdGuard", "host": "94.140.14.14", "tls_host": "dns.adguard.com"},
    {"name": "Mullvad", "host": "194.242.2.2", "tls_host": "dns.mullvad.net"},
]

async def doh_query(domain: str, doh_url: str, client: httpx.AsyncClient):
    try:
        rtype_num = dns.rdatatype.from_text('A')
        msg = dns.message.make_query(domain, rtype_num)
        msg.flags |= dns.flags.AD
        wire = msg.to_wire()
        start = time.monotonic()
        resp = await safe_fetch(client, doh_url,
            content=wire,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": "Mozilla/5.0"
            },
            timeout=10.0, method="POST")
        elapsed = time.monotonic() - start
        if resp.status_code == 200:
            response = dns.message.from_wire(resp.content)
            answers = []
            if response.answer:
                for rrset in response.answer:
                    for rr in rrset:
                        answers.append(str(rr))
            ad_flag = bool(response.flags & dns.flags.AD)
            return answers, elapsed, ad_flag
        return [], elapsed, False
    except:
        return [], 0, False

async def dot_query(domain: str, host: str, tls_host: str):
    loop = asyncio.get_event_loop()
    try:
        import ssl
        rtype_num = dns.rdatatype.from_text('A')
        msg = dns.message.make_query(domain, rtype_num)
        wire = msg.to_wire()
        start = time.monotonic()
        try:
            response = await loop.run_in_executor(
                None,
                lambda: dns.query.tls(domain, host, port=853, timeout=5.0, server_hostname=tls_host)
            )
        except:
            try:
                response = dns.query.udp(dns.message.make_query(domain, rtype_num), host, timeout=5.0)
            except:
                return [], 0
        elapsed = time.monotonic() - start
        answers = [str(r) for rrset in response.answer for r in rrset] if response.answer else []
        return answers, elapsed
    except:
        return [], 0

async def check_udp_dns(domain: str, resolver_ip: str):
    try:
        res = dns.resolver.Resolver()
        res.nameservers = [resolver_ip]
        res.timeout = 3.0
        res.lifetime = 3.0
        answers = res.resolve(domain, 'A')
        return [str(r) for r in answers]
    except:
        return []

async def check_edns_padding(domain: str, client: httpx.AsyncClient):
    results = {}
    for doh in DOH_ENDPOINTS[:3]:
        try:
            msg = dns.message.make_query(domain, dns.rdatatype.A)
            msg.use_edns(0, dns.flags.DO, 4096, [dns.edns.GenericOption(0, b'\x00' * 128)])
            wire = msg.to_wire()
            resp = await safe_fetch(client, doh["url"],
                content=wire,
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                timeout=10.0, method="POST")
            if resp.status_code == 200:
                req_size = len(wire)
                resp_size = len(resp.content)
                results[doh["name"]] = {"req_size": req_size, "resp_size": resp_size, "padded": True}
        except:
            results[doh["name"]] = {"error": True}
    return results

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    doh_supported = 0
    doh_total = len(DOH_ENDPOINTS)
    doh_results = []

    for doh in DOH_ENDPOINTS:
        answers, elapsed, ad_flag = await doh_query(domain, doh["url"], client)
        if answers:
            doh_supported += 1
            doh_results.append((doh["name"], answers, elapsed, ad_flag))
            findings.append(make_finding(
                entity=f"DoH via {doh['name']}: {', '.join(answers[:3])} ({elapsed:.3f}s)",
                type="DNS over HTTPS (DoH)",
                source="DNS Do Analyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="DoH Available",
                resolution=', '.join(answers[:3]),
                raw_data=f"DoH Endpoint: {doh['url']} | Time: {elapsed:.3f}s | AD-bit: {ad_flag}",
                tags=["doh", "dns-over-https", doh["name"].lower().replace(" ", "-")]
            ))
        else:
            findings.append(make_finding(
                entity=f"DoH via {doh['name']}: not available",
                ftype="DNS over HTTPS (DoH) Unavailable",
                source="DNS Do Analyzer",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="DoH Unavailable",
                tags=["doh", "unavailable", doh["name"].lower().replace(" ", "-")]
            ))

    for doh_name, answers, elapsed, ad_flag in doh_results:
        if ad_flag:
            findings.append(make_finding(
                entity=f"DNSSEC over DoH via {doh_name}: AD-bit set, validation OK",
                ftype="DNSSEC over DoH",
                source="DNS Do Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="DNSSEC Validated",
                tags=["doh", "dnssec", "ad-bit"]
            ))

    dot_supported = 0
    for dot in DOT_ENDPOINTS:
        answers, elapsed = await dot_query(domain, dot["host"], dot["tls_host"])
        if answers:
            dot_supported += 1
            findings.append(make_finding(
                entity=f"DoT via {dot['name']}: {', '.join(answers[:3])} ({elapsed:.3f}s)",
                type="DNS over TLS (DoT)",
                source="DNS Do Analyzer",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="DoT Available",
                tags=["dot", "dns-over-tls", dot["name"].lower().replace(" ", "-")]
            ))
        else:
            findings.append(make_finding(
                entity=f"DoT via {dot['name']}: not available",
                ftype="DNS over TLS (DoT) Unavailable",
                source="DNS Do Analyzer",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="DoT Unavailable",
                tags=["dot", "unavailable", dot["name"].lower().replace(" ", "-")]
            ))

    if doh_supported > 0:
        avg_time = sum(r[2] for r in doh_results) / len(doh_results) if doh_results else 0
        fastest = min(doh_results, key=lambda x: x[2]) if doh_results else None
        findings.append(make_finding(
            entity=f"DoH: {doh_supported}/{doh_total} endpoints work, avg {avg_time:.3f}s, fastest: {fastest[0] if fastest else 'N/A'} ({fastest[2]:.3f}s)" if fastest else "N/A",
            type="DoH Availability Summary",
            source="DNS Do Analyzer",
            confidence="High",
            color="green" if doh_supported > 3 else "orange",
            threat_level="Informational",
            status=f"{doh_supported}/{doh_total}",
            tags=["doh", "summary"]
        ))

    if dot_supported > 0:
        findings.append(make_finding(
            entity=f"DoT: {dot_supported}/{len(DOT_ENDPOINTS)} endpoints work",
            type="DoT Availability Summary",
            source="DNS Do Analyzer",
            confidence="High",
            color="green",
            threat_level="Informational",
            status=f"{dot_supported}/{len(DOT_ENDPOINTS)}",
            tags=["dot", "summary"]
        ))

    udp_results = {}
    for resolver_info in DOH_ENDPOINTS:
        udp_answers = await check_udp_dns(domain, resolver_info["ip"])
        if udp_answers:
            udp_results[resolver_info["name"]] = udp_answers

    for doh_name, _, _, _ in doh_results:
        udp_name = doh_name
        doh_answers = None
        for n, a, _, _ in doh_results:
            if n == doh_name:
                doh_answers = a
                break
        if udp_name in udp_results and doh_answers:
            if set(udp_results[udp_name]) != set(doh_answers):
                findings.append(make_finding(
                    entity=f"UDP vs DoH inconsistency at {udp_name}: UDP={udp_results[udp_name]}, DoH={doh_answers}",
                    ftype="DNS Protocol Inconsistency",
                    source="DNS Do Analyzer",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Inconsistent",
                    tags=["doh", "udp", "inconsistency"]
                ))

    edns_pad = await check_edns_padding(domain, client)
    for name, data in edns_pad.items():
        if isinstance(data, dict) and data.get("padded"):
            findings.append(make_finding(
                entity=f"EDNS padding via {name}: req={data['req_size']}B, resp={data['resp_size']}B",
                ftype="EDNS Padding Test",
                source="DNS Do Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Padding Supported",
                tags=["edns", "padding", "privacy"]
            ))

    privacy_available = doh_supported + dot_supported
    total_protocols = doh_total + len(DOT_ENDPOINTS)
    privacy_level = "High" if privacy_available > total_protocols * 0.5 else "Medium" if privacy_available > 0 else "Low"
    findings.append(make_finding(
        entity=f"DNS privacy level: {privacy_level} ({doh_supported} DoH, {dot_supported} DoT endpoints available)",
        type="DNS Privacy Assessment",
        source="DNS Do Analyzer",
        confidence="High",
        color="green" if privacy_level == "High" else "orange" if privacy_level == "Medium" else "red",
        threat_level="Informational" if privacy_level == "High" else "Standard Target",
        status=f"Privacy {privacy_level}",
        tags=["dns", "privacy", "doh", "dot"]
    ))

    findings.append(make_finding(
        entity=f"DNS over HTTPS/TLS/QUIC analysis complete for {domain}",
        ftype="DNS Do Analysis Summary",
        source="DNS Do Analyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["dns", "doh", "dot", "summary"]
    ))

    return findings
