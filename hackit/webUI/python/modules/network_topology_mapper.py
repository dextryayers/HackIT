import httpx
import re
import socket
import asyncio
import json
from models import IntelligenceFinding
from urllib.parse import urlparse


async def resolve_ip(target: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
    except:
        return target if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target) else ""


async def check_cdn_edges(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        base_url = f"https://{target}" if not target.startswith("http") else target
        resp = await client.get(base_url, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        via = headers.get("via", "").lower()
        cf_ray = headers.get("cf-ray", "")
        edge = ""

        if "cloudflare" in server or cf_ray:
            edge = "Cloudflare"
        elif "akamaighost" in server or "akamai" in server:
            edge = "Akamai"
        elif "fastly" in server:
            edge = "Fastly"
        elif "amazons3" in server or "amazon" in server or "cloudfront" in server:
            edge = "AWS CloudFront / S3"
        elif "cloudflare" in via:
            edge = "Cloudflare (via header)"
        elif "stackpath" in server or "stackpath" in via:
            edge = "StackPath"
        elif "keycdn" in server:
            edge = "KeyCDN"
        elif "cdn" in server:
            edge = f"CDN: {server[:50]}"

        if edge:
            findings.append(IntelligenceFinding(
                entity=edge,
                type="CDN Edge Detection",
                source="NetworkTopologyMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status=f"Behind {edge}",
                raw_data=f"Server: {server}, Via: {via}, CF-Ray: {cf_ray}",
                tags=["cdn", "edge", edge.lower().replace(" ", "-")]
            ))

        if cf_ray:
            colo = cf_ray.split("-")[-1] if "-" in cf_ray else ""
            if colo:
                findings.append(IntelligenceFinding(
                    entity=f"Cloudflare PoP: {colo}",
                    type="CDN Point of Presence",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"CF-Ray: {cf_ray}",
                    tags=["cdn", "cloudflare", "pop"]
                ))
    except:
        pass
    return findings


async def get_bgp_info(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            asn = data.get("asn", {})
            if isinstance(asn, dict) and asn.get("asn"):
                asn_num = asn["asn"]
                findings.append(IntelligenceFinding(
                    entity=asn_num,
                    type="BGP: ASN",
                    source="NetworkTopologyMapper (ipinfo.io)",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Found",
                    resolution=org,
                    raw_data=f"ASN: {asn_num}, Org: {org}",
                    tags=["bgp", "asn", asn_num]
                ))
            elif isinstance(org, str) and "AS" in org:
                parts = org.split(" ", 1)
                asn_val = parts[0] if len(parts) > 0 else org
                findings.append(IntelligenceFinding(
                    entity=asn_val,
                    type="BGP: ASN",
                    source="NetworkTopologyMapper (ipinfo.io)",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Found",
                    resolution=org,
                    tags=["bgp", "asn"]
                ))

            city = data.get("city", "")
            region = data.get("region", "")
            country = data.get("country", "")
            loc = data.get("loc", "")
            if city:
                findings.append(IntelligenceFinding(
                    entity=f"{city}, {region}, {country}",
                    type="Geo: Location",
                    source="NetworkTopologyMapper (ipinfo.io)",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    resolution=loc,
                    tags=["geo", "location", country.lower()]
                ))
    except:
        pass

    # BGP.HE.NET lookup
    try:
        resp = await client.get(
            f"https://bgp.he.net/ip/{ip}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            text = resp.text
            asn_matches = re.findall(r'AS(\d+)', text)
            seen = set()
            for asn in asn_matches:
                if asn not in seen:
                    seen.add(asn)
                    findings.append(IntelligenceFinding(
                        entity=f"AS{asn}",
                        type="BGP: Adjacent ASN",
                        source="NetworkTopologyMapper (bgp.he.net)",
                        confidence="Medium",
                        color="orange",
                        threat_level="Informational",
                        tags=["bgp", f"as{asn}"]
                    ))
            prefix_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b', text)
            for prefix in prefix_matches[:5]:
                findings.append(IntelligenceFinding(
                    entity=prefix,
                    type="BGP: Announced Prefix",
                    source="NetworkTopologyMapper (bgp.he.net)",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["bgp", "prefix"]
                ))
    except:
        pass

    # RDAP lookup
    try:
        resp = await client.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            entities = []
            if "entities" in data:
                for ent in data["entities"]:
                    if isinstance(ent, dict):
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) >= 3 and item[0] == "fn":
                                    entities.append(item[3])
            if entities:
                findings.append(IntelligenceFinding(
                    entity=", ".join(entities[:3]),
                    type="RDAP: Network Organization",
                    source="NetworkTopologyMapper (RDAP)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=str(data)[:500],
                    tags=["rdap", "whois", "registration"]
                ))
            handle = data.get("handle", "")
            if handle:
                findings.append(IntelligenceFinding(
                    entity=handle,
                    type="RDAP: Network Handle",
                    source="NetworkTopologyMapper (RDAP)",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["rdap", "handle"]
                ))
    except:
        pass

    return findings


async def trace_route_analysis(target: str) -> list:
    findings = []
    domain = target.strip().lower()
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
        findings.append(IntelligenceFinding(
            entity=ip,
            type="Network: Resolved IP",
            source="NetworkTopologyMapper",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status=f"Resolved {domain}",
            raw_data=f"{domain} -> {ip}",
            tags=["dns", "resolution", "ip"]
        ))

        # Try reverse DNS
        try:
            hostname = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip))
            if hostname:
                findings.append(IntelligenceFinding(
                    entity=hostname[0],
                    type="Network: Reverse DNS (PTR)",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="PTR record found",
                    resolution=ip,
                    raw_data=f"{ip} -> {hostname[0]}",
                    tags=["dns", "ptr", "reverse-dns"]
                ))
        except:
            pass

        # Additional A and AAAA records if there are load balancers
        try:
            ips = await loop.run_in_executor(
                None,
                lambda: [addr[4][0] for addr in socket.getaddrinfo(domain, 80)]
            )
            unique_ips = list(set(ips))
            if len(unique_ips) > 1:
                findings.append(IntelligenceFinding(
                    entity=f"{len(unique_ips)} resolved IPs for {domain}",
                    type="Network: Multi-IP Resolution",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"IPs: {', '.join(unique_ips)}",
                    tags=["dns", "multi-ip", "load-balancing"]
                ))
        except:
            pass
    except Exception as e:
        pass
    return findings


async def check_icmp_reachability(target: str) -> list:
    findings = []
    domain = target.strip().lower()
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "3", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
        output = stdout.decode() if stdout else ""
        ttl_match = re.search(r'ttl=(\d+)', output)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            ttl_info = "Windows/Linux mixed" if ttl < 64 else ("Linux/Unix" if ttl < 128 else "Windows")
            findings.append(IntelligenceFinding(
                entity=f"TTL={ttl} ({ttl_info})",
                type="Network: TTL Analysis",
                source="NetworkTopologyMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=output[:500],
                tags=["ttl", "icmp", "os-detection"]
            ))
        time_match = re.search(r'time=([0-9.]+)\s*ms', output)
        if time_match:
            latency = time_match.group(1)
            findings.append(IntelligenceFinding(
                entity=f"Latency: {latency}ms",
                type="Network: Latency",
                source="NetworkTopologyMapper",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                tags=["latency", "icmp"]
            ))
    except:
        pass
    return findings


async def get_ip_ranges(target: str) -> list:
    findings = []
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"https://raw.githubusercontent.com/\
client-ip/ranges/main/{target}.txt",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                ranges = [l.strip() for l in resp.text.split("\n") if l.strip()]
                for r in ranges[:5]:
                    findings.append(IntelligenceFinding(
                        entity=r,
                        type="Network: Known IP Range",
                        source="NetworkTopologyMapper",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["ip-range", "network"]
                    ))
    except:
        pass
    return findings


async def check_network_boundaries(target: str, ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            asn_val = data.get("asn", "")
            network = data.get("network", "")
            version = data.get("version", "")

            if asn_val:
                findings.append(IntelligenceFinding(
                    entity=asn_val,
                    type="Network Boundary: ASN",
                    source="NetworkTopologyMapper (ipapi.co)",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    resolution=org,
                    tags=["asn", "network-boundary"]
                ))
            if network:
                findings.append(IntelligenceFinding(
                    entity=network,
                    type="Network Boundary: CIDR",
                    source="NetworkTopologyMapper (ipapi.co)",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["cidr", "network-boundary"]
                ))
    except:
        pass

    # Check whois for IP range
    try:
        resp = await client.get(
            f"https://whois.arin.net/rest/ip/{ip}.json",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            net = data.get("net", {})
            if isinstance(net, dict):
                start = net.get("startAddress", "")
                end = net.get("endAddress", "")
                if start and end:
                    findings.append(IntelligenceFinding(
                        entity=f"{start} - {end}",
                        type="Network Range (ARIN)",
                        source="NetworkTopologyMapper (ARIN)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["arin", "ip-range"]
                    ))
    except:
        pass

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ip = await resolve_ip(domain)

    tasks = [
        check_cdn_edges(domain, client),
        trace_route_analysis(domain),
        check_icmp_reachability(domain),
        get_ip_ranges(domain),
    ]

    if ip:
        tasks.append(get_bgp_info(ip, client))
        tasks.append(check_network_boundaries(domain, ip, client))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    hop_count = sum(1 for f in findings if "BGP" in f.type or "ASN" in f.type or "Network" in f.type or "IP" in f.type)
    findings.append(IntelligenceFinding(
        entity=f"Network Topology: {hop_count} network data points mapped",
        type="Network Topology Summary",
        source="NetworkTopologyMapper",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"Mapped {hop_count} elements",
        resolution=f"Target: {domain}, IP: {ip}",
        tags=["network-topology", "summary"]
    ))

    return findings
