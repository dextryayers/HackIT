import httpx
import asyncio
import socket
import re
from collections import defaultdict
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
BGP_HE_BASE = "https://bgp.he.net"

IRR_SOURCES = ["RADB", "RIPE", "ARIN", "APNIC", "LACNIC", "AFRINIC", "NTTCOM"]

RPKI_STATES = {"Valid": "emerald", "Unknown": "slate", "Invalid": "red"}

async def resolve_to_ips(domain: str) -> list:
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

async def scrape_asn_page(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BGP_HE_BASE}/AS{asn}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code != 200:
            return {}
        text = resp.text
        info = {}
        m = re.search(r'<title>AS(\d+)\s+(.+?)</title>', text)
        if m:
            info["asn"] = m.group(1)
            info["name"] = m.group(2).strip()
        m = re.search(r'Country:\s*</td><td>([^<]+)', text)
        if m:
            info["country"] = m.group(1).strip()
        m = re.search(r'Registry:\s*</td><td>([^<]+)', text)
        if m:
            info["registry"] = m.group(1).strip()
        m = re.search(r'Source:\s*</td><td>([^<]+)', text)
        if m:
            info["source"] = m.group(1).strip()
        ipv4_prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
        ipv6_prefixes = re.findall(r'([0-9a-fA-F:]+/\d+)', text)
        info["ipv4_prefixes"] = list(set(ipv4_prefixes))[:15]
        info["ipv6_prefixes"] = list(set(p for p in ipv6_prefixes if ":" in p))[:10]
        peers = re.findall(r'/AS(\d+)', text)
        info["peers"] = list(set(peers))[:20]

        upstream_match = re.search(r'Upstreams:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if upstream_match:
            info["upstreams"] = re.findall(r'/AS(\d+)', upstream_match.group(1))[:10]
        downstream_match = re.search(r'Downstreams:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if downstream_match:
            info["downstreams"] = re.findall(r'/AS(\d+)', downstream_match.group(1))[:10]

        return info
    except:
        return {}

async def scrape_prefix_history(asn: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"{BGP_HE_BASE}/AS{asn}#_prefixes",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code != 200:
            return []
        text = resp.text
        prefixes = set()
        for m in re.finditer(r'<a href="/net/(\d+\.\d+\.\d+\.\d+/\d+)">', text):
            prefixes.add(m.group(1))
        for m in re.finditer(r'>(\d+\.\d+\.\d+\.\d+/\d+)</a>', text):
            prefixes.add(m.group(1))
        return list(prefixes)[:15]
    except:
        return []

async def scrape_irr_lookup(asn: str, client: httpx.AsyncClient) -> list:
    irr_records = []
    for source in IRR_SOURCES:
        try:
            resp = await client.get(
                f"{BGP_HE_BASE}/irr.cgi?cmd=show+route+AS{asn}&source={source}",
                headers={"User-Agent": UA},
                timeout=15.0,
            )
            if resp.status_code == 200:
                routes = re.findall(r'route:\s+(\S+)', resp.text, re.IGNORECASE)
                if routes:
                    irr_records.append((source, routes[:5]))
        except:
            continue
    return irr_records

async def scrape_rpki_status(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BGP_HE_BASE}/AS{asn}#_rpki",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            valid = len(re.findall(r'class="valid"', text))
            invalid = len(re.findall(r'class="invalid"', text))
            unknown = len(re.findall(r'class="unknown"', text))
            return {"valid": valid, "invalid": invalid, "unknown": unknown}
    except:
        pass
    return {}

async def scrape_roa_records(asn: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://rpki.grumptech.com/AS{asn}/",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            roas = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', resp.text)
            return roas[:10]
    except:
        pass
    return []

async def build_adjacent_graph(asn: str, client: httpx.AsyncClient) -> list:
    graph_items = []
    info = await scrape_asn_page(asn, client)
    if not info:
        return []
    all_connections = defaultdict(list)
    for peer in info.get("peers", [])[:8]:
        all_connections["peers"].append(peer)
    for up in info.get("upstreams", [])[:5]:
        all_connections["upstreams"].append(up)
    for down in info.get("downstreams", [])[:5]:
        all_connections["downstreams"].append(up)
    return all_connections

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    ips = await resolve_to_ips(t)
    if not ips:
        ips = [t]

    seen_asns = set()

    for ip in ips[:2]:
        try:
            resp = await client.get(
                f"{BGP_HE_BASE}/ip/{ip}",
                headers={"User-Agent": UA},
                timeout=15.0,
            )
            if resp.status_code == 200:
                text = resp.text
                asns_found = re.findall(r'/AS(\d+)', text)
                prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
                for asn in asns_found:
                    if asn not in seen_asns:
                        seen_asns.add(asn)

                        findings.append(IntelligenceFinding(
                            entity=f"AS{asn}",
                            type="BGP: ASN Discovery",
                            source="BGP.HE.net",
                            confidence="High",
                            color="orange",
                            status="Confirmed",
                            resolution=ip,
                            tags=["asn", "bgp"],
                        ))

                        info = await scrape_asn_page(asn, client)
                        if info:
                            org_name = info.get("name", "")
                            if org_name:
                                findings.append(IntelligenceFinding(
                                    entity=f"{org_name}",
                                    type="BGP: Organization",
                                    source="BGP.HE.net",
                                    confidence="High",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "organization"],
                                ))

                            country = info.get("country", "")
                            if country:
                                findings.append(IntelligenceFinding(
                                    entity=country,
                                    type="BGP: Country",
                                    source="BGP.HE.net",
                                    confidence="High",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "geo"],
                                ))

                            registry = info.get("registry", "")
                            if registry:
                                findings.append(IntelligenceFinding(
                                    entity=registry,
                                    type="BGP: Registry",
                                    source="BGP.HE.net",
                                    confidence="High",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "registry"],
                                ))

                            for prefix in info.get("ipv4_prefixes", [])[:8]:
                                findings.append(IntelligenceFinding(
                                    entity=prefix,
                                    type="BGP: IPv4 Prefix",
                                    source="BGP.HE.net",
                                    confidence="High",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "bgp", "prefix"],
                                ))

                            for prefix6 in info.get("ipv6_prefixes", [])[:6]:
                                findings.append(IntelligenceFinding(
                                    entity=prefix6,
                                    type="BGP: IPv6 Prefix",
                                    source="BGP.HE.net",
                                    confidence="High",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "bgp", "ipv6", "prefix"],
                                ))

                            peer_count = len(info.get("peers", []))
                            up_count = len(info.get("upstreams", []))
                            down_count = len(info.get("downstreams", []))
                            findings.append(IntelligenceFinding(
                                entity=f"Peers: {peer_count}, Upstreams: {up_count}, Downstreams: {down_count}",
                                type="BGP: Adjacency Summary",
                                source="BGP.HE.net",
                                confidence="High",
                                color="blue" if peer_count > 100 else "slate",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "bgp", "topology"],
                            ))

                            for peer in info.get("peers", [])[:12]:
                                findings.append(IntelligenceFinding(
                                    entity=f"AS{peer}",
                                    type="BGP: Peer",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn} → AS{peer}",
                                    tags=["asn", "bgp", "peering"],
                                ))

                            for up in info.get("upstreams", [])[:8]:
                                findings.append(IntelligenceFinding(
                                    entity=f"AS{up}",
                                    type="BGP: Upstream",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="blue",
                                    status="Confirmed",
                                    resolution=f"AS{asn} → AS{up}",
                                    tags=["asn", "bgp", "transit"],
                                ))

                            for down in info.get("downstreams", [])[:8]:
                                findings.append(IntelligenceFinding(
                                    entity=f"AS{down}",
                                    type="BGP: Downstream",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn} ← AS{down}",
                                    tags=["asn", "bgp", "transit"],
                                ))

                        irr_data = await scrape_irr_lookup(asn, client)
                        for source, routes in irr_data:
                            for route in routes:
                                findings.append(IntelligenceFinding(
                                    entity=f"[{source}] {route}",
                                    type="BGP: IRR Record",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "irr", "routing"],
                                ))

                        rpki = await scrape_rpki_status(asn, client)
                        if rpki and any(rpki.values()):
                            total_rpki = sum(rpki.values())
                            rpki_color = "red" if rpki.get("invalid", 0) > 0 else "emerald"
                            findings.append(IntelligenceFinding(
                                entity=f"Valid: {rpki.get('valid', 0)}, Invalid: {rpki.get('invalid', 0)}, Unknown: {rpki.get('unknown', 0)}",
                                type="BGP: RPKI Status",
                                source="BGP.HE.net",
                                confidence="High",
                                color=rpki_color,
                                threat_level="High Risk" if rpki.get("invalid", 0) > 0 else "Informational",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "rpki", "security"],
                            ))

                        roas = await scrape_roa_records(asn, client)
                        if roas:
                            findings.append(IntelligenceFinding(
                                entity=f"{len(roas)} ROA record(s) for AS{asn}",
                                type="BGP: ROA Records",
                                source="RPKI GrumpTech",
                                confidence="Medium",
                                color="emerald",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "rpki", "roa"],
                            ))

                for prefix in prefixes[:5]:
                    findings.append(IntelligenceFinding(
                        entity=prefix,
                        type="BGP: Prefix for IP",
                        source="BGP.HE.net",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["bgp", "prefix"],
                    ))

        except:
            continue

    if not seen_asns:
        findings.append(IntelligenceFinding(
            entity=f"No BGP data found for {t}",
            type="BGP: No Results",
            source="BGP.HE.net",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["error"],
        ))

    return findings
