import httpx
import asyncio
import socket
import re
import json
from collections import defaultdict
from urllib.parse import urlparse
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

BGPVIEW_API = "https://api.bgpview.io"
RIPE_STAT_API = "https://stat.ripe.net/data"
PEERINGDB_API = "https://www.peeringdb.com/api"
HE_BASE = "https://bgp.he.net"
IPINFO_API = "https://ipinfo.io"
CIDR_REPORT = "http://www.cidr-report.org/as2.0"
RADB_API = "https://www.radb.net/api"

TIER1_ASNS = {174, 209, 286, 293, 701, 702, 703, 1239, 1299, 1741, 2914, 3257, 3320, 3356, 3549, 5511, 6453, 6461, 6762, 6830, 7018, 7922, 12956, 20485, 22822}
MAJOR_CLOUD_ASNS = {16509, 14618, 8075, 12076, 15169, 36040, 13335, 209242, 16276, 14061, 20473, 63949, 24961, 45102, 31898}
MAJOR_CDN_ASNS = {13335, 20940, 16625, 54113, 15133, 22822, 30081, 11179, 200332, 203420}

async def resolve_to_ips(domain: str):
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except: return []

async def query_bgpview(path: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{BGPVIEW_API}{path}", headers={"Accept": "application/json", "User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            return data if data.get("status") == "ok" else {}
    except: pass
    return {}

async def query_ripe(path: str, client: httpx.AsyncClient, params: dict = None):
    try:
        resp = await client.get(f"{RIPE_STAT_API}{path}", params=params or {}, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200: return resp.json()
    except: pass
    return {}

async def query_ipinfo(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{IPINFO_API}/{ip}/json", headers={"User-Agent": UA}, timeout=10.0)
        if resp.status_code == 200: return resp.json()
    except: pass
    return {}

async def scrape_he_asn(asn: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{HE_BASE}/AS{asn}", headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            text = resp.text
            info = {}
            m = re.search(r'<title>AS(\d+)\s+(.+?)</title>', text)
            if m: info["name"] = m.group(2).strip()
            m = re.search(r'Country:\s*</td><td>([^<]+)', text)
            if m: info["country"] = m.group(1).strip()
            m = re.search(r'Registry:\s*</td><td>([^<]+)', text)
            if m: info["registry"] = m.group(1).strip()
            peers = re.findall(r'/AS(\d+)', text)
            info["peers"] = list(set(peers))[:50]
            prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
            info["prefixes"] = list(set(prefixes))[:20]
            info["all_peer_count"] = len(set(peers))
            m = re.search(r'IPs Originated:\s*</td><td[^>]*>([\d,]+)', text)
            if m: info["ips_originated"] = int(m.group(1).replace(",", ""))
            return info
    except: pass
    return {}

async def query_peeringdb(asn: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{PEERINGDB_API}/net/asn/{asn}", headers={"Accept": "application/json", "User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            nets = data.get("data", [])
            if nets: return nets[0]
    except: pass
    return {}

async def scrape_he_irv(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{HE_BASE}/irv.cgi?ip={ip}", headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            text = resp.text
            info = {}
            m = re.search(r'<b>Origin AS:</b>\s*AS(\d+)', text)
            if m: info["origin_as"] = m.group(1)
            m = re.search(r'<b>Prefix:</b>\s*([^\s<]+)', text)
            if m: info["prefix"] = m.group(1)
            m = re.search(r'<b>AS Path:</b>\s*([^<]+)', text)
            if m: info["as_path"] = m.group(1).strip()
            return info
    except: pass
    return {}

async def check_rpki_ripe(asn: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{RIPE_STAT_API}/rpki-validation/data.json", params={"resource": asn}, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                roas = data.get("data", {}).get("roas", [])
                valid = sum(1 for r in roas if r.get("status") == "valid")
                invalid = sum(1 for r in roas if r.get("status") == "invalid")
                not_found = sum(1 for r in roas if r.get("status") == "not_found")
                return {"valid": valid, "invalid": invalid, "not_found": not_found, "total": len(roas)}
    except: pass
    return {}

async def check_moas(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"{RIPE_STAT_API}/routing-status/data.json", params={"resource": ip}, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                origins = data.get("data", {}).get("origins", [])
                if len(origins) > 1:
                    return {"moas": True, "origins": [o.get("asn", "") for o in origins[:10]], "count": len(origins)}
    except: pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ips = await resolve_to_ips(domain)
    if not ips:
        try:
            socket.inet_aton(domain)
            ips = [domain]
        except:
            pass
    if not ips:
        ips = [domain]

    seen_asns = set()

    for ip in ips[:3]:
        ipinfo_data = await query_ipinfo(ip, client)
        if ipinfo_data:
            org = ipinfo_data.get("org", "")
            asn_str = ""
            if org:
                parts = org.split(" ", 1)
                if parts[0].startswith("AS"):
                    asn_str = parts[0][2:]
            if asn_str:
                seen_asns.add(asn_str)

        irv = await scrape_he_irv(ip, client)
        if irv and irv.get("origin_as"):
            seen_asns.add(irv["origin_as"])
            findings.append(IntelligenceFinding(
                entity=f"AS{irv['origin_as']} | Prefix: {irv.get('prefix', '?')}",
                type="BGP: Origin AS via IRV",
                source="HE.net IRV",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Origin Found",
                resolution=ip,
                tags=["bgp", "origin", "irv"]
            ))
            if irv.get("as_path"):
                path_asns = re.findall(r'(\d+)', irv["as_path"])
                findings.append(IntelligenceFinding(
                    entity=f"AS Path: {' -> '.join(f'AS{a}' for a in path_asns[:15])}",
                    type="BGP: AS Path",
                    source="HE.net IRV",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Active",
                    resolution=ip,
                    tags=["bgp", "as-path"]
                ))

        moas = await check_moas(ip, client)
        if moas and moas.get("moas"):
            findings.append(IntelligenceFinding(
                entity=f"MOAS detected: {moas['count']} origins for {ip}: {', '.join(moas['origins'][:8])}",
                type="BGP: MOAS (Multiple Origin AS)",
                source="RIPE Stat",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                status="MOAS Detected",
                resolution=ip,
                tags=["bgp", "moas", "hijack"]
            ))

    for asn in list(seen_asns)[:5]:
        he = await scrape_he_asn(asn, client)
        if he:
            findings.append(IntelligenceFinding(
                entity=f"AS{asn} | {he.get('name', 'Unknown')} | {he.get('country', '?')}",
                type="BGP: ASN Information",
                source="HE.net",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Identified",
                tags=["bgp", "asn", "info"]
            ))

            peer_count = he.get("all_peer_count", 0)
            prefix_count = len(he.get("prefixes", []))
            ips_originated = he.get("ips_originated", 0)
            findings.append(IntelligenceFinding(
                entity=f"AS{asn}: {peer_count} peers, {prefix_count} prefixes, {ips_originated:,} IPs",
                type="BGP: ASN Scale Metrics",
                source="HE.net",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Measured",
                tags=["bgp", "scale"]
            ))

            tier = "Tier 1" if int(asn) in TIER1_ASNS else "Cloud Provider" if int(asn) in MAJOR_CLOUD_ASNS else "CDN" if int(asn) in MAJOR_CDN_ASNS else "Standard"
            findings.append(IntelligenceFinding(
                entity=f"AS{asn} classified as: {tier}",
                type="BGP: ASN Tier Classification",
                source="Comprehensive ASN/BGP",
                confidence="High",
                color="purple" if tier == "Tier 1" else "orange" if tier in ("Cloud Provider", "CDN") else "slate",
                threat_level="Informational",
                status=tier,
                tags=["bgp", "tier", tier.lower().replace(" ", "-")]
            ))

        bgpv = await query_bgpview(f"/asn/{asn}", client)
        if bgpv:
            data = bgpv.get("data", {})
            prefix_count_v4 = data.get("prefix_count", 0)
            prefix_count_v6 = data.get("prefix_count6", 0)
            peer_count_bv = data.get("peers", {}).get("count", data.get("peer_count", len(data.get("peers", []))))
            upstream_count_bv = data.get("upstreams", {}).get("count", len(data.get("upstreams", [])))
            downstream_count_bv = data.get("downstreams", {}).get("count", len(data.get("downstreams", [])))
            findings.append(IntelligenceFinding(
                entity=f"BGPView: {prefix_count_v4} v4, {prefix_count_v6} v6 prefixes | {peer_count_bv} peers, {upstream_count_bv} upstreams, {downstream_count_bv} downstreams",
                type="BGP: BGPView Statistics",
                source="BGPView.io",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Enriched",
                tags=["bgp", "bgpview"]
            ))

            for up in data.get("upstreams", [])[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{up.get('asn', '')} | {up.get('name', '')}",
                    type="BGP: Upstream Provider",
                    source="BGPView.io",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    status=f"AS{asn} -> AS{up.get('asn', '')}",
                    tags=["bgp", "upstream"]
                ))

            for peer in data.get("peers", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{peer.get('asn', '')} | {peer.get('name', '')}",
                    type="BGP: Peer AS",
                    source="BGPView.io",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status=f"AS{asn} <-> AS{peer.get('asn', '')}",
                    tags=["bgp", "peer"]
                ))

            for down in data.get("downstreams", [])[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{down.get('asn', '')} | {down.get('name', '')}",
                    type="BGP: Downstream Customer",
                    source="BGPView.io",
                    confidence="Medium",
                    color="green",
                    threat_level="Informational",
                    status=f"AS{asn} <- AS{down.get('asn', '')}",
                    tags=["bgp", "downstream"]
                ))

        pdb = await query_peeringdb(asn, client)
        if pdb:
            policy = pdb.get("policy_general", "")
            info_type = pdb.get("info_type", "")
            ixlans = pdb.get("ixlans", [])
            if ixlans:
                ix_names = [ix.get("name", "") for ix in ixlans[:10]]
                findings.append(IntelligenceFinding(
                    entity=f"PeeringDB: policy={policy}, type={info_type}, IXPs: {', '.join(ix_names[:5])}",
                    type="BGP: PeeringDB Info",
                    source="PeeringDB",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Enriched",
                    tags=["bgp", "peeringdb"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"PeeringDB: policy={policy}, type={info_type}",
                    type="BGP: PeeringDB Info",
                    source="PeeringDB",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Enriched",
                    tags=["bgp", "peeringdb"]
                ))

        rpki = await check_rpki_ripe(asn, client)
        if rpki:
            rpki_color = "red" if rpki.get("invalid", 0) > 0 else "green"
            findings.append(IntelligenceFinding(
                entity=f"RPKI: {rpki['valid']} valid, {rpki['invalid']} invalid, {rpki['not_found']} not found ({rpki['total']} total ROAs)",
                type="BGP: RPKI/ROV Status",
                source="RIPE Stat",
                confidence="High",
                color=rpki_color,
                threat_level="Elevated Risk" if rpki.get("invalid", 0) > 0 else "Informational",
                status="RPKI Checked",
                tags=["bgp", "rpki", "rov"]
            ))
            if rpki.get("invalid", 0) > 3:
                findings.append(IntelligenceFinding(
                    entity=f"{rpki['invalid']} RPKI-invalid prefixes - potential BGP hijack!",
                    type="BGP: RPKI Hijack Alert",
                    source="RIPE Stat",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Hijack Risk",
                    tags=["bgp", "rpki", "hijack"]
                ))

        ripe_routing = await query_ripe("/routing-status/data.json", client, {"resource": asn})
        if ripe_routing and ripe_routing.get("status") == "ok":
            vis = ripe_routing.get("data", {}).get("visibility", {})
            if vis:
                findings.append(IntelligenceFinding(
                    entity=f"Route visibility: {vis.get('percentage', '?')}% ({vis.get('visible', '?')}/{vis.get('total', '?')} routes)",
                    type="BGP: Route Visibility",
                    source="RIPE Stat",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Visible",
                    tags=["bgp", "visibility"]
                ))

        traffic_est = bgpv.get("data", {}).get("traffic_estimation", "") if bgpv else ""
        if traffic_est:
            findings.append(IntelligenceFinding(
                entity=f"Traffic estimation: {traffic_est}",
                type="BGP: Traffic Estimation",
                source="BGPView.io",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Estimated",
                tags=["bgp", "traffic"]
            ))

    if seen_asns:
        findings.append(IntelligenceFinding(
            entity=f"Analyzed {len(seen_asns)} ASN(s): {', '.join(f'AS{a}' for a in seen_asns)}",
            type="BGP: Comprehensive Analysis Summary",
            source="ASN/BGP Comprehensive",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Complete",
            tags=["bgp", "asn", "summary"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No ASN information found for {domain}",
            type="BGP: No Results",
            source="ASN/BGP Comprehensive",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="No ASN",
            tags=["bgp", "no-results"]
        ))

    return findings
