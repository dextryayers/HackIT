import httpx
import asyncio
import socket
import re
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RIPE_STAT_API = "https://stat.ripe.net/data"
CYMRU_WHOIS = "whois.cymru.com"
BGP_TOOLS_API = "https://api.bgp.tools"
CLOUDFLARE_RADAR = "https://radar.cloudflare.com"
ROUTEVIEWS = "https://routeviews.org"

def score_asn_role(peer_count: int, upstream_count: int, downstream_count: int) -> tuple:
    total = peer_count + upstream_count + downstream_count
    if total > 5000:
        return "Tier 1 Provider", "purple"
    if total > 1000:
        return "Large Network", "blue"
    if total > 200:
        return "Mid-size Network", "orange"
    return "Small Network", "slate"

async def resolve_to_ips(domain: str) -> list:
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

async def resolve_to_asn_cymru(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(CYMRU_WHOIS, 43), timeout=10.0
        )
        writer.write(f"{ip}\r\n".encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        writer.close()
        text = response.decode("utf-8", errors="ignore")
        lines = text.strip().split("\n")
        for line in lines:
            if "|" in line and ip in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    return {
                        "asn": parts[0],
                        "ip": parts[1],
                        "prefix": parts[2],
                        "country": parts[3],
                        "registry": parts[4],
                        "allocated": parts[5],
                        "name": parts[6],
                    }
    except:
        pass
    return {}

async def query_ripe_stat(endpoint: str, params: dict = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            resp = await c.get(f"{RIPE_STAT_API}/{endpoint}", params=params or {})
            return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def scrape_bgp_he_asn(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://bgp.he.net/AS{asn}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            info = {}
            m = re.search(r'<title>AS(\d+)\s+(.+?)</title>', text)
            if m:
                info["number"] = m.group(1)
                info["name"] = m.group(2).strip()
            m = re.search(r'Country:\s*</td><td>([^<]+)', text)
            if m:
                info["country"] = m.group(1).strip()
            m = re.search(r'Registry:\s*</td><td>([^<]+)', text)
            if m:
                info["registry"] = m.group(1).strip()
            peers = re.findall(r'/AS(\d+)', text)
            info["peers"] = list(set(peers))[:30]
            prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
            info["prefixes"] = list(set(prefixes))[:20]
            return info
    except:
        pass
    return {}

async def query_bgp_tools(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://bgp.tools/as/{asn}.json",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_cloudflare_radar(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://radar.cloudflare.com/api/v1/asns/{asn}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        return {}

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

    for ip in ips[:3]:
        cymru_data = await resolve_to_asn_cymru(ip)
        if cymru_data:
            asn = cymru_data.get("asn", "").lstrip("AS")
            if asn and asn not in seen_asns:
                seen_asns.add(asn)
                findings.append(IntelligenceFinding(
                    entity=f"AS{asn} | {cymru_data.get('name', 'Unknown')}",
                    type="ASN: Organization",
                    source="Team Cymru",
                    confidence="High",
                    color="orange",
                    status="Confirmed",
                    resolution=ip,
                    raw_data=f"ASN={asn} Prefix={cymru_data.get('prefix', '')} Registry={cymru_data.get('registry', '')}",
                    tags=["asn", "network"],
                ))
                findings.append(IntelligenceFinding(
                    entity=cymru_data.get("country", ""),
                    type="ASN: Country",
                    source="Team Cymru",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "geo"],
                ))
                findings.append(IntelligenceFinding(
                    entity=cymru_data.get("registry", ""),
                    type="ASN: Registry",
                    source="Team Cymru",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "registry"],
                ))
                findings.append(IntelligenceFinding(
                    entity=cymru_data.get("prefix", ""),
                    type="ASN: Prefix",
                    source="Team Cymru",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "bgp"],
                ))

            he_data = await scrape_bgp_he_asn(asn, client)
            if he_data:
                role, role_color = score_asn_role(
                    len(he_data.get("peers", [])),
                    0, 0
                )
                findings.append(IntelligenceFinding(
                    entity=f"{he_data.get('name', '')} ({role})",
                    type="ASN: HE.net Enrichment",
                    source="BGP.HE.net",
                    confidence="High",
                    color=role_color,
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "bgp", "enrichment"],
                ))

                he_country = he_data.get("country", "")
                if he_country:
                    findings.append(IntelligenceFinding(
                        entity=he_country,
                        type="ASN: HE Country",
                        source="BGP.HE.net",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "geo"],
                    ))

                for peer_asn in he_data.get("peers", [])[:15]:
                    findings.append(IntelligenceFinding(
                        entity=f"AS{peer_asn}",
                        type="ASN: Peer",
                        source="BGP.HE.net",
                        confidence="Medium",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn} <-> AS{peer_asn}",
                        tags=["asn", "bgp", "peering"],
                    ))

                for prefix in he_data.get("prefixes", [])[:10]:
                    findings.append(IntelligenceFinding(
                        entity=prefix,
                        type="ASN: Advertised Prefix",
                        source="BGP.HE.net",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "bgp", "prefix"],
                    ))

            ripe_data = await query_ripe_stat("as-overview", {"resource": asn})
            if ripe_data and ripe_data.get("status") == "ok":
                rd = ripe_data.get("data", {})
                asn_holder = rd.get("holder", "")
                if asn_holder:
                    findings.append(IntelligenceFinding(
                        entity=asn_holder,
                        type="ASN: RIPE Holder",
                        source="RIPE Stat",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "ripe"],
                    ))

            bt_data = await query_bgp_tools(asn, client)
            if bt_data and isinstance(bt_data, dict):
                first_seen = bt_data.get("first_seen", "")
                if first_seen:
                    findings.append(IntelligenceFinding(
                        entity=first_seen,
                        type="ASN: First Seen (BGP.tools)",
                        source="BGP.tools",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "history"],
                    ))
                full_name = bt_data.get("name", "") or bt_data.get("as_name", "")
                if full_name:
                    findings.append(IntelligenceFinding(
                        entity=full_name,
                        type="ASN: Full Name (BGP.tools)",
                        source="BGP.tools",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "enrichment"],
                    ))

            cf_data = await query_cloudflare_radar(asn, client)
            if cf_data and isinstance(cf_data, dict):
                rank = cf_data.get("rank", 0)
                if rank:
                    findings.append(IntelligenceFinding(
                        entity=f"Rank #{rank}",
                        type="ASN: Cloudflare Radar Rank",
                        source="Cloudflare Radar",
                        confidence="Medium",
                        color="blue",
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        tags=["asn", "rank"],
                    ))

    if not seen_asns:
        findings.append(IntelligenceFinding(
            entity=f"Could not resolve ASN for {t}",
            type="ASN Lookup Status",
            source="ASNBGPRadar",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["asn", "error"],
        ))

    return findings
