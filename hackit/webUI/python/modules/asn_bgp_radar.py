import httpx
import asyncio
import socket
import re
import json
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

RIPE_STAT_API = "https://stat.ripe.net/data"
CYMRU_WHOIS = "whois.cymru.com"
BGP_TOOLS_API = "https://api.bgp.tools"
CLOUDFLARE_RADAR = "https://radar.cloudflare.com"
ROUTEVIEWS = "https://routeviews.org"
PEERINGDB_API = "https://www.peeringdb.com/api"
BGPVIEW_API = "https://api.bgpview.io"
IPINFO_API = "https://ipinfo.io"

MAJOR_IXPS = {
    "AMS-IX": "Amsterdam Internet Exchange",
    "DE-CIX": "Deutscher Commercial Internet Exchange",
    "LINX": "London Internet Exchange",
    "Equinix IX": "Equinix Internet Exchange",
    "NYIIX": "New York International Internet Exchange",
    "IX.br": "Ponto de Troca de Tráfego (Brazil)",
    "JPNAP": "Japan Network Access Point",
    "HKIX": "Hong Kong Internet Exchange",
    "SGIX": "Singapore Internet Exchange",
    "Any2": "Any2 Indonesia",
    "MICE": "Minnesota Internet Exchange",
    "FL-IX": "Florida Internet Exchange",
    "France-IX": "France Internet Exchange",
    "MIX": "Milan Internet Exchange",
    "LONAP": "London Access Point",
    "MSK-IX": "Moscow Internet Exchange",
    "DATA-IX": "DataIX (Romania)",
    "NetIX": "NetIX (Bulgaria)",
    "BCIX": "Berlin Commercial Internet Exchange",
    "ECIX": "European Commercial Internet Exchange",
    "ECIX-Manhattan": "ECIX Manhattan",
    "NAP Africa": "NAP Africa (Johannesburg)",
    "JINX": "Johannesburg Internet Exchange",
    "CINX": "Cape Town Internet Exchange",
    "IXPN": "Internet Exchange Point Nigeria",
    "KIXP": "Kenya Internet Exchange",
    "MIXI": "Milan Internet Exchange (MIXI)",
    "NAMEX": "Naples Internet Exchange",
    "TIX": "Trentino Internet Exchange",
    "TOP-IX": "Top-IX Consortium",
    "VSIX": "Veneto Internet Exchange",
    "MIXP": "Mumbai Internet Exchange",
    "INNAP": "INNAP (Moscow data center)",
    "DATA-IX": "DataIX (Bucharest)",
    "GR-IX": "Greek Internet Exchange",
    "CY-IX": "Cyprus Internet Exchange",
    "LU-CIX": "Luxembourg CIX",
    "MALTEX": "Malta Internet Exchange",
    "SWISSIX": "Swiss IX (Zurich)",
    "TIX": "Trentino IX",
    "JPIX": "Japan Internet Exchange",
    "JPNAP": "Japan Network Access Point",
    "BBIX": "BBIX (Tokyo/Osaka)",
    "KINX": "Korea Internet Exchange",
    "KIX": "Korea IX (Seoul)",
    "TWIX": "Taiwan Internet Exchange",
    "TPIX": "Taipei Internet Exchange",
    "HGC": "HGC (Hong Kong)",
    "EQUINIX-HK": "Equinix Hong Kong",
    "SGIX": "Singapore IX",
    "EXT-IX": "Extreme IX (Singapore)",
    "IX-AU": "IX Australia",
    "MEGAPORT": "Megaport (Australia)",
    "PIPE-NET": "Pipe Networks (Australia)",
    "WAIX": "Western Australia IX",
    "VICIX": "Victoria IX",
    "NSWIX": "NSW IX",
    "QLDIX": "Queensland IX",
    "SAIX": "South Australia IX",
    "TASIX": "Tasmania IX",
    "PLIX": "Philippines IX",
    "VNIX": "Vietnam Internet Exchange",
    "THIX": "Thailand Internet Exchange",
    "MYIX": "Malaysia Internet Exchange",
    "IDIHP": "Indonesia Internet Exchange",
    "BDIX": "Bangladesh Internet Exchange",
    "PNIX": "Pakistan Internet Exchange",
    "NPIX": "Nepal Internet Exchange",
    "LKIX": "Sri Lanka Internet Exchange",
    "IRIXP": "Iran Internet Exchange",
    "UA-IX": "Ukraine Internet Exchange",
    "UAIX": "Ukrainian IX",
    "DTEL-IX": "DTEL-IX (Ukraine)",
    "KA-ZIX": "Kazakhstan Internet Exchange",
    "AZIX": "Azerbaijan Internet Exchange",
    "GEIX": "Georgia Internet Exchange",
    "AMIX": "Armenia Internet Exchange",
    "MKD-IX": "Macedonia IX",
    "BIX": "Bulgaria IX",
    "RO-IX": "Romania Internet Exchange",
    "INTERLAN": "InterLAN (Romania)",
    "BALSE": "Balkan Serbia Exchange",
    "SIX": "Slovenia Internet Exchange",
    "NAIX": "Naix (Croatia)",
    "BHIX": "Bosnia IX",
    "BSE": "Banja Luka Internet Exchange",
    "CIX": "Croatian Internet Exchange",
    "ESIX": "Estonian Internet Exchange",
    "LIX": "Latvian Internet Exchange",
    "LITIX": "Lithuanian Internet Exchange",
    "YES": "Yesil Net (Turkey)",
    "IST-IX": "Istanbul Internet Exchange",
    "TURK-IX": "Turkish Internet Exchange",
    "MENA-X": "MENA Exchange (Egypt)",
    "CRISP": "CRISP (Saudi Arabia)",
    "MEX-IX": "Mexico Internet Exchange",
    "PTT": "PTT (Brazil)",
    "NAP-EC": "NAP Ecuador",
    "CABASE": "CABASE (Argentina)",
    "IXPCL": "IXP Chile",
    "IXP-PE": "IXP Peru",
    "NTI-X": "NTI-X (Colombia)",
    "INEX": "INEX (Costa Rica)",
    "IXP-PY": "IXP Paraguay",
    "IXP-BO": "IXP Bolivia",
    "IXP-UY": "IXP Uruguay",
    "CUDI": "CUDI (Mexico)",
    "CAN-IX": "Canadian Internet Exchange",
    "TORIX": "Toronto Internet Exchange",
    "ONTIX": "Ontario IX",
    "BCIX-CAN": "BCIX Canada",
    "YIX": "Yegua Internet Exchange (Canada)",
    "WPGIX": "Winnipeg IX",
    "MTLIX": "Montreal IX",
    "QIX": "Quebec Internet Exchange",
    "OTTAIX": "Ottawa IX",
    "EQUINIX-CA": "Equinix Canada",
    "HILA": "Hila Internet Exchange",
}

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

async def query_ripe_stat(endpoint: str, client: httpx.AsyncClient, params: dict = None) -> dict:
    try:
        resp = await client.get(f"{RIPE_STAT_API}/{endpoint}", params=params or {}, timeout=15.0)
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
            ipv6_prefixes = re.findall(r'([0-9a-fA-F:]+/\d+)', text)
            info["ipv6_prefixes"] = list(set(p for p in ipv6_prefixes if ":" in p))[:10]
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

async def search_bgp_he_prefix(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.post(
            "https://bgp.he.net/search",
            headers={"User-Agent": UA},
            data={"search[search]": ip, "search[commit]": "Search"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            results = {}
            asns_found = re.findall(r'/AS(\d+)', text)
            if asns_found:
                results["asns"] = list(set(asns_found))[:20]
            prefixes_found = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
            if prefixes_found:
                results["prefixes"] = list(set(prefixes_found))[:20]
            org_names = re.findall(r'<td>([A-Za-z0-9\s\.\-]+)</td>', text)
            results["org_names"] = [n.strip() for n in org_names if len(n.strip()) > 3][:10]
            return results
    except:
        pass
    return {}

async def scrape_bgp_he_irv(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://bgp.he.net/irv.cgi?ip={ip}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            result = {}
            m = re.search(r'<b>Origin AS:</b>\s*AS(\d+)', text)
            if m:
                result["origin_as"] = m.group(1)
            m = re.search(r'<b>Prefix:</b>\s*([^\s<]+)', text)
            if m:
                result["prefix"] = m.group(1)
            m = re.search(r'<b>Next Hop:</b>\s*([^\s<]+)', text)
            if m:
                result["next_hop"] = m.group(1)
            m = re.search(r'<b>AS Path:</b>\s*([^<]+)', text)
            if m:
                result["as_path"] = m.group(1).strip()
            m = re.search(r'<b>Route Preference:</b>\s*([^<]+)', text)
            if m:
                result["route_preference"] = m.group(1).strip()
            m = re.search(r'<b>Community:</b>\s*([^<]+)', text)
            if m:
                result["community"] = m.group(1).strip()
            return result
    except:
        pass
    return {}

async def query_peeringdb(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{PEERINGDB_API}/net/asn/{asn}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            nets = data.get("data", [])
            if nets:
                net = nets[0]
                result = {
                    "name": net.get("name", ""),
                    "aka": net.get("aka", ""),
                    "asn": net.get("asn", ""),
                    "policy_general": net.get("policy_general", ""),
                    "policy_url": net.get("policy_url", ""),
                    "policy_locations": net.get("policy_locations", ""),
                    "info_type": net.get("info_type", ""),
                    "notes": net.get("notes", ""),
                }
                ixlans = net.get("ixlans", [])
                if ixlans:
                    result["ixp_memberships"] = []
                    for ix in ixlans:
                        result["ixp_memberships"].append({
                            "name": ix.get("name", ""),
                            "ix_id": ix.get("ix_id", ""),
                            "speed": ix.get("speed", ""),
                        })
                netfac_ids = net.get("netfac_ids", [])
                if netfac_ids:
                    result["facility_ids"] = netfac_ids[:20]
                org_id = net.get("org_id")
                if org_id:
                    try:
                        org_resp = await client.get(
                            f"{PEERINGDB_API}/org/{org_id}",
                            headers={"User-Agent": UA, "Accept": "application/json"},
                            timeout=10.0,
                        )
                        if org_resp.status_code == 200:
                            org_data = org_resp.json()
                            orgs = org_data.get("data", [])
                            if orgs:
                                org = orgs[0]
                                result["org_name"] = org.get("name", "")
                                result["org_website"] = org.get("website", "")
                    except:
                        pass
                return result
    except:
        pass
    return {}

async def query_cidr_report(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"http://www.cidr-report.org/as2.0/AS{asn}/index.html",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            result = {}
            m = re.search(r'Prefixes\s*Announced\s*:?\s*(\d[\d,\.]*)', text, re.IGNORECASE)
            if m:
                result["prefix_count"] = m.group(1).replace(",", "").strip()
            m = re.search(r'Ranking\s*:?\s*(\d+)', text, re.IGNORECASE)
            if m:
                result["ranking"] = m.group(1)
            m = re.search(r'Total\s*AS\s*:?\s*(\d[\d,]*)', text, re.IGNORECASE)
            if m:
                result["total_asns"] = m.group(1).replace(",", "").strip()
            m = re.search(r'Origin\s*AS\s*Count\s*:?\s*(\d[\d,]*)', text, re.IGNORECASE)
            if m:
                result["origin_as_count"] = m.group(1).replace(",", "").strip()
            return result
        else:
            try:
                resp2 = await client.get(
                    f"http://www.cidr-report.org/cgi-bin/as_report?as=AS{asn}",
                    headers={"User-Agent": UA},
                    timeout=15.0,
                )
                if resp2.status_code == 200:
                    text2 = resp2.text
                    result = {}
                    m = re.search(r'prefixes\s*announced\s*:?\s*(\d[\d,\.]*)', text2, re.IGNORECASE)
                    if m:
                        result["prefix_count"] = m.group(1).replace(",", "").strip()
                    m = re.search(r'rank\s*:?\s*(\d+)', text2, re.IGNORECASE)
                    if m:
                        result["ranking"] = m.group(1)
                    return result
            except:
                pass
    except:
        pass
    return {}

async def query_bgpview(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BGPVIEW_API}/asn/{asn}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                result = {
                    "asn": d.get("asn", ""),
                    "name": d.get("name", ""),
                    "description_short": d.get("description_short", ""),
                    "country_code": d.get("country_code", ""),
                    "website": d.get("website", ""),
                    "traffic_estimation": d.get("traffic_estimation", ""),
                    "traffic_ratio": d.get("traffic_ratio", ""),
                    "scope": d.get("scope", ""),
                    "prefix_count": d.get("prefix_count", 0),
                    "prefix_count6": d.get("prefix_count6", 0),
                    "peer_count": len(d.get("peers", [])),
                    "upstream_count": len(d.get("upstreams", [])),
                    "downstream_count": len(d.get("downstreams", [])),
                }
                prefixes = d.get("prefixes", [])
                if prefixes:
                    result["prefixes_v4"] = [p.get("prefix", "") for p in prefixes if ":" not in p.get("prefix", "")][:20]
                    result["prefixes_v6"] = [p.get("prefix", "") for p in prefixes if ":" in p.get("prefix", "")][:10]
                peers = d.get("peers", [])
                if peers:
                    result["peers"] = [{"asn": p.get("asn", ""), "name": p.get("name", "")} for p in peers[:30]]
                upstreams = d.get("upstreams", [])
                if upstreams:
                    result["upstreams"] = [{"asn": u.get("asn", ""), "name": u.get("name", "")} for u in upstreams[:15]]
                downstreams = d.get("downstreams", [])
                if downstreams:
                    result["downstreams"] = [{"asn": d2.get("asn", ""), "name": d2.get("name", "")} for d2 in downstreams[:15]]
                return result
    except:
        pass
    return {}

async def query_ipinfo(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{IPINFO_API}/{ip}/json",
            headers={"User-Agent": UA},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": data.get("ip", ""),
                "hostname": data.get("hostname", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", ""),
                "org": data.get("org", ""),
                "postal": data.get("postal", ""),
                "timezone": data.get("timezone", ""),
                "loc": data.get("loc", ""),
            }
            org = data.get("org", "")
            if org:
                parts = org.split(" ", 1)
                if len(parts) == 2 and parts[0].startswith("AS"):
                    result["asn"] = parts[0][2:]
                    result["asn_org"] = parts[1]
            return result
    except:
        pass
    return {}

async def query_ripe_routing_status(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{RIPE_STAT_API}/routing-status/data.json",
            params={"resource": asn},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                result = {}
                rpki_data = d.get("rpki", {})
                if rpki_data:
                    result["rpki_valid"] = rpki_data.get("valid", 0)
                    result["rpki_invalid"] = rpki_data.get("invalid", 0)
                    result["rpki_not_found"] = rpki_data.get("not_found", 0)
                visibility = d.get("visibility", {})
                if visibility:
                    result["visibility_percentage"] = visibility.get("percentage", 0)
                    result["visible_routes"] = visibility.get("visible", 0)
                    result["total_routes_expected"] = visibility.get("total", 0)
                result["time"] = d.get("time", "")
                return result
    except:
        pass
    return {}

async def query_ripe_abuse_contact(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{RIPE_STAT_API}/abuse-contact-finder/data.json",
            params={"resource": asn},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                contacts = d.get("abuse_contacts", [])
                if contacts:
                    return {"abuse_contacts": contacts[:5]}
    except:
        pass
    return {}

async def query_ripe_prefix_count(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{RIPE_STAT_API}/prefix-count/data.json",
            params={"resource": asn},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                result = {}
                timeline = d.get("timeline", [])
                if timeline:
                    result["current_count"] = timeline[-1].get("count", 0) if timeline else 0
                    counts = [t.get("count", 0) for t in timeline if "count" in t]
                    if counts:
                        result["min_count"] = min(counts)
                        result["max_count"] = max(counts)
                        result["avg_count"] = round(sum(counts) / len(counts), 1)
                    dates = [t.get("date", "") for t in timeline[:5]]
                    result["last_5_dates"] = dates
                earliest = d.get("earliest", {})
                if earliest:
                    result["first_seen"] = earliest.get("time", "")
                    result["first_seen_count"] = earliest.get("count", 0)
                latest = d.get("latest", {})
                if latest:
                    result["last_changed"] = latest.get("time", "")
                    result["last_changed_count"] = latest.get("count", 0)
                return result
    except:
        pass
    return {}

async def query_ripe_asn_neighbours(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{RIPE_STAT_API}/asn-neighbours/data.json",
            params={"resource": asn},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                result = {}
                neighbours = d.get("neighbours", [])
                upstreams = []
                peers = []
                downstreams = []
                for n in neighbours:
                    asn_n = n.get("asn", "")
                    rel_type = n.get("type", "")
                    power = n.get("power", 0)
                    entry = {"asn": asn_n, "power": power}
                    if rel_type in ("upstream", "provider"):
                        upstreams.append(entry)
                    elif rel_type in ("downstream", "customer"):
                        downstreams.append(entry)
                    else:
                        peers.append(entry)
                result["upstreams"] = upstreams[:15]
                result["peers"] = peers[:30]
                result["downstreams"] = downstreams[:15]
                result["upstream_count"] = len(upstreams)
                result["peer_count"] = len(peers)
                result["downstream_count"] = len(downstreams)
                return result
    except:
        pass
    return {}

async def check_rpki_for_prefixes(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{RIPE_STAT_API}/rpki-validation/data.json",
            params={"resource": asn},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "ok":
                d = data.get("data", {})
                result = {}
                roas = d.get("roas", [])
                if roas:
                    valid = sum(1 for r in roas if r.get("status") == "valid")
                    invalid = sum(1 for r in roas if r.get("status") == "invalid")
                    not_found = sum(1 for r in roas if r.get("status") == "not_found")
                    result["total_roas"] = len(roas)
                    result["rpki_valid"] = valid
                    result["rpki_invalid"] = invalid
                    result["rpki_not_found"] = not_found
                    invalid_roas = [r for r in roas if r.get("status") == "invalid"]
                    if invalid_roas:
                        result["invalid_prefixes"] = [r.get("prefix", "") for r in invalid_roas[:10]]
                hijack_status = "clean"
                if invalid > 0:
                    hijack_status = "potential_rpki_hijack"
                elif invalid > 5:
                    hijack_status = "critical_rpki_invalid"
                result["hijack_status"] = hijack_status
                return result
    except:
        pass
    return {}

async def generate_summary_report(asn: str, asn_data: dict, ip: str) -> IntelligenceFinding:
    summary_parts = []
    summary_parts.append(f"ASN: AS{asn}")
    if asn_data.get("organization"):
        summary_parts.append(f"Org: {asn_data['organization']}")
    if asn_data.get("asn_name"):
        summary_parts.append(f"Name: {asn_data['asn_name']}")
    if asn_data.get("country"):
        summary_parts.append(f"Country: {asn_data['country']}")
    if asn_data.get("registry"):
        summary_parts.append(f"Registry: {asn_data['registry']}")
    if asn_data.get("prefix_count"):
        summary_parts.append(f"Prefix Count: {asn_data['prefix_count']}")
    if asn_data.get("peer_count"):
        summary_parts.append(f"Peers: {asn_data['peer_count']}")
    if asn_data.get("upstream_count") is not None:
        summary_parts.append(f"Upstreams: {asn_data['upstream_count']}")
    if asn_data.get("downstream_count") is not None:
        summary_parts.append(f"Downstreams: {asn_data['downstream_count']}")
    if asn_data.get("network_role"):
        summary_parts.append(f"Role: {asn_data['network_role']}")
    if asn_data.get("first_seen"):
        summary_parts.append(f"First Seen: {asn_data['first_seen']}")
    if asn_data.get("ixp_memberships"):
        summary_parts.append(f"IXP Memberships: {', '.join(asn_data['ixp_memberships'][:5])}")
    if asn_data.get("peering_policy"):
        summary_parts.append(f"Peering Policy: {asn_data['peering_policy']}")
    if asn_data.get("hijack_status"):
        summary_parts.append(f"Hijack Status: {asn_data['hijack_status']}")
    if asn_data.get("cf_rank"):
        summary_parts.append(f"CF Radar Rank: #{asn_data['cf_rank']}")
    if asn_data.get("rpki_stats"):
        summary_parts.append(f"RPKI: {asn_data['rpki_stats']}")
    if asn_data.get("traffic_estimation"):
        summary_parts.append(f"Traffic: {asn_data['traffic_estimation']}")
    if asn_data.get("cidr_ranking"):
        summary_parts.append(f"CIDR Rank: #{asn_data['cidr_ranking']}")

    color = "green"
    if asn_data.get("hijack_status") in ("potential_rpki_hijack", "critical_rpki_invalid"):
        color = "red"
    elif asn_data.get("network_role") == "Tier 1 Provider":
        color = "purple"
    elif asn_data.get("network_role") in ("Large Network", "Mid-size Network"):
        color = "blue"
    else:
        color = "slate"

    return IntelligenceFinding(
        entity=f"AS{asn} | {asn_data.get('asn_name', asn_data.get('organization', 'Unknown'))}",
        type="ASN: Summary Report",
        source="ASN-BGP-Radar",
        confidence="High",
        color=color,
        status="Confirmed",
        resolution=ip,
        raw_data=" | ".join(summary_parts),
        tags=["asn", "summary", "bgp", "radar"],
    )

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
    all_asn_data = {}

    for ip in ips[:3]:
        ipinfo_data = await query_ipinfo(ip, client)
        if ipinfo_data and ipinfo_data.get("asn"):
            asn = ipinfo_data["asn"]
            seen_asns.add(asn)
            if asn not in all_asn_data:
                all_asn_data[asn] = {}
            all_asn_data[asn]["ipinfo_org"] = ipinfo_data.get("org", "")
            if not all_asn_data[asn].get("ip_resolved"):
                all_asn_data[asn]["ip_resolved"] = ip
            findings.append(IntelligenceFinding(
                entity=f"AS{asn} | {ipinfo_data.get('org', '')}",
                type="ASN: IPInfo Mapping",
                source="IPInfo.io",
                confidence="High",
                color="orange",
                status="Confirmed",
                resolution=ip,
                raw_data=json.dumps(ipinfo_data),
                tags=["asn", "ipinfo", "network"],
            ))
            if ipinfo_data.get("country"):
                findings.append(IntelligenceFinding(
                    entity=ipinfo_data["country"],
                    type="ASN: IPInfo Country",
                    source="IPInfo.io",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "geo"],
                ))
            if ipinfo_data.get("city"):
                findings.append(IntelligenceFinding(
                    entity=ipinfo_data["city"],
                    type="ASN: IPInfo City",
                    source="IPInfo.io",
                    confidence="Medium",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "geo"],
                ))

        cymru_data = await resolve_to_asn_cymru(ip)
        if cymru_data:
            asn = cymru_data.get("asn", "").lstrip("AS")
            if asn and asn not in seen_asns:
                seen_asns.add(asn)
                if asn not in all_asn_data:
                    all_asn_data[asn] = {}
                all_asn_data[asn]["organization"] = cymru_data.get("name", "")
                all_asn_data[asn]["country"] = cymru_data.get("country", "")
                all_asn_data[asn]["registry"] = cymru_data.get("registry", "")
                all_asn_data[asn]["prefix_cymru"] = cymru_data.get("prefix", "")
                all_asn_data[asn]["allocated"] = cymru_data.get("allocated", "")
                if not all_asn_data[asn].get("ip_resolved"):
                    all_asn_data[asn]["ip_resolved"] = ip
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

        he_search = await search_bgp_he_prefix(ip, client)
        if he_search:
            for s_asn in he_search.get("asns", [])[:10]:
                if s_asn not in seen_asns:
                    seen_asns.add(s_asn)
                    if s_asn not in all_asn_data:
                        all_asn_data[s_asn] = {}
                    all_asn_data[s_asn]["ip_resolved"] = ip
                    findings.append(IntelligenceFinding(
                        entity=f"AS{s_asn}",
                        type="ASN: Discovered via HE Search",
                        source="BGP.HE.net Search",
                        confidence="Medium",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["asn", "bgp", "discovery"],
                    ))
            for prefix in he_search.get("prefixes", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=prefix,
                    type="ASN: Prefix (HE Search)",
                    source="BGP.HE.net Search",
                    confidence="Medium",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["asn", "bgp", "prefix"],
                ))

        irv_data = await scrape_bgp_he_irv(ip, client)
        if irv_data:
            findings.append(IntelligenceFinding(
                entity=f"IRV Lookup for {ip}",
                type="ASN: IRV Routing Info",
                source="BGP.HE.net IRV",
                confidence="High",
                color="slate",
                status="Confirmed",
                resolution=ip,
                raw_data=json.dumps(irv_data),
                tags=["asn", "bgp", "irv", "routing"],
            ))
            if irv_data.get("origin_as"):
                oasn = irv_data["origin_as"]
                if oasn not in seen_asns:
                    seen_asns.add(oasn)
                    if oasn not in all_asn_data:
                        all_asn_data[oasn] = {}
                    all_asn_data[oasn]["ip_resolved"] = ip
                findings.append(IntelligenceFinding(
                    entity=f"AS{oasn}",
                    type="ASN: Origin from IRV",
                    source="BGP.HE.net IRV",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["asn", "bgp", "origin"],
                ))
            if irv_data.get("as_path"):
                path_asns = re.findall(r'(\d+)', irv_data["as_path"])
                if path_asns:
                    findings.append(IntelligenceFinding(
                        entity=" -> ".join([f"AS{a}" for a in path_asns[:15]]),
                        type="ASN: AS Path",
                        source="BGP.HE.net IRV",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["asn", "bgp", "as_path"],
                    ))

    for asn in list(seen_asns):
        if asn not in all_asn_data:
            all_asn_data[asn] = {}

        he_data = await scrape_bgp_he_asn(asn, client)
        if he_data:
            all_asn_data[asn]["asn_name"] = he_data.get("name", "")
            if not all_asn_data[asn].get("country"):
                all_asn_data[asn]["country"] = he_data.get("country", "")
            if not all_asn_data[asn].get("registry"):
                all_asn_data[asn]["registry"] = he_data.get("registry", "")
            role, role_color = score_asn_role(
                len(he_data.get("peers", [])),
                0, 0
            )
            all_asn_data[asn]["network_role"] = role
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

        ripe_data = await query_ripe_stat("as-overview", client, {"resource": asn})
        if ripe_data and ripe_data.get("status") == "ok":
            rd = ripe_data.get("data", {})
            asn_holder = rd.get("holder", "")
            if asn_holder:
                all_asn_data[asn]["ripe_holder"] = asn_holder
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
                all_asn_data[asn]["first_seen"] = first_seen
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
                all_asn_data[asn]["asn_name"] = full_name
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

        bgpview_data = await query_bgpview(asn, client)
        if bgpview_data:
            all_asn_data[asn]["prefix_count"] = bgpview_data.get("prefix_count", 0)
            all_asn_data[asn]["prefix_count6"] = bgpview_data.get("prefix_count6", 0)
            all_asn_data[asn]["peer_count"] = bgpview_data.get("peer_count", 0)
            all_asn_data[asn]["upstream_count"] = bgpview_data.get("upstream_count", 0)
            all_asn_data[asn]["downstream_count"] = bgpview_data.get("downstream_count", 0)
            all_asn_data[asn]["traffic_estimation"] = bgpview_data.get("traffic_estimation", "")
            all_asn_data[asn]["scope"] = bgpview_data.get("scope", "")
            if not all_asn_data[asn].get("asn_name"):
                all_asn_data[asn]["asn_name"] = bgpview_data.get("name", "")
            if not all_asn_data[asn].get("country"):
                all_asn_data[asn]["country"] = bgpview_data.get("country_code", "")

            role, role_color = score_asn_role(
                bgpview_data.get("peer_count", 0),
                bgpview_data.get("upstream_count", 0),
                bgpview_data.get("downstream_count", 0),
            )
            all_asn_data[asn]["network_role_from_bgpview"] = role
            findings.append(IntelligenceFinding(
                entity=f"{bgpview_data.get('name', '')} ({role})",
                type="ASN: BGPView Details",
                source="BGPView.io",
                confidence="High",
                color=role_color,
                status="Confirmed",
                resolution=f"AS{asn}",
                raw_data=json.dumps({
                    "prefix_v4": bgpview_data.get("prefix_count", 0),
                    "prefix_v6": bgpview_data.get("prefix_count6", 0),
                    "peers": bgpview_data.get("peer_count", 0),
                    "upstreams": bgpview_data.get("upstream_count", 0),
                    "downstreams": bgpview_data.get("downstream_count", 0),
                    "traffic": bgpview_data.get("traffic_estimation", ""),
                    "scope": bgpview_data.get("scope", ""),
                }),
                tags=["asn", "bgpview", "enrichment"],
            ))

            if bgpview_data.get("prefix_count", 0):
                findings.append(IntelligenceFinding(
                    entity=f"{bgpview_data['prefix_count']} prefixes (v4) + {bgpview_data.get('prefix_count6', 0)} prefixes (v6)",
                    type="ASN: Prefix Count (BGPView)",
                    source="BGPView.io",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "bgp", "prefix_count"],
                ))

            if bgpview_data.get("peer_count", 0):
                findings.append(IntelligenceFinding(
                    entity=f"{bgpview_data['peer_count']} peers",
                    type="ASN: Peer Count (BGPView)",
                    source="BGPView.io",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "bgp", "peering"],
                ))

            up_count = bgpview_data.get("upstream_count", 0)
            down_count = bgpview_data.get("downstream_count", 0)
            if up_count or down_count:
                findings.append(IntelligenceFinding(
                    entity=f"{up_count} upstream(s), {down_count} downstream(s)",
                    type="ASN: Relationship Analysis (BGPView)",
                    source="BGPView.io",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    raw_data=f"Upstreams: {up_count}, Downstreams: {down_count}",
                    tags=["asn", "bgp", "relationship"],
                ))

            for up in bgpview_data.get("upstreams", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{up.get('asn', '')} | {up.get('name', '')}",
                    type="ASN: Upstream (Transit Provider)",
                    source="BGPView.io",
                    confidence="Medium",
                    color="blue",
                    status="Confirmed",
                    resolution=f"AS{asn} -> AS{up.get('asn', '')}",
                    tags=["asn", "bgp", "transit", "upstream"],
                ))

            for down in bgpview_data.get("downstreams", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{down.get('asn', '')} | {down.get('name', '')}",
                    type="ASN: Downstream (Customer)",
                    source="BGPView.io",
                    confidence="Medium",
                    color="green",
                    status="Confirmed",
                    resolution=f"AS{asn} -> AS{down.get('asn', '')}",
                    tags=["asn", "bgp", "customer", "downstream"],
                ))

        peeringdb_data = await query_peeringdb(asn, client)
        if peeringdb_data:
            all_asn_data[asn]["peering_policy"] = peeringdb_data.get("policy_general", "")
            ixp_memberships = peeringdb_data.get("ixp_memberships", [])
            if ixp_memberships:
                ixp_names = [ix.get("name", "") for ix in ixp_memberships]
                all_asn_data[asn]["ixp_memberships"] = ixp_names
                for ix in ixp_memberships:
                    ix_name = ix.get("name", "")
                    ixp_color = "green"
                    for known_ixp in MAJOR_IXPS:
                        if known_ixp.lower() in ix_name.lower():
                            ixp_color = "purple"
                            break
                    findings.append(IntelligenceFinding(
                        entity=ix_name,
                        type="ASN: IXP Membership",
                        source="PeeringDB",
                        confidence="High",
                        color=ixp_color,
                        status="Confirmed",
                        resolution=f"AS{asn}",
                        raw_data=f"Speed: {ix.get('speed', 'N/A')}",
                        tags=["asn", "ixp", "peering"],
                    ))
            org_name = peeringdb_data.get("org_name", "")
            if org_name:
                all_asn_data[asn]["org_name"] = org_name
                findings.append(IntelligenceFinding(
                    entity=org_name,
                    type="ASN: PeeringDB Organization",
                    source="PeeringDB",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "peeringdb"],
                ))
            policy = peeringdb_data.get("policy_general", "")
            if policy:
                all_asn_data[asn]["peering_policy"] = policy
                findings.append(IntelligenceFinding(
                    entity=policy,
                    type="ASN: Peering Policy",
                    source="PeeringDB",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    raw_data=f"Policy: {policy} | URL: {peeringdb_data.get('policy_url', 'N/A')}",
                    tags=["asn", "peeringdb", "peering_policy"],
                ))

        cidr_data = await query_cidr_report(asn, client)
        if cidr_data:
            all_asn_data[asn]["cidr_prefix_count"] = cidr_data.get("prefix_count", "")
            all_asn_data[asn]["cidr_ranking"] = cidr_data.get("ranking", "")
            findings.append(IntelligenceFinding(
                entity=f"Prefix Count: {cidr_data.get('prefix_count', 'N/A')} | Rank: #{cidr_data.get('ranking', 'N/A')}",
                type="ASN: CIDR Report Stats",
                source="CIDR-Report.org",
                confidence="Medium",
                color="slate",
                status="Confirmed",
                resolution=f"AS{asn}",
                raw_data=json.dumps(cidr_data),
                tags=["asn", "cidr", "rank"],
            ))

        ripe_routing = await query_ripe_routing_status(asn, client)
        if ripe_routing:
            all_asn_data[asn]["rpki_stats"] = f"Valid: {ripe_routing.get('rpki_valid', 0)}, Invalid: {ripe_routing.get('rpki_invalid', 0)}, Not Found: {ripe_routing.get('rpki_not_found', 0)}"
            all_asn_data[asn]["visibility_pct"] = ripe_routing.get("visibility_percentage", 0)
            findings.append(IntelligenceFinding(
                entity=f"Visibility: {ripe_routing.get('visibility_percentage', 'N/A')}% | RPKI Valid: {ripe_routing.get('rpki_valid', 0)} Invalid: {ripe_routing.get('rpki_invalid', 0)}",
                type="ASN: Routing Status",
                source="RIPE Stat",
                confidence="High",
                color="slate",
                status="Confirmed",
                resolution=f"AS{asn}",
                raw_data=json.dumps(ripe_routing),
                tags=["asn", "routing", "rpki"],
            ))

        ripe_abuse = await query_ripe_abuse_contact(asn, client)
        if ripe_abuse:
            contacts = ripe_abuse.get("abuse_contacts", [])
            all_asn_data[asn]["abuse_contacts"] = contacts
            for contact in contacts[:3]:
                findings.append(IntelligenceFinding(
                    entity=contact,
                    type="ASN: Abuse Contact",
                    source="RIPE Stat",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "abuse", "contact"],
                ))

        ripe_pcount = await query_ripe_prefix_count(asn, client)
        if ripe_pcount:
            all_asn_data[asn]["ripe_prefix_current"] = ripe_pcount.get("current_count", "")
            all_asn_data[asn]["ripe_first_seen"] = ripe_pcount.get("first_seen", "")
            all_asn_data[asn]["ripe_last_changed"] = ripe_pcount.get("last_changed", "")
            findings.append(IntelligenceFinding(
                entity=f"Current: {ripe_pcount.get('current_count', 'N/A')} | Min: {ripe_pcount.get('min_count', 'N/A')} Max: {ripe_pcount.get('max_count', 'N/A')} Avg: {ripe_pcount.get('avg_count', 'N/A')}",
                type="ASN: Prefix Count Timeline",
                source="RIPE Stat",
                confidence="High",
                color="slate",
                status="Confirmed",
                resolution=f"AS{asn}",
                raw_data=json.dumps(ripe_pcount),
                tags=["asn", "history", "prefix_stability"],
            ))

        ripe_neighbours = await query_ripe_asn_neighbours(asn, client)
        if ripe_neighbours:
            all_asn_data[asn]["ripe_upstream_count"] = ripe_neighbours.get("upstream_count", 0)
            all_asn_data[asn]["ripe_peer_count"] = ripe_neighbours.get("peer_count", 0)
            all_asn_data[asn]["ripe_downstream_count"] = ripe_neighbours.get("downstream_count", 0)
            findings.append(IntelligenceFinding(
                entity=f"Upstreams: {ripe_neighbours.get('upstream_count', 0)} | Peers: {ripe_neighbours.get('peer_count', 0)} | Downstreams: {ripe_neighbours.get('downstream_count', 0)}",
                type="ASN: RIPE Neighbourhood",
                source="RIPE Stat",
                confidence="High",
                color="slate",
                status="Confirmed",
                resolution=f"AS{asn}",
                raw_data=json.dumps(ripe_neighbours),
                tags=["asn", "bgp", "neighbourhood"],
            ))

            for n_up in ripe_neighbours.get("upstreams", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{n_up.get('asn', '')} (power: {n_up.get('power', 0)})",
                    type="ASN: RIPE Upstream",
                    source="RIPE Stat",
                    confidence="Medium",
                    color="blue",
                    status="Confirmed",
                    resolution=f"AS{asn} -> AS{n_up.get('asn', '')}",
                    tags=["asn", "bgp", "relationship", "transit"],
                ))

            for n_down in ripe_neighbours.get("downstreams", [])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"AS{n_down.get('asn', '')} (power: {n_down.get('power', 0)})",
                    type="ASN: RIPE Downstream",
                    source="RIPE Stat",
                    confidence="Medium",
                    color="green",
                    status="Confirmed",
                    resolution=f"AS{asn} -> AS{n_down.get('asn', '')}",
                    tags=["asn", "bgp", "relationship", "customer"],
                ))

        cf_data = await query_cloudflare_radar(asn, client)
        if cf_data and isinstance(cf_data, dict):
            rank = cf_data.get("rank", 0)
            if rank:
                all_asn_data[asn]["cf_rank"] = rank
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

        rpki_check = await check_rpki_for_prefixes(asn, client)
        if rpki_check:
            all_asn_data[asn]["hijack_status"] = rpki_check.get("hijack_status", "clean")
            all_asn_data[asn]["rpki_valid"] = rpki_check.get("rpki_valid", 0)
            all_asn_data[asn]["rpki_invalid"] = rpki_check.get("rpki_invalid", 0)

            hijack_color = "green"
            if rpki_check.get("hijack_status") == "potential_rpki_hijack":
                hijack_color = "orange"
            elif rpki_check.get("hijack_status") == "critical_rpki_invalid":
                hijack_color = "red"

            findings.append(IntelligenceFinding(
                entity=rpki_check.get("hijack_status", "clean").replace("_", " ").title(),
                type="ASN: RPKI / Hijack Detection",
                source="RIPE Stat RPKI",
                confidence="High",
                color=hijack_color,
                status="Confirmed" if rpki_check.get("hijack_status") == "clean" else "Warning",
                resolution=f"AS{asn}",
                raw_data=json.dumps(rpki_check),
                tags=["asn", "bgp", "hijack", "rpki"],
            ))

            invalid_prefixes = rpki_check.get("invalid_prefixes", [])
            if invalid_prefixes:
                for inv_pfx in invalid_prefixes[:5]:
                    findings.append(IntelligenceFinding(
                        entity=inv_pfx,
                        type="ASN: RPKI Invalid Prefix",
                        source="RIPE Stat RPKI",
                        confidence="High",
                        color="red",
                        status="Warning",
                        resolution=f"AS{asn}",
                        tags=["asn", "bgp", "hijack", "rpki_invalid"],
                    ))

        ripe_hist_endpoint = await query_ripe_stat("as-overview", client, {"resource": asn})
        if ripe_hist_endpoint and ripe_hist_endpoint.get("status") == "ok":
            rd = ripe_hist_endpoint.get("data", {})
            first_day = rd.get("first_day", "")
            last_day = rd.get("last_day", "")
            if first_day:
                all_asn_data[asn]["ripe_first_day"] = first_day
                findings.append(IntelligenceFinding(
                    entity=first_day,
                    type="ASN: RIPE First Day",
                    source="RIPE Stat",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "history", "ripe"],
                ))
            if last_day:
                all_asn_data[asn]["ripe_last_day"] = last_day
                findings.append(IntelligenceFinding(
                    entity=last_day,
                    type="ASN: RIPE Last Day",
                    source="RIPE Stat",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=f"AS{asn}",
                    tags=["asn", "history", "ripe"],
                ))

        if all_asn_data.get(asn, {}).get("first_seen") or all_asn_data.get(asn, {}).get("ripe_first_seen"):
            first = all_asn_data[asn].get("first_seen") or all_asn_data[asn].get("ripe_first_seen") or "unknown"
            last_changed = all_asn_data[asn].get("ripe_last_changed") or "unknown"
            findings.append(IntelligenceFinding(
                entity=f"First Seen: {first} | Last Change: {last_changed}",
                type="ASN: Historical Data Summary",
                source="BGP.tools / RIPE Stat",
                confidence="Medium",
                color="slate",
                status="Confirmed",
                resolution=f"AS{asn}",
                tags=["asn", "history", "timeline"],
            ))

        if asn in all_asn_data:
            summary = await generate_summary_report(asn, all_asn_data[asn], all_asn_data[asn].get("ip_resolved", t))
            findings.append(summary)

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
