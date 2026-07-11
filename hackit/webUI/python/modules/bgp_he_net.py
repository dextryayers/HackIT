import httpx
import asyncio
import socket
import re
import json
import math
from datetime import datetime
from collections import defaultdict
from typing import List
from module_common import safe_fetch, safe_fetch_json, make_finding
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
BGP_HE_BASE = "https://bgp.he.net"

IRR_SOURCES = ["RADB", "RIPE", "ARIN", "APNIC", "LACNIC", "AFRINIC", "NTTCOM"]

RPKI_STATES = {"Valid": "emerald", "Unknown": "slate", "Invalid": "red"}

COMMON_DESTINATIONS = {
    "Google": {"asns": [15169, 36040, 19527, 19424, 16591], "desc": "Google"},
    "Cloudflare": {"asns": [13335, 209242, 203898, 394507], "desc": "Cloudflare"},
    "Facebook/Meta": {"asns": [32934, 63293, 54113, 13767], "desc": "Facebook/Meta"},
    "Amazon/AWS": {"asns": [16509, 14618, 10124, 17493, 8987], "desc": "Amazon AWS"},
    "Microsoft/Azure": {"asns": [8075, 12076, 3598, 4009], "desc": "Microsoft Azure"},
    "Akamai": {"asns": [16625, 20940, 33905, 12222], "desc": "Akamai"},
    "Fastly": {"asns": [54113, 54114, 43529], "desc": "Fastly"},
    "Apple": {"asns": [714, 2709, 6185, 7734], "desc": "Apple"},
    "Netflix": {"asns": [40027, 2906, 40472], "desc": "Netflix"},
    "OVH": {"asns": [16276, 35540, 42261], "desc": "OVH"},
    "DigitalOcean": {"asns": [14061, 62567, 203466], "desc": "DigitalOcean"},
    "Hetzner": {"asns": [24961, 55328], "desc": "Hetzner"},
    "Vultr": {"asns": [20473, 21501], "desc": "Vultr"},
    "Linode": {"asns": [63949, 3598], "desc": "Linode"},
    "Oracle Cloud": {"asns": [31898, 394382], "desc": "Oracle Cloud"},
    "IBM Cloud": {"asns": [36351, 14384, 8111], "desc": "IBM Cloud"},
    "Alibaba Cloud": {"asns": [45102, 37963], "desc": "Alibaba Cloud"},
    "Tencent Cloud": {"asns": [132203, 45090], "desc": "Tencent Cloud"},
    "Scaleway": {"asns": [12876, 29695], "desc": "Scaleway"},
    "Cogent": {"asns": [174, 22822], "desc": "Cogent"},
    "Level 3 / CenturyLink": {"asns": [3356, 3549, 22561], "desc": "Level 3 / Lumen"},
    "GTT (formerly nLayer)": {"asns": [3257, 17409, 8429], "desc": "GTT"},
    "TATA": {"asns": [6453, 1273, 15830], "desc": "TATA Communications"},
    "NTT": {"asns": [2914, 5400, 34239], "desc": "NTT Communications"},
    "Verizon / UUNET": {"asns": [701, 702, 703], "desc": "Verizon"},
    "AT&T": {"asns": [7018, 26827, 714], "desc": "AT&T"},
    "Deutsche Telekom": {"asns": [3320, 6805, 5430], "desc": "Deutsche Telekom"},
    "Comcast": {"asns": [7922, 33490, 33491], "desc": "Comcast"},
    "Zayo": {"asns": [6461, 2856, 6460], "desc": "Zayo"},
    "Telia Carrier": {"asns": [1299, 24499, 2113], "desc": "Telia Carrier"},
    "Sprint": {"asns": [1239, 1759, 20128], "desc": "Sprint / T-Mobile"},
    "China Telecom": {"asns": [4134, 4809, 23724], "desc": "China Telecom"},
    "China Unicom": {"asns": [4837, 9929, 17799], "desc": "China Unicom"},
    "China Mobile": {"asns": [58453, 24444, 56046], "desc": "China Mobile"},
    "Samsung": {"asns": [38605, 45368], "desc": "Samsung"},
    "Twitter/X": {"asns": [13414, 35995], "desc": "Twitter/X"},
    "LinkedIn": {"asns": [14413, 20055], "desc": "LinkedIn"},
    "Spotify": {"asns": [15348, 48493], "desc": "Spotify"},
    "PayPal": {"asns": [30363, 10442], "desc": "PayPal"},
    "Shopify": {"asns": [20121, 53699], "desc": "Shopify"},
    "Twitch": {"asns": [46489, 13414], "desc": "Twitch"},
    "Netflix": {"asns": [40027, 2906, 40472], "desc": "Netflix"},
    "Discord": {"asns": [30293, 51167], "desc": "Discord"},
    "Cisco": {"asns": [109, 398200], "desc": "Cisco"},
    "Oracle": {"asns": [31898, 394382, 45963], "desc": "Oracle"},
    "SAP": {"asns": [34066, 26629], "desc": "SAP"},
    "Salesforce": {"asns": [14340, 46135], "desc": "Salesforce"},
    "Akamai": {"asns": [16625, 20940, 33905, 12222], "desc": "Akamai"},
    "Fastly": {"asns": [54113, 54114, 43529], "desc": "Fastly"},
    "Cloudfront": {"asns": [16509, 14618], "desc": "AWS (CloudFront origin)"},
    "NEUSTAR": {"asns": [7786, 19905], "desc": "Neustar"},
    "StackPath": {"asns": [33438, 25713], "desc": "StackPath / Highwinds"},
    "BunnyCDN": {"asns": [200332, 62044], "desc": "Bunny CDN"},
    "KeyCDN": {"asns": [203420, 45871], "desc": "KeyCDN"},
    "CacheFly": {"asns": [30081, 13444], "desc": "CacheFly"},
    "Edgecast": {"asns": [15133, 43204], "desc": "Edgecast / Verizon Digital Media"},
    "Limelight": {"asns": [22822, 22684], "desc": "Limelight Networks"},
    "StackPath": {"asns": [33438], "desc": "StackPath"},
}

CONTENT_PROVIDER_KEYWORDS = ["cdn", "content delivery", "hosting", "webhost", "web host",
                             "datacenter", "data center", "cloud", "saas", "paas", "iaas",
                             "colocation", "colo", "server", "managed hosting"]
ENTERPRISE_KEYWORDS = ["inc", "corp", "corporation", "llc", "ltd", "limited", "company",
                       "enterprise", "group", "holdings", "international", "global",
                       "industries", "solutions"]
TELECOM_KEYWORDS = ["telecom", "telecommunication", "isp", "internet service", "broadband",
                    "fiber", "fibre", "wireless", "mobile", "cellular", "gsm", "lte",
                    "5g", "network operator", "carrier", "backbone", "transit"]
CLOUD_KEYWORDS = ["cloud", "aws", "azure", "gcp", "google cloud", "amazon web",
                  "microsoft azure", "oracle cloud", "ibm cloud", "digitalocean",
                  "digital ocean", "linode", "vultr", "heroku", "scaleway",
                  "upcloud", "ovhcloud", "hetzner"]

GOVERNMENT_TLDS = [".gov", ".gouv", ".go.", ".gob", ".govt", ".state.", ".gov.",
                   ".mil", ".police", ".defense"]
EDUCATION_TLDS = [".edu", ".ac.", ".edu.", ".schule", ".university", ".college",
                  ".school", "university", "college", "institute of technology"]

COMMON_PEER_THRESHOLD_TIER1 = 500


async def resolve_to_ips(domain: str) -> list:
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []


async def fetch_he_net(path: str, client: httpx.AsyncClient, timeout: int = 15) -> str:
    try:
        resp = await safe_fetch(client, 
            f"{BGP_HE_BASE}{path}",
            headers={"User-Agent": UA},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return ""


async def scrape_asn_page(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
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
        info["peers"] = list(set(peers))[:50]

        upstream_match = re.search(r'Upstreams:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if upstream_match:
            info["upstreams"] = re.findall(r'/AS(\d+)', upstream_match.group(1))[:20]
        downstream_match = re.search(r'Downstreams:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if downstream_match:
            info["downstreams"] = re.findall(r'/AS(\d+)', downstream_match.group(1))[:20]

        m = re.search(r'IPs Originated:\s*</td><td[^>]*>([\d,]+)', text)
        if m:
            info["ips_originated"] = int(m.group(1).replace(",", ""))

        m = re.search(r'Prefixes Originated:\s*</td><td[^>]*>(\d+)', text)
        if m:
            info["prefixes_originated"] = int(m.group(1))

        m = re.search(r'AS Path:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if m:
            as_path_text = re.sub(r'<[^>]+>', '', m.group(1)).strip()
            info["as_path"] = re.findall(r'(\d+)', as_path_text)

        m = re.search(r'Allocation Date:\s*</td><td[^>]*>([^<]+)', text)
        if m:
            info["allocation_date"] = m.group(1).strip()

        m = re.search(r'Member of:\s*</td><td[^>]*>(.*?)</td>', text, re.DOTALL)
        if m:
            info["ixp_member"] = re.findall(r'([A-Za-z0-9\-]+)', m.group(1))

        return info
    except:
        return {}


async def scrape_prefix_history(asn: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await safe_fetch(client, 
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
    missing_sources = []
    for source in IRR_SOURCES:
        try:
            resp = await safe_fetch(client, 
                f"{BGP_HE_BASE}/irr.cgi?cmd=show+route+AS{asn}&source={source}",
                headers={"User-Agent": UA},
                timeout=15.0,
            )
            if resp.status_code == 200:
                routes = re.findall(r'route:\s+(\S+)', resp.text, re.IGNORECASE)
                if routes:
                    irr_records.append((source, routes[:5]))
                else:
                    missing_sources.append(source)
            else:
                missing_sources.append(source)
        except:
            missing_sources.append(source)
            continue
    return irr_records, missing_sources


async def scrape_rpki_status(asn: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
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
        resp = await safe_fetch(client, 
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


async def scrape_irv_data(asn: str, client: httpx.AsyncClient) -> dict:
    irv_result = {"valid_paths": 0, "invalid_paths": 0, "origin_mismatches": 0, "path_consistency": "unknown"}
    try:
        irv_text = await fetch_he_net(f"/irv.cgi?asn=AS{asn}&cmd=show+route", client)
        if irv_text:
            valid = re.findall(r'(?:valid|ok|match|correct)', irv_text, re.IGNORECASE)
            invalid = re.findall(r'(?:invalid|mismatch|incorrect|bad)', irv_text, re.IGNORECASE)
            irv_result["valid_paths"] = len(valid)
            irv_result["invalid_paths"] = len(invalid)
            total = len(valid) + len(invalid)
            if total > 0:
                ratio = len(valid) / total
                if ratio > 0.9:
                    irv_result["path_consistency"] = "high"
                elif ratio > 0.7:
                    irv_result["path_consistency"] = "moderate"
                else:
                    irv_result["path_consistency"] = "low"
    except:
        pass

    try:
        origin_text = await fetch_he_net(f"/irv.cgi?asn=AS{asn}&cmd=show+origin", client)
        if origin_text:
            mismatches = re.findall(r'(?:mismatch|conflict|different|unexpected)', origin_text, re.IGNORECASE)
            irv_result["origin_mismatches"] = len(mismatches)
    except:
        pass

    return irv_result


async def build_adjacent_graph(asn: str, client: httpx.AsyncClient) -> dict:
    graph_items = {}
    info = await scrape_asn_page(asn, client)
    if not info:
        return {}
    all_connections = defaultdict(list)
    for peer in info.get("peers", [])[:30]:
        all_connections["peers"].append({"asn": peer, "type": "peer"})
    for up in info.get("upstreams", [])[:15]:
        all_connections["upstreams"].append({"asn": up, "type": "upstream"})
    for down in info.get("downstreams", [])[:15]:
        all_connections["downstreams"].append({"asn": down, "type": "downstream"})
    graph_items = dict(all_connections)
    return graph_items


def build_graph_json(asn: str, info: dict, graph_adj: dict) -> str:
    nodes = []
    edges = []
    seen_nodes = set()

    target_asn = f"AS{asn}"
    nodes.append({
        "id": target_asn,
        "label": info.get("name", target_asn),
        "type": "target",
        "group": "target",
        "size": 30,
        "country": info.get("country", ""),
        "registry": info.get("registry", ""),
    })
    seen_nodes.add(target_asn)

    for rel_type, connections in graph_adj.items():
        for conn in connections:
            conn_asn = conn["asn"]
            conn_id = f"AS{conn_asn}"
            if conn_id not in seen_nodes:
                nodes.append({
                    "id": conn_id,
                    "label": conn_id,
                    "type": rel_type.rstrip("s"),
                    "group": rel_type.rstrip("s"),
                    "size": 15,
                })
                seen_nodes.add(conn_id)
            rel_label = "peers-with" if rel_type == "peers" else f"provides-{rel_type.rstrip('s')}-to"
            if rel_type == "downstreams":
                edges.append({"source": conn_id, "target": target_asn, "relationship": "downstream", "label": "downstream"})
            elif rel_type == "upstreams":
                edges.append({"source": conn_id, "target": target_asn, "relationship": "upstream", "label": "upstream"})
            else:
                edges.append({"source": target_asn, "target": conn_id, "relationship": "peer", "label": "peer"})

    return json.dumps({"nodes": nodes, "edges": edges}, indent=2)


async def trace_as_path(target_asn: str, dest_asns: list, client: httpx.AsyncClient) -> dict:
    results = {}
    for dest_asn_list_entry in dest_asns[:3]:
        dest_asn = str(dest_asn_list_entry)
        try:
            resp = await safe_fetch(client, 
                f"{BGP_HE_BASE}/bgp.cgi?as1=AS{target_asn}&as2=AS{dest_asn}",
                headers={"User-Agent": UA},
                timeout=15.0,
            )
            if resp.status_code == 200:
                text = resp.text
                path_match = re.search(r'AS Path[:\s]+<[^>]*>([^<]+)', text, re.IGNORECASE)
                if path_match:
                    raw_path = path_match.group(1)
                    path_asns = re.findall(r'(\d+)', raw_path)
                    hop_count = len(path_asns)
                    results[dest_asn] = {
                        "path": path_asns,
                        "hops": hop_count,
                        "raw": raw_path.strip(),
                    }
                else:
                    path_all = re.findall(r'(\d+)\s+', text)
                    if path_all:
                        path_all = list(dict.fromkeys(path_all))
                        if dest_asn in path_all or target_asn in path_all:
                            results[dest_asn] = {
                                "path": path_all,
                                "hops": len(path_all),
                                "raw": " -> ".join(path_all),
                            }
        except:
            continue
    return results


def categorize_asn(info: dict) -> dict:
    name = (info.get("name") or "").lower()
    registry = (info.get("registry") or "").lower()
    country = (info.get("country") or "").lower()

    categories = {
        "content_provider": False,
        "enterprise": False,
        "education": False,
        "government": False,
        "telecom_isp": False,
        "cloud_provider": False,
    }
    evidence = []

    if any(kw in name for kw in CONTENT_PROVIDER_KEYWORDS):
        categories["content_provider"] = True
        evidence.append("name_matches_content_provider_keywords")

    if any(kw in name for kw in ENTERPRISE_KEYWORDS):
        categories["enterprise"] = True
        evidence.append("name_matches_enterprise_keywords")

    if any(tld in name for tld in EDUCATION_TLDS):
        categories["education"] = True
        evidence.append("name_matches_education_keywords")

    if any(tld in name for tld in GOVERNMENT_TLDS):
        categories["government"] = True
        evidence.append("name_matches_government_keywords")

    if any(kw in name for kw in TELECOM_KEYWORDS):
        categories["telecom_isp"] = True
        evidence.append("name_matches_telecom_keywords")

    if any(kw in name for kw in CLOUD_KEYWORDS):
        categories["cloud_provider"] = True
        evidence.append("name_matches_cloud_keywords")

    if not any(categories.values()):
        categories["enterprise"] = True
        evidence.append("default_enterprise_classification")

    primary_category = "Unknown"
    for cat in ["cloud_provider", "telecom_isp", "government", "education", "content_provider", "enterprise"]:
        if categories[cat]:
            primary_category = cat
            break

    return {
        "categories": categories,
        "primary_category": primary_category.replace("_", " ").title(),
        "evidence": evidence,
    }


async def get_prefix_geolocation(prefixes: list, client: httpx.AsyncClient) -> list:
    geo_results = []
    seen_nets = set()
    for prefix in prefixes[:5]:
        try:
            resp = await safe_fetch(client, 
                f"{BGP_HE_BASE}/net/{prefix}",
                headers={"User-Agent": UA},
                timeout=15.0,
            )
            if resp.status_code == 200:
                text = resp.text
                net_name = ""
                m = re.search(r'Net Name:\s*</td><td[^>]*>([^<]+)', text)
                if m:
                    net_name = m.group(1).strip()
                net_country = ""
                m = re.search(r'Country:\s*</td><td>([^<]+)', text)
                if m:
                    net_country = m.group(1).strip()
                net_city = ""
                m = re.search(r'City:\s*</td><td>([^<]+)', text)
                if m:
                    net_city = m.group(1).strip()
                net_ip = ""
                m = re.search(r'IP:\s*</td><td[^>]*>([^<]+)', text)
                if m:
                    net_ip = m.group(1).strip()
                if net_country or net_city:
                    key = f"{prefix}:{net_country}:{net_city}"
                    if key not in seen_nets:
                        seen_nets.add(key)
                        geo_results.append({
                            "prefix": prefix,
                            "net_name": net_name,
                            "country": net_country,
                            "city": net_city,
                            "ip": net_ip,
                        })
        except:
            continue
    return geo_results


def analyze_transit_free(info: dict) -> dict:
    upstreams = info.get("upstreams", [])
    peers = info.get("peers", [])
    downstreams = info.get("downstreams", [])

    is_tier1_candidate = False
    reasoning = []

    if len(upstreams) == 0 and len(peers) > 100:
        is_tier1_candidate = True
        reasoning.append("no upstreams detected (potential Tier 1)")
        reasoning.append(f"large peer set: {len(peers)} peers")
    elif len(upstreams) == 0 and len(peers) > 50:
        is_tier1_candidate = True
        reasoning.append("no upstreams with moderate peer set")
        reasoning.append(f"{len(peers)} peers")
    elif len(upstreams) <= 1 and len(peers) > COMMON_PEER_THRESHOLD_TIER1:
        is_tier1_candidate = True
        reasoning.append(f"minimal upstreams ({len(upstreams)}) with very large peer set ({len(peers)})")
    elif len(upstreams) == 0:
        is_tier1_candidate = False
        reasoning.append("no upstreams but small peer set - possibly isolated or stub AS")
    else:
        reasoning.append(f"has {len(upstreams)} upstream(s) - not transit-free")

    tier_level = "Tier 1" if is_tier1_candidate else "Tier 2/3"
    if not upstreams and len(peers) < 10:
        tier_level = "Stub/Isolated"

    return {
        "is_tier1_candidate": is_tier1_candidate,
        "tier_level": tier_level,
        "upstream_count": len(upstreams),
        "peer_count": len(peers),
        "downstream_count": len(downstreams),
        "reasoning": reasoning,
    }


async def get_asn_age_info(asn: str, info: dict, client: httpx.AsyncClient) -> dict:
    age_info = {
        "allocation_date": info.get("allocation_date", ""),
        "estimated_age_years": 0,
        "registry": info.get("registry", ""),
        "historical_prefix_count": None,
    }

    allocation_date_str = info.get("allocation_date", "")
    if allocation_date_str:
        try:
            for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y", "%Y"]:
                try:
                    alloc_date = datetime.strptime(allocation_date_str.strip(), fmt)
                    now = datetime.now()
                    age_info["estimated_age_years"] = math.floor((now - alloc_date).days / 365.25)
                    break
                except ValueError:
                    continue
        except:
            pass

    try:
        prefix_history_urls = [
            f"{BGP_HE_BASE}/AS{asn}#_prefixes",
            f"https://stat.ripe.net/AS{asn}/prefixes.json",
        ]
        resp = await safe_fetch(client, 
            prefix_history_urls[0],
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            prefix_count = len(re.findall(r'/net/\d+\.\d+\.\d+\.\d+/\d+', text))
            if prefix_count > 0:
                age_info["historical_prefix_count"] = prefix_count
    except:
        pass

    return age_info


async def find_comparable_asns(info: dict, client: httpx.AsyncClient) -> list:
    comparable = []
    target_registry = info.get("registry", "").lower()
    target_country = info.get("country", "").lower()
    target_peer_count = len(info.get("peers", []))
    target_prefix_count = len(info.get("ipv4_prefixes", []))

    lower_bound = max(0, target_peer_count - 50)
    upper_bound = target_peer_count + 50

    search_urls = []
    if target_registry:
        search_urls.append(f"{BGP_HE_BASE}/search?q={target_registry.upper()}+AS&commit=Search")
    if target_country:
        search_urls.append(f"{BGP_HE_BASE}/search?q=country%3A{target_country}&commit=Search")

    seen_candidates = set()
    for surl in search_urls[:1]:
        try:
            resp = await safe_fetch(client, surl, headers={"User-Agent": UA}, timeout=15.0)
            if resp.status_code == 200:
                found_asns = re.findall(r'/AS(\d+)', resp.text)
                found_names = re.findall(r'/AS\d+\s*[">]([^<]+)', resp.text)
                for i, candidate_asn in enumerate(found_asns[:10]):
                    if candidate_asn not in seen_candidates:
                        seen_candidates.add(candidate_asn)
                        cname = found_names[i] if i < len(found_names) else ""
                        comparable.append({
                            "asn": candidate_asn,
                            "name": cname.strip(),
                            "registry": target_registry,
                            "country": target_country,
                        })
        except:
            continue

    return comparable[:5]


async def assess_bgp_risk(asn: str, info: dict, rpki_data: dict, irr_records: list, irr_missing: list) -> dict:
    risks = []
    total_risk_score = 0
    max_risk_score = 0

    rpki_invalid = rpki_data.get("invalid", 0) if rpki_data else 0
    rpki_valid = rpki_data.get("valid", 0) if rpki_data else 0
    rpki_total = sum(rpki_data.values()) if rpki_data else 0

    if rpki_invalid > 0:
        risk_score = min(100, rpki_invalid * 20)
        total_risk_score += risk_score
        max_risk_score += 100
        risks.append({
            "category": "RPKI Invalid Prefixes",
            "severity": "Critical" if rpki_invalid > 3 else "High",
            "score": risk_score,
            "detail": f"{rpki_invalid} RPKI invalid prefix(es) found - potential BGP hijack or misconfiguration",
            "mitigation": "Review and correct ROA objects for affected prefixes",
        })
    elif rpki_total == 0:
        risks.append({
            "category": "Missing RPKI",
            "severity": "Medium",
            "score": 30,
            "detail": "No RPKI data available - prefixes cannot be cryptographically verified",
            "mitigation": "Consider deploying RPKI and creating ROA objects",
        })
        total_risk_score += 30
        max_risk_score += 100
    else:
        max_risk_score += 100

    total_possible_irr = len(IRR_SOURCES)
    missing_irr_count = len(irr_missing)
    irr_ratio = 1.0
    if total_possible_irr > 0:
        irr_ratio = (total_possible_irr - missing_irr_count) / total_possible_irr

    if irr_ratio < 0.3:
        risk_score = 60
        total_risk_score += risk_score
        max_risk_score += 100
        risks.append({
            "category": "Missing IRR Records",
            "severity": "High",
            "score": risk_score,
            "detail": f"IRR records missing from {missing_irr_count}/{total_possible_irr} sources ({irr_ratio*100:.0f}% coverage)",
            "mitigation": "Ensure route objects are registered in major IRR databases",
        })
    elif irr_ratio < 0.7:
        risk_score = 30
        total_risk_score += risk_score
        max_risk_score += 100
        risks.append({
            "category": "Incomplete IRR Coverage",
            "severity": "Medium",
            "score": risk_score,
            "detail": f"IRR data present in some but not all sources ({irr_ratio*100:.0f}% coverage)",
            "mitigation": "Register route objects in additional IRR databases",
        })

    peers = info.get("peers", [])
    upstreams = info.get("upstreams", [])
    downstreams = info.get("downstreams", [])

    if len(peers) < 5 and len(upstreams) < 2:
        risk_score = 50
        total_risk_score += risk_score
        max_risk_score += 100
        risks.append({
            "category": "Reliability - Limited Connectivity",
            "severity": "High",
            "score": risk_score,
            "detail": f"Only {len(peers)} peer(s) and {len(upstreams)} upstream(s) - single point of failure risk",
            "mitigation": "Diversify peering and transit relationships",
        })
    elif len(upstreams) <= 1 and len(peers) < 20:
        risk_score = 25
        total_risk_score += risk_score
        max_risk_score += 100
        risks.append({
            "category": "Reliability - Low Redundancy",
            "severity": "Medium",
            "score": risk_score,
            "detail": f"Dependence on {len(upstreams)} upstream(s) with limited peering ({len(peers)} peers)",
            "mitigation": "Establish additional transit/peering relationships",
        })

    registry = info.get("registry", "")
    if registry:
        risks.append({
            "category": "Registry Information",
            "severity": "Informational",
            "score": 0,
            "detail": f"Registered with {registry}",
            "mitigation": "",
        })

    overall_risk_score = round((total_risk_score / max(max_risk_score, 1)) * 100)
    risk_level = "Low"
    if overall_risk_score >= 70:
        risk_level = "Critical"
    elif overall_risk_score >= 50:
        risk_level = "High"
    elif overall_risk_score >= 30:
        risk_level = "Medium"

    return {
        "overall_score": overall_risk_score,
        "risk_level": risk_level,
        "total_risk_score": total_risk_score,
        "max_risk_score": max_risk_score,
        "risks": risks,
    }


def build_detailed_graph_json(asn: str, info: dict, graph_adj: dict,
                              prefix_geo: list, bgp_paths: dict,
                              risk_assessment: dict, categorization: dict,
                              transit_info: dict) -> str:
    nodes = []
    edges = []
    seen_nodes = set()

    target_id = f"AS{asn}"
    target_label = info.get("name", target_id)

    nodes.append({
        "id": target_id,
        "label": target_label,
        "type": "target",
        "group": categorization.get("primary_category", "Unknown"),
        "size": 35,
        "country": info.get("country", ""),
        "registry": info.get("registry", ""),
        "allocation_date": info.get("allocation_date", ""),
        "ips_originated": info.get("ips_originated", 0),
        "prefixes_originated": info.get("prefixes_originated", 0),
        "tier_level": transit_info.get("tier_level", "Unknown"),
        "risk_level": risk_assessment.get("risk_level", "Unknown"),
        "risk_score": risk_assessment.get("overall_score", 0),
        "category": categorization.get("primary_category", "Unknown"),
        "peer_count": len(info.get("peers", [])),
        "upstream_count": len(info.get("upstreams", [])),
        "downstream_count": len(info.get("downstreams", [])),
    })
    seen_nodes.add(target_id)

    for rel_type, connections in graph_adj.items():
        for conn in connections:
            conn_id = f"AS{conn['asn']}"
            if conn_id not in seen_nodes:
                nodes.append({
                    "id": conn_id,
                    "label": conn_id,
                    "type": rel_type.rstrip("s"),
                    "group": "neighbor",
                    "size": 12,
                })
                seen_nodes.add(conn_id)
            if rel_type == "downstreams":
                edges.append({
                    "source": conn_id,
                    "target": target_id,
                    "relationship": "downstream",
                    "label": "provides transit to",
                    "weight": 2,
                })
            elif rel_type == "upstreams":
                edges.append({
                    "source": conn_id,
                    "target": target_id,
                    "relationship": "upstream",
                    "label": "provides transit to",
                    "weight": 3,
                })
            else:
                edges.append({
                    "source": target_id,
                    "target": conn_id,
                    "relationship": "peer",
                    "label": "peers with",
                    "weight": 1,
                })

    for geo_item in prefix_geo:
        prefix_id = f"prefix:{geo_item['prefix']}"
        if prefix_id not in seen_nodes:
            nodes.append({
                "id": prefix_id,
                "label": geo_item['prefix'],
                "type": "prefix",
                "group": "prefix",
                "size": 8,
                "country": geo_item.get("country", ""),
                "city": geo_item.get("city", ""),
                "net_name": geo_item.get("net_name", ""),
            })
            seen_nodes.add(prefix_id)
            edges.append({
                "source": target_id,
                "target": prefix_id,
                "relationship": "originates",
                "label": "originates",
                "weight": 1,
            })

    for dest_asn, path_data in bgp_paths.items():
        path = path_data.get("path", [])
        prev = target_id
        for hop_asn in path:
            hop_id = f"AS{hop_asn}" if not hop_asn.startswith("AS") else hop_asn
            if hop_id not in seen_nodes:
                nodes.append({
                    "id": hop_id,
                    "label": hop_id,
                    "type": "path_hop",
                    "group": "path",
                    "size": 10,
                })
                seen_nodes.add(hop_id)
            edge_key = f"{prev}->{hop_id}"
            if not any(e.get("source") == prev and e.get("target") == hop_id and e.get("relationship") == "path" for e in edges):
                edges.append({
                    "source": prev,
                    "target": hop_id,
                    "relationship": "path",
                    "label": f"AS{asn} -> AS{dest_asn} path",
                    "weight": 1,
                })
            prev = hop_id

    graph_data = {
        "metadata": {
            "target_asn": f"AS{asn}",
            "target_name": target_label,
            "generated_at": datetime.now().isoformat(),
            "source": "BGP.HE.net",
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        },
        "nodes": nodes,
        "edges": edges,
        "analysis": {
            "categorization": categorization,
            "transit_free": transit_info,
            "risk_assessment": risk_assessment,
            "bgp_paths": {f"AS{d}": p for d, p in bgp_paths.items()},
        },
    }

    return json.dumps(graph_data, indent=2)


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
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
            resp = await safe_fetch(client, 
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

                        findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
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
                            findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
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
                                findings.append(make_finding(
                                    entity=f"AS{down}",
                                    type="BGP: Downstream",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn} ← AS{down}",
                                    tags=["asn", "bgp", "transit"],
                                ))

                        irr_data, irr_missing = await scrape_irr_lookup(asn, client)
                        for source, routes in irr_data:
                            for route in routes:
                                findings.append(make_finding(
                                    entity=f"[{source}] {route}",
                                    type="BGP: IRR Record",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "irr", "routing"],
                                ))

                        if irr_missing:
                            findings.append(make_finding(
                                entity=f"Missing IRR in: {', '.join(irr_missing)}",
                                type="BGP: IRR Coverage Gap",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="yellow",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "irr", "gap"],
                            ))

                        rpki = await scrape_rpki_status(asn, client)
                        if rpki and any(rpki.values()):
                            total_rpki = sum(rpki.values())
                            rpki_color = "red" if rpki.get("invalid", 0) > 0 else "emerald"
                            findings.append(make_finding(
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
                            findings.append(make_finding(
                                entity=f"{len(roas)} ROA record(s) for AS{asn}",
                                type="BGP: ROA Records",
                                source="RPKI GrumpTech",
                                confidence="Medium",
                                color="emerald",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "rpki", "roa"],
                            ))

                        if info:
                            graph_adj = await build_adjacent_graph(asn, client)

                            graph_json = build_graph_json(asn, info, graph_adj)
                            findings.append(make_finding(
                                entity=f"AS{asn} Graph: {len(json.loads(graph_json)['nodes'])} nodes, {len(json.loads(graph_json)['edges'])} edges",
                                type="BGP: Adjacency Graph",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="slate",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                raw_data=graph_json,
                                tags=["asn", "graph", "visualization"],
                            ))

                            categorization = categorize_asn(info)
                            findings.append(make_finding(
                                entity=f"AS{asn} is a {categorization['primary_category']}",
                                type="BGP: Organization Category",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="slate",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "category", categorization['primary_category'].lower().replace(" ", "_")],
                            ))

                            transit_info = analyze_transit_free(info)
                            findings.append(make_finding(
                                entity=f"Tier Level: {transit_info['tier_level']}",
                                type="BGP: Transit-Free Analysis",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="green" if transit_info['is_tier1_candidate'] else "slate",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "tier", "transit"],
                            ))

                            prefix_geo = await get_prefix_geolocation(info.get("ipv4_prefixes", [])[:5], client)
                            for geo_item in prefix_geo:
                                findings.append(make_finding(
                                    entity=f"{geo_item['prefix']} - {geo_item.get('country', '?')}/{geo_item.get('city', '?')}",
                                    type="BGP: Prefix Geolocation",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "geo", "prefix"],
                                ))

                            age_info = await get_asn_age_info(asn, info, client)
                            if age_info.get("allocation_date"):
                                findings.append(make_finding(
                                    entity=f"Allocated: {age_info['allocation_date']} (~{age_info['estimated_age_years']} years ago)",
                                    type="BGP: ASN Age",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "history", "age"],
                                ))

                            comparable = await find_comparable_asns(info, client)
                            if comparable:
                                cmp_str = ", ".join([f"AS{c['asn']}" for c in comparable[:3]])
                                findings.append(make_finding(
                                    entity=f"Comparable ASNs: {cmp_str}",
                                    type="BGP: Comparison",
                                    source="BGP.HE.net",
                                    confidence="Low",
                                    color="slate",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "comparison", "benchmark"],
                                ))

                            risk_assessment = await assess_bgp_risk(asn, info, rpki, irr_data, irr_missing)
                            for risk in risk_assessment.get("risks", []):
                                sev_color = "red" if risk["severity"] in ("Critical", "High") else "yellow" if risk["severity"] == "Medium" else "slate"
                                findings.append(make_finding(
                                    entity=f"[{risk['severity']}] {risk['category']}: {risk['detail']}",
                                    type="BGP: Risk Assessment",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color=sev_color,
                                    threat_level=risk["severity"],
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "risk", risk["category"].lower().replace(" ", "_")],
                                ))

                            findings.append(make_finding(
                                entity=f"Overall BGP Risk: {risk_assessment['overall_score']}/100 ({risk_assessment['risk_level']})",
                                type="BGP: Overall Risk Score",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="red" if risk_assessment['risk_level'] in ("Critical", "High") else "yellow" if risk_assessment['risk_level'] == "Medium" else "emerald",
                                threat_level=risk_assessment["risk_level"],
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                tags=["asn", "risk", "overall"],
                            ))

                            bgp_paths = await trace_as_path(asn, [item for sublist in [v["asns"] for v in COMMON_DESTINATIONS.values()] for item in sublist], client)
                            for dest_name, dest_info in COMMON_DESTINATIONS.items():
                                for dasn in dest_info["asns"]:
                                    dasn_str = str(dasn)
                                    if dasn_str in bgp_paths:
                                        path_data = bgp_paths[dasn_str]
                                        findings.append(make_finding(
                                            entity=f"Path to {dest_name} (AS{dasn_str}): {path_data['raw'][:80]}",
                                            type="BGP: Path Analysis",
                                            source="BGP.HE.net",
                                            confidence="Medium",
                                            color="slate",
                                            status="Confirmed",
                                            resolution=f"AS{asn} → {dest_name}",
                                            tags=["asn", "bgp", "path", dest_name.lower().replace("/", "_")],
                                        ))

                            irv_data = await scrape_irv_data(asn, client)
                            if irv_data.get("path_consistency") != "unknown":
                                irv_color = "emerald" if irv_data["path_consistency"] == "high" else "yellow" if irv_data["path_consistency"] == "moderate" else "red"
                                findings.append(make_finding(
                                    entity=f"IRV Path Consistency: {irv_data['path_consistency'].title()} (valid: {irv_data['valid_paths']}, invalid: {irv_data['invalid_paths']}, origin mismatches: {irv_data['origin_mismatches']})",
                                    type="BGP: IRV Analysis",
                                    source="BGP.HE.net",
                                    confidence="Medium",
                                    color=irv_color,
                                    threat_level="High Risk" if irv_data["path_consistency"] == "low" else "Informational",
                                    status="Confirmed",
                                    resolution=f"AS{asn}",
                                    tags=["asn", "irv", "routing", "validation"],
                                ))

                            detailed_graph = build_detailed_graph_json(asn, info, graph_adj, prefix_geo, bgp_paths, risk_assessment, categorization, transit_info)
                            findings.append(make_finding(
                                entity=f"AS{asn} Network Graph ({len(json.loads(detailed_graph)['nodes'])} nodes)",
                                type="BGP: Structured Graph Export",
                                source="BGP.HE.net",
                                confidence="Medium",
                                color="slate",
                                status="Confirmed",
                                resolution=f"AS{asn}",
                                raw_data=detailed_graph,
                                tags=["asn", "graph", "json", "structured_data"],
                            ))

                for prefix in prefixes[:5]:
                    findings.append(make_finding(
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
        findings.append(make_finding(
            entity=f"No BGP data found for {t}",
            type="BGP: No Results",
            source="BGP.HE.net",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["error"],
        ))

    async def analyze_asn_landscape():
        findings.append(make_finding(entity=f"Total ASNs discovered: {len(seen_asns)}", type="BGP: ASN Count", source="BGP.HE.net", confidence="High", color="slate", tags=["analysis"]))
        asn_types = {"peer": 0, "upstream": 0, "downstream": 0}
        for f in findings:
            if f.type == "BGP: Peer": asn_types["peer"] += 1
            elif f.type == "BGP: Upstream": asn_types["upstream"] += 1
            elif f.type == "BGP: Downstream": asn_types["downstream"] += 1
        findings.append(make_finding(entity=f"Peers: {asn_types['peer']}, Upstream: {asn_types['upstream']}, Downstream: {asn_types['downstream']}", type="BGP: Relationship Breakdown", source="BGP.HE.net", confidence="Medium", color="slate", tags=["analysis"]))
        org_names = set()
        for f in findings:
            if f.type == "BGP: Organization":
                org_names.add(f.entity)
        findings.append(make_finding(entity=f"Organizations: {len(org_names)}", type="BGP: Org Count", source="BGP.HE.net", confidence="Medium", color="slate", tags=["analysis"]))
        findings.append(make_finding(entity=f"Target: {t}", type="BGP: Target Summary", source="BGP.HE.net", confidence="High", color="slate", tags=["analysis"]))

    async def analyze_bgp_security():
        risks = [f for f in findings if f.type == "BGP: Risk Assessment"]
        findings.append(make_finding(entity=f"BGP risk findings: {len(risks)}", type="BGP: Risk Count", source="BGP.HE.net", confidence="Medium", color="red" if len(risks) > 2 else "emerald", tags=["security"]))
        invalid_rpki = sum(1 for f in findings if "invalid" in f.entity.lower() and f.type == "BGP: RPKI Status")
        findings.append(make_finding(entity=f"RPKI invalid prefixes: {invalid_rpki}", type="BGP: RPKI Invalid Count", source="BGP.HE.net", confidence="Medium", color="red" if invalid_rpki else "emerald", tags=["security"]))
        irr_gaps = sum(1 for f in findings if f.type == "BGP: IRR Coverage Gap")
        findings.append(make_finding(entity=f"IRR coverage gaps: {irr_gaps}", type="BGP: IRR Gap Count", source="BGP.HE.net", confidence="Medium", color="yellow" if irr_gaps else "emerald", tags=["security"]))

    async def analyze_prefix_geography():
        geo_count = sum(1 for f in findings if f.type == "BGP: Prefix Geolocation")
        findings.append(make_finding(entity=f"Prefixes with geolocation: {geo_count}", type="BGP: Geo Prefix Count", source="BGP.HE.net", confidence="Medium", color="slate", tags=["geo"]))
        countries = set()
        for f in findings:
            if f.type == "BGP: Prefix Geolocation":
                parts = f.entity.split("-")
                if len(parts) >= 2:
                    countries.add(parts[1].split("/")[0].strip())
        findings.append(make_finding(entity=f"Countries represented: {', '.join(sorted(countries)) if countries else 'N/A'}", type="BGP: Country Spread", source="BGP.HE.net", confidence="Medium", color="slate", tags=["geo"]))
        findings.append(make_finding(entity=f"Routing data source: BGP.HE.net (Hurricane Electric)", type="BGP: Data Source", source="BGP.HE.net", confidence="High", color="slate", tags=["geo"]))

    async def analyze_routing_summary():
        total_prefixes = sum(1 for f in findings if f.type in ("BGP: IPv4 Prefix", "BGP: IPv6 Prefix", "BGP: Prefix for IP"))
        findings.append(make_finding(entity=f"Total prefixes found: {total_prefixes}", type="BGP: Prefix Count", source="BGP.HE.net", confidence="High", color="slate", tags=["routing"]))
        findings.append(make_finding(entity=f"Peer connections: {sum(1 for f in findings if f.type == 'BGP: Peer')}", type="BGP: Peer Connections", source="BGP.HE.net", confidence="Medium", color="slate", tags=["routing"]))
        findings.append(make_finding(entity=f"Transit relationships: {sum(1 for f in findings if f.type in ('BGP: Upstream', 'BGP: Downstream'))}", type="BGP: Transit Links", source="BGP.HE.net", confidence="Medium", color="slate", tags=["routing"]))

    async def analyze_network_health():
        graphs = sum(1 for f in findings if f.type in ("BGP: Adjacency Graph", "BGP: Structured Graph Export"))
        findings.append(make_finding(entity=f"Network graphs generated: {graphs}", type="BGP: Graph Count", source="BGP.HE.net", confidence="Medium", color="slate", tags=["health"]))
        paths = sum(1 for f in findings if f.type == "BGP: Path Analysis")
        findings.append(make_finding(entity=f"BGP paths traced: {paths}", type="BGP: Path Count", source="BGP.HE.net", confidence="Medium", color="slate", tags=["health"]))
        irv = sum(1 for f in findings if f.type == "BGP: IRV Analysis")
        findings.append(make_finding(entity=f"IRV validations: {irv}", type="BGP: IRV Count", source="BGP.HE.net", confidence="Medium", color="slate", tags=["health"]))

    await asyncio.gather(
        analyze_asn_landscape(),
        analyze_bgp_security(),
        analyze_prefix_geography(),
        analyze_routing_summary(),
        analyze_network_health(),
    )

    return findings
