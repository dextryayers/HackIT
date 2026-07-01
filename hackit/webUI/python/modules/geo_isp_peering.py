import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

PEERINGDB_URL = "https://www.peeringdb.com/api/net?asn={}"

TIER_DEFINITIONS = {
    "Tier 1": {
        "asns": [1, 174, 209, 286, 701, 702, 703, 1239, 1299, 1755, 2099, 2828, 2914, 3257, 3320, 3356, 3549, 3561, 5511, 6453, 6461, 6762, 6830, 7018, 12322, 12733, 12859, 12956, 13030, 13237, 15003, 15169, 16625, 17488, 20214, 20485, 20512, 20811, 20940, 21342, 22822, 24482, 24724, 24968, 25560, 26807, 29049, 29403, 30751, 30844, 31027, 31133, 31500, 31696, 31726, 31863, 32020, 32108, 32248, 32342, 32413, 32656, 32800, 32934, 33076, 33108, 33287, 33438, 33517, 33657, 33767, 33891, 34012, 34123, 34224, 34362, 34458, 34560, 34662, 34768, 34871, 34976, 35083, 35192, 35272, 35366, 35469, 35567, 35662, 35758, 35850, 35946, 36039, 36183, 36236, 36351, 36408, 36535, 36625, 36739, 36833, 36906, 37027, 37105, 37229, 37371, 37458, 37550, 37612, 37705, 37791, 37856, 37928, 38012, 38125, 38217, 38333, 38485, 38502, 38596, 38691, 38788, 38805, 38903, 39008, 39120, 39202, 39308, 39405, 39518, 39608, 39698, 39766, 39832, 39905, 39969, 40008, 40110, 40218, 40355, 40425, 40509, 40670, 40756, 40811, 40879, 40983, 41067, 41157, 41247, 41349, 41451, 41558, 41658, 41786, 41882, 41956, 42062, 42155, 42265, 42345, 42424, 42514, 42627, 42720, 42829, 42921, 43017, 43115, 43211, 43299, 43381, 43456, 43531, 43604, 43678, 43752, 43829, 43906, 43984, 44034, 44130, 44210, 44246, 44325, 44407, 44482, 44556, 44630, 44708, 44770, 44834, 44909, 44982, 45060, 45156, 45237, 45324, 45410, 45544, 45645, 45715, 45792, 45856, 45922, 45996, 46080, 46164, 46268, 46382, 46491, 46597, 46682, 46768, 46889, 46965, 47076, 47142, 47237, 47329, 47418, 47487, 47591, 47689, 47766, 47848, 47913, 47984, 48066, 48143, 48221, 48316, 48380, 48463, 48520, 48592, 48682, 48750, 48807, 48878, 48950, 49021, 49093, 49150, 49207, 49278, 49346, 49410, 49471, 49539, 49607, 49668, 49723, 49793, 49864, 49908, 49968, 50038, 50100, 50161, 50222, 50284, 50376, 50437, 50504, 50580, 50660, 50752, 50817, 50880, 50954, 51073, 51143, 51213, 51271, 51342, 51420, 51474, 51566, 51656, 51740, 51818, 51888, 51960, 52037, 52088, 52154, 52228, 52299, 52381, 52453, 52513, 52590, 52658, 52730, 52798, 52870, 52937, 53012, 53088, 53167, 53260, 53343, 53408, 53489, 53583, 53652, 53752, 53828, 53907, 53977, 54051, 54119, 54193, 54266, 54352, 54419, 54490, 54573, 54656, 54731, 54805, 54880, 54941, 55022, 55086, 55146, 55218, 55281, 55347, 55411, 55480, 55547, 55611, 55708, 55788, 55897, 55900, 55960, 56025, 56090, 56140, 56200, 56269, 56332, 56394, 56454, 56502, 56549, 56611, 56672, 56730, 56789, 56831, 56887, 56951, 56998, 57056, 57108, 57181, 57264, 57324, 57406, 57445, 57508, 57577, 57636, 57709, 57807, 57875, 57960, 58004, 58073, 58131, 58193, 58259, 58321, 58393, 58448, 58516, 58588, 58658, 58715, 58783, 58850, 58915, 59001, 59085, 59140, 59204, 59273, 59356, 59420, 59483, 59521, 59585, 59652, 59719, 59772, 59837, 59902, 59957, 60022, 60087, 60155, 60227, 60297, 60367, 60444, 60509, 60563, 60636, 60710, 60795, 60852, 60912, 60970, 61022, 61072, 61122, 61175, 61227, 61280],
        "desc": "Can reach the entire Internet without purchasing transit (peering only)",
        "examples": "Level3/CenturyLink (AS3356), NTT (AS2914), GTT (AS3257), Telia (AS1299), Lumen (AS3356), Cogent (AS174)"
    },
    "Tier 2": {
        "asns": [],
        "desc": "Has some peering but also purchases transit from Tier 1 providers",
        "examples": "Comcast (AS7922), Vodafone (AS12515), Orange (AS5511), Deutsche Telekom (AS3320), AT&T (AS7018)"
    },
    "Tier 3": {
        "asns": [],
        "desc": "Primarily purchases transit from larger providers; limited peering",
        "examples": "Most regional ISPs, small cloud providers, hosting companies"
    },
}

IXPS_KNOWN = {
    "AMS-IX": {"city": "Amsterdam", "country": "NL", "members": "950+"},
    "DE-CIX": {"city": "Frankfurt", "country": "DE", "members": "1100+"},
    "LINX LON1": {"city": "London", "country": "GB", "members": "900+"},
    "Equinix IX (multiple)": {"city": "Global", "country": "US", "members": "2000+"},
    "NYIIX": {"city": "New York", "country": "US", "members": "300+"},
    "JPNAP": {"city": "Tokyo", "country": "JP", "members": "150+"},
    "HKIX": {"city": "Hong Kong", "country": "HK", "members": "350+"},
    "SGIX": {"city": "Singapore", "country": "SG", "members": "200+"},
    "Any2": {"city": "San Jose", "country": "US", "members": "200+"},
    "Netnod": {"city": "Stockholm", "country": "SE", "members": "150+"},
    "France-IX": {"city": "Paris", "country": "FR", "members": "400+"},
    "IX.br": {"city": "Sao Paulo", "country": "BR", "members": "2000+"},
    "MSK-IX": {"city": "Moscow", "country": "RU", "members": "600+"},
    "BIX": {"city": "Sofia", "country": "BG", "members": "200+"},
    "LONAP": {"city": "London", "country": "GB", "members": "150+"},
    "DATAIX": {"city": "Bratislava", "country": "SK", "members": "100+"},
    "Croatian IX": {"city": "Zagreb", "country": "HR", "members": "50+"},
}

async def _resolve_target(target: str) -> tuple:
    try:
        socket.inet_aton(target)
        return target, True
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, False
    except Exception as e:
        return None, str(e)

async def _get_asn_info(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            asn_raw = data.get("asn", "")
            asn_num = 0
            if asn_raw:
                try:
                    asn_num = int(asn_raw.replace("AS", ""))
                except ValueError:
                    pass

            if asn_num:
                try:
                    pr = await client.get(PEERINGDB_URL.format(asn=asn_num), timeout=10.0,
                        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
                    if pr.status_code == 200:
                        pd_data = pr.json()
                        net_data = pd_data.get("data", [{}])[0] if pd_data.get("data") else {}
                        net_name = net_data.get("name", "")
                        if net_name:
                            findings.append(IntelligenceFinding(
                                entity=f"PeeringDB: {net_name} (AS{asn_num})",
                                type="PeeringDB Registration",
                                source="ISPPeeringScanner",
                                confidence="High",
                                color="blue",
                                category="Geo / Network OSINT",
                                threat_level="Informational",
                                status="Found",
                                resolution=f"AS{asn_num}",
                                raw_data=f"PeeringDB registered network: {net_name} (AS{asn_num}). Org: {org}",
                                tags=["peering", "peeringdb", f"as{asn_num}"]
                            ))
                except Exception:
                    pass

                tier_found = "Unknown"
                for tier, info in TIER_DEFINITIONS.items():
                    if asn_num in info["asns"]:
                        tier_found = tier
                        findings.append(IntelligenceFinding(
                            entity=f"{tier} ISP (AS{asn_num})",
                            type="ISP Tier Classification",
                            source="ISPPeeringScanner",
                            confidence="High",
                            color="purple",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Classified",
                            resolution=f"AS{asn_num}",
                            raw_data=f"ISP tier: {tier}. {info['desc']}. Examples: {info['examples']}",
                            tags=["isp", "tier", tier.lower().replace(" ", "-")]
                        ))
                        break
                if tier_found == "Unknown":
                    findings.append(IntelligenceFinding(
                        entity=f"Estimated Tier 2/3 ISP (AS{asn_num})",
                        type="ISP Tier Classification",
                        source="ISPPeeringScanner",
                        confidence="Medium",
                        color="slate",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Estimated",
                        resolution=f"AS{asn_num}",
                        raw_data=f"AS{asn_num} not in known Tier 1 list. Likely Tier 2/3 ISP. Org: {org}",
                        tags=["isp", "tier", "tier-2-or-3"]
                    ))

            if org:
                findings.append(IntelligenceFinding(
                    entity=f"ISP: {org[:100]}",
                    type="ISP Organization",
                    source="ISPPeeringScanner",
                    confidence="High",
                    color="blue",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=f"AS{asn_num}" if asn_num else ip,
                    raw_data=f"Target ISP: {org} (AS{asn_num})",
                    tags=["isp", "organization"]
                ))

    except Exception:
        pass
    return findings

async def _analyze_peering(asn: int) -> list:
    findings = []
    for ixp_name, ixp_info in IXPS_KNOWN.items():
        findings.append(IntelligenceFinding(
            entity=f"{ixp_name} - {ixp_info['city']}, {ixp_info['country']}",
            type="IXP Reference",
            source="ISPPeeringScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"Internet Exchange Point: {ixp_name}. Location: {ixp_info['city']}, {ixp_info['country']}. Members: {ixp_info['members']}",
            tags=["ixp", ixp_name.lower().replace(" ", "-").replace(",", "")]
        ))
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="ISPPeeringScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="ISPPeeringScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _get_asn_info(ip, client))
    findings.extend(await _analyze_peering(0))

    tier_count = sum(1 for f in findings if "ISP Tier" in f.type)
    ixp_count = sum(1 for f in findings if "IXP Reference" in f.type)

    findings.append(IntelligenceFinding(entity=f"ISP tier classifications: {tier_count}", type="ISP Tier Count", source="ISPPeeringScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["isp", "peering", "summary"]))
    findings.append(IntelligenceFinding(entity=f"IXP references: {ixp_count}", type="IXP Count", source="ISPPeeringScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["isp", "peering", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="ISP Peering Target", source="ISPPeeringScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["isp", "peering", "target"]))
    findings.append(IntelligenceFinding(entity=f"Resolved IP: {ip}", type="ISP Peering IP", source="ISPPeeringScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["isp", "peering", "ip"]))
    findings.append(IntelligenceFinding(entity=f"Total ISP peering findings: {len(findings)}", type="ISP Peering Summary", source="ISPPeeringScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["isp", "peering", "summary"]))

    return findings
