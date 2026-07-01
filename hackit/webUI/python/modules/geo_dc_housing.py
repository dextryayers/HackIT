import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

DATACENTER_PROVIDERS = {
    "Equinix": {
        "asns": [15830, 15831, 15832, 15833, 15834, 15835, 15836, 15837, 20940, 23352, 23589, 24429, 30822, 31015, 34083, 39356, 39499, 39788, 40007, 40528, 41938, 42563, 42858, 42954, 46198, 49936, 52426, 53126, 53721, 54043, 54248, 54357],
        "desc": "World's largest data center and colocation provider",
        "location": "Global (250+ facilities)"
    },
    "Digital Realty": {
        "asns": [13768, 20080, 22925, 26642, 27434, 30693, 32408, 32744, 33437, 33793, 33812, 34610, 36438, 36839, 37318, 39510, 39672, 39855, 39944, 40029, 40314, 42376, 42810, 43315, 43624, 44238, 44447, 44740, 44747, 45444, 45688, 45929, 46308, 46482, 46873, 47196, 47323, 47783, 47836, 48459, 48557, 48826, 49309, 49454, 49782, 49918, 50084, 50466, 50579, 50613, 50970, 51048, 51251],
        "desc": "Global provider of data center, colocation and interconnection solutions",
        "location": "Global (300+ facilities)"
    },
    "CyrusOne": {
        "asns": [11815, 14537, 14709, 14711, 14712, 15070, 16116, 19355, 20061, 20313, 20370, 21332, 21818, 22317, 22456, 22509, 22811, 23025, 23026, 23230, 23328, 24267, 25756, 25757, 26052, 26220, 26238, 26366, 26368, 26369, 26551, 26778, 26902, 27219, 27234, 27254, 27341, 27358, 29789, 29862, 30088, 30124, 30249, 30339, 30558, 30903, 30980, 31021, 31084, 31147, 31154, 31197, 31254, 31370, 31567, 31643, 31782],
        "desc": "Enterprise data center and colocation provider",
        "location": "US, Europe, Asia"
    },
    "QTS": {
        "asns": [12061, 13907, 14395, 14546, 14713, 14714, 14715, 14716, 14717, 14718, 14719, 14720, 14721, 14722, 14723, 14724, 14725, 14726, 14727, 14728, 14729, 14730, 14731, 14732, 14733, 14734, 14735, 14736, 14737, 14738, 14739, 14740, 14741, 14742, 14743, 14744, 14745, 14746, 14747, 14748, 14749, 14750, 14751, 14752, 14753, 14754, 14755, 14756, 14757, 14758, 14759, 14760, 14761, 14762, 14763, 14764, 14765, 14766, 14767, 14768, 14769, 14770],
        "desc": "Quality Technology Services - data center and colocation",
        "location": "US (30+ facilities)"
    },
    "CoreSite": {
        "asns": [13329, 13412, 13413, 13414, 13819, 14538, 14842, 14843, 15108, 15224, 15255, 15935, 16952, 17074, 17127, 17350, 17674, 17697, 17716, 18277, 18438, 18440, 18503, 18599, 18860, 18866, 18937, 18938, 19096, 19134, 19283, 19437, 19545, 19596, 19631, 19840, 19926, 20055, 20471, 20659, 21018, 21190, 21408, 21425, 21426, 21502, 21503, 21504, 21505, 21506, 21507, 62461],
        "desc": "Data center and colocation (acquired by Digital Realty)",
        "location": "US (25+ facilities)"
    },
    "Iron Mountain": {
        "asns": [24316, 24428, 27277, 27278, 29763, 30149, 30778, 32114, 32297, 32622, 33954, 36411, 37215, 39408, 39423, 39961, 39962, 39963, 39964, 39965, 39966, 39967, 39968, 39969, 39970, 39971, 39972, 39973, 39974, 39975, 39976, 39977, 39978, 39979, 39980, 39981, 39982],
        "desc": "Data center and colocation with focus on compliance/security",
        "location": "US, Europe"
    },
    "Switch": {
        "asns": [23005, 23520, 23868, 23907, 24087, 24537, 24618, 24953, 25065, 25066, 25272, 25379, 25423, 25576, 25685, 25804, 25880, 25961, 26070, 26128, 26274, 26339, 26489, 26570, 26799, 26877, 26901, 26918, 27059, 27200, 27389, 27729, 27765, 27817, 27834, 27867, 27868, 27925, 28088, 28106, 28133, 28191, 28210, 28344, 28375, 28427, 28508, 28552, 28678, 28733, 28839, 28903, 28911, 28982, 29081, 29190, 29212, 29324, 29393, 29452, 29578, 29611, 29638, 29688, 29765, 29844, 29886, 29939, 30042, 30117, 30221, 30381],
        "desc": "Data center and colocation (SuperNAP, The Citadel)",
        "location": "US (Las Vegas, Reno, Grand Rapids)"
    },
    "NTT": {
        "asns": [2914],
        "desc": "NTT Communications - global data center and colocation",
        "location": "Global (140+ facilities)"
    },
    "Telehouse": {
        "asns": [3257, 3786, 4058, 4261, 4502, 4780, 4781, 4812, 4863, 4887, 5047, 5050, 5384, 5413, 5529, 5539, 5693, 5908, 5941, 6040, 6074, 6104, 6192, 6226, 6233, 6662, 6692, 6774, 6791, 6880, 7004, 7023, 7108, 7206, 7232, 7338, 7402, 7460, 7609, 7871, 7961, 7993, 8001, 8220, 8285, 8374, 8447, 8511, 8607, 8717, 8847, 8894, 8912, 8927, 9121, 9329, 9381, 9498, 9558, 9584, 9595, 9622, 9644, 9670, 9678, 9730, 9731, 9732, 9830, 9935, 9941, 9994, 10013, 10069, 10100, 10147, 10269, 10348, 10432, 10503, 10555, 10610, 10728, 10832, 10866, 10998, 11036, 11086, 11142, 11231, 11370, 11449, 11538, 11620, 11653, 11731, 11848, 11949, 12044, 12147, 12208, 12244],
        "desc": "Data center and colocation (Telehouse/Telecity)",
        "location": "Global (40+ facilities)"
    },
    "Interxion": {
        "asns": [5507, 12466, 12631, 12731, 12816, 12820, 12916, 12993, 13208, 13244, 13285, 13468, 13470, 13715, 13738, 13750, 13850, 13876, 13961, 14045, 14155, 14242, 14376, 14478, 14592, 14872, 14910, 14935, 15016, 15043, 15190, 15266, 15389, 15482, 15547, 15666, 15750, 15878, 15899, 15916, 15935, 16000, 16128, 16247, 16298, 16315, 16401, 16499, 16554, 16627, 16681, 16749, 16834, 16910, 16955, 17054, 17114, 17197, 17325, 17507, 17524, 17746, 17846, 17950, 18087, 18104, 18189, 18265, 18390, 18510, 18568, 18719, 18782, 18817, 18909, 18974],
        "desc": "European data center and colocation (acquired by Digital Realty)",
        "location": "Europe (50+ facilities)"
    },
    "KDDI": {
        "asns": [2516],
        "desc": "Telecommunications and data center (Japan)",
        "location": "Japan, Asia"
    },
    "China Telecom": {
        "asns": [4134, 4809, 4812, 23764],
        "desc": "Data center and cloud infrastructure (China)",
        "location": "China, Global"
    },
    "Zayo": {
        "asns": [6461, 13138, 19653, 22561, 22821, 23396, 23509, 23569, 23822, 26937, 26949, 29811, 29832, 30238, 30617, 30629, 30637, 30673, 30691, 30852, 31365, 31452, 31567, 31682, 31720, 31838, 31897, 31937, 32097, 32236, 32268, 32347, 32446, 32525, 32621, 32782, 32957, 33010, 33176, 33248, 33309, 33382, 33441, 33494, 33541, 33562, 33570, 33618, 33664, 33789, 33808, 33927, 33972, 34029, 34073, 34118, 34149, 34225, 34226, 34236, 34309, 34365, 34401, 34452, 34512, 34568, 34669, 34704, 34798, 34860, 34916, 35001],
        "desc": "Bandwidth infrastructure and colocation (now part of Digital Colony)",
        "location": "US, Europe"
    },
    "Vantage": {
        "asns": [],
        "desc": "Hyperscale data center developer and operator",
        "location": "US, Europe, Canada"
    },
    "Aligned": {
        "asns": [],
        "desc": "Data center and colocation with adaptive cooling",
        "location": "US (Phoenix, Chicago, Dallas, New York)"
    },
    "STACK": {
        "asns": [],
        "desc": "Data center infrastructure and colocation",
        "location": "US (12+ markets)"
    },
    "Compass": {
        "asns": [],
        "desc": "Hyperscale data center design and construction",
        "location": "US, Europe, Asia"
    },
    "Sabey": {
        "asns": [],
        "desc": "Data center and colocation provider",
        "location": "US (Seattle, Quincy, New York)"
    },
    "Cyxtera": {
        "asns": [13768, 22925, 26642, 27434, 30693, 32408, 32744, 33437, 33793, 33812, 34610, 36438, 36839, 37318, 39510, 39672, 39855, 39944, 40029, 40314, 42376, 42810, 43315, 43624, 44238, 44447, 44740, 44747, 45444, 45688, 45929, 46308, 46482, 46873, 47196, 47323, 47783, 47836, 48459, 48557, 48826, 49309, 49454, 49782, 49918, 50084, 50466, 50579, 50613, 50970, 51048, 51251, 62461],
        "desc": "Data center and colocation (bankruptcy 2023, acquired)",
        "location": "US (60+ facilities)"
    },
}

DC_KEYWORDS = ["datacenter", "data center", "colo", "colocation", "dc ", "colo-", "dc-", "colo."]

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

async def _get_org_info(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "")
            asn_str = data.get("asn", "")
            asn_num = 0
            if asn_str:
                try:
                    asn_num = int(asn_str.replace("AS", ""))
                except ValueError:
                    pass

            if org:
                for dc_name, dc_info in DATACENTER_PROVIDERS.items():
                    if dc_info["asns"] and asn_num in dc_info["asns"]:
                        findings.append(IntelligenceFinding(
                            entity=f"{dc_name} Data Center",
                            type="Data Center Provider (ASN Match)",
                            source="DataCenterHousingScanner",
                            confidence="High",
                            color="orange",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Identified",
                            resolution=ip,
                            raw_data=f"Data center provider: {dc_name}. {dc_info['desc']}. Location: {dc_info['location']}",
                            tags=["dc", "colocation", dc_name.lower().replace(" ", "-")]
                        ))
                        break
                else:
                    for dc_name, dc_info in DATACENTER_PROVIDERS.items():
                        if dc_name.lower() in org.lower():
                            findings.append(IntelligenceFinding(
                                entity=f"{dc_name} Data Center (via org name)",
                                type="Data Center Provider (Org Match)",
                                source="DataCenterHousingScanner",
                                confidence="High",
                                color="orange",
                                category="Geo / Network OSINT",
                                threat_level="Informational",
                                status="Identified",
                                resolution=ip,
                                raw_data=f"Data center provider: {dc_name} matched via org '{org}'",
                                tags=["dc", "colocation", dc_name.lower().replace(" ", "-")]
                            ))
                            break

                is_dc_keyword = any(kw in org.lower() for kw in DC_KEYWORDS)
                if is_dc_keyword:
                    findings.append(IntelligenceFinding(
                        entity=f"Data Center Keyword in Org: {org[:80]}",
                        type="Data Center Indicator",
                        source="DataCenterHousingScanner",
                        confidence="Medium",
                        color="blue",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Suspected",
                        resolution=ip,
                        raw_data=f"Organization '{org}' contains data center related keywords",
                        tags=["dc", "indicator"]
                    ))

    except Exception:
        pass
    return findings

async def _check_dc_from_rdns(ip: str) -> list:
    findings = []
    try:
        ptr = socket.gethostbyaddr(ip)
        ptr_name = ptr[0].lower()
        for dc_name in DATACENTER_PROVIDERS.keys():
            if dc_name.lower() in ptr_name:
                findings.append(IntelligenceFinding(
                    entity=f"{dc_name} Data Center (rDNS)",
                    type="Data Center Provider (rDNS Match)",
                    source="DataCenterHousingScanner",
                    confidence="High",
                    color="orange",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    raw_data=f"rDNS {ptr_name} matches {dc_name}",
                    tags=["dc", "colocation", "rdns", dc_name.lower().replace(" ", "-")]
                ))
                break
        for kw in DC_KEYWORDS:
            if kw in ptr_name:
                findings.append(IntelligenceFinding(
                    entity=f"DC keyword in rDNS: {ptr_name}",
                    type="Data Center rDNS Indicator",
                    source="DataCenterHousingScanner",
                    confidence="Medium",
                    color="slate",
                    category="Geo / Network OSINT",
                    threat_level="Informational",
                    status="Suspected",
                    resolution=ip,
                    raw_data=f"rDNS contains DC-related keyword '{kw}': {ptr_name}",
                    tags=["dc", "rdns", "indicator"]
                ))
                break
    except Exception:
        pass
    return findings

async def _list_all_dc_providers() -> list:
    findings = []
    for dc_name, dc_info in DATACENTER_PROVIDERS.items():
        findings.append(IntelligenceFinding(
            entity=f"{dc_name} - {dc_info['location']}",
            type="Data Center Provider Reference",
            source="DataCenterHousingScanner",
            confidence="Medium",
            color="slate",
            category="Geo / Network OSINT",
            threat_level="Informational",
            status="Referenced",
            raw_data=f"{dc_name}: {dc_info['desc']}. Locations: {dc_info['location']}",
            tags=["dc", dc_name.lower().replace(" ", "-")]
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
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="DataCenterHousingScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="DataCenterHousingScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _get_org_info(ip, client))
    findings.extend(await _check_dc_from_rdns(ip))
    findings.extend(await _list_all_dc_providers())

    in_dc = any(f for f in findings if "Data Center Provider" in f.type)
    findings.append(IntelligenceFinding(entity=f"Data Center Hosted: {'Yes' if in_dc else 'No / Unknown'}", type="Data Center Status", source="DataCenterHousingScanner", confidence="Medium" if in_dc else "Low", color="orange" if in_dc else "slate", category="Geo / Network OSINT", threat_level="Informational", status="Identified" if in_dc else "Unknown", resolution=ip, tags=["dc", "status"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="DC Scan Target", source="DataCenterHousingScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["dc", "target"]))
    findings.append(IntelligenceFinding(entity=f"Total DC findings: {len(findings)}", type="DC Scan Summary", source="DataCenterHousingScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["dc", "summary"]))

    return findings
