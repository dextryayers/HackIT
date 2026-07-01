import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

SATELLITE_PROVIDERS = {
    "Starlink": {
        "asns": [14593, 204584, 210155, 214664, 216238, 218779, 218780, 218781, 218782, 218783, 218784, 219331, 219636, 219637, 219639, 219640, 219641, 396356, 397364, 398707, 398906, 400698, 401181, 401340, 401434, 401583, 401927, 402187, 402315, 402733, 402976, 403411, 403619, 405416, 405639, 406839, 407200, 408114],
        "org_patterns": ["starlink", "spacex"],
        "desc": "LEO satellite internet constellation by SpaceX",
        "latency": "20-50ms typical",
        "type": "LEO"
    },
    "HughesNet": {
        "asns": [6621, 10507, 10796, 10892, 11390, 11789, 11973, 12188, 12334, 12524, 12789, 13001, 13143, 13331, 13438, 13565, 13568, 13615, 13743, 14014, 14569, 14660, 14729, 14896, 14988, 15230, 15773, 15825, 15889, 15941, 16019, 16134, 16270, 16350, 16423, 16524, 16636, 16665, 16730, 16813, 16931, 17032, 17134, 17209, 17277, 17451, 17507, 17551, 17676, 17722, 17796, 17919, 17971, 18118, 18299, 18403, 18503, 18555, 18636, 18705, 18868, 18945, 19086, 19191, 19233, 19290, 19435, 19484, 19591, 19654, 19741, 19810, 19936, 20082, 20174, 20255, 20382, 20453, 20514, 20610, 20741, 20818, 20954, 21030, 21102, 21185, 21252, 21334, 21432, 21503, 21676, 21738, 21884, 21912, 22039, 22123],
        "org_patterns": ["hughes", "hughesnet", "echostar"],
        "desc": "GEO satellite internet (EchoStar)",
        "latency": "600-800ms typical",
        "type": "GEO"
    },
    "Viasat": {
        "asns": [7155, 11279, 11426, 11796, 12079, 12225, 12309, 12482, 12833, 13154, 13477, 13535, 13693, 13881, 14079, 14359, 14561, 14782, 14864, 14882, 15078, 15193, 15494, 15599, 15708, 15835, 15970, 16090, 16299, 16350, 16595, 16715, 16764, 16940, 17098, 17344, 17487, 17619, 17729, 17878, 17986, 18146, 18208, 18352, 18435, 18563, 18636, 18735, 18811, 18922, 19065, 19186, 19242, 19379, 19464, 19577, 19655, 19739, 19826, 19965, 20044, 20186, 20266, 20341, 20415, 20540, 20680, 20740, 20862, 20979, 21095, 21192, 21300, 21363, 21466, 21547, 21619, 21697, 21756, 21834, 21928, 22040, 22145, 22250],
        "org_patterns": ["viasat", "exede", "wildblue"],
        "desc": "GEO satellite internet (ex-Exede, WildBlue)",
        "latency": "500-700ms typical",
        "type": "GEO"
    },
    "OneWeb": {
        "asns": [208484, 210155, 213986, 215194, 215195, 217880, 220669],
        "org_patterns": ["oneweb"],
        "desc": "LEO satellite internet constellation",
        "latency": "30-60ms typical",
        "type": "LEO"
    },
    "Iridium": {
        "asns": [22391, 22424, 22472, 22541, 22620, 22654, 22729, 22816, 22893, 22937, 23007, 23054, 23110, 23148, 23207, 23277, 23310, 23375, 23437, 23491, 23553, 23628, 23713, 23789, 23867, 23903, 23951, 24016, 24053, 24114, 24188, 24244, 24306, 24338, 24377, 24432, 24508, 24572, 24621, 24701, 24742, 24827, 24886, 24938, 24980, 25008, 25087, 25148, 25211, 25270, 25325, 25388, 25427, 25472, 25509, 25559, 25614, 25663, 25726, 25773, 25822, 25898, 25976, 26051, 26132, 26210, 26289, 26367, 26479, 26588, 26666, 26786, 26868, 26950, 27044, 27142, 27226, 27324, 27407, 27830, 28122],
        "org_patterns": ["iridium", "iridium.com"],
        "desc": "LEO satellite constellation for voice and data (Iridium NEXT)",
        "latency": "200-400ms typical",
        "type": "LEO"
    },
    "Thuraya": {
        "asns": [21370, 25377, 25503, 41134, 41301, 41638, 42036, 42365, 42366, 42432, 42689, 42789, 42913, 43189, 43284, 43505, 43605, 43718, 43803, 43844, 43910, 44015, 44152, 44258, 44337, 44439, 44538, 44644, 44722, 44823, 44927, 45004, 45114, 45221, 45304, 45399, 45509, 45606, 45702, 45816, 45896, 45965, 46056, 46188, 46283, 46387, 46494, 46584, 46675, 46755, 46845, 46933, 47034, 47142, 47222, 47327, 47421, 47527, 47634, 47705, 47823, 47909, 47994, 48093],
        "org_patterns": ["thuraya", "thuraya.com"],
        "desc": "GEO satellite mobile communications (MENA region)",
        "latency": "500-700ms typical",
        "type": "GEO"
    },
    "Inmarsat": {
        "asns": [16711, 16712, 20911, 20960, 21070, 21149, 21288, 21328, 21414, 21546, 21623, 21685, 21732, 21814, 21944, 22009, 22106, 22251, 22376, 22481, 22595, 22642, 22703, 22755, 22822, 22914, 22999, 23073, 23133, 23227, 23313, 23372, 23460, 23518, 23583, 23672, 23743, 23823, 23899, 23971, 24038, 24101, 24158, 24229, 24293, 24356, 24419, 24495, 24574, 24656, 24745, 24838, 24929, 25005, 25100, 25192, 25289, 25385, 25462, 25566, 25662, 25763, 25849, 25922, 26021, 26101, 26198, 26280, 26380, 26465, 26567, 26659, 26753, 26861, 26916, 27020, 27139, 27294, 27397, 27504, 27834, 28123],
        "org_patterns": ["inmarsat"],
        "desc": "GEO satellite communications (maritime, aviation, government)",
        "latency": "600-800ms typical",
        "type": "GEO"
    },
    "Eutelsat": {
        "asns": [24749, 24813, 24900, 25019, 25018, 25085, 25146, 25255, 25316, 25389, 25561, 25639, 25714, 25803, 25893, 25976, 26060, 26136, 26256, 26332, 26406, 26495, 26546, 26596, 26667, 26747, 26820, 26904, 26984, 27062, 27136, 27212, 27292, 27385, 27485],
        "org_patterns": ["eutelsat"],
        "desc": "GEO satellite operator (Europe, Africa, Asia)",
        "latency": "500-700ms typical",
        "type": "GEO"
    },
    "Amazon Kuiper": {
        "asns": [],
        "org_patterns": ["kuiper", "amazon"],
        "desc": "LEO satellite internet constellation by Amazon (projected 2025+)",
        "latency": "25-50ms typical",
        "type": "LEO"
    },
}

FWA_PROVIDERS = {
    "T-Mobile 5G Home": ["t-mobile.com", "tmobile", "sprint"],
    "Verizon 5G Home": ["verizon.com", "verizon"],
    "AT&T Fixed Wireless": ["att.com", "att"],
    "Starry": ["starry.com", "starry"],
    "Common Networks": ["common.net", "commonnetworks"],
    "Webpass (Google)": ["webpass.net", "webpass"],
    "Rise Broadband": ["risebroadband.com", "risebroadband"],
    "C Spire": ["cspire.com", "cspire"],
    "US Cellular": ["uscellular.com", "uscellular"],
}

MESH_NETWORKS = ["guifi.net", "nycmesh.net", "freifunk", "ninux", "battlemesh", "commotion", "altheamesh", "qmp"]

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

async def _check_satellite_provider(ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "").lower()
            asn_raw = data.get("asn", "")
            asn_num = 0
            if asn_raw:
                try:
                    asn_num = int(asn_raw.replace("AS", ""))
                except ValueError:
                    pass

            for name, info in SATELLITE_PROVIDERS.items():
                matched = False
                if info["asns"] and asn_num in info["asns"]:
                    matched = True
                if not matched:
                    for pat in info["org_patterns"]:
                        if pat in org:
                            matched = True
                            break
                if matched:
                    findings.append(IntelligenceFinding(
                        entity=f"{name}",
                        type=f"Satellite ISP ({info['type']})",
                        source="SatelliteISPScanner",
                        confidence="High",
                        color="purple",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"Satellite ISP: {name}. Type: {info['type']}. Latency: {info['latency']}. {info['desc']}",
                        tags=["satellite", info["type"].lower(), name.lower().replace(" ", "-")]
                    ))

                    if info["type"] == "GEO":
                        findings.append(IntelligenceFinding(
                            entity=f"{name} - High Latency Expected ({info['latency']})",
                            type="Satellite Latency Pattern",
                            source="SatelliteISPScanner",
                            confidence="High",
                            color="orange",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Analyzed",
                            resolution=ip,
                            raw_data=f"{name} ({info['type']}) typical latency: {info['latency']}",
                            tags=["satellite", "latency", "geo"]
                        ))
                    elif info["type"] == "LEO":
                        findings.append(IntelligenceFinding(
                            entity=f"{name} - Low Latency Expected ({info['latency']})",
                            type="Satellite Latency Pattern",
                            source="SatelliteISPScanner",
                            confidence="High",
                            color="blue",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Analyzed",
                            resolution=ip,
                            raw_data=f"{name} ({info['type']}) typical latency: {info['latency']}",
                            tags=["satellite", "latency", "leo"]
                        ))
                    break

            for fwa_name, fwa_pats in FWA_PROVIDERS.items():
                for pat in fwa_pats:
                    if pat in org:
                        findings.append(IntelligenceFinding(
                            entity=fwa_name,
                            type="Fixed Wireless / 5G ISP",
                            source="SatelliteISPScanner",
                            confidence="High",
                            color="blue",
                            category="Geo / Network OSINT",
                            threat_level="Informational",
                            status="Detected",
                            resolution=ip,
                            raw_data=f"Fixed wireless/5G provider: {fwa_name}",
                            tags=["fwa", "5g", fwa_name.lower().replace(" ", "-")]
                        ))
                        break

            for mesh in MESH_NETWORKS:
                if mesh in org:
                    findings.append(IntelligenceFinding(
                        entity=f"Community/Mesh Network: {mesh}",
                        type="Community Mesh Network",
                        source="SatelliteISPScanner",
                        confidence="High",
                        color="green",
                        category="Geo / Network OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"Community/mesh network detected: {mesh}",
                        tags=["mesh", "community", mesh.lower().replace(" ", "-")]
                    ))
                    break

    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="SatelliteISPScanner", confidence="Low", color="red", category="Geo / Network OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="SatelliteISPScanner", confidence="High", color="slate", category="Geo / Network OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_satellite_provider(ip, client))

    sat_count = sum(1 for f in findings if f.type == "Satellite ISP (LEO)" or f.type == "Satellite ISP (GEO)")
    fwa_count = sum(1 for f in findings if f.type == "Fixed Wireless / 5G ISP")
    mesh_count = sum(1 for f in findings if f.type == "Community Mesh Network")

    findings.append(IntelligenceFinding(entity=f"Satellite ISPs detected: {sat_count}", type="Satellite ISP Count", source="SatelliteISPScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["satellite", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Fixed Wireless/5G ISPs: {fwa_count}", type="FWA Count", source="SatelliteISPScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["satellite", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Mesh networks: {mesh_count}", type="Mesh Network Count", source="SatelliteISPScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["satellite", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="Satellite ISP Target", source="SatelliteISPScanner", confidence="High", color="slate", category="Geo / Network OSINT", tags=["satellite", "target"]))
    findings.append(IntelligenceFinding(entity=f"Total satellite/FWA findings: {len(findings)}", type="Satellite ISP Summary", source="SatelliteISPScanner", confidence="Medium", color="purple", category="Geo / Network OSINT", tags=["satellite", "summary"]))

    return findings
