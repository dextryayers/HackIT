import re
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

BOTNET_C2_FEEDS = [
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://mirai.securitytracker.com/mirai.txt",
    "https://mozi-tracker.net/mozi.txt",
    "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/botnet-iocs.txt",
    "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/indicators/botnet.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/botnet.txt",
]

BOTNET_FAMILIES = {
    "Mirai": ["mirai", "okiru", "satori", "omni", "pure_mirai", "masuta"],
    "Mozi": ["mozi", "mozi_botnet", "p2p_botnet"],
    "Qbot": ["qbot", "qakbot", "pinkslipbot"],
    "Emotet": ["emotet", "gepys", "botnet_emotet"],
    "TrickBot": ["trickbot", "trick_botnet", "anchor_dns"],
    "Sality": ["sality", "sality_botnet", "sality_p2p"],
    "ZeroAccess": ["zeroaccess", "zero_access", "sirefef"],
    "Zeus": ["zeus", "zbot", "gameover", "p2pzeus"],
    "Conficker": ["conficker", "downadup", "kido"],
    "Necurs": ["necurs", "necurs_botnet"],
    "Andromeda": ["andromeda", "gamaru", "wauchos"],
    "DarkComet": ["darkcomet", "dark_comet", "fynloski"],
    "Pushdo": ["pushdo", "cutwail", "ponmocup"],
    "Ramnit": ["ramnit", "ramnit_botnet"],
    "Smokeloader": ["smokeloader", "smoke_botnet"],
    "RisePro": ["risepro", "rise_pro"],
}

BOTNET_PORTS = [23, 80, 443, 6667, 6668, 6669, 7000, 8080, 8443, 31337,
                48101, 48102, 2323, 7547, 5555, 135, 139, 445, 1433, 3306,
                22, 3389, 5900, 6379, 11211, 27017, 9200, 9300]

DGA_PATTERNS = [
    re.compile(r'^[a-z]{10,25}\.(com|net|org|xyz|top|club)$'),
    re.compile(r'^[a-z]{8,16}\.(xyz|top|club|work|life|live|online|site)$'),
    re.compile(r'^\d{8,}[a-z]{2,}\.(com|net|org|ru)$'),
    re.compile(r'^[a-z]{2}\d{6,}[a-z]{2}\.(com|net|org)$'),
    re.compile(r'^[b-df-hj-np-tv-z]{10,}\.(com|net|org|info)$'),
]

FAST_FLUX_PATTERNS = [
    re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    re.compile(r'(?:[a-z0-9-]+\.){4,}[a-z]{2,}'),
]

EXPLOIT_KIT_INDICATORS = [
    "exploit kit", "ek", "angler", "nuclear", "magnitude", "rig",
    "neutrino", "sundown", "grandsoft", "terror", "kairos",
    "lucky", "spelevo", "sweet orange", "strontium",
    "fallout", "underminer", "arbor", "blackhole", "cool",
    "critical", "crimepack", "crypter", "fiesta", "gong da",
]

async def check_ssl_blacklist_botnet(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "list": "SSL Blacklist", "type": "botnet_c2"})
    except:
        pass
    return results

async def check_feodo_tracker_botnet(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "list": "Feodo Tracker", "type": "botnet_c2"})
    except:
        pass
    return results

async def check_mirai_tracker(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://mirai.securitytracker.com/mirai.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "list": "Mirai Tracker", "type": "mirai_botnet"})
    except:
        pass
    return results

async def check_mozi_tracker(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://mozi-tracker.net/mozi.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "list": "Mozi Tracker", "type": "mozi_botnet"})
    except:
        pass
    return results

async def check_botnet_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for feed_url in BOTNET_C2_FEEDS:
            try:
                resp = await safe_fetch(client,feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        feed_name = feed_url.split("/")[-1].replace(".txt", "")
                        results.append({"feed": feed_name, "url": feed_url, "found": True})
            except:
                pass
    except:
        pass
    return results

async def check_botnet_ports(target: str) -> list:
    results = []
    try:
        if ":" in target:
            port_part = target.split(":")[-1]
            if port_part.isdigit():
                port = int(port_part)
                if port in BOTNET_PORTS:
                    results.append({"port": port, "details": f"Known botnet port {port}"})
    except:
        pass
    return results

async def detect_dga_patterns(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for pattern in DGA_PATTERNS:
            if pattern.match(target_lower):
                results.append({"pattern": str(pattern)[:60], "target": target_lower})
    except:
        pass
    return results

async def detect_fast_flux(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for pattern in FAST_FLUX_PATTERNS:
            if pattern.match(target_lower) or pattern.search(target_lower):
                results.append({"pattern": str(pattern)[:40], "target": target_lower})
    except:
        pass
    return results

async def classify_botnet_family(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for family, indicators in BOTNET_FAMILIES.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"family": family, "matched": ind, "confidence": "High"})
                    break
    except:
        pass
    return results

async def check_exploit_kit_indicators(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for indicator in EXPLOIT_KIT_INDICATORS:
            if indicator in target_lower:
                results.append({"indicator": indicator, "type": "exploit_kit"})
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    sslbl_results = await check_ssl_blacklist_botnet(client, query)
    for r in sslbl_results:
        findings.append(make_finding(
            entity=f"SSL Blacklist: {r['ip']} - Botnet C2 server",
            ftype="Botnet C2 Detection",
            source="SSL Blacklist (abuse.ch)",
            confidence="High",
            color="red",
            category="Botnet Intelligence",
            threat_level="Critical",
            status="Botnet C2 Listed",
            resolution=query,
            tags=["botnet", "c2", "ssl-blacklist"]
        ))

    feodo_results = await check_feodo_tracker_botnet(client, query)
    for r in feodo_results:
        findings.append(make_finding(
            entity=f"Feodo Tracker: {r['ip']} - Botnet C2 (Dridex/Emotet infrastructure)",
            ftype="Botnet C2 Detection",
            source="Feodo Tracker (abuse.ch)",
            confidence="High",
            color="red",
            category="Botnet Intelligence",
            threat_level="Critical",
            status="C2 Blacklisted",
            resolution=query,
            tags=["botnet", "feodo", "dridex", "emotet"]
        ))

    mirai_results = await check_mirai_tracker(client, query)
    for r in mirai_results:
        findings.append(make_finding(
            entity=f"Mirai Tracker: {r['ip']} - IoT botnet member",
            ftype="IoT Botnet Detection",
            source="Mirai Tracker",
            confidence="High",
            color="red",
            category="Botnet Intelligence",
            threat_level="Critical",
            status="Mirai Botnet",
            resolution=query,
            tags=["botnet", "mirai", "iot", "ddos"]
        ))

    mozi_results = await check_mozi_tracker(client, query)
    for r in mozi_results:
        findings.append(make_finding(
            entity=f"Mozi Tracker: {r['ip']} - P2P botnet member",
            ftype="P2P Botnet Detection",
            source="Mozi Tracker",
            confidence="High",
            color="red",
            category="Botnet Intelligence",
            threat_level="Critical",
            status="Mozi Botnet",
            resolution=query,
            tags=["botnet", "mozi", "p2p"]
        ))

    feed_results = await check_botnet_feeds(client, query)
    for r in feed_results:
        findings.append(make_finding(
            entity=f"Botnet feed match: {r['feed']}",
            ftype="Botnet Feed Detection",
            source=r['feed'],
            confidence="Medium",
            color="orange",
            category="Botnet Intelligence",
            threat_level="High Risk",
            status="Feed Hit",
            resolution=query,
            tags=["botnet", "feed", r['feed'].lower()]
        ))

    port_results = await check_botnet_ports(query)
    for r in port_results:
        findings.append(make_finding(
            entity=f"Botnet port: {r['port']} - {r['details']}",
            ftype="Botnet Port Detection",
            source="Botnet Detector",
            confidence="Medium",
            color="yellow",
            category="Botnet Intelligence",
            threat_level="Elevated Risk",
            status="Suspicious Port",
            resolution=query,
            tags=["botnet", "port", f"port-{r['port']}"]
        ))

    dga_results = await detect_dga_patterns(query)
    for r in dga_results:
        findings.append(make_finding(
            entity=f"DGA pattern detected: {r['target']} (pattern: {r['pattern'][:40]}...)",
            ftype="DGA Detection",
            source="Botnet Detector",
            confidence="Medium",
            color="yellow",
            category="Botnet Intelligence",
            threat_level="Elevated Risk",
            status="DGA Suspected",
            resolution=query,
            tags=["botnet", "dga", "domain-generation"]
        ))

    flux_results = await detect_fast_flux(query)
    for r in flux_results:
        findings.append(make_finding(
            entity=f"Fast-flux pattern detected: {r['target']}",
            ftype="Fast-Flux Detection",
            source="Botnet Detector",
            confidence="Medium",
            color="orange",
            category="Botnet Intelligence",
            threat_level="High Risk",
            status="Fast-Flux Suspected",
            resolution=query,
            tags=["botnet", "fast-flux", "dns-abuse"]
        ))

    family_results = await classify_botnet_family(query)
    for r in family_results:
        findings.append(make_finding(
            entity=f"Botnet family: {r['family']} (matched: {r['matched']})",
            ftype="Botnet Family Classification",
            source="Botnet Detector",
            confidence=r['confidence'],
            color="orange",
            category="Botnet Intelligence",
            threat_level="High Risk",
            status="Family Identified",
            resolution=query,
            tags=["botnet", "family", r['family'].lower().replace(" ", "-")]
        ))

    ek_results = await check_exploit_kit_indicators(query)
    for r in ek_results:
        findings.append(make_finding(
            entity=f"Exploit kit indicator: {r['indicator']}",
            ftype="Exploit Kit Detection",
            source="Botnet Detector",
            confidence="Low",
            color="yellow",
            category="Botnet Intelligence",
            threat_level="Elevated Risk",
            status="Indicator Found",
            resolution=query,
            tags=["botnet", "exploit-kit", r['indicator'].replace(" ", "-")]
        ))

    findings.append(make_finding(
        entity=f"Botnet detection complete for {query}: checked {len(BOTNET_C2_FEEDS)} feeds, {len(BOTNET_FAMILIES)} families, {len(BOTNET_PORTS)} ports",
        ftype="Botnet Detection Summary",
        source="Botnet Detector",
        confidence="Medium",
        color="slate",
        category="Botnet Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["botnet", "summary", "detection"]
    ))

    return findings
