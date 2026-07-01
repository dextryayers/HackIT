import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

MITRE_ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

MITRE_ATTACK_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1055": "Process Injection",
    "T1055.001": "Dynamic-link Library Injection",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1047": "Windows Management Instrumentation",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.006": "Windows Remote Management",
    "T1090": "Proxy",
    "T1090.002": "External Proxy",
    "T1090.003": "Multi-hop Proxy",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1485": "Data Destruction",
}

THREAT_ACTOR_GROUPS = {
    "APT29 (Cozy Bear)": ["apt29", "cozy bear", "the dukes", "yty", "cozyduke"],
    "APT28 (Fancy Bear)": ["apt28", "fancy bear", "sednit", "sofacy", "strontium", "pawn storm"],
    "Lazarus Group": ["lazarus", "hidden cobra", "guardians of peace", "zinc"],
    "Kimsuky": ["kimsuky", "velvet chollima", "black banshee"],
    "APT1 (Comment Crew)": ["apt1", "comment crew", "comment panda", "msup"],
    "APT33 (Elfin)": ["apt33", "elfin", "magnallium", "refined kitten"],
    "APT41 (Winnti)": ["apt41", "winnti", "barium", "double dragon"],
    "TA505": ["ta505", "sector 04", "graceful spider", "fin11"],
    "Silent Librarian": ["silent librarian", "cobalt dickens", "maple leaf", "ta407"],
    "FIN7": ["fin7", "carbanak", "navigator group", "golden kitten"],
    "Maze/CyberSpy": ["maze", "cyberspy", "chafer", "remix kitten"],
    "DarkSide": ["darkside", "darkside gang", "blackmatter"],
    "Conti": ["conti", "conti gang", "wizard spider"],
    "LockBit": ["lockbit", "lockbit gang", "lockbit ransomware"],
    "REvil (Sodinokibi)": ["revil", "sodinokibi", "pinchy spider"],
    "HEAT": ["heat", "heat group", "unc1878"],
    "Mustang Panda": ["mustang panda", "bronze president", "ta416", "red delta"],
    "TA444": ["ta444", "silver spider", "sparkling goblin"],
    "Scattered Spider": ["scattered spider", "scatter spider", "unc104"],
    "Volt Typhoon": ["volt typhoon", "vtyphoon", "unc152"],
    "UNC1878": ["unc1878", "heat group"],
    "Pantegana": ["pantegana", "dragonblood"],
}

async def fetch_mitre_attack_data(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await client.get(
            f"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            objects = data.get("objects", [])
            target_lower = target.lower()
            for obj in objects[:200]:
                name = obj.get("name", "").lower()
                desc = obj.get("description", "").lower()
                if target_lower in name or target_lower in desc:
                    results.append({
                        "id": obj.get("id", ""),
                        "name": obj.get("name", ""),
                        "type": obj.get("type", ""),
                        "description": obj.get("description", "")[:200],
                    })
                    if len(results) >= 5:
                        break
    except:
        pass
    return results

async def check_threat_actor_overlap(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for group, indicators in THREAT_ACTOR_GROUPS.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({
                        "group": group,
                        "matched_indicator": ind,
                        "confidence": "High" if len(ind) > 5 else "Medium"
                    })
                    break
    except:
        pass
    return results

async def check_ioc_overlap_with_campaigns(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        campaign_feeds = [
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/apthunting-iocs.txt",
            "https://raw.githubusercontent.com/pan0pt1c0n/Malicious-IOCs/main/apt_iocs.txt",
            "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/indicators/apt.txt",
        ]
        for feed_url in campaign_feeds:
            try:
                resp = await client.get(feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        feed_name = feed_url.split("/")[-1].replace(".txt", "")
                        results.append({"feed": feed_name, "url": feed_url, "campaign_overlap": True})
            except:
                pass
    except:
        pass
    return results

async def analyze_ttp_patterns(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for tech_id, tech_name in MITRE_ATTACK_TECHNIQUES.items():
            tech_keywords = tech_name.lower().split()
            for kw in tech_keywords:
                if len(kw) > 3 and kw in target_lower:
                    results.append({
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                        "matched_keyword": kw
                    })
                    break
    except:
        pass
    return results

async def check_malware_family_attribution(target: str) -> list:
    results = []
    try:
        malware_attribution = {
            "PlugX": ["apt", "china", "plugx"],
            "CobaltStrike": ["cobalt", "beacon"],
            "QuasarRAT": ["quasar", "rat"],
            "AsyncRAT": ["asyncrat", "rat"],
            "Imminent": ["imminent", "monitor"],
            "Nanocore": ["nanocore", "rat"],
            "DarkComet": ["darkcomet", "rat"],
            "Remcos": ["remcos", "rat"],
            "Warzone RAT": ["warzone", "rat"],
            "AgentTesla": ["agent tesla", "spyware"],
        }
        target_lower = target.lower()
        for malware, attribution_keywords in malware_attribution.items():
            for kw in attribution_keywords:
                if kw in target_lower:
                    results.append({
                        "malware": malware,
                        "matched": kw,
                        "attribution": True
                    })
                    break
    except:
        pass
    return results

async def analyze_geography_timing(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        geo_indicators = {
            "Russian-speaking": ["ru", ".ru", "rus", "moscow", "saint petersburg"],
            "Chinese-speaking": ["cn", ".cn", "shanghai", "beijing", "shenzhen"],
            "North Korean": ["kp", ".kp", "pyongyang"],
            "Iranian": ["ir", ".ir", "tehran"],
            "English-speaking": ["us", "uk", "ca", "au", ".com", ".net", ".org"],
        }
        for geo, indicators in geo_indicators.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"geography": geo, "matched": ind})
                    break
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    mitre_results = await fetch_mitre_attack_data(client, query)
    for r in mitre_results:
        findings.append(IntelligenceFinding(
            entity=f"MITRE ATT&CK: {r['name']} ({r['id']}) - {r['description'][:100]}",
            type="MITRE ATT&CK Mapping",
            source="MITRE CTI",
            confidence="Medium",
            color="slate",
            category="Threat Attribution",
            threat_level="Informational",
            status="TTP Mapped",
            resolution=query,
            raw_data=json.dumps(r),
            tags=["mitre-attack", "ttp", r['id'].lower(), r['type']]
        ))

    actor_results = await check_threat_actor_overlap(query)
    for r in actor_results:
        findings.append(IntelligenceFinding(
            entity=f"Threat actor group: {r['group']} (indicator: {r['matched_indicator']})",
            type="Threat Actor Attribution",
            source="OSINT Attribution",
            confidence=r['confidence'],
            color="red",
            category="Threat Attribution",
            threat_level="Critical",
            status="Group Identified",
            resolution=query,
            tags=["threat-actor", "attribution", r['group'].lower().replace(" ", "-").replace("(", "").replace(")", "")]
        ))

    campaign_results = await check_ioc_overlap_with_campaigns(client, query)
    for r in campaign_results:
        findings.append(IntelligenceFinding(
            entity=f"IoC overlap with known campaigns: {r['feed']}",
            type="Campaign Overlap Detection",
            source=r['feed'],
            confidence="High",
            color="red",
            category="Threat Attribution",
            threat_level="Critical",
            status="Campaign Overlap",
            resolution=query,
            tags=["campaign", "ioc-overlap", r['feed'].lower()]
        ))

    ttp_results = await analyze_ttp_patterns(query)
    for r in ttp_results:
        findings.append(IntelligenceFinding(
            entity=f"TTP detected: {r['technique_id']} - {r['technique_name']}",
            type="TTP Identification",
            source="OSINT Attribution",
            confidence="Low",
            color="yellow",
            category="Threat Attribution",
            threat_level="Elevated Risk",
            status="TTP Identified",
            resolution=query,
            tags=["ttp", r['technique_id'].lower(), r['technique_name'].lower().replace(" ", "-")]
        ))

    malware_attr_results = await check_malware_family_attribution(query)
    for r in malware_attr_results:
        findings.append(IntelligenceFinding(
            entity=f"Malware attribution: {r['malware']} (matched: {r['matched']})",
            type="Malware Attribution",
            source="OSINT Attribution",
            confidence="Medium",
            color="orange",
            category="Threat Attribution",
            threat_level="High Risk",
            status="Malware Attributed",
            resolution=query,
            tags=["malware", "attribution", r['malware'].lower().replace(" ", "-")]
        ))

    geo_results = await analyze_geography_timing(query)
    for r in geo_results:
        findings.append(IntelligenceFinding(
            entity=f"Geography indicator: {r['geography']} (matched: {r['matched']})",
            type="Geography Attribution",
            source="OSINT Attribution",
            confidence="Low",
            color="slate",
            category="Threat Attribution",
            threat_level="Informational",
            status="Geo Pattern Noted",
            resolution=query,
            tags=["geography", "attribution", r['geography'].lower().replace(" ", "-")]
        ))

    for tactic in MITRE_ATTACK_TACTICS:
        findings.append(IntelligenceFinding(
            entity=f"MITRE ATT&CK tactic coverage: {tactic}",
            type="MITRE Tactic Coverage",
            source="OSINT Attribution",
            confidence="Low",
            color="slate",
            category="Threat Attribution",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["mitre-attack", "tactic", tactic.lower().replace(" ", "-")]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Threat attribution complete for {query}: checked {len(THREAT_ACTOR_GROUPS)} groups, {len(MITRE_ATTACK_TECHNIQUES)} techniques, {len(MITRE_ATTACK_TACTICS)} tactics",
        type="Threat Attribution Summary",
        source="OSINT Attribution",
        confidence="Medium",
        color="slate",
        category="Threat Attribution",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["attribution", "summary", "threat-intel"]
    ))

    return findings
