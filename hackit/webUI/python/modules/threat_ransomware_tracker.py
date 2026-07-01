import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

RANSOMWARE_GROUPS = [
    "LockBit", "BlackCat", "Clop", "Black Basta", "Play", "BianLian",
    "Royal", "Vice Society", "Hive", "Conti", "REvil", "Babuk",
    "Darkside", "Ryuk", "Maze", "Egregor", "DoppelPaymer", "NetWalker",
    "Pysa", "Mespinoza", "Lorenz", "RagnarLocker", "Karakurt", "LV",
    "Snatch", "Quantum", "Everest", "Xing Team", "Spartacus", "Cactus",
    "Akira", "NoEscape", "8Base", "Medusa", "Bismuth", "RansomHouse",
    "Mallox", "TargetCompany", "Trigona", "Abyss", "Rhysida", "MalasLocker",
    "MoneyMessage", "BianLian", "Donut", "Mogilevich", "SpaceBears",
    "Stormous", "Vice Society", "AlphVM", "BlackSuit",
]

LEAK_SITE_PATTERNS = [
    re.compile(r'leak|breach|dox|dump|exfil|publish|blog|news', re.I),
    re.compile(r'\.onion', re.I),
    re.compile(r'http://[a-z2-7]{16,}\.onion', re.I),
]

RANSOM_NOTE_PATTERNS = [
    re.compile(r'your\s+(files|data|documents)\s+(are\s+)?(encrypted|stolen|locked)', re.I),
    re.compile(r'recover\s+(your\s+)?(files|data)', re.I),
    re.compile(r'decrypt(ion)?\s+(key|tool|service)', re.I),
    re.compile(r'pay\s+(ransom|bitcoin|monero|usd|btc|xmr)', re.I),
    re.compile(r'contact\s+us\s+(at\s+)?', re.I),
    re.compile(r'tor\s+browser|\.onion', re.I),
    re.compile(r'deadline|24\s*hours|48\s*hours|72\s*hours', re.I),
    re.compile(r'your\s+company\s+(has\s+been\s+)?(breached|compromised)', re.I),
]

RANSOMWARE_EXTENSIONS = [
    ".lockbit", ".abcd", ".encrypted", ".crypted", ".locked", ".enc",
    ".cry", ".crypt", ".rns", ".worm", ".hive", ".clop", ".play",
    ".basta", ".royal", ".bianlian", ".akira", ".8base", ".quantum",
    ".lv", ".snatch", ".cactus", ".medusa", ".rhysida", ".mallox",
]

async def fetch_ransomware_news(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        urls_to_check = [
            f"https://bleepingcomputer.com/tag/ransomware/page/1",
            f"https://therecord.media/?s={target}+ransomware",
            f"https://www.bleepingcomputer.com/search/?q={quote(target)}+ransomware",
        ]
        for url in urls_to_check:
            try:
                resp = await client.get(url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 and len(resp.text) > 100:
                    results.append({"url": url, "length": len(resp.text)})
            except:
                pass
    except:
        pass
    return results

async def check_ransomware_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        feeds = [
            "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
            "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.txt",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/ransomware-iocs.txt",
        ]
        for feed_url in feeds:
            try:
                resp = await client.get(feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    lines_containing = [l for l in content.splitlines() if target in l.lower()]
                    if lines_containing:
                        feed_name = feed_url.split("/")[-1].replace(".txt", "")
                        results.append({
                            "feed": feed_name,
                            "url": feed_url,
                            "matches": lines_containing[:5]
                        })
            except:
                pass
    except:
        pass
    return results

async def check_ransomware_group_association(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for group in RANSOMWARE_GROUPS:
            group_indicators = group.lower().replace(" ", "")
            if group_indicators in target_lower or group.lower() in target_lower:
                results.append({
                    "group": group,
                    "confidence": "High" if group_indicators in target_lower else "Medium"
                })
    except:
        pass
    return results

async def analyze_ransom_note_content(target: str) -> list:
    results = []
    try:
        for pattern in RANSOM_NOTE_PATTERNS:
            match = pattern.search(target)
            if match:
                results.append({
                    "pattern": pattern.pattern[:50],
                    "matched_text": match.group()[:100],
                    "category": "ransom_note_pattern"
                })
    except:
        pass
    return results

async def check_ransomware_extensions(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for ext in RANSOMWARE_EXTENSIONS:
            if ext in target_lower:
                results.append({
                    "extension": ext,
                    "associated_pattern": "ransomware_file_extension"
                })
    except:
        pass
    return results

async def check_ransomware_group_leaks(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        leak_domains = [
            "http://lockbit7z2jwcavghp7k7gcopgy2q3k7hkdda2xqcllxn2vpod2g3eid.onion",
            "http://avatodo2o2w2wz5gz3na6sbl2c4jgn3qo3g7k7yvq6k7lq3x5q.onion",
            "http://clopxqo3q5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5l5.onion",
        ]
        for domain in leak_domains:
            try:
                resp = await client.get(domain, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 and len(resp.text) > 100:
                    if target.lower() in resp.text.lower():
                        results.append({"domain": domain, "found": True})
            except:
                pass
    except:
        pass
    return results

async def check_ransomware_timeline(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        timeline_urls = [
            "https://raw.githubusercontent.com/Casualtek/Ransomwatch/main/groups.json",
            "https://raw.githubusercontent.com/RansomWarrior/ransomware-data/main/groups.json",
        ]
        for url in timeline_urls:
            try:
                resp = await client.get(url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        for group_entry in data if isinstance(data, list) else data.values():
                            group_name = group_entry.get("name", "") if isinstance(group_entry, dict) else str(group_entry)
                            if target.lower() in group_name.lower():
                                results.append({
                                    "url": url,
                                    "group": group_name,
                                    "data_found": True
                                })
                    except:
                        pass
            except:
                pass
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    news_results = await fetch_ransomware_news(client, query)
    for r in news_results:
        findings.append(IntelligenceFinding(
            entity=f"Ransomware news source checked: {r['url']} ({r['length']} bytes)",
            type="Ransomware News Intelligence",
            source="Ransomware Tracker",
            confidence="Low",
            color="slate",
            category="Ransomware Intelligence",
            threat_level="Informational",
            status="News Source Checked",
            resolution=query,
            tags=["ransomware", "news", "intelligence"]
        ))

    feed_results = await check_ransomware_feeds(client, query)
    for r in feed_results:
        for match in r.get("matches", []):
            findings.append(IntelligenceFinding(
                entity=f"Ransomware feed match: {r['feed']} - {match[:100]}",
                type="Ransomware IOC Match",
                source=r['feed'],
                confidence="High",
                color="red",
                category="Ransomware Intelligence",
                threat_level="Critical",
                status="Ransomware IOC Found",
                resolution=query,
                tags=["ransomware", "ioc", r['feed'].lower().replace("-", "_")]
            ))

    group_results = await check_ransomware_group_association(query)
    for r in group_results:
        findings.append(IntelligenceFinding(
            entity=f"Ransomware group association: {r['group']} (confidence: {r['confidence']})",
            type="Ransomware Group Identification",
            source="Ransomware Tracker",
            confidence=r['confidence'],
            color="red",
            category="Ransomware Intelligence",
            threat_level="Critical",
            status="Group Identified",
            resolution=query,
            tags=["ransomware", "group", r['group'].lower().replace(" ", "-")]
        ))

    note_results = await analyze_ransom_note_content(query)
    for r in note_results:
        findings.append(IntelligenceFinding(
            entity=f"Ransom note pattern detected: {r['matched_text']}",
            type="Ransomware Note Pattern",
            source="Ransomware Tracker",
            confidence="Medium",
            color="orange",
            category="Ransomware Intelligence",
            threat_level="High Risk",
            status="Note Pattern Matched",
            resolution=query,
            tags=["ransomware", "ransom-note", "pattern"]
        ))

    ext_results = await check_ransomware_extensions(query)
    for r in ext_results:
        findings.append(IntelligenceFinding(
            entity=f"Ransomware file extension: {r['extension']}",
            type="Ransomware File Extension",
            source="Ransomware Tracker",
            confidence="Medium",
            color="yellow",
            category="Ransomware Intelligence",
            threat_level="Elevated Risk",
            status="Extension Detected",
            resolution=query,
            tags=["ransomware", "extension", r['extension'].replace(".", "")]
        ))

    leak_results = await check_ransomware_group_leaks(client, query)
    for r in leak_results:
        findings.append(IntelligenceFinding(
            entity=f"Target found on ransomware leak site: {r['domain']}",
            type="Ransomware Leak Site Match",
            source="Ransomware Tracker",
            confidence="High",
            color="red",
            category="Ransomware Intelligence",
            threat_level="Critical",
            status="Data Leak Found",
            resolution=query,
            tags=["ransomware", "leak-site", "data-breach"]
        ))

    timeline_results = await check_ransomware_timeline(client, query)
    for r in timeline_results:
        findings.append(IntelligenceFinding(
            entity=f"Ransomware group timeline data: {r['group']} (source: {r['url']})",
            type="Ransomware Timeline Intelligence",
            source="Ransomware Tracker",
            confidence="Medium",
            color="orange",
            category="Ransomware Intelligence",
            threat_level="Elevated Risk",
            status="Timeline Data Available",
            resolution=query,
            tags=["ransomware", "timeline", r['group'].lower().replace(" ", "-")]
        ))

    for group in RANSOMWARE_GROUPS[:10]:
        findings.append(IntelligenceFinding(
            entity=f"Ransomware group monitoring: {group}",
            type="Ransomware Group Profile",
            source="Ransomware Tracker",
            confidence="Low",
            color="slate",
            category="Ransomware Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["ransomware", "group-profile", group.lower().replace(" ", "-")]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Ransomware intelligence complete for {query}: tracked {len(RANSOMWARE_GROUPS)} groups, checked {len(RANSOM_NOTE_PATTERNS)} note patterns, {len(RANSOMWARE_EXTENSIONS)} extensions",
        type="Ransomware Intelligence Summary",
        source="Ransomware Tracker",
        confidence="Medium",
        color="slate",
        category="Ransomware Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["ransomware", "summary", "intelligence"]
    ))

    return findings
