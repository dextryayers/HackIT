import httpx
import asyncio
import json
import re
import ipaddress
from datetime import datetime
from typing import List, Optional
from collections import defaultdict
from models import IntelligenceFinding

THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://threatfox.abuse.ch/export/json/ip/",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/scriptzteam/Threat-Intelligence/master/ips.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.dshield.org/block.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://malc0de.com/bl/IP_Blacklist.txt",
    "https://www.binarydefense.com/banlist.txt",
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
    "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
    "https://raw.githubusercontent.com/Elbarbons/Threat-Intel/master/ips.md",
    "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/ips.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/wordlist-collections/real-world-ips.txt",
    "https://raw.githubusercontent.com/blackdotsh/OpenThreatIntel/master/threatintel.csv",
]

ADDITIONAL_FEEDS = [
    ("URLhaus", "https://urlhaus.abuse.ch/downloads/text/"),
    ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt"),
    ("Spamhaus EDROP", "https://www.spamhaus.org/drop/edrop.txt"),
    ("OpenPhish Feed", "https://openphish.com/feed.txt"),
    ("PhishStats", "https://phishstats.info/phish_stats.csv"),
    ("Cybercrime Tracker", "https://cybercrime-tracker.net/all.php"),
    ("Botvrij.eu", "https://www.botvrij.eu/data/ioclist.ip-dst"),
    ("Circl.lu", "https://www.circl.lu/doc/misp/feed-osint"),
    ("MISP Feed", "https://misppriv.circl.lu/feed-osint"),
    ("AlienVault Reputation", "https://reputation.alienvault.com/reputation.data"),
    ("Greensnow", "https://blocklist.greensnow.co/greensnow.txt"),
    ("Darklist", "https://www.darklist.de/raw.php"),
    ("Blocklist.net.ua", "https://blocklist.net.ua/blocklist.csv"),
    ("Ransomware Tracker", "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"),
    ("Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist"),
    ("SSL Blacklist", "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"),
    ("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/feodotracker.csv"),
]

CIDR_BLOCKLISTS = [
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://lists.blocklist.de/lists/all.txt",
]

THREAT_CATEGORIES = {
    "malware": ["malware", "trojan", "virus", "worm", "download", "dropper", "payload"],
    "phishing": ["phish", "phishing", "fake", "spoof", "lookalike", "login page"],
    "c2": ["c2", "command & control", "command and control", "cnc", "cc server", "botnet", "bot"],
    "botnet": ["botnet", "bot", "zombie", "ddos agent", "irc bot"],
    "ransomware": ["ransom", "lockbit", "hive", "blackcat", "clop", "encrypt"],
    "scan": ["scanner", "scan", "portscan", "probe", "recon"],
    "exploit": ["exploit", "cve", "vuln", "rce", "sql injection", "xss", "code exec"],
    "spam": ["spam", "spammer", "email abuse", "phish mail", "malspam"],
    "ddos": ["ddos", "amplification", "reflection", "flood", "attack target"],
    "proxy": ["proxy", "open proxy", "socks", "vpn", "tor exit"],
}

IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
    "url": re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+'),
    "md5": re.compile(r'\b[a-f0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-f0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-f0-9]{64}\b'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
}

RELIABILITY_RATINGS = {
    "abuse.ch": "High",
    "firehol": "High",
    "blocklist.de": "High",
    "dshield": "High",
    "emergingthreats": "High",
    "binarydefense": "Medium",
    "cinsscore": "Medium",
    "malc0de": "Medium",
    "stamparm": "Medium",
    "stevenblack": "Medium",
    "spamhaus": "High",
    "openphish": "High",
    "alienvault": "High",
    "circl": "High",
}

KNOWN_CIDR_RANGES = [
    ("10.0.0.0/8", "RFC1918 Private"),
    ("172.16.0.0/12", "RFC1918 Private"),
    ("192.168.0.0/16", "RFC1918 Private"),
    ("127.0.0.0/8", "Loopback"),
    ("0.0.0.0/8", "Invalid"),
    ("169.254.0.0/16", "Link-Local"),
    ("224.0.0.0/4", "Multicast"),
    ("240.0.0.0/4", "Reserved"),
]

async def fetch_feed(client: httpx.AsyncClient, url: str, feed_name: str) -> dict:
    result = {"name": feed_name, "iocs": [], "lines": [], "source_url": url}
    try:
        resp = await client.get(url, timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            result["lines"] = lines[:100]
            for line in lines[:500]:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("//"):
                    for ioc_type, pattern in IOC_PATTERNS.items():
                        matches = pattern.findall(line)
                        for m in matches:
                            result["iocs"].append({"type": ioc_type, "value": m, "raw": line[:200]})
    except:
        pass
    return result

async def fetch_multiple_feeds(client: httpx.AsyncClient, urls: list) -> list:
    tasks = []
    for url in urls:
        name = url.split("/")[-1] if "/" in url else url
        tasks.append(fetch_feed(client, url, name))
    return await asyncio.gather(*tasks, return_exceptions=True)

async def extract_iocs(text: str) -> dict:
    iocs = defaultdict(list)
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        for m in matches:
            if m and len(m) > 3:
                iocs[ioc_type].append(m)
    return {k: list(set(v))[:10] for k, v in iocs.items()}

async def check_cidr_reputation(target_ip: str) -> list:
    results = []
    try:
        ip_obj = ipaddress.ip_address(target_ip)
        for cidr, desc in KNOWN_CIDR_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                results.append({"cidr": cidr, "description": desc})
    except:
        pass
    return results

async def classify_threat_category(text: str) -> list:
    categories = []
    text_lower = text.lower()
    for category, keywords in THREAT_CATEGORIES.items():
        for kw in keywords:
            if kw in text_lower:
                categories.append(category)
                break
    return categories

async def calculate_threat_score(feed_results: list, target: str) -> dict:
    score = 0
    total_feeds = len(feed_results)
    feeds_with_data = sum(1 for r in feed_results if isinstance(r, dict) and r.get("iocs"))
    total_iocs = sum(len(r.get("iocs", [])) for r in feed_results if isinstance(r, dict))

    score += min(feeds_with_data * 5, 30)
    score += min(total_iocs // 10, 30)
    target_iocs = await extract_iocs(target)
    if any(target_iocs.values()):
        score += 20
    score = min(score, 100)
    if score >= 70:
        severity = "Critical"
    elif score >= 50:
        severity = "High Risk"
    elif score >= 30:
        severity = "Elevated Risk"
    elif score >= 10:
        severity = "Low Risk"
    else:
        severity = "Informational"
    return {"score": score, "severity": severity, "feeds_with_data": feeds_with_data, "total_feeds": total_feeds, "total_iocs": total_iocs}

async def check_target_iocs_in_feeds(target: str, feed_results: list) -> list:
    matches = []
    target_lower = target.lower()
    for result in feed_results:
        if isinstance(result, dict):
            for ioc in result.get("iocs", []):
                if target_lower in ioc["value"].lower():
                    matches.append({"feed": result["name"], "ioc": ioc["value"], "type": ioc["type"]})
    return matches[:20]

async def fetch_additional_sources(client: httpx.AsyncClient) -> list:
    results = []
    for name, url in ADDITIONAL_FEEDS:
        try:
            resp = await client.get(url, timeout=20.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "text/plain,text/csv,application/json"})
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                ips_found = 0
                domains_found = 0
                for line in lines[:300]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if IOC_PATTERNS["ipv4"].match(line):
                            ips_found += 1
                        elif IOC_PATTERNS["domain"].match(line):
                            domains_found += 1
                results.append({"name": name, "url": url, "ips": ips_found, "domains": domains_found, "total_lines": len(lines)})
        except:
            pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    feed_results = await fetch_multiple_feeds(client, THREAT_FEEDS)

    for result in feed_results:
        if isinstance(result, dict) and result.get("iocs"):
            findings.append(IntelligenceFinding(
                entity=f"Feed: {result['name']} - {len(result['iocs'])} IOC(s)",
                type="Threat Feed Data",
                source=result['name'],
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="IOCs Available",
                resolution=query,
                raw_data=f"Source: {result['source_url']}",
                tags=["threat-feed", "ioc", result['name'].lower()]
            ))

    all_iocs = defaultdict(list)
    for result in feed_results:
        if isinstance(result, dict):
            for ioc in result.get("iocs", []):
                all_iocs[ioc["type"]].append(ioc["value"])

    for ioc_type, values in all_iocs.items():
        if values:
            unique_values = list(set(values))[:10]
            findings.append(IntelligenceFinding(
                entity=f"{len(set(values))} unique {ioc_type} IOCs collected from feeds",
                type=f"IOC Collection: {ioc_type.upper()}",
                source="ThreatIntel",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Collected",
                resolution=query,
                tags=["ioc", ioc_type, "collection"]
            ))

    target_iocs = await extract_iocs(query)
    for ioc_type, values in target_iocs.items():
        if values:
            findings.append(IntelligenceFinding(
                entity=f"Target contains {ioc_type}: {', '.join(values[:5])}",
                type=f"Target IOC: {ioc_type.upper()}",
                source="ThreatIntel",
                confidence="Low",
                color="orange",
                threat_level="Elevated Risk",
                status="Detected",
                resolution=query,
                tags=["target", "ioc", ioc_type]
            ))

    feed_stats = defaultdict(int)
    for result in feed_results:
        if isinstance(result, dict):
            source = result.get("name", "Unknown")
            feed_stats[source] = len(result.get("iocs", []))

    if feed_stats:
        top_feeds = sorted(feed_stats.items(), key=lambda x: -x[1])[:5]
        for feed, count in top_feeds:
            findings.append(IntelligenceFinding(
                entity=f"{feed}: {count} IOCs",
                type="Threat Feed Statistics",
                source="ThreatIntel",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                resolution=query,
                tags=["statistics", feed.lower()]
            ))

    additional = await fetch_additional_sources(client)
    for src in additional:
        findings.append(IntelligenceFinding(
            entity=f"Additional feed: {src['name']} - {src['ips']} IPs, {src['domains']} domains ({src['total_lines']} lines)",
            type="Additional Threat Feed",
            source=src['name'],
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            status="Fetched",
            resolution=query,
            raw_data=f"URL: {src['url']}",
            tags=["threat-feed", "additional", src['name'].lower().replace(" ", "-")]
        ))

    cidr_results = await check_cidr_reputation(query)
    for cidr_info in cidr_results:
        findings.append(IntelligenceFinding(
            entity=f"Target within {cidr_info['cidr']} ({cidr_info['description']})",
            type="CIDR Range Check",
            source="ThreatIntel",
            confidence="High",
            color="yellow",
            threat_level="Informational",
            status="Verified",
            resolution=query,
            tags=["cidr", cidr_info['description'].lower().replace(" ", "-")]
        ))

    threat_categories = await classify_threat_category(query)
    for cat in threat_categories:
        findings.append(IntelligenceFinding(
            entity=f"Threat category: {cat}",
            type="Threat Category Classification",
            source="ThreatIntel",
            confidence="Low",
            color="orange",
            threat_level="Elevated Risk",
            status="Classified",
            resolution=query,
            tags=["threat-category", cat]
        ))

    threat_score = await calculate_threat_score(feed_results, query)
    findings.append(IntelligenceFinding(
        entity=f"Threat Score: {threat_score['score']}/100 ({threat_score['severity']}) - {threat_score['feeds_with_data']}/{threat_score['total_feeds']} feeds reporting",
        type="Threat Score Assessment",
        source="ThreatIntel",
        confidence="Medium",
        color="red" if threat_score['score'] >= 50 else "orange",
        threat_level=threat_score['severity'],
        status=f"Score: {threat_score['score']}",
        resolution=query,
        raw_data=json.dumps(threat_score),
        tags=["threat-score", threat_score['severity'].lower().replace(" ", "-")]
    ))

    target_matches = await check_target_iocs_in_feeds(query, feed_results)
    if target_matches:
        for match in target_matches[:10]:
            findings.append(IntelligenceFinding(
                entity=f"Target matches IOC in {match['feed']}: {match['ioc']} ({match['type']})",
                type="Target IOC Match",
                source=match['feed'],
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Match Found",
                resolution=query,
                tags=["ioc-match", match['type']]
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No threat intelligence data collected",
            type="Threat Intel Complete",
            source="ThreatIntel",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["threat-intel", "clean"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Queried {len(THREAT_FEEDS) + len(ADDITIONAL_FEEDS)} threat feeds ({len(THREAT_FEEDS)} primary + {len(ADDITIONAL_FEEDS)} additional)",
        type="Threat Feed Coverage Summary",
        source="ThreatIntel",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["coverage", "summary"]
    ))

    return findings
