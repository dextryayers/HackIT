import httpx
import asyncio
import json
import re
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
}

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
        entity=f"Queried {len(THREAT_FEEDS)} threat feeds",
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
