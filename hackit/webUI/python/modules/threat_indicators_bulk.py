import re
import json
import ipaddress
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

IOC_PATTERNS = {
    "ipv4": re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    "ipv6": re.compile(r'^[0-9a-fA-F:]+$'),
    "md5": re.compile(r'^[a-f0-9]{32}$'),
    "sha1": re.compile(r'^[a-f0-9]{40}$'),
    "sha256": re.compile(r'^[a-f0-9]{64}$'),
    "domain": re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'),
    "url": re.compile(r'^https?://'),
    "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
}

IOC_FEEDS = [
    ("AbuseIPDB", "https://abuseipdb.com/check/{}/json"),
    ("VirusTotal", "https://www.virustotal.com/api/v3/ip_addresses/{}"),
    ("AlienVault OTX", "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"),
    ("ThreatCrowd", "https://threatcrowd.org/searchApi/v2/ip/report/?ip={}"),
    ("CIRCL", "https://www.circl.lu/doc/misp/feed-osint"),
    ("URLScan", "https://urlscan.io/api/v1/search/?q={}"),
    ("ThreatFox", "https://threatfox.abuse.ch/api/v1/"),
    ("IBM X-Force", "https://api.xforce.ibmcloud.com/ipr/{}"),
]

DETECTION_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.dshield.org/block.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://malc0de.com/bl/IP_Blacklist.txt",
    "https://www.binarydefense.com/banlist.txt",
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
    "https://blocklist.greensnow.co/greensnow.txt",
    "https://www.darklist.de/raw.php",
    "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
    "https://check.torproject.org/torbulkexitlist",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://openphish.com/feed.txt",
]

async def classify_ioc_type(target: str) -> list:
    results = []
    try:
        for ioc_type, pattern in IOC_PATTERNS.items():
            if pattern.match(target.strip()):
                results.append({"type": ioc_type, "target": target})
                break
        if not results:
            results.append({"type": "unknown", "target": target})
    except:
        pass
    return results

async def check_abuseipdb(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,
            f"https://www.abuseipdb.com/check/{target}/json",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                results.append({
                    "source": "AbuseIPDB",
                    "confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt", ""),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                })
        else:
            results.append({"source": "AbuseIPDB", "status": resp.status_code, "note": "Rate limited or unavailable"})
    except:
        pass
    return results

async def check_detection_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for feed_url in DETECTION_FEEDS:
            try:
                resp = await safe_fetch(client,feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        feed_name = feed_url.split("/")[2] if "//" in feed_url else feed_url
                        results.append({"feed": feed_name, "url": feed_url, "detected": True})
            except:
                pass
    except:
        pass
    return results

async def check_alienvault_otx(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "source": "AlienVault OTX",
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": data.get("pulse_info", {}).get("pulses", [])[:3],
            })
    except:
        pass
    return results

async def calculate_malicious_probability(feed_hits: list, abuseipdb_data: list, total_feeds: int) -> dict:
    try:
        feed_detection_count = len(feed_hits)
        abuse_score = 0
        for r in abuseipdb_data:
            if isinstance(r, dict) and "confidence" in r:
                abuse_score = r.get("confidence", 0)
        base_score = (feed_detection_count / max(total_feeds, 1)) * 50
        abuse_weight = abuse_score * 0.5
        probability = min(base_score + abuse_weight, 100)
        if probability >= 70:
            severity = "Malicious"
        elif probability >= 40:
            severity = "Suspicious"
        elif probability >= 10:
            severity = "Low Risk"
        else:
            severity = "Benign"
        return {
            "probability": round(probability, 1),
            "severity": severity,
            "feeds_detected": feed_detection_count,
            "total_feeds_checked": total_feeds,
            "abuseipdb_confidence": abuse_score,
        }
    except:
        return {"probability": 0, "severity": "Unknown", "feeds_detected": 0, "total_feeds_checked": 0, "abuseipdb_confidence": 0}

async def check_threatcrowd(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,
            f"https://threatcrowd.org/searchApi/v2/ip/report/?ip={target}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("response_code") == "1":
                results.append({
                    "source": "ThreatCrowd",
                    "resolutions": data.get("resolutions", [])[:5],
                    "hashes": data.get("hashes", [])[:5],
                    "references": data.get("references", [])[:5],
                    "votes": data.get("votes", 0),
                })
    except:
        pass
    return results

async def build_ioc_timeline(feed_hits: list, abuseipdb_data: list) -> list:
    timeline = []
    try:
        for r in abuseipdb_data:
            if isinstance(r, dict) and "last_reported" in r:
                timeline.append({"source": "AbuseIPDB", "date": r.get("last_reported", "N/A")})
        for r in feed_hits:
            timeline.append({"source": r.get("feed", "Unknown"), "date": "Active"})
    except:
        pass
    return timeline

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    ioc_type_results = await classify_ioc_type(query)
    for r in ioc_type_results:
        findings.append(make_finding(
            entity=f"IoC type classified: {r['type']} for target {r['target']}",
            ftype="IoC Type Classification",
            source="Bulk IoC Analyzer",
            confidence="High",
            color="slate",
            category="Indicator Analysis",
            threat_level="Informational",
            status="Classified",
            resolution=query,
            tags=["ioc", r['type'], "classification"]
        ))

    abuseipdb_results = await check_abuseipdb(client, query)
    for r in abuseipdb_results:
        findings.append(make_finding(
            entity=f"AbuseIPDB: {r.get('confidence', 0)}% confidence, {r.get('total_reports', 0)} reports, ISP: {r.get('isp', 'N/A')}",
            ftype="IP Reputation Check",
            source="AbuseIPDB",
            confidence="High" if r.get("confidence", 0) > 50 else "Medium",
            color="red" if r.get("confidence", 0) > 50 else "yellow",
            category="Indicator Analysis",
            threat_level="High Risk" if r.get("confidence", 0) > 50 else "Elevated Risk",
            status=f"Confidence: {r.get('confidence', 0)}%",
            resolution=query,
            raw_data=json.dumps(r),
            tags=["abuseipdb", "reputation", f"confidence-{r.get('confidence', 0)}"]
        ))

    feed_hits = await check_detection_feeds(client, query)
    for r in feed_hits:
        findings.append(make_finding(
            entity=f"Detection feed hit: {r['feed']}",
            ftype="Bulk Feed Detection",
            source=r['feed'],
            confidence="Medium",
            color="orange",
            category="Indicator Analysis",
            threat_level="Elevated Risk",
            status="Feed Hit",
            resolution=query,
            tags=["detection", "feed", r['feed'].lower().split(".")[0] if "." in r['feed'] else r['feed'].lower()]
        ))

    otx_results = await check_alienvault_otx(client, query)
    for r in otx_results:
        findings.append(make_finding(
            entity=f"AlienVault OTX: {r.get('pulse_count', 0)} pulses related to target",
            ftype="OTX Pulse Check",
            source="AlienVault OTX",
            confidence="Medium",
            color="orange",
            category="Indicator Analysis",
            threat_level="Elevated Risk",
            status=f"{r.get('pulse_count', 0)} Pulses",
            resolution=query,
            tags=["alienvault", "otx", "pulse"]
        ))

    threatcrowd_results = await check_threatcrowd(client, query)
    for r in threatcrowd_results:
        findings.append(make_finding(
            entity=f"ThreatCrowd: {len(r.get('resolutions', []))} resolutions, {len(r.get('hashes', []))} hashes, {r.get('votes', 0)} votes",
            ftype="ThreatCrowd Check",
            source="ThreatCrowd",
            confidence="Medium",
            color="orange",
            category="Indicator Analysis",
            threat_level="Elevated Risk",
            status="Data Available",
            resolution=query,
            tags=["threatcrowd", "community", "votes"]
        ))

    risk_score = await calculate_malicious_probability(feed_hits, abuseipdb_results, len(DETECTION_FEEDS))
    findings.append(make_finding(
        entity=f"Malicious probability score: {risk_score['probability']}/100 ({risk_score['severity']}) - {risk_score['feeds_detected']}/{risk_score['total_feeds_checked']} feeds",
        ftype="Malicious Probability Score",
        source="Bulk IoC Analyzer",
        confidence="Medium",
        color="red" if risk_score['probability'] >= 50 else "yellow",
        category="Indicator Analysis",
        threat_level=risk_score['severity'],
        status=f"Score: {risk_score['probability']}",
        resolution=query,
        raw_data=json.dumps(risk_score),
        tags=["risk-score", risk_score['severity'].lower().replace(" ", "-"), "probability"]
    ))

    timeline = await build_ioc_timeline(feed_hits, abuseipdb_results)
    for t in timeline:
        findings.append(make_finding(
            entity=f"IoC timeline: {t['source']} - last seen: {t['date']}",
            ftype="IoC Timeline",
            source="Bulk IoC Analyzer",
            confidence="Low",
            color="slate",
            category="Indicator Analysis",
            threat_level="Informational",
            status="Timeline Entry",
            resolution=query,
            tags=["timeline", "ioc", t['source'].lower().replace(" ", "-")]
        ))

    for ioc_type in IOC_PATTERNS.keys():
        findings.append(make_finding(
            entity=f"IoC type monitored: {ioc_type}",
            ftype="IoC Type Coverage",
            source="Bulk IoC Analyzer",
            confidence="Low",
            color="slate",
            category="Indicator Analysis",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["ioc", "coverage", ioc_type]
        ))

    findings.append(make_finding(
        entity=f"Bulk IoC analysis complete for {query}: checked {len(DETECTION_FEEDS)} feeds, {len(IOC_PATTERNS)} types, multiple sources",
        ftype="Bulk IoC Analysis Summary",
        source="Bulk IoC Analyzer",
        confidence="Medium",
        color="slate",
        category="Indicator Analysis",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["bulk", "ioc", "summary", "analysis"]
    ))

    return findings
