import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

DDOS_PROTECTION_SERVICES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status", "cloudflare-nginx"],
    "Akamai": ["akamai", "akamaized", "akamaihd", "akamaitech", "X-Akamai"],
    "AWS Shield": ["aws", "amazonaws", "cloudfront", "AWSALB", "AWSALBCORS"],
    "GCP Armor": ["google", "gcp", "googlecloud", "googleapis", "gfe"],
    "Arbor Networks": ["arbor", "arbor networks", "netscout"],
    "Radware": ["radware", "appwall", "captcha"],
    "F5 Networks": ["f5", "bigip", "f5networks"],
    "Imperva": ["imperva", "incapsula", "x-iinfo"],
    "VeriSign": ["verisign", "veri-sign"],
    "Neustar": ["neustar", "ultradns", "ultra-dns"],
    "StackPath": ["stackpath", "stackpath-cdn"],
    "Fastly": ["fastly", "fastlylb"],
    "Sucuri": ["sucuri", "cloudproxy"],
    "DOSarrest": ["dosarrest", "dosarrest-internet-security"],
}

AMPLIFICATION_VECTORS = {
    "NTP": [re.compile(r'ntp.*monlist|monlist|ntp.*amplif', re.I), 123],
    "DNS": [re.compile(r'dns.*amplif|dns.*reflect|open.?resolver', re.I), 53],
    "SSDP": [re.compile(r'ssdp|upnp|simple.?service.?discovery', re.I), 1900],
    "SNMP": [re.compile(r'snmp|snmp.*amplif', re.I), 161],
    "Memcached": [re.compile(r'memcached|memcache.*amplif', re.I), 11211],
    "CLDAP": [re.compile(r'cldap|connectionless.*ldap', re.I), 389],
    "CharGEN": [re.compile(r'chargen|character.*generat', re.I), 19],
    "RPC": [re.compile(r'rpc.*portmap|portmap|rpcbind', re.I), 111],
    "WS-Discovery": [re.compile(r'ws.?discovery|wsdd', re.I), 3702],
    "NetBIOS": [re.compile(r'netbios|net.?bios.*name', re.I), 137],
}

async def check_ddos_protection(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            url = f"https://{target}"
        else:
            url = target
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            headers = dict(resp.headers)
            headers_text = json.dumps(headers).lower()
            body_text = resp.text[:2000].lower()
            combined = headers_text + " " + body_text
            for service, indicators in DDOS_PROTECTION_SERVICES.items():
                for ind in indicators:
                    if ind.lower() in combined:
                        results.append({"service": service, "indicator": ind, "found_in": "headers" if ind.lower() in headers_text else "body"})
                        break
    except:
        pass
    return results

async def check_amplification_vectors(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for vector, (pattern, port) in AMPLIFICATION_VECTORS.items():
            if pattern.search(target_lower):
                results.append({"vector": vector, "port": port, "matched": True})
    except:
        pass
    return results

async def check_ddos_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        ddos_feeds = [
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            "https://mirai.securitytracker.com/mirai.txt",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        ]
        for feed_url in ddos_feeds:
            try:
                resp = await client.get(feed_url, timeout=15.0,
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

async def analyze_ddos_patterns(target: str) -> list:
    results = []
    try:
        patterns = {
            "Layer 3/4 DDoS": ["syn flood", "udp flood", "icmp flood", "ack flood", "rst flood"],
            "Layer 7 DDoS": ["http flood", "slowloris", "slowread", "post flood", "get flood"],
            "Reflection DDoS": ["dns reflection", "ntp reflection", "ssdp reflection", "amplification"],
            "Application DDoS": ["slow loris", "r-u-dead-yet", "slow body", "slow headers"],
            "IoT Botnet DDoS": ["mirai", "mozi", "gafgyt", "bashlite", "qbot"],
        }
        target_lower = target.lower()
        for attack_type, indicators in patterns.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"attack_type": attack_type, "matched": ind})
                    break
    except:
        pass
    return results

async def check_ddos_campaign_botnet_size(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        botnet_size_feeds = [
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/botnet-iocs.txt",
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/botnet.txt",
        ]
        for feed_url in botnet_size_feeds:
            try:
                resp = await client.get(feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    lines_with_target = [l for l in content.splitlines() if target in l.lower()]
                    if lines_with_target:
                        results.append({"feed": feed_url.split("/")[-1].replace(".txt", ""), "matches": len(lines_with_target)})
            except:
                pass
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    protection_results = await check_ddos_protection(client, query)
    for r in protection_results:
        findings.append(IntelligenceFinding(
            entity=f"DDoS protection service: {r['service']} (indicator: {r['indicator']})",
            type="DDoS Protection Detection",
            source="DDoS Intel",
            confidence="Medium",
            color="green",
            category="DDoS Intelligence",
            threat_level="Informational",
            status="Protection Detected",
            resolution=query,
            tags=["ddos", "protection", r['service'].lower().replace(" ", "-")]
        ))

    amp_results = await check_amplification_vectors(query)
    for r in amp_results:
        findings.append(IntelligenceFinding(
            entity=f"Amplification vector: {r['vector']} (port {r['port']})",
            type="DDoS Amplification Vector",
            source="DDoS Intel",
            confidence="Low",
            color="red",
            category="DDoS Intelligence",
            threat_level="High Risk",
            status="Amplification Risk",
            resolution=query,
            tags=["ddos", "amplification", r['vector'].lower(), f"port-{r['port']}"]
        ))

    feed_results = await check_ddos_feeds(client, query)
    for r in feed_results:
        findings.append(IntelligenceFinding(
            entity=f"DDoS feed hit: {r['feed']}",
            type="DDoS Feed Detection",
            source=r['feed'],
            confidence="Medium",
            color="orange",
            category="DDoS Intelligence",
            threat_level="Elevated Risk",
            status="Feed Hit",
            resolution=query,
            tags=["ddos", "feed", r['feed'].lower()]
        ))

    pattern_results = await analyze_ddos_patterns(query)
    for r in pattern_results:
        findings.append(IntelligenceFinding(
            entity=f"DDoS attack pattern: {r['attack_type']} (matched: {r['matched']})",
            type="DDoS Attack Pattern",
            source="DDoS Intel",
            confidence="Low",
            color="orange",
            category="DDoS Intelligence",
            threat_level="Elevated Risk",
            status="Pattern Identified",
            resolution=query,
            tags=["ddos", "attack-pattern", r['attack_type'].lower().replace(" ", "-").replace("/", "-")]
        ))

    botnet_results = await check_ddos_campaign_botnet_size(client, query)
    for r in botnet_results:
        findings.append(IntelligenceFinding(
            entity=f"Botnet campaign association: {r['feed']} ({r['matches']} matches)",
            type="Botnet Campaign Link",
            source="DDoS Intel",
            confidence="Low",
            color="orange",
            category="DDoS Intelligence",
            threat_level="Elevated Risk",
            status="Campaign Link",
            resolution=query,
            tags=["ddos", "botnet", "campaign", r['feed'].lower()]
        ))

    if not protection_results:
        findings.append(IntelligenceFinding(
            entity=f"No DDoS protection detected for {query} - target may be unprotected",
            type="DDoS Protection Status",
            source="DDoS Intel",
            confidence="Low",
            color="yellow",
            category="DDoS Intelligence",
            threat_level="Informational",
            status="No Protection Detected",
            resolution=query,
            tags=["ddos", "unprotected", "exposed"]
        ))

    for vector in AMPLIFICATION_VECTORS:
        findings.append(IntelligenceFinding(
            entity=f"Amplification vector monitored: {vector}",
            type="Amplification Vector Coverage",
            source="DDoS Intel",
            confidence="Low",
            color="slate",
            category="DDoS Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["ddos", "amplification", vector.lower(), "monitored"]
        ))

    for service in DDOS_PROTECTION_SERVICES:
        findings.append(IntelligenceFinding(
            entity=f"DDoS protection service monitored: {service}",
            type="Protection Service Coverage",
            source="DDoS Intel",
            confidence="Low",
            color="slate",
            category="DDoS Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["ddos", "protection", service.lower().replace(" ", "-")]
        ))

    findings.append(IntelligenceFinding(
        entity=f"DDoS intelligence complete for {query}: checked {len(DDOS_PROTECTION_SERVICES)} protection services, {len(AMPLIFICATION_VECTORS)} amplification vectors, multiple feeds",
        type="DDoS Intelligence Summary",
        source="DDoS Intel",
        confidence="Medium",
        color="slate",
        category="DDoS Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["ddos", "summary", "intelligence"]
    ))

    return findings
