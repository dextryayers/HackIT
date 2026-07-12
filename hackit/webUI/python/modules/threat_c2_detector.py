import re
import json
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

C2_FEEDS = [
    "https://threatfox.abuse.ch/export/json/ip/",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://cybercrime-tracker.net/all.php",
    "https://malc0de.com/bl/IP_Blacklist.txt",
    "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt",
    "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/indicators/c2.txt",
    "https://raw.githubusercontent.com/pan0pt1c0n/Malicious-IOCs/main/c2_domains.txt",
]

C2_PORTS = [80, 443, 4444, 8080, 8443, 447, 6655, 7001, 8081, 8333,
            1234, 1337, 31337, 3389, 5900, 5800, 6969, 5555, 6666, 7777,
            10050, 50050, 4443, 9443, 10443, 7070, 8070, 9090, 9898, 11223]

C2_FRAMEWORKS = {
    "CobaltStrike": ["cobalt", "cs_", "malleable", "aggressor", "4143", "50050", "beacon"],
    "Empire": ["empire", "powershell_empire", "starkiller", "http_listener"],
    "Metasploit": ["metasploit", "msf", "meterpreter", "reverse_tcp", "payload"],
    "Sliver": ["sliver", "sliver_client", "sliver_server", "implant"],
    "Brute Ratel": ["bruteratel", "badger", "c4", "brute_ratel"],
    "Covenant": ["covenant", "covenant_c2", "grunt", "elite"],
    "PoshC2": ["poshc2", "posh", "powershell_c2", "implant_handler"],
    "Mythic": ["mythic", "mythic_c2", "poseidon", "apollo", "athena"],
    "Havoc": ["havoc", "havoc_c2", "demon", "teamserver"],
    "Villain": ["villain", "villain_c2", "evil_lnk"],
    "NimPlant": ["nimplant", "nim_c2"],
    "DeimosC2": ["deimos", "deimos_c2"],
    "Merlin": ["merlin_c2", "merlin_agent"],
    "TrevorC2": ["trevor", "trevor_c2"],
}

DGA_PATTERNS = [
    re.compile(r'^[a-z]{10,25}\.(com|net|org|xyz|top|club|info|site)$'),
    re.compile(r'^[a-z]{2,6}[0-9]{2,6}[a-z]{2,6}\.(com|net|org)$'),
    re.compile(r'^[a-z0-9]{8,}\.(xyz|top|club|work|life|live|online)$'),
    re.compile(r'^\d{6,}[a-z]{2,}\.(com|net|org)$'),
    re.compile(r'^[b-df-hj-np-tv-z]{8,}\.(com|net|org|xyz)$'),
]

C2_PATH_PATTERNS = [
    "/admin", "/gate", "/api/auth", "/beacon", "/checkin", "/task",
    "/result", "/submit", "/c2", "/command", "/manage", "/panel",
    "/server", "/agent", "/client", "/heartbeat", "/poll", "/pwn",
    "/shell", "/exec", "/cmd", "/upload", "/download", "/proxy",
    "/login/process", "/auth/check", "/api/agent", "/api/task",
    "/modules", "/listener", "/stager", "/payload", "/inject",
]

async def check_threatfox(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,
            f"https://threatfox.abuse.ch/api/v1/",
            params={"query": "search_ioc", "search_term": target},
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                for ioc_data in data.get("data", []):
                    results.append({
                        "ioc": ioc_data.get("ioc", ""),
                        "malware": ioc_data.get("malware_printable", "Unknown"),
                        "malware_alias": ioc_data.get("malware_alias", ""),
                        "threat_type": ioc_data.get("threat_type_desc", ""),
                        "first_seen": ioc_data.get("first_seen", ""),
                        "confidence_level": ioc_data.get("confidence_level", 0),
                    })
    except:
        pass
    return results

async def check_feodo_tracker(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "source": "Feodo Tracker"})
    except:
        pass
    return results

async def check_ssl_blacklist(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and target in line:
                    results.append({"ip": line, "source": "SSL Blacklist"})
    except:
        pass
    return results

async def check_cybercrime_tracker(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://cybercrime-tracker.net/all.php", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            if target in resp.text:
                results.append({"source": "Cybercrime Tracker", "found": True})
    except:
        pass
    return results

async def check_dga_patterns(target: str) -> list:
    results = []
    try:
        domain = target.lower()
        for pattern in DGA_PATTERNS:
            if pattern.match(domain):
                results.append({
                    "pattern": pattern.pattern[:50],
                    "domain": domain,
                    "description": "Domain matches DGA-like pattern"
                })
    except:
        pass
    return results

async def check_c2_framework_indicators(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for framework, indicators in C2_FRAMEWORKS.items():
            matched = []
            for ind in indicators:
                if ind in target_lower:
                    matched.append(ind)
            if matched:
                results.append({
                    "framework": framework,
                    "matched_indicators": matched,
                    "confidence": "High" if len(matched) >= 2 else "Medium"
                })
    except:
        pass
    return results

async def check_c2_ports(target: str) -> list:
    results = []
    try:
        if ":" in target:
            port_part = target.split(":")[-1]
            if port_part.isdigit():
                port = int(port_part)
                if port in C2_PORTS:
                    results.append({
                        "port": port,
                        "description": f"Known C2 port {port} detected"
                    })
    except:
        pass
    return results

async def check_c2_paths(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            base = f"https://{target}"
        else:
            base = target
        for path in C2_PATH_PATTERNS[:10]:
            try:
                url = f"{base}{path}"
                resp = await safe_fetch(client,url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code in [200, 201, 202, 204]:
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "url": url
                    })
            except:
                pass
    except:
        pass
    return results

async def analyze_ssl_certificate(target: str) -> list:
    results = []
    try:
        hostname = target.split(":")[0].split("/")[0]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((hostname, 443), timeout=5)
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            if cert:
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                is_self_signed = issuer.get("organizationName") == subject.get("organizationName") if issuer.get("organizationName") else False
                is_expired = False
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        is_expired = expiry < datetime.now()
                    except:
                        pass
                results.append({
                    "issuer": issuer,
                    "subject": subject,
                    "self_signed": is_self_signed,
                    "expired": is_expired,
                    "not_before": not_before,
                    "not_after": not_after
                })
    except:
        pass
    return results

async def check_c2_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for feed_url in C2_FEEDS:
            try:
                resp = await safe_fetch(client,feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    feed_name = feed_url.split("/")[2] if "//" in feed_url else feed_url
                    content = resp.text
                    if target in content:
                        results.append({
                            "feed": feed_name,
                            "url": feed_url,
                            "found": True
                        })
            except:
                pass
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    threatfox_results = await check_threatfox(client, query)
    for r in threatfox_results:
        findings.append(make_finding(
            entity=f"ThreatFox C2 IOC: {r['ioc']} ({r['malware']})",
            ftype="C2 IOC Detection",
            source="ThreatFox",
            confidence="High" if r.get("confidence_level", 0) > 50 else "Medium",
            color="red",
            category="Threat Intelligence",
            threat_level="Critical",
            status="Active C2",
            resolution=query,
            raw_data=json.dumps(r),
            tags=["c2", "command-control", r['malware'].lower().replace(" ", "-"), "threatfox"]
        ))

    feodo_results = await check_feodo_tracker(client, query)
    for r in feodo_results:
        findings.append(make_finding(
            entity=f"Feodo Tracker: {r['ip']} listed as C2 server",
            ftype="C2 IP Blocklist",
            source="Feodo Tracker",
            confidence="High",
            color="red",
            category="Threat Intelligence",
            threat_level="Critical",
            status="Blacklisted",
            resolution=query,
            tags=["c2", "feodo", "dridex", "emotet"]
        ))

    ssl_blacklist_results = await check_ssl_blacklist(client, query)
    for r in ssl_blacklist_results:
        findings.append(make_finding(
            entity=f"SSL Blacklist: {r['ip']} associated with malicious SSL",
            ftype="SSL C2 Detection",
            source="SSL Blacklist (abuse.ch)",
            confidence="High",
            color="red",
            category="Threat Intelligence",
            threat_level="Critical",
            status="Blacklisted",
            resolution=query,
            tags=["c2", "ssl-blacklist", "malicious-ssl"]
        ))

    cybercrime_results = await check_cybercrime_tracker(client, query)
    for r in cybercrime_results:
        findings.append(make_finding(
            entity=f"Cybercrime Tracker: target found in C2 database",
            ftype="Cybercrime C2 Detection",
            source="Cybercrime Tracker",
            confidence="Medium",
            color="red",
            category="Threat Intelligence",
            threat_level="High Risk",
            status="Listed",
            resolution=query,
            tags=["c2", "cybercrime", "tracker"]
        ))

    dga_results = await check_dga_patterns(query)
    for r in dga_results:
        findings.append(make_finding(
            entity=f"DGA Pattern Detected: {r['domain']} matches {r['description']}",
            ftype="DGA Domain Detection",
            source="C2 Detector",
            confidence="Medium",
            color="yellow",
            category="Threat Intelligence",
            threat_level="Elevated Risk",
            status="DGA Flagged",
            resolution=query,
            tags=["dga", "domain-generation", "algorithm"]
        ))

    framework_results = await check_c2_framework_indicators(query)
    for r in framework_results:
        findings.append(make_finding(
            entity=f"C2 Framework: {r['framework']} indicators detected ({', '.join(r['matched_indicators'])})",
            ftype="C2 Framework Identification",
            source="C2 Detector",
            confidence=r['confidence'],
            color="orange",
            category="Threat Intelligence",
            threat_level="High Risk",
            status="Framework Identified",
            resolution=query,
            tags=["c2-framework", r['framework'].lower().replace(" ", "-")]
        ))

    port_results = await check_c2_ports(query)
    for r in port_results:
        findings.append(make_finding(
            entity=f"C2 Port Detected: {r['port']} - {r['description']}",
            ftype="C2 Port Detection",
            source="C2 Detector",
            confidence="Medium",
            color="yellow",
            category="Threat Intelligence",
            threat_level="Elevated Risk",
            status="Suspicious Port",
            resolution=query,
            tags=["c2-port", f"port-{r['port']}"]
        ))

    ssl_results = await analyze_ssl_certificate(query)
    for r in ssl_results:
        if r.get("self_signed"):
            findings.append(make_finding(
                entity=f"Self-signed SSL certificate detected for {query}",
                ftype="Suspicious SSL Certificate",
                source="C2 Detector",
                confidence="Medium",
                color="yellow",
                category="Threat Intelligence",
                threat_level="Elevated Risk",
                status="Self-Signed Cert",
                resolution=query,
                raw_data=json.dumps(r),
                tags=["ssl", "self-signed", "suspicious-cert"]
            ))
        if r.get("expired"):
            findings.append(make_finding(
                entity=f"Expired SSL certificate for {query} (not_after: {r.get('not_after', 'N/A')})",
                ftype="Expired SSL Certificate",
                source="C2 Detector",
                confidence="Medium",
                color="orange",
                category="Threat Intelligence",
                threat_level="Elevated Risk",
                status="Expired",
                resolution=query,
                tags=["ssl", "expired-cert"]
            ))

    c2_feed_results = await check_c2_feeds(client, query)
    for r in c2_feed_results:
        findings.append(make_finding(
            entity=f"Target found in C2 feed: {r['feed']}",
            ftype="C2 Feed Match",
            source=r['feed'],
            confidence="High",
            color="red",
            category="Threat Intelligence",
            threat_level="Critical",
            status="Feed Match",
            resolution=query,
            tags=["c2-feed", "blacklist", r['feed'].lower().split(".")[0]]
        ))

    path_results = await check_c2_paths(client, query)
    for r in path_results:
        findings.append(make_finding(
            entity=f"Suspicious C2 path responds: {r['url']} (HTTP {r['status']}, {r['length']} bytes)",
            ftype="C2 Path Discovery",
            source="C2 Detector",
            confidence="Low",
            color="orange",
            category="Threat Intelligence",
            threat_level="Elevated Risk",
            status="Path Responding",
            resolution=query,
            tags=["c2-path", "suspicious-endpoint"]
        ))

    findings.append(make_finding(
        entity=f"C2 detection complete for {query}: checked ThreatFox, Feodo, SSL Blacklist, {len(C2_FRAMEWORKS)} frameworks, {len(C2_PORTS)} ports, {len(C2_PATH_PATTERNS)} paths",
        ftype="C2 Detection Summary",
        source="C2 Detector",
        confidence="Medium",
        color="slate",
        category="Threat Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["c2", "summary", "detection"]
    ))

    return findings
