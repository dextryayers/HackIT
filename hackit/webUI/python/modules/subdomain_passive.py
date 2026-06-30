import httpx
from models import IntelligenceFinding
import re
import asyncio
import socket
from collections import defaultdict

SOURCE_RELIABILITY = {
    "crt.sh": 0.95,
    "HackerTarget": 0.90,
    "BufferOver": 0.85,
    "RapidDNS": 0.80,
    "AlienVault OTX": 0.85,
    "ThreatCrowd": 0.70,
    "Anubis": 0.75,
    "URLScan.io": 0.80,
    "Riddler": 0.65,
    "Sonar Omnisint": 0.85,
    "Wayback Machine": 0.75,
    "Shodan": 0.90,
    "Censys": 0.90,
    "FOFA": 0.80,
    "ZoomEye": 0.75,
    "BinaryEdge": 0.80,
    "Netlas": 0.75,
    "FullHunt": 0.70,
    "LeakIX": 0.65,
    "IntelX": 0.70,
    "ONYPHE": 0.75,
}

SUBDOMAIN_CLASSIFIER = {
    r"\b(admin|administrator)\b": "Administrative",
    r"\b(api|rest|graphql|endpoint|service|grpc|soap)\b": "API",
    r"\b(dev|develop|staging|stage|test|testing|qa|uat|integration|canary)\b": "Development",
    r"\b(mail|email|webmail|smtp|imap|pop3|exchange|outlook|zimbra|roundcube)\b": "Email",
    r"\b(cdn|static|assets|media|img|css|js|fonts|images|upload|download)\b": "CDN/Static Assets",
    r"\b(blog|news|press|media|article)\b": "Blog/Content",
    r"\b(shop|store|cart|checkout|payment|billing|order|shopping)\b": "E-Commerce",
    r"\b(forum|community|chat|support|helpdesk|help|ticket|discuss)\b": "Community/Support",
    r"\b(login|signin|signup|register|auth|oauth|sso|saml|openid|oidc)\b": "Authentication",
    r"\b(monitor|status|health|uptime|alerts|logs|metrics|grafana|prometheus)\b": "Monitoring",
    r"\b(vpn|remote|access|gateway|tunnel|proxy|rdp|ssh)\b": "Remote Access/VPN",
    r"\b(files|docs|document|wiki|kb|knowledgebase|confluence)\b": "Documentation",
    r"\b(jobs|careers|apply|recruit|hr|employment)\b": "HR/Jobs",
    r"\b(partner|affiliate|reseller|vendor|distributor|channel)\b": "Partners",
    r"\b(m|mobile|app|ios|android|play|itunes|mobileapp)\b": "Mobile",
    r"\b(sftp|ftp|ftps|ssh|scp|rsync|webdav)\b": "File Transfer",
    r"\b(git|svn|hg|repo|repository|code|jenkins|ci|cd|build|jira|confluence)\b": "Development/CI-CD",
    r"\b(backup|backup|recovery|disaster|dr|failover|replica)\b": "Backup/DR",
    r"\b(podcast|radio|stream|video|tv|media|live)\b": "Media Streaming",
    r"\b(java|tomcat|jboss|jetty|wildfly|websphere|weblogic)\b": "Java Application Server",
    r"\b(php|phpmyadmin|phpadmin|phpinfo)\b": "PHP Admin",
    r"\b(db|database|mysql|postgres|mongo|redis|elastic|sql|oracle|mariadb)\b": "Database",
    r"\b(docker|k8s|kubernetes|cluster|node|pod|container)\b": "Container/Orchestration",
    r"\b(ws|wss|websocket|socket|mqtt|amqp)\b": "WebSocket/Messaging",
    r"\b(stats|statistics|analytics|piwik|matomo|ga|google-analytics)\b": "Analytics",
    r"\b(preprod|pre-production|preprod|sandbox|demo|trial)\b": "Sandbox/Demo",
    r"\b(proxy|forward|reverse)\b": "Proxy",
    r"\b(ldap|ad|active-directory|directory|dc|domain-controller)\b": "Directory Services",
    r"\b(ns|dns|dns1|dns2|ns1|ns2|ns3|ns4|authoritative)\b": "DNS/Nameserver",
    r"\b(ntp|time|clock|chrony)\b": "NTP/Time",
    r"\b(sip|voip|phone|call|telephony|asterisk|freeswitch)\b": "VoIP/Telephony",
    r"\b(vcenter|vmware|vsphere|esxi|vcloud|virtual)\b": "Virtualization",
    r"\b(nexus|artifactory|docker-registry|registry|repository)\b": "Artifact Repository",
    r"\b(webcam|camera|cctv|security-camera|surveillance)\b": "Surveillance",
    r"\b(iot|sensor|device|embedded|firmware)\b": "IoT/Devices",
    r"\b(dashboard|panel|control)\b": "Control Panel",
    r"\b(localhost|local|loopback)\b": "Internal/Test",
}


async def _resolve_dns(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


async def _http_probe(subdomain: str, client: httpx.AsyncClient) -> dict:
    result = {"status": None, "title": "", "server": "", "ip": None, "location": ""}
    ip = await _resolve_dns(subdomain)
    result["ip"] = ip
    if not ip:
        return result
    for proto in ["https", "http"]:
        try:
            resp = await client.get(
                f"{proto}://{subdomain}", timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                follow_redirects=False
            )
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("server", "")
            result["location"] = resp.headers.get("location", "")
            m = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:5000], re.DOTALL | re.IGNORECASE)
            if m:
                result["title"] = m.group(1).strip()[:100]
            break
        except:
            continue
    return result


def _classify_subdomain(sub: str) -> str:
    sub_lower = sub.split(".")[0].lower()
    for pattern, category in SUBDOMAIN_CLASSIFIER.items():
        if re.search(pattern, sub_lower):
            return category
    return "General/Uncategorized"


async def crawl(target, client):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    seen = set()
    seen_ips = set()
    ip_clusters = defaultdict(list)
    source_counts = defaultdict(int)
    source_reliability_total = 0
    source_reliability_count = 0

    async def from_crtsh():
        nonlocal source_reliability_total, source_reliability_count
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = await client.get(url, timeout=20.0)
            if resp.status_code == 200:
                data = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if (sub.endswith("." + domain) or sub == domain) and "*" not in sub:
                            if sub not in seen:
                                seen.add(sub)
                                source_counts["crt.sh"] += 1
                                findings.append(IntelligenceFinding(
                                    entity=sub, type="Subdomain (Passive)", source="crt.sh",
                                    confidence="High", color="emerald",
                                    category="Domain & DNS Enumeration",
                                    threat_level="Standard Target", status="Existing",
                                    raw_data="Found in Certificate Transparency Logs"
                                ))
                                source_reliability_total += SOURCE_RELIABILITY.get("crt.sh", 0.8)
                                source_reliability_count += 1
        except:
            pass

    async def from_hackertarget():
        nonlocal source_reliability_total, source_reliability_count
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = await client.get(url, timeout=15.0)
            if resp.status_code == 200:
                for line in resp.text.split("\n"):
                    if "," in line:
                        sub, ip = line.split(",")
                        sub = sub.strip().lower()
                        if sub not in seen:
                            seen.add(sub)
                            source_counts["HackerTarget"] += 1
                            findings.append(IntelligenceFinding(
                                entity=sub, type="Subdomain (Passive)", source="HackerTarget",
                                confidence="High", color="emerald",
                                category="Domain & DNS Enumeration",
                                threat_level="Standard Target", status="Existing",
                                resolution=ip,
                                raw_data=f"Resolved to {ip} via passive DNS"
                            ))
                            source_reliability_total += SOURCE_RELIABILITY.get("HackerTarget", 0.8)
                            source_reliability_count += 1
        except:
            pass

    async def from_bufferover():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://dns.bufferover.run/dns?q=.{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry_type in ["FDNS_A", "RDNS"]:
                    for entry in data.get(entry_type, []):
                        if isinstance(entry, str) and ',' in entry:
                            parts = entry.split(',')
                            sub = parts[1].strip().lower() if len(parts) >= 2 else ""
                            ip_part = parts[0].strip() if len(parts) >= 2 else ""
                            if sub.endswith("." + domain) and sub not in seen:
                                seen.add(sub)
                                source_counts["BufferOver"] += 1
                                findings.append(IntelligenceFinding(
                                    entity=sub, type="Subdomain (Passive)", source="BufferOver",
                                    confidence="High", color="emerald",
                                    category="Domain & DNS Enumeration",
                                    threat_level="Standard Target",
                                    resolution=ip_part,
                                    raw_data=f"Found via {entry_type} DNS data"
                                ))
                                source_reliability_total += SOURCE_RELIABILITY.get("BufferOver", 0.8)
                                source_reliability_count += 1
        except:
            pass

    async def from_rapiddns():
        nonlocal source_reliability_total, source_reliability_count
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = await client.get(url, timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["RapidDNS"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="RapidDNS",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via RapidDNS.io"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("RapidDNS", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_alienvault():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    sub = entry.get("hostname", "").lower()
                    if sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        source_counts["AlienVault OTX"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="AlienVault OTX",
                            confidence="High", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            resolution=entry.get("address", ""),
                            raw_data=f"Found via AlienVault OTX passive DNS"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("AlienVault OTX", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_threatcrowd():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    sub = sub.lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["ThreatCrowd"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="ThreatCrowd",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via ThreatCrowd"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("ThreatCrowd", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_anubis():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://jldc.me/anubis/subdomains/{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200 and resp.text.strip().startswith("["):
                data = resp.json()
                for sub in data:
                    if isinstance(sub, str) and sub.lower().endswith("." + domain) and sub.lower() not in seen:
                        sub = sub.lower()
                        seen.add(sub)
                        source_counts["Anubis"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Anubis",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Anubis subdomain DB"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Anubis", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_urlscan():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    sub = page.get("domain", "").lower()
                    if sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        source_counts["URLScan.io"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="URLScan.io",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            resolution=page.get("ip", ""),
                            raw_data=f"Found via URLScan.io - {page.get('url', '')}"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("URLScan.io", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_riddler():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://riddler.io/api/search?q=host:{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                entries = data if isinstance(data, list) else data.get("results", [])
                for entry in entries:
                    sub = entry.get("host", "").lower() if isinstance(entry, dict) else ""
                    if sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        source_counts["Riddler"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Riddler",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Riddler.io"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Riddler", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_sonar_omnisint():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://sonar.omnisint.io/subdomains/{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200 and resp.text.strip().startswith("["):
                data = resp.json()
                for sub in data:
                    if isinstance(sub, str) and sub.lower().endswith("." + domain) and sub.lower() not in seen:
                        sub = sub.lower()
                        seen.add(sub)
                        source_counts["Sonar Omnisint"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Sonar Omnisint",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Sonar Omnisint"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Sonar Omnisint", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_web_archive():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
                timeout=20.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                sub_pattern = re.compile(rf'https?://([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for row in data[1:]:
                    if isinstance(row, list) and len(row) > 0:
                        url = row[0]
                        m = sub_pattern.search(url)
                        if m:
                            sub = m.group(1).lower()
                            if sub not in seen:
                                seen.add(sub)
                                source_counts["Wayback Machine"] += 1
                                findings.append(IntelligenceFinding(
                                    entity=sub, type="Subdomain (Passive)", source="Wayback Machine",
                                    confidence="Medium", color="emerald",
                                    category="Domain & DNS Enumeration",
                                    threat_level="Standard Target",
                                    raw_data="Found via Wayback Machine CDX"
                                ))
                                source_reliability_total += SOURCE_RELIABILITY.get("Wayback Machine", 0.8)
                                source_reliability_count += 1
        except:
            pass

    async def from_shodan():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://www.shodan.io/search?query=hostname%3A.{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["Shodan"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Shodan",
                            confidence="High", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Shodan search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Shodan", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_censys():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://search.censys.io/search?resource=hosts&q=services.service_name%3A%22HTTP%22+AND+dns.names%3A.{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["Censys"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Censys",
                            confidence="High", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Censys search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Censys", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_fofa():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://en.fofa.info/result?qbase64=Ym9keT0iJTI1Lntkb21haW59IiYm",  # placeholder
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["FOFA"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="FOFA",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via FOFA search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("FOFA", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_zoomeye():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://www.zoomeye.org/searchResult?q=hostname%3A.{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["ZoomEye"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="ZoomEye",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via ZoomEye search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("ZoomEye", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_binaryedge():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://app.binaryedge.io/api/v2/query/search?query=domain%3A{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for event in data.get("events", data.get("results", [])):
                    if isinstance(event, dict):
                        sub = event.get("hostname", event.get("domain", "")).lower()
                        if sub.endswith("." + domain) and sub not in seen:
                            seen.add(sub)
                            source_counts["BinaryEdge"] += 1
                            findings.append(IntelligenceFinding(
                                entity=sub, type="Subdomain (Passive)", source="BinaryEdge",
                                confidence="Medium", color="emerald",
                                category="Domain & DNS Enumeration",
                                threat_level="Standard Target",
                                resolution=event.get("ip", ""),
                                raw_data="Found via BinaryEdge search"
                            ))
                            source_reliability_total += SOURCE_RELIABILITY.get("BinaryEdge", 0.8)
                            source_reliability_count += 1
        except:
            pass

    async def from_netlas():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://app.netlas.io/domains/?q=domain%3A.{domain}&source_type=include",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["Netlas"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="Netlas",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via Netlas search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("Netlas", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_fullhunt():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", data.get("domains", data.get("results", []))):
                    if isinstance(sub, str) and sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        source_counts["FullHunt"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="FullHunt",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via FullHunt search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("FullHunt", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_leakix():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://leakix.net/search?q=domain%3A{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["LeakIX"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="LeakIX",
                            confidence="Low", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via LeakIX search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("LeakIX", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_intelx():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://intelx.io/?s={domain}&t=domain",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["IntelX"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="IntelX",
                            confidence="Low", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via IntelX search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("IntelX", 0.8)
                        source_reliability_count += 1
        except:
            pass

    async def from_onyphe():
        nonlocal source_reliability_total, source_reliability_count
        try:
            resp = await client.get(
                f"https://www.onyphe.io/search?query=domain%3A{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        source_counts["ONYPHE"] += 1
                        findings.append(IntelligenceFinding(
                            entity=sub, type="Subdomain (Passive)", source="ONYPHE",
                            confidence="Medium", color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via ONYPHE search"
                        ))
                        source_reliability_total += SOURCE_RELIABILITY.get("ONYPHE", 0.8)
                        source_reliability_count += 1
        except:
            pass

    await asyncio.gather(
        from_crtsh(),
        from_hackertarget(),
        from_bufferover(),
        from_rapiddns(),
        from_alienvault(),
        from_threatcrowd(),
        from_anubis(),
        from_urlscan(),
        from_riddler(),
        from_sonar_omnisint(),
        from_web_archive(),
        from_shodan(),
        from_censys(),
        from_fofa(),
        from_zoomeye(),
        from_binaryedge(),
        from_netlas(),
        from_fullhunt(),
        from_leakix(),
        from_intelx(),
        from_onyphe(),
    )

    if findings:
        sources_used = defaultdict(int)
        for f in findings:
            sources_used[f.source] += 1
        source_str = ", ".join(f"{s}: {c}" for s, c in sorted(sources_used.items(), key=lambda x: -x[1]))

        findings.insert(0, IntelligenceFinding(
            entity=f"Total: {len(seen)} passive subdomains from {len(sources_used)} sources",
            type="Passive Subdomain Summary",
            source="Passive Recon",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=source_str
        ))

        avg_reliability = (source_reliability_total / source_reliability_count) if source_reliability_count > 0 else 0
        reliability_score = f"{avg_reliability:.0%}" if avg_reliability > 0 else "N/A"
        findings.append(IntelligenceFinding(
            entity=f"Source Reliability Score: {reliability_score} (avg of {source_reliability_count} signals)",
            type="Source Reliability Assessment",
            source="Passive Recon",
            confidence="High",
            color="emerald" if avg_reliability >= 0.8 else ("orange" if avg_reliability >= 0.6 else "red"),
            threat_level="Informational",
            status=f"{avg_reliability:.0%} reliability",
            raw_data=f"Average reliability: {avg_reliability:.3f} across {source_reliability_count} findings",
            tags=["reliability", "quality"]
        ))

        sub_list_for_probe = list(seen)[:30]
        classification_counts = defaultdict(int)
        for sub in sub_list_for_probe:
            sub_class = _classify_subdomain(sub)
            classification_counts[sub_class] += 1

        for cat, count in sorted(classification_counts.items(), key=lambda x: -x[1])[:8]:
            findings.append(IntelligenceFinding(
                entity=f"Classification: {cat} ({count} subdomains)",
                type="Subdomain Classification",
                source="Passive Recon",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Classified",
                raw_data=f"Category '{cat}' has {count} subdomains",
                tags=["classification", cat.lower().replace('/', '-').replace(' ', '-')]
            ))

        probe_results = []
        for sub in sub_list_for_probe:
            probe = await _http_probe(sub, client)
            if probe.get("status"):
                probe_results.append((sub, probe))
                ip_clusters[probe.get("ip", "unknown")].append(sub)
                if probe.get("ip") and probe["ip"] not in seen_ips:
                    seen_ips.add(probe["ip"])

                findings.append(IntelligenceFinding(
                    entity=f"{sub}: HTTP {probe['status']}",
                    type="HTTP Probe (Live Check)",
                    source="Passive Recon",
                    confidence="High",
                    color="emerald" if probe["status"] < 400 else "slate",
                    threat_level="Informational",
                    status="Active" if probe["status"] < 400 else "Inactive",
                    resolution=probe.get("ip", ""),
                    raw_data=f"HTTP {probe['status']} on {sub} | Server: {probe.get('server', 'N/A')} | Title: {probe.get('title', 'N/A')}",
                    tags=["http-probe", "live"]
                ))
                if probe.get("title"):
                    findings.append(IntelligenceFinding(
                        entity=f"Title: {probe['title']}",
                        type="Page Title (HTTP Probe)",
                        source="Passive Recon",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        status="Captured",
                        resolution=probe.get("ip", ""),
                        raw_data=f"Title for {sub}: {probe['title']}",
                        tags=["title", "http-probe"]
                    ))
                if probe.get("server"):
                    findings.append(IntelligenceFinding(
                        entity=f"Server: {probe['server']}",
                        type="Server Banner (HTTP Probe)",
                        source="Passive Recon",
                        confidence="Medium",
                        color="slate",
                        status="Detected",
                        resolution=probe.get("ip", ""),
                        raw_data=f"Server header for {sub}: {probe['server']}",
                        tags=["server", "http-probe"]
                    ))

        if ip_clusters:
            for ip, subs in sorted(ip_clusters.items(), key=lambda x: -len(x[1]))[:10]:
                if len(subs) > 1:
                    findings.append(IntelligenceFinding(
                        entity=f"IP {ip} hosts {len(subs)} subdomains",
                        type="IP Cluster (Shared Hosting Detected)",
                        source="Passive Recon",
                        confidence="High",
                        color="blue",
                        threat_level="Standard Target",
                        status="Clustered",
                        raw_data=f"Subdomains on {ip}: {', '.join(subs)}",
                        tags=["ip-cluster", "shared-hosting", "co-hosting"]
                    ))

        live_count = sum(1 for _, p in probe_results if p.get("status") and p["status"] < 400)
        if probe_results:
            findings.append(IntelligenceFinding(
                entity=f"HTTP Probe Summary: {len(probe_results)} resolved, {live_count} live (HTTP <400)",
                type="HTTP Probe Summary",
                source="Passive Recon",
                confidence="High",
                color="emerald" if live_count > 0 else "slate",
                threat_level="Informational",
                status="Probed",
                raw_data=f"Total probed: {len(probe_results)}, Live: {live_count}, Unique IPs: {len(seen_ips)}",
                tags=["http-probe", "summary"]
            ))

    return findings
