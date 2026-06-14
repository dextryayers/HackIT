import httpx
import asyncio
import socket
import re
from collections import defaultdict
from models import IntelligenceFinding

BINARYEDGE_API = "https://api.binaryedge.io/v2"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

PORT_CATEGORIES = {
    (20, 21): ("FTP", "File Transfer"),
    (22, 22): ("SSH", "Remote Access"),
    (23, 23): ("Telnet", "Remote Access"),
    (25, 25): ("SMTP", "Email"),
    (53, 53): ("DNS", "Infrastructure"),
    (80, 80): ("HTTP", "Web"),
    (110, 110): ("POP3", "Email"),
    (143, 143): ("IMAP", "Email"),
    (443, 443): ("HTTPS", "Web"),
    (445, 445): ("SMB", "File Sharing"),
    (993, 993): ("IMAPS", "Email"),
    (995, 995): ("POP3S", "Email"),
    (1080, 1080): ("SOCKS", "Proxy"),
    (1433, 1433): ("MSSQL", "Database"),
    (1521, 1521): ("Oracle DB", "Database"),
    (2049, 2049): ("NFS", "File Sharing"),
    (2375, 2376): ("Docker", "Container"),
    (3306, 3306): ("MySQL", "Database"),
    (3389, 3389): ("RDP", "Remote Access"),
    (5432, 5432): ("PostgreSQL", "Database"),
    (5900, 5900): ("VNC", "Remote Access"),
    (6379, 6379): ("Redis", "Database"),
    (8080, 8080): ("HTTP-Alt", "Web"),
    (8443, 8443): ("HTTPS-Alt", "Web"),
    (27017, 27017): ("MongoDB", "Database"),
    (11211, 11211): ("Memcached", "Database"),
}

VULN_KEYWORDS = [
    "cve", "vulnerability", "exploit", "rce", "remote code",
    "xss", "sqli", "sql injection", "path traversal",
    "authentication bypass", "privilege escalation",
]

SERVICE_RISK_SCORE = {
    "Telnet": 9, "FTP": 7, "SMB": 9, "RDP": 8, "VNC": 9,
    "MongoDB": 8, "Redis": 8, "Memcached": 7, "MySQL": 6,
    "MSSQL": 7, "PostgreSQL": 6, "Oracle DB": 7,
    "SMTP": 4, "DNS": 4, "HTTP": 3, "HTTPS": 2, "SSH": 3,
}

async def resolve_to_ips(domain: str) -> list:
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

def classify_port(port: int) -> tuple:
    for (lo, hi), (service, cat) in PORT_CATEGORIES.items():
        if lo <= port <= hi:
            return service, cat
    return f"Port {port}", "Other"

def risk_for_service(service: str) -> int:
    return SERVICE_RISK_SCORE.get(service, 5)

async def query_host(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/ip/{ip}",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def query_domain(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/domain/{domain}",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def query_port_history(ip: str, port: int, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/ip/{ip}/port/{port}",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def query_cve(ip: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/cve/ip/{ip}",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("results", [])[:10]
    except:
        pass
    return []

async def query_dataleaks(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/dataleaks/domain/{domain}",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("results", [])[:10]
    except:
        pass
    return []

async def query_events(ip: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"{BINARYEDGE_API}/query/ip/{ip}/events",
            headers={"User-Agent": UA, "X-Key": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("events", [])[:50]
    except:
        pass
    return []

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    ips = await resolve_to_ips(t)
    if not ips:
        ips = [t]

    for ip in ips[:3]:
        host_data = await query_host(ip, client)
        if host_data:
            result = host_data.get("result", {})
            if result:
                findings.append(IntelligenceFinding(
                    entity=ip,
                    type="BinaryEdge: Host Found",
                    source="BinaryEdge",
                    confidence="High",
                    color="orange",
                    status="Confirmed",
                    resolution=ip,
                    tags=["host", "scan"],
                ))

            ports = result.get("ports", [])
            if ports:
                port_summary = defaultdict(list)
                for pdata in ports[:30]:
                    port = pdata.get("port", 0)
                    proto = pdata.get("protocol", "tcp")
                    service, cat = classify_port(port)
                    port_summary[cat].append((port, proto, service))
                    ssl_info = pdata.get("ssl", {})
                    extra = f" | SSL: {ssl_info.get('version', '')}" if ssl_info else ""

                    risk = risk_for_service(service)
                    threat = "High Risk" if risk >= 8 else ("Elevated Risk" if risk >= 6 else "Standard Target")
                    findings.append(IntelligenceFinding(
                        entity=f"{ip}:{port}/{proto} ({service}){extra}",
                        type="BinaryEdge: Open Port",
                        source="BinaryEdge",
                        confidence="High",
                        color="red" if risk >= 8 else ("orange" if risk >= 6 else "slate"),
                        threat_level=threat,
                        status="Confirmed",
                        resolution=f"{ip}:{port}",
                        tags=["port", cat.lower().replace(" ", "-"), "exposed"],
                    ))

                    if proto and proto != "tcp":
                        findings.append(IntelligenceFinding(
                            entity=f"Protocol: {proto}",
                            type="BinaryEdge: Port Protocol",
                            source="BinaryEdge",
                            confidence="High",
                            color="slate",
                            status="Confirmed",
                            resolution=f"{ip}:{port}",
                            tags=["protocol"],
                        ))

                for cat, entries in port_summary.items():
                    findings.append(IntelligenceFinding(
                        entity=f"{cat}: {len(entries)} port(s)",
                        type="BinaryEdge: Service Category",
                        source="BinaryEdge",
                        confidence="Medium",
                        color="slate",
                        status="Analyzed",
                        resolution=ip,
                        tags=["service", cat.lower().replace(" ", "-")],
                    ))

                total_risk = sum(risk_for_service(s) for _, _, s in sum(port_summary.values(), []))
                avg_risk = total_risk / len(ports) if ports else 0
                findings.append(IntelligenceFinding(
                    entity=f"Average exposure risk: {avg_risk:.1f}/10 across {len(ports)} port(s)",
                    type="BinaryEdge: Threat Score",
                    source="BinaryEdge",
                    confidence="Medium",
                    color="red" if avg_risk >= 7 else ("orange" if avg_risk >= 5 else "emerald"),
                    threat_level="Elevated Risk" if avg_risk >= 5 else "Informational",
                    status="Analyzed",
                    resolution=ip,
                    tags=["threat", "risk-assessment"],
                ))

        cves = await query_cve(ip, client)
        if cves:
            for cve_item in cves[:8]:
                cve_id = cve_item.get("cve", cve_item.get("id", ""))
                severity = cve_item.get("severity", cve_item.get("cvss", 0))
                if isinstance(severity, (int, float)):
                    sev_label = "Critical" if severity >= 9 else ("High" if severity >= 7 else ("Medium" if severity >= 4 else "Low"))
                    findings.append(IntelligenceFinding(
                        entity=f"{cve_id} (CVSS: {severity})",
                        type="BinaryEdge: CVE",
                        source="BinaryEdge",
                        confidence="High",
                        color="red" if severity >= 7 else "orange",
                        threat_level=sev_label,
                        status="Confirmed",
                        resolution=ip,
                        raw_data=cve_item.get("description", "")[:500],
                        tags=["vulnerability", "cve"],
                    ))

        leaks = await query_dataleaks(t, client)
        if leaks:
            for leak in leaks[:5]:
                leak_name = leak.get("name", leak.get("title", ""))
                leak_date = leak.get("date", leak.get("discovered", ""))
                findings.append(IntelligenceFinding(
                    entity=f"{leak_name} ({leak_date})" if leak_date else leak_name,
                    type="BinaryEdge: Data Leak",
                    source="BinaryEdge",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Confirmed",
                    resolution=t,
                    tags=["leak", "breach"],
                ))

        events = await query_events(ip, client)
        if events:
            event_types = defaultdict(int)
            for ev in events[:30]:
                evt_type = ev.get("type", ev.get("event_type", "unknown"))
                event_types[evt_type] += 1
            for evt_type, count in sorted(event_types.items(), key=lambda x: -x[1])[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"{evt_type}: {count} event(s)",
                    type="BinaryEdge: Event Summary",
                    source="BinaryEdge",
                    confidence="Medium",
                    color="slate",
                    status="Analyzed",
                    resolution=ip,
                    tags=["events", evt_type],
                ))

    subdomain_data = await query_domain(t, client)
    if subdomain_data:
        subs = subdomain_data.get("subdomains", []) or subdomain_data.get("dns", {}).get("subdomains", [])
        for sub in subs[:15]:
            findings.append(IntelligenceFinding(
                entity=sub,
                type="BinaryEdge: Subdomain",
                source="BinaryEdge",
                confidence="High",
                color="blue",
                status="Confirmed",
                resolution=f"{sub}.{t}",
                tags=["dns", "subdomain"],
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No BinaryEdge data for {t}",
            type="BinaryEdge: No Results",
            source="BinaryEdge",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["error"],
        ))

    return findings
