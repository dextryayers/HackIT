import asyncio
import json
from datetime import datetime
from typing import List, Optional
from ..module_common import make_finding, resolve_ip

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE", 514: "Syslog", 587: "SMTP Submission",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1025: "RPC", 1080: "SOCKS", 1194: "OpenVPN",
    1352: "Lotus Notes", 1433: "MSSQL", 1434: "MSSQL Monitor",
    1521: "Oracle DB", 2049: "NFS", 2082: "CPanel",
    2083: "CPanel SSL", 2086: "WHM", 2087: "WHM SSL",
    2095: "Webmail", 2096: "Webmail SSL", 2222: "DirectAdmin",
    2375: "Docker", 2376: "Docker TLS", 2483: "Oracle DB",
    2484: "Oracle DB SSL", 3128: "Squid Proxy", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4333: "SIP", 4443: "HTTPS Alt",
    4444: "Metasploit", 4500: "IPsec", 4848: "GlassFish",
    4899: "Radmin", 5000: "UPnP/Flask", 5001: "Flask/Tor",
    5003: "FileMaker", 5038: "Asterisk", 5060: "SIP",
    5061: "SIP TLS", 5143: "SWAT", 5432: "PostgreSQL",
    5555: "Android ADB", 5632: "PCAnywhere", 5800: "VNC",
    5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM SSL",
    6000: "X11", 6001: "X11", 6379: "Redis", 6443: "Kubernetes",
    6666: "IRC", 6667: "IRC", 6668: "IRC", 6669: "IRC",
    7001: "WebLogic", 7002: "WebLogic SSL", 7077: "Mesos",
    8000: "HTTP Alt", 8001: "HTTP Alt", 8008: "HTTP Alt",
    8009: "AJP", 8010: "HTTP Alt", 8020: "HTTP Alt",
    8021: "Zope", 8030: "HTTP Alt", 8040: "HTTP Alt",
    8041: "HTTP Alt", 8042: "HTTP Alt", 8069: "Odoo",
    8070: "HTTP Alt", 8080: "HTTP Proxy", 8081: "HTTP Alt",
    8082: "HTTP Alt", 8083: "HTTP Alt", 8084: "HTTP Alt",
    8085: "HTTP Alt", 8086: "InfluxDB", 8087: "HTTP Alt",
    8088: "HTTP Alt", 8089: "HTTP Alt", 8090: "HTTP Alt",
    8091: "Couchbase", 8092: "Couchbase", 8093: "Couchbase",
    8094: "Couchbase", 8095: "Couchbase", 8096: "Emby",
    8097: "HTTP Alt", 8098: "Riak", 8099: "HTTP Alt",
    8100: "HTTP Alt", 8200: "Vault", 8300: "Consul",
    8400: "HTTP Alt", 8443: "HTTPS Alt", 8500: "Consul API",
    8545: "Ethereum", 8600: "Consul DNS", 8646: "HTTP Alt",
    8647: "HTTP Alt", 8648: "HTTP Alt", 8649: "Ganglia",
    8651: "HTTP Alt", 8652: "HTTP Alt", 8653: "HTTP Alt",
    8686: "HTTP Alt", 8700: "HTTP Alt", 8787: "HTTP Alt",
    8800: "HTTP Alt", 8834: "Nessus", 8843: "HTTPS Alt",
    8877: "HTTP Alt", 8880: "HTTP Alt", 8888: "HTTP Alt",
    8889: "HTTP Alt", 8890: "HTTP Alt", 8891: "HTTP Alt",
    8892: "HTTP Alt", 8893: "HTTP Alt", 8894: "HTTP Alt",
    8895: "HTTP Alt", 8896: "HTTP Alt", 8897: "HTTP Alt",
    8898: "HTTP Alt", 8899: "HTTP Alt", 8900: "HTTP Alt",
    8901: "HTTP Alt", 8902: "HTTP Alt", 8903: "HTTP Alt",
    8904: "HTTP Alt", 8905: "HTTP Alt", 8906: "HTTP Alt",
    8907: "HTTP Alt", 8908: "HTTP Alt", 8909: "HTTP Alt",
    8910: "HTTP Alt", 8990: "HTTP Alt", 8991: "HTTP Alt",
    8992: "HTTP Alt", 8993: "HTTP Alt", 8994: "HTTP Alt",
    8995: "HTTP Alt", 8996: "HTTP Alt", 8997: "HTTP Alt",
    8998: "HTTP Alt", 8999: "HTTP Alt", 9000: "SonarQube",
    9001: "HTTP Alt", 9002: "HTTP Alt", 9003: "HTTP Alt",
    9004: "HTTP Alt", 9005: "HTTP Alt", 9006: "HTTP Alt",
    9007: "HTTP Alt", 9008: "HTTP Alt", 9009: "HTTP Alt",
    9010: "HTTP Alt", 9042: "Cassandra", 9043: "WebSphere",
    9050: "Socks", 9051: "Socks", 9090: "WebSphere",
    9091: "JMX", 9092: "Kafka", 9100: "JetDirect",
    9150: "Tor", 9151: "Tor", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9443: "HTTPS Alt", 9448: "HTTP Alt",
    9500: "HTTP Alt", 9530: "HTTP Alt", 9595: "HTTP Alt",
    9600: "HTTP Alt", 9876: "HTTP Alt", 9898: "HTTP Alt",
    9900: "HTTP Alt", 9990: "WildFly", 9999: "HTTP Alt",
    10000: "Webmin", 10001: "HTTP Alt", 10002: "HTTP Alt",
    10003: "HTTP Alt", 10004: "HTTP Alt", 10005: "HTTP Alt",
    10006: "HTTP Alt", 10007: "HTTP Alt", 10008: "HTTP Alt",
    10009: "HTTP Alt", 10010: "HTTP Alt", 10011: "HTTP Alt",
    10012: "HTTP Alt", 10013: "HTTP Alt", 10014: "HTTP Alt",
    10015: "HTTP Alt", 10016: "HTTP Alt", 10017: "HTTP Alt",
    10018: "HTTP Alt", 10019: "HTTP Alt", 10020: "HTTP Alt",
    10050: "Zabbix", 10051: "Zabbix", 10100: "HTTP Alt",
    10101: "HTTP Alt", 10102: "HTTP Alt", 10103: "HTTP Alt",
    10104: "HTTP Alt", 10105: "HTTP Alt", 10106: "HTTP Alt",
    10107: "HTTP Alt", 10108: "HTTP Alt", 10109: "HTTP Alt",
    10110: "HTTP Alt", 10250: "Kubelet", 10255: "Kubelet",
    11211: "Memcached", 11214: "Memcached", 11215: "Memcached",
    12000: "DynamoDB", 12345: "NetBus", 13579: "HTTP Alt",
    13724: "HTTP Alt", 13782: "HTTP Alt", 13783: "HTTP Alt",
    14147: "FileZilla", 16010: "HBase", 16020: "HBase",
    16030: "HBase", 16100: "HTTP Alt", 16379: "Redis",
    16509: "oVirt", 16514: "oVirt", 17000: "HTTP Alt",
    17200: "HTTP Alt", 17201: "HTTP Alt", 17202: "HTTP Alt",
    17203: "HTTP Alt", 17204: "HTTP Alt", 17205: "HTTP Alt",
    17300: "HTTP Alt", 17400: "HTTP Alt", 17500: "Dropbox",
    18080: "HTTP Alt", 18081: "HTTP Alt", 18082: "HTTP Alt",
    18083: "HTTP Alt", 18084: "HTTP Alt", 18085: "HTTP Alt",
    18086: "HTTP Alt", 18087: "HTTP Alt", 18088: "HTTP Alt",
    18089: "HTTP Alt", 18090: "HTTP Alt", 18091: "HTTP Alt",
    18092: "HTTP Alt", 18093: "HTTP Alt", 18094: "HTTP Alt",
    18095: "HTTP Alt", 18096: "HTTP Alt", 18097: "HTTP Alt",
    18098: "HTTP Alt", 18099: "HTTP Alt", 18100: "HTTP Alt",
    19000: "HTTP Alt", 19100: "HTTP Alt", 19200: "HTTP Alt",
    19300: "HTTP Alt", 19400: "HTTP Alt", 19500: "HTTP Alt",
    19600: "HTTP Alt", 19700: "HTTP Alt", 19800: "HTTP Alt",
    19900: "HTTP Alt", 20000: "HTTP Alt", 20001: "HTTP Alt",
    20002: "HTTP Alt", 20003: "HTTP Alt", 20004: "HTTP Alt",
    20005: "HTTP Alt", 20006: "HTTP Alt", 20007: "HTTP Alt",
    20008: "HTTP Alt", 20009: "HTTP Alt", 20010: "HTTP Alt",
    20011: "HTTP Alt", 20012: "HTTP Alt", 20013: "HTTP Alt",
     20014: "HTTP Alt", 20015: "HTTP Alt",
}

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 465, 500, 514, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375, 2376, 3128, 3306, 3389, 3690, 4444, 5432, 5555, 5800, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 6666, 6667, 6668, 6669, 7001, 7002, 7077, 8000, 8001, 8008, 8080, 8081, 8086, 8090, 8091, 8443, 8500, 8545, 8834, 9000, 9001, 9042, 9050, 9090, 9092, 9200, 9300, 9443, 10000, 10050, 10250, 11211, 12345, 14147, 16379, 17000, 18080, 27017, 27018, 27019, 28017, 31337, 49152, 49153, 49154, 49155, 49156, 65535]

async def check_port(host: str, port: int) -> Optional[int]:
    try:
        _, _ = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.settimeout(2) or socket.create_connection((host, port), timeout=2)
            ),
            timeout=3.0
        )
        return port
    except:
        return None

async def grab_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
        if port in (80, 8080, 8000, 443, 8443):
            writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        writer.close()
        return data.decode("utf-8", errors="ignore")[:200]
    except:
        return ""

PORT_CATEGORIES = {
    "Web": [80, 443, 8080, 8443, 8000, 8008, 8888, 9443],
    "Database": [3306, 5432, 6379, 27017, 1433, 1521, 9042, 9200],
    "Remote Access": [22, 3389, 5900, 5901, 5800, 6000, 6001],
    "Email": [25, 465, 587, 110, 143, 993, 995],
    "File Transfer": [21, 445, 2049, 3690, 990],
    "DNS/NTP": [53, 123, 161, 389, 636],
    "Management": [2082, 2083, 2087, 9090, 10000, 8834],
    "Message Queue": [5672, 61616, 9092, 11211],
    "Container/Orch": [2375, 2376, 6443, 10250, 10255, 8472],
    "Dev Tools": [3000, 4200, 5000, 9000, 9876],
}

BANNER_PORTS = [21, 22, 25, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 1433, 1521, 5900, 5901]

async def scan_live_ports(host: str) -> list:
    open_ports = []
    batch_size = 50
    for i in range(0, len(SCAN_PORTS), batch_size):
        batch = SCAN_PORTS[i:i+batch_size]
        tasks = [check_port(host, port) for port in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r:
                open_ports.append(r)
    return open_ports

async def grab_banners(host: str, ports: list) -> list:
    findings = []
    for port in ports:
        if port in BANNER_PORTS:
            banner = await grab_banner(host, port)
            if banner:
                findings.append(make_finding(
                    entity=f"Banner on port {port}: {banner[:200]}",
                    ftype="Port Scanner: Banner Grabbing",
                    source="PortScanner",
                    confidence="Medium",
                    color="slate",
                    status="Banner Retrieved",
                    resolution=host,
                    tags=["port", "banner", str(port)]
                ))
    return findings

async def crawl(target: str, client: AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    ip = resolve_ip(t) or t

    findings.append(make_finding(
        entity=f"Scanning {len(SCAN_PORTS)} common ports on {t} ({ip})",
        ftype="Port Scanner: Configuration",
        source="PortScanner",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Configured",
        resolution=t,
        tags=["port", "scan", "configuration"]
    ))

    findings.append(make_finding(
        entity=f"Port database: {len(COMMON_PORTS)} service definitions loaded",
        ftype="Port Scanner: Service Database",
        source="PortScanner",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Ready",
        resolution=t,
        tags=["port", "services", "database"]
    ))

    for cat_name, cat_ports in PORT_CATEGORIES.items():
        cat_detail = ", ".join(f"{p} ({COMMON_PORTS.get(p, 'Unknown')})" for p in cat_ports[:5])
        findings.append(make_finding(
            entity=f"Category {cat_name}: {len(cat_ports)} ports ({cat_detail}...)",
            ftype="Port Scanner: Port Category",
            source="PortScanner",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Categorized",
            resolution=t,
            tags=["port", "category", cat_name.lower().replace(" ", "-")]
        ))

    open_ports = await scan_live_ports(ip)
    if open_ports:
        findings.append(make_finding(
            entity=f"{len(open_ports)} open ports found on {t}",
            ftype="Port Scanner: Open Ports",
            source="PortScanner",
            confidence="High",
            color="red",
            threat_level="High Risk" if len(open_ports) > 5 else "Elevated Risk",
            status=f"{len(open_ports)} open",
            resolution=t,
            tags=["port", "open", str(len(open_ports))]
        ))
        for p in open_ports[:15]:
            findings.append(make_finding(
                entity=f"Open port {p}: {COMMON_PORTS.get(p, 'Unknown service')}",
                ftype="Port Scanner: Open Port Detail",
                source="PortScanner",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                status="Open",
                resolution=t,
                tags=["port", "open", str(p), COMMON_PORTS.get(p, "unknown").lower()]
            ))

        banner_results = await grab_banners(ip, open_ports)
        findings.extend(banner_results)

    for port, service in list(COMMON_PORTS.items())[:30]:
        findings.append(make_finding(
            entity=f"Port {port}: {service}",
            ftype="Port Scanner: Common Service",
            source="PortScanner",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Listed",
            resolution=t,
            tags=["port", "service", service.lower()]
        ))

    if not findings:
        findings.append(make_finding(
            entity="Port scanner initialized",
            ftype="Port Scanner: Ready",
            source="PortScanner",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Ready",
            resolution=t,
            tags=["port", "ready"]
        ))

    return findings
