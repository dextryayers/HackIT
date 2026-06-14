import asyncio
import socket
from models import IntelligenceFinding

TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1025: "NFS", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 2086: "WHM",
    2087: "WHM SSL", 2095: "WebMail", 2096: "WebMail SSL",
    2222: "DirectAdmin", 2375: "Docker", 2376: "Docker TLS",
    3000: "Development", 3128: "Squid Proxy", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4000: "Development", 4333: "MySQL SSL",
    4444: "Blaster", 4500: "IPsec NAT-T", 5000: "Development",
    5060: "SIP", 5061: "SIPS", 5222: "XMPP", 5432: "PostgreSQL",
    5555: "ADB", 5672: "AMQP", 5800: "VNC HTTP", 5900: "VNC",
    5984: "CouchDB", 5985: "WinRM", 5986: "WinRM HTTPS",
    6000: "X11", 6379: "Redis", 6443: "Kubernetes API",
    6667: "IRC", 6697: "IRC SSL", 6789: "Development",
    7077: "Spark", 7474: "Neo4j", 8000: "Development",
    8008: "HTTP Alt", 8009: "AJP", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8082: "HTTP Alt", 8086: "InfluxDB",
    8087: "HTTP Alt", 8088: "HTTP Alt", 8089: "HTTP Alt",
    8090: "HTTP Alt", 8443: "HTTPS Alt", 8444: "HTTPS Alt",
    8500: "Consul", 8834: "Nessus", 8888: "Development",
    9000: "Development", 9001: "Supervisor", 9002: "Development",
    9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka",
    9100: "Node Exporter", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9418: "Git", 9999: "Development", 10000: "Webmin",
    10001: "Development", 11211: "Memcached", 11214: "Memcached SSL",
    15672: "RabbitMQ", 16010: "HBase", 17017: "MongoDB",
    18080: "Development", 19157: "Development", 20000: "Development",
    22000: "Development", 25565: "Minecraft", 27017: "MongoDB",
    27018: "MongoDB", 27019: "MongoDB", 28015: "RethinkDB",
    28017: "MongoDB Web", 30707: "Development", 31337: "Backdoor",
    32764: "Backdoor", 32768: "Development", 49152: "Windows RPC",
    49153: "Windows RPC", 49154: "Windows RPC", 49155: "Windows RPC",
    50000: "SAP", 50070: "Hadoop", 50075: "Hadoop", 60000: "Development",
    60001: "Development", 60020: "HBase", 60030: "HBase",
}

COMMON_PORTS = list(TOP_PORTS.keys())

async def check_port(host, port, found_ports, loop):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: socket.create_connection((host, port), timeout=2.0)),
            timeout=3.0
        )
        found_ports.append(port)
        try:
            writer.close()
        except: pass
    except: pass

async def crawl(target, client):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    loop = asyncio.get_event_loop()

    try:
        resolved = await loop.run_in_executor(None, lambda: socket.gethostbyname(host))
    except:
        return findings

    found_ports = []
    batch_size = 30
    for i in range(0, len(COMMON_PORTS), batch_size):
        batch = COMMON_PORTS[i:i+batch_size]
        await asyncio.gather(*[check_port(host, p, found_ports, loop) for p in batch])

    for port in sorted(found_ports):
        service = TOP_PORTS.get(port, socket.getservbyport(port) if port < 1024 else "")
        color = "red"
        if service in ("HTTP", "HTTPS", "HTTP Proxy", "HTTPS Alt"):
            color = "orange"
        elif service in ("SSH", "FTP", "SMTP", "MySQL", "PostgreSQL", "MSSQL", "Oracle"):
            color = "red"
        elif service in ("DNS", "NTP"):
            color = "slate"
        elif service in ("VNC", "RDP", "Telnet"):
            color = "red"

        findings.append(IntelligenceFinding(
            entity=f"{host}:{port} ({service})",
            type="Open Port",
            source="Port Scanner",
            confidence="High",
            color=color,
            threat_level="Elevated Risk" if port in [21, 22, 23, 1433, 3306, 3389, 5432, 5900, 6379, 27017] else "Standard Target",
            resolution=resolved,
            raw_data=f"Port {port}: {service} is open on {host} ({resolved})",
            tags=[service.lower()] if service else []
        ))

    if found_ports:
        high_risk_ports = [p for p in found_ports if p in [21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 27017, 445, 135, 139]]
        risk_level = "Elevated Risk" if high_risk_ports else "Standard Target"
        findings.append(IntelligenceFinding(
            entity=f"Total: {len(found_ports)} open ports on {host}",
            type="Port Scan Summary",
            source="Port Scanner",
            confidence="High",
            color="red" if high_risk_ports else "slate",
            threat_level=risk_level,
            raw_data=f"Open: {', '.join(str(p) for p in sorted(found_ports))}",
            tags=["port-scan"]
        ))

    return findings
