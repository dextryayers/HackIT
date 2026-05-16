import httpx
import asyncio
import socket
import struct
from models import IntelligenceFinding

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n))

async def reverse_dns_probe(ip):
    try:
        # Using loop.run_in_executor for blocking socket operations
        loop = asyncio.get_event_loop()
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return ip, name
    except:
        return ip, None

async def crawl(target, client):
    findings = []
    
    # 1. Resolve Target Domain to IP
    try:
        target_ip = socket.gethostbyname(target)
    except:
        # If already an IP
        target_ip = target
        
    try:
        socket.inet_aton(target_ip)
    except:
        # Not an IP and couldn't resolve
        return findings

    # 2. Map Network Neighbors (Adjacent IPs)
    # Concept from sfp_dnsneighbor: check -2 to +2 adjacent IPs
    ip_int = ip_to_int(target_ip)
    neighbors = [int_to_ip(ip_int + i) for i in range(-2, 3) if i != 0]
    
    tasks = [reverse_dns_probe(ip) for ip in neighbors]
    results = await asyncio.gather(*tasks)
    
    for ip, hostname in results:
        if hostname:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Infrastructure Neighbor",
                source="Network Topology Mapper",
                confidence="High",
                color="blue",
                category="Infrastructure",
                threat_level="Informational",
                status="Active Neighbor",
                raw_data=f"Adjacent IP {ip} resolves to {hostname}. This may belong to the same infrastructure or cloud provider."
            ))

    # 3. HackerTarget Host Search (from sfp_hackertarget concept)
    try:
        resp = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={target_ip}", timeout=10.0)
        if resp.status_code == 200 and "error" not in resp.text:
            hosts = resp.text.strip().split('\n')
            for host in hosts:
                if host and host != target:
                    findings.append(IntelligenceFinding(
                        entity=host,
                        type="Co-Hosted Domain",
                        source="HackerTarget Radar",
                        confidence="Certain",
                        color="teal",
                        category="Infrastructure",
                        threat_level="Informational",
                        status="Co-Hosted",
                        raw_data=f"Domain {host} is hosted on the same IP ({target_ip})."
                    ))
    except:
        pass
        
    return findings
