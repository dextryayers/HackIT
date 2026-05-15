import httpx
from models import IntelligenceFinding
import socket

async def crawl(target, client):
    findings = []
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # First, resolve target to IP if needed
    try:
        import asyncio
        ip = await asyncio.get_event_loop().run_in_executor(None, lambda: socket.gethostbyname(domain))
    except:
        return []

    # 1. Shodan (Passive UI Check/InternetDB)
    # InternetDB is a free, no-auth API from Shodan
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            
            # Ports
            ports = data.get("ports", [])
            for port in ports:
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port}",
                    type="Open Port",
                    source="Shodan (InternetDB)",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Open",
                    raw_data=f"Vulns found: {len(data.get('vulns', []))}"
                ))
            
            # Hostnames
            for host in data.get("hostnames", []):
                findings.append(IntelligenceFinding(
                    entity=host,
                    type="Hostname",
                    source="Shodan",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational"
                ))
                
            # Vulnerabilities
            for vuln in data.get("vulns", []):
                findings.append(IntelligenceFinding(
                    entity=f"{ip} ({vuln})",
                    type="Vulnerability",
                    source="Shodan",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Unpatched",
                    raw_data=f"CVE: {vuln}"
                ))
    except: pass

    # 2. BinaryEdge (Alternative if Shodan fails)
    # We can add more here later
    
    return findings
