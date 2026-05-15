import httpx
import socket
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    """Shodan InternetDB — free, no API key. Returns ports/vulns/hostnames for an IP."""
    findings = []
    try:
        # Resolve domain to IP first
        import asyncio
        ip = await asyncio.get_event_loop().run_in_executor(None, lambda: socket.gethostbyname(target))
        
        url = f"https://internetdb.shodan.io/{ip}"
        resp = await client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            # Open ports
            for port in data.get("ports", []):
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port}",
                    type="Open Port",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk"
                ))
            # Hostnames
            for hostname in data.get("hostnames", []):
                findings.append(IntelligenceFinding(
                    entity=hostname,
                    type="Subdomain",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="blue",
                    resolution=ip
                ))
            # Vulnerabilities
            for vuln in data.get("vulns", []):
                findings.append(IntelligenceFinding(
                    entity=vuln,
                    type="Vulnerability",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="red",
                    threat_level="High Risk"
                ))
            # CPEs (technologies)
            for cpe in data.get("cpes", []):
                findings.append(IntelligenceFinding(
                    entity=cpe,
                    type="Tech Stack",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="orange"
                ))
    except Exception as e:
        print(f"[Shodan] Error: {e}")
    return findings
