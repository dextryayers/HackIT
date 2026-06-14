import httpx
import socket
import asyncio
from models import IntelligenceFinding

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
        except:
            findings.append(IntelligenceFinding(
                entity=target,
                type="Shodan Error",
                source="Shodan InternetDB",
                confidence="Low",
                color="red",
                threat_level="Informational",
                raw_data="Could not resolve hostname to IP"
            ))
            return findings

        url = f"https://internetdb.shodan.io/{ip}"
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            vulns = data.get("vulns", [])
            cpes = data.get("cpes", [])

            if not ports and not hostnames and not vulns and not cpes:
                findings.append(IntelligenceFinding(
                    entity=ip,
                    type="Shodan InternetDB Result",
                    source="Shodan InternetDB",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data="No data found in Shodan InternetDB"
                ))
                return findings

            for port in sorted(ports):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = ""
                findings.append(IntelligenceFinding(
                    entity=f"{ip}:{port}",
                    type="Open Port",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    resolution=f"Port {port} ({service}) is exposed",
                    raw_data=f"Port: {port}, Service: {service}, IP: {ip}"
                ))

            for hostname in hostnames:
                findings.append(IntelligenceFinding(
                    entity=hostname,
                    type="Subdomain",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="blue",
                    resolution=ip,
                    raw_data=f"Hostname {hostname} resolves to {ip}"
                ))

            vuln_risk = {
                "CVE-2021": "Elevated Risk",
                "CVE-2022": "High Risk",
                "CVE-2023": "High Risk",
                "CVE-2024": "Critical",
                "CVE-2025": "Critical",
            }
            for vuln in vulns:
                risk = "High Risk"
                for prefix, level in vuln_risk.items():
                    if vuln.startswith(prefix):
                        risk = level
                        break
                findings.append(IntelligenceFinding(
                    entity=vuln,
                    type="Known Vulnerability",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="red",
                    threat_level=risk,
                    resolution=f"Affects {ip}",
                    raw_data=f"Vulnerability: {vuln} on {ip}",
                    tags=["cve", "vulnerability"]
                ))

            for cpe in cpes:
                findings.append(IntelligenceFinding(
                    entity=cpe,
                    type="Technology (CPE)",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"CPE: {cpe}"
                ))

            if ports:
                findings.append(IntelligenceFinding(
                    entity=f"{len(ports)} open ports detected",
                    type="Shodan Summary",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"Open ports: {', '.join(map(str, sorted(ports)))}"
                ))
            if vulns:
                findings.append(IntelligenceFinding(
                    entity=f"{len(vulns)} known vulnerabilities detected",
                    type="Shodan Vulnerability Summary",
                    source="Shodan InternetDB",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Vulnerabilities: {', '.join(vulns)}",
                    tags=["cve", "summary"]
                ))

        elif resp.status_code == 404:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Shodan InternetDB",
                source="Shodan InternetDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data="IP not found in Shodan InternetDB"
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Shodan error: {str(e)[:100]}",
            type="Shodan Error",
            source="Shodan InternetDB",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))
    return findings
