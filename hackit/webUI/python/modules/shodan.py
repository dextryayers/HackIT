import httpx
import socket
from urllib.parse import urlparse
from module_base import BaseScanner
from settings_store import get_api_key

SHODAN_API = "https://api.shodan.io"

class ShodanScanner(BaseScanner):
    name = "shodan"

    async def resolve_host(self, target: str) -> str:
        try: return socket.gethostbyname(target)
        except: return target

    async def shodan_host(self, ip: str) -> dict:
        try:
            resp = await self.safe_request(f"{SHODAN_API}/shodan/host/{ip}",
                params={"key": get_api_key("shodan")},
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, timeout=15)
            return resp.json() if resp and resp.status_code==200 else {}
        except: return {}

    async def scan(self) -> list:
        results = []
        t = self.target
        ip = await self.resolve_host(t)
        host_data = await self.shodan_host(ip)

        if not host_data:
            f = self.finding(entity="No Shodan data available for this host",
                ftype="Shodan Check Complete", confidence="Low", color="slate",
                threat_level="Informational", status="Not Found", resolution=ip, tags=["shodan","empty"])
            if f: results.append(f)
            return results

        ports = host_data.get("ports", [])
        if ports:
            sorted_ports = sorted(ports)
            f = self.finding(entity=f"Open ports: {len(ports)} ({', '.join(map(str, sorted_ports[:10]))})",
                ftype="Shodan Open Ports", confidence="High", color="orange",
                threat_level="Elevated Risk", status="Open", resolution=ip, tags=["shodan","ports"])
            if f: results.append(f)

        for hn in host_data.get("hostnames", [])[:5]:
            f = self.finding(entity=f"Hostname: {hn}", ftype="Shodan Hostname",
                confidence="High", color="slate", status="Confirmed", resolution=ip, tags=["shodan","hostname"])
            if f: results.append(f)

        os_val = host_data.get("os","")
        if os_val:
            f = self.finding(entity=f"OS: {os_val}", ftype="Shodan Operating System",
                confidence="Medium", color="slate", status="Detected", resolution=ip, tags=["shodan","os"])
            if f: results.append(f)

        country, city = host_data.get("country_name",""), host_data.get("city","")
        if country or city:
            loc = f"{city}, {country}" if city else country
            f = self.finding(entity=f"Location: {loc}", ftype="Shodan Geolocation",
                confidence="Medium", color="slate", status="Confirmed", resolution=ip, tags=["shodan","geo"])
            if f: results.append(f)

        org, isp = host_data.get("org",""), host_data.get("isp","")
        if org or isp:
            f = self.finding(entity=f"Organization: {org or isp}", ftype="Shodan Organization",
                confidence="High", color="slate", status="Identified", resolution=ip, tags=["shodan","org"])
            if f: results.append(f)

        for vuln in host_data.get("vulns", [])[:5]:
            f = self.finding(entity=f"Vulnerability: {vuln}", ftype="Shodan Vulnerability",
                confidence="High", color="red", threat_level="High Risk", status="Vulnerable",
                resolution=ip, tags=["shodan","vulnerability", vuln.lower()])
            if f: results.append(f)

        for service in host_data.get("data", [])[:5]:
            product = service.get("product","")
            if product:
                port = service.get("port",0)
                transport = service.get("transport","tcp")
                version = service.get("version","")
                f = self.finding(entity=f"Port {port}/{transport}: {product} {version}".strip(),
                    ftype="Shodan Service Banner", confidence="High", color="slate",
                    status="Active", resolution=ip, raw_data=(service.get("data","")[:300]),
                    tags=["shodan","service", product.lower()])
                if f: results.append(f)

        domains = host_data.get("domains", [])
        if domains:
            f = self.finding(entity=f"Domains: {', '.join(domains[:5])}", ftype="Shodan Domains",
                confidence="Medium", color="slate", status="Resolved", resolution=ip, tags=["shodan","domains"])
            if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = ShodanScanner(target, client)
    return await scanner.scan()
