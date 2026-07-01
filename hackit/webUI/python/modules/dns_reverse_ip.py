import httpx
import asyncio
import socket
import re
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

async def resolve_to_ips(domain: str):
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

async def get_ptr(ip: str):
    loop = asyncio.get_event_loop()
    try:
        import dns.resolver
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve_address(ip))
        return [str(a) for a in answers]
    except:
        return []

async def query_viewdns(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://viewdns.info/reverseip/?host={ip}&t=1",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=15.0
        )
        if resp.status_code == 200:
            domains = re.findall(r'<tr><td>([^<]+)</td><td>[^<]+</td></tr>', resp.text)
            return [d.strip().lower() for d in domains if d.strip()][:50]
    except:
        pass
    return []

async def query_hackertarget(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.post(
            "https://api.hackertarget.com/reverseiplookup/",
            data={"q": ip},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            domains = [l.strip().lower() for l in lines if l.strip() and not l.startswith("API")]
            return domains[:50]
    except:
        pass
    return []

async def query_securitytrails(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://api.securitytrails.com/v1/ips/{ip}",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json"
            },
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            domains = []
            for record in data.get("records", data.get("domains", [])):
                if isinstance(record, dict):
                    domains.append(record.get("hostname", record.get("domain", "")).lower())
                elif isinstance(record, str):
                    domains.append(record.lower())
            return domains[:50]
    except:
        pass
    return []

async def query_ipinfo(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=10.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_yougetsignal(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.post(
            "https://domains.yougetsignal.com/domains.php",
            data={"remoteAddress": ip, "key": ""},
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://www.yougetsignal.com/tools/web-sites-on-web-server/"
            },
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            domains = data.get("domainArray", [])
            return [d[0].lower() for d in domains if d and len(d) > 0][:50]
    except:
        pass
    return []

async def query_ipapi(ip: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ips = await resolve_to_ips(domain)
    if not ips:
        try:
            ips = [domain]
        except:
            pass

    for ip in ips[:5]:
        findings.append(IntelligenceFinding(
            entity=ip,
            type="Target IP Address",
            source="DNS Reverse IP",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Resolved",
            tags=["ip", "target"]
        ))

        ptrs = await get_ptr(ip)
        if ptrs:
            findings.append(IntelligenceFinding(
                entity=f"PTR: {ip} -> {', '.join(ptrs)}",
                type="Reverse DNS (PTR)",
                source="DNS Reverse IP",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="PTR Found",
                resolution=ip,
                tags=["ptr", "rdns"]
            ))

        ipinfo = await query_ipinfo(ip, client)
        if ipinfo:
            org = ipinfo.get("org", "")
            country = ipinfo.get("country", "")
            city = ipinfo.get("city", "")
            hostname_v = ipinfo.get("hostname", "")
            if org:
                findings.append(IntelligenceFinding(
                    entity=f"ISP/Org: {org}",
                    type="IP Organization",
                    source="IPInfo.io",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    tags=["ip", "organization"]
                ))
            if country:
                findings.append(IntelligenceFinding(
                    entity=f"Country: {country}",
                    type="IP Geolocation",
                    source="IPInfo.io",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Located",
                    resolution=ip,
                    tags=["ip", "geo"]
                ))
            if city:
                findings.append(IntelligenceFinding(
                    entity=f"City: {city}, {country}",
                    type="IP City",
                    source="IPInfo.io",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Located",
                    resolution=ip,
                    tags=["ip", "geo"]
                ))

        ipapi = await query_ipapi(ip, client)
        if ipapi and ipapi.get("status") == "success":
            isp = ipapi.get("isp", "")
            org2 = ipapi.get("org", "")
            asn = ipapi.get("as", "")
            if isp:
                findings.append(IntelligenceFinding(
                    entity=f"ISP: {isp}",
                    type="IP ISP (ip-api)",
                    source="ip-api.com",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    status="Identified",
                    resolution=ip,
                    tags=["ip", "isp"]
                ))

        all_domains = set()
        sources_used = []

        vd_domains = await query_viewdns(ip, client)
        if vd_domains:
            all_domains.update(vd_domains)
            sources_used.append("ViewDNS")
            findings.append(IntelligenceFinding(
                entity=f"ViewDNS: {len(vd_domains)} domains on {ip}",
                type="Reverse IP Source",
                source="ViewDNS.info",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(vd_domains)} Domains",
                resolution=ip,
                tags=["reverse-ip", "viewdns"]
            ))

        ht_domains = await query_hackertarget(ip, client)
        if ht_domains:
            all_domains.update(ht_domains)
            sources_used.append("HackerTarget")
            findings.append(IntelligenceFinding(
                entity=f"HackerTarget: {len(ht_domains)} domains on {ip}",
                type="Reverse IP Source",
                source="HackerTarget",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(ht_domains)} Domains",
                resolution=ip,
                tags=["reverse-ip", "hackertarget"]
            ))

        st_domains = await query_securitytrails(ip, client)
        if st_domains:
            all_domains.update(st_domains)
            sources_used.append("SecurityTrails")
            findings.append(IntelligenceFinding(
                entity=f"SecurityTrails: {len(st_domains)} domains on {ip}",
                type="Reverse IP Source",
                source="SecurityTrails",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(st_domains)} Domains",
                resolution=ip,
                tags=["reverse-ip", "securitytrails"]
            ))

        yg_domains = await query_yougetsignal(ip, client)
        if yg_domains:
            all_domains.update(yg_domains)
            sources_used.append("YouGetSignal")
            findings.append(IntelligenceFinding(
                entity=f"YouGetSignal: {len(yg_domains)} domains on {ip}",
                type="Reverse IP Source",
                source="YouGetSignal",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status=f"{len(yg_domains)} Domains",
                resolution=ip,
                tags=["reverse-ip", "yougetsignal"]
            ))

        if all_domains:
            shared_count = len(all_domains)
            findings.append(IntelligenceFinding(
                entity=f"Total: {shared_count} unique domains hosted on {ip}",
                type="Reverse IP Summary",
                source="DNS Reverse IP",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status=f"{shared_count} Domains",
                resolution=ip,
                raw_data=f"Sources: {', '.join(sources_used)}",
                tags=["reverse-ip", "summary"]
            ))

            if shared_count > 50:
                findings.append(IntelligenceFinding(
                    entity=f"Shared hosting detected: {shared_count} domains on {ip}",
                    type="Shared Hosting Detection",
                    source="DNS Reverse IP",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Shared Hosting",
                    resolution=ip,
                    tags=["reverse-ip", "shared-hosting"]
                ))

            for d in sorted(all_domains)[:20]:
                findings.append(IntelligenceFinding(
                    entity=d,
                    type="Co-Hosted Domain",
                    source="DNS Reverse IP",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Co-Hosted",
                    resolution=ip,
                    tags=["reverse-ip", "co-hosted", "neighbor"]
                ))

            for d in sorted(all_domains)[:5]:
                try:
                    d_ips = await resolve_to_ips(d)
                    if d_ips and ip not in d_ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{d} now resolves to {', '.join(d_ips)} (no longer on {ip})",
                            type="Domain IP Change Detected",
                            source="DNS Reverse IP",
                            confidence="Medium",
                            color="orange",
                            threat_level="Informational",
                            status="IP Changed",
                            tags=["reverse-ip", "ip-change"]
                        ))
                except:
                    pass

        if not all_domains:
            findings.append(IntelligenceFinding(
                entity=f"No co-hosted domains found for {ip}",
                type="Reverse IP: No Results",
                source="DNS Reverse IP",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="No Domains",
                resolution=ip,
                tags=["reverse-ip", "no-results"]
            ))

    findings.append(IntelligenceFinding(
        entity=f"Reverse IP lookup complete for {len(ips)} IP(s)",
        type="Reverse IP Overall Summary",
        source="DNS Reverse IP",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["reverse-ip", "summary"]
    ))

    return findings
