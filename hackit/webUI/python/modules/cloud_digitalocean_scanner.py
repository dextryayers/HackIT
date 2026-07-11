import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

DO_SERVICES = {
    "Droplets": [".digitalocean.com", "digitalocean"],
    "Spaces": ["digitaloceanspaces.com", ".nyc3.digitaloceanspaces", ".ams3.digitaloceanspaces", ".sgp1.digitaloceanspaces"],
    "App Platform": ["ondigitalocean.app", "apps.digitalocean"],
    "Kubernetes (DOKS)": ["k8s.digitalocean", "doks.digitalocean"],
    "Functions": ["faas.digitalocean", "functions.digitalocean"],
    "Databases": ["db.digitalocean", "database.digitalocean"],
    "Load Balancers": ["digitalocean.com", "lb.digitalocean"],
    "Floating IPs": ["digitalocean.com"],
    "Container Registry": ["registry.digitalocean", "docker.digitalocean"],
    "VPC": ["vpc.digitalocean"],
    "Monitoring": ["monitoring.digitalocean"],
    "CDN": ["cdn.digitalocean", "digitaloceanspaces.com"],
}

DO_REGIONS = {
    "nyc1": [("104.131.0.0", "104.131.255.255")],
    "nyc3": [("138.197.0.0", "138.197.255.255")],
    "sfo2": [("107.170.0.0", "107.170.255.255")],
    "sfo3": [("159.65.0.0", "159.65.255.255")],
    "ams3": [("188.166.0.0", "188.166.255.255")],
    "sgp1": [("128.199.0.0", "128.199.255.255")],
    "lon1": [("146.185.0.0", "146.185.255.255")],
    "fra1": [("138.68.0.0", "138.68.255.255")],
    "blr1": [("139.59.0.0", "139.59.255.255")],
}

DO_IPS = [
    (("104.131.0.0", "104.131.255.255"), "DO NYC"),
    (("104.236.0.0", "104.236.255.255"), "DO SFO"),
    (("107.170.0.0", "107.170.255.255"), "DO SFO"),
    (("128.199.0.0", "128.199.255.255"), "DO SGP"),
    (("138.68.0.0", "138.68.255.255"), "DO FRA"),
    (("138.197.0.0", "138.197.255.255"), "DO NYC"),
    (("139.59.0.0", "139.59.255.255"), "DO BLR"),
    (("143.110.0.0", "143.110.255.255"), "DO Global"),
    (("146.185.0.0", "146.185.255.255"), "DO LON"),
    (("157.230.0.0", "157.230.255.255"), "DO NYC3"),
    (("159.65.0.0", "159.65.255.255"), "DO SFO3"),
    (("161.35.0.0", "161.35.255.255"), "DO FRA"),
    (("162.243.0.0", "162.243.255.255"), "DO NYC"),
    (("164.90.0.0", "164.90.255.255"), "DO Global"),
    (("165.22.0.0", "165.22.255.255"), "DO SGP"),
    (("167.71.0.0", "167.71.255.255"), "DO SFO3"),
    (("167.99.0.0", "167.99.255.255"), "DO FRA"),
    (("174.138.0.0", "174.138.255.255"), "DO SFO"),
    (("178.62.0.0", "178.62.255.255"), "DO LON"),
    (("188.166.0.0", "188.166.255.255"), "DO AMS"),
    (("192.241.0.0", "192.241.255.255"), "DO NYC"),
    (("198.199.0.0", "198.199.255.255"), "DO NYC"),
    (("206.189.0.0", "206.189.255.255"), "DO SFO3"),
    (("209.97.0.0", "209.97.255.255"), "DO AMS3"),
]

DO_SPACES_URLS = [
    "https://{name}.digitaloceanspaces.com",
    "https://{name}.nyc3.digitaloceanspaces.com",
    "https://{name}.ams3.digitaloceanspaces.com",
    "https://{name}.sgp1.digitaloceanspaces.com",
    "https://{name}.fra1.digitaloceanspaces.com",
    "https://{name}.sfo3.digitaloceanspaces.com",
]

LB_PATTERNS = [".digitalocean.com", "lb-", "loadbalancer"]

FLOATING_IP_URL = "https://api.digitalocean.com/v2/floating_ips"

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _check_ip_ranges(ip: str) -> list:
    findings = []
    try:
        parts = ip.split(".")
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except Exception:
        return findings
    for (s, e), region in DO_IPS:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(make_finding(
                    entity=f"DigitalOcean {region}",
                    type="DO IP Range Match",
                    source="DigitalOceanCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} falls in DO range {s}-{e} ({region})",
                    tags=["cloud", "digitalocean", "ip-range"]
                ))
                break
        except Exception:
            continue
    for region, ranges in DO_REGIONS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(make_finding(
                        entity=f"DO Region: {region}",
                        type="DO Region Detected (IP)",
                        source="DigitalOceanCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to DO region {region}",
                        tags=["cloud", "digitalocean", "region", region]
                    ))
                    break
            except Exception:
                continue
    return findings

async def _check_dns_services(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for svc, patterns in DO_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=f"DigitalOcean {svc}",
                                type="DO Service (CNAME)",
                                source="DigitalOceanCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches DO {svc} pattern '{pat}'",
                                tags=["cloud", "digitalocean", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                if "digitalocean" in ns:
                    findings.append(make_finding(
                        entity="DigitalOcean DNS",
                        type="DO DNS Service (NS)",
                        source="DigitalOceanCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS record {ns} indicates DO DNS",
                        tags=["cloud", "digitalocean", "dns"]
                    ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        if "digitalocean" in server or "do-" in server:
            findings.append(make_finding(
                entity="DigitalOcean (Server Header)",
                type="DO Infrastructure",
                source="DigitalOceanCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server header indicates DO: {server}",
                tags=["cloud", "digitalocean"]
            ))
        if "x-do-" in all_vals or "x-digitalocean-" in all_vals:
            findings.append(make_finding(
                entity="DigitalOcean Headers Present",
                type="DO Service (Header)",
                source="DigitalOceanCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-do-* headers detected",
                tags=["cloud", "digitalocean"]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "digitalocean" in html or "digitalocean" in html:
            findings.append(make_finding(
                entity="DO (HTML Indicator)",
                type="DO Cloud (HTML)",
                source="DigitalOceanCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="DigitalOcean-related content in HTML",
                tags=["cloud", "digitalocean"]
            ))
    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="DO Scan Error",
            source="DigitalOceanCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_do_spaces(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    suffixes = ["", "-data", "-assets", "-backup", "-storage", "-files", "-media", "-public", "-static", "-cdn", "-bucket", "-uploads", "-config", "-logs"]
    for s in suffixes:
        name = f"{base}{s}" if s else base
        for url_tmpl in DO_SPACES_URLS:
            url = url_tmpl.format(name=name)
            try:
                resp = await safe_fetch(client, url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text[:200]
                    is_listing = "ListBucketResult" in body or "<Contents>" in body or "Key>" in body
                    findings.append(make_finding(
                        entity=f"do-spaces://{name}",
                        type="DO Space (Public)",
                        source="DigitalOceanCloudScanner",
                        confidence="High",
                        color="red" if is_listing else "orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical" if is_listing else "Medium",
                        status="Public" + (" + Listing" if is_listing else ""),
                        resolution=url,
                        raw_data=f"DO Space {name} publicly accessible at {url}",
                        tags=["cloud", "digitalocean", "spaces"]
                    ))
                    break
                elif resp.status_code == 403:
                    body = resp.text[:200]
                    if "AccessDenied" in body:
                        findings.append(make_finding(
                            entity=f"do-spaces://{name}",
                            type="DO Space (Exists)",
                            source="DigitalOceanCloudScanner",
                            confidence="High",
                            color="yellow",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Low",
                            status="Exists (Denied)",
                            resolution=url,
                            raw_data=f"DO Space {name} exists but access denied",
                            tags=["cloud", "digitalocean", "spaces"]
                        ))
                        break
            except Exception:
                continue
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    ip, is_ip = await _resolve_target(target)
    if ip is None:
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="DigitalOceanCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="DigitalOceanCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_ip_ranges(ip))
    findings.extend(await _check_dns_services(target))
    findings.extend(await _analyze_headers(target, client))
    findings.extend(await _check_do_spaces(target, client))

    services = sum(1 for f in findings if "DO Service" in f.type)
    do_ip = sum(1 for f in findings if "DO IP Range" in f.type)
    spaces = sum(1 for f in findings if "DO Space" in f.type or "do-spaces" in f.entity)

    findings.append(make_finding(entity=f"DO services detected: {services}", type="DO Service Count", source="DigitalOceanCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "summary"]))
    findings.append(make_finding(entity=f"DO IP match: {'Yes' if do_ip else 'No'}", type="DO Hosting Status", source="DigitalOceanCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "summary"]))
    findings.append(make_finding(entity=f"DO Spaces: {spaces}", type="DO Space Count", source="DigitalOceanCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="DO Scan Target", source="DigitalOceanCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="DO Resolved Address", source="DigitalOceanCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "ip"]))
    findings.append(make_finding(entity=f"Total DO findings: {len(findings)}", type="DO Scan Summary", source="DigitalOceanCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["digitalocean", "summary"]))

    return findings
