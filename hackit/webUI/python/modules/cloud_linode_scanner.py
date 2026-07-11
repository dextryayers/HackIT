import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

LINODE_SERVICES = {
    "Linodes": ["linode.com", "linodeusercontent.com", ".linode."],
    "Object Storage": ["linodeobjects.com", ".us-east-1.linodeobjects", ".eu-central-1.linodeobjects", ".ap-south-1.linodeobjects"],
    "NodeBalancers": ["linode.com", "nodebalancer", "nb-"],
    "Kubernetes (LKE)": ["k8s.linode.com", "lke.linode.com", ".linode.com"],
    "Databases": ["db.linode.com", "database.linode.com"],
    "DNS Manager": ["ns1.linode.com", "ns2.linode.com", "ns3.linode.com", "ns4.linode.com", "ns5.linode.com"],
    "Block Storage": ["linode.com"],
    "StackScripts": ["linode.com"],
    "Firewall": ["linode.com"],
}

LINODE_REGIONS = {
    "us-east": [("139.162.0.0", "139.162.255.255")],
    "us-central": [("172.104.0.0", "172.104.255.255")],
    "us-west": [("45.56.0.0", "45.56.127.255")],
    "eu-west": [("176.58.0.0", "176.58.127.255")],
    "eu-central": [("185.19.28.0", "185.19.31.255")],
    "ap-northeast": [("45.118.0.0", "45.118.31.255")],
    "ap-south": [("172.105.0.0", "172.105.255.255")],
    "ca-central": [("172.106.0.0", "172.106.255.255")],
}

LINODE_IPS = [
    (("23.92.0.0", "23.92.31.255"), "Linode Newark"),
    (("45.33.0.0", "45.33.127.255"), "Linode Newark"),
    (("45.56.0.0", "45.56.127.255"), "Linode Atlanta"),
    (("45.79.0.0", "45.79.127.255"), "Linode Dallas"),
    (("45.118.0.0", "45.118.31.255"), "Linode Tokyo"),
    (("50.116.0.0", "50.116.63.255"), "Linode Newark"),
    (("66.175.0.0", "66.175.63.255"), "Linode London"),
    (("69.164.0.0", "69.164.31.255"), "Linode Fremont"),
    (("72.14.0.0", "72.14.63.255"), "Linode Atlanta"),
    (("74.207.0.0", "74.207.255.255"), "Linode Fremont"),
    (("85.159.0.0", "85.159.15.255"), "Linode London"),
    (("96.126.0.0", "96.126.63.255"), "Linode Newark"),
    (("97.107.0.0", "97.107.31.255"), "Linode Fremont"),
    (("103.3.60.0", "103.3.63.255"), "Linode Singapore"),
    (("106.187.0.0", "106.187.31.255"), "Linode Tokyo"),
    (("108.61.0.0", "108.61.63.255"), "Linode Newark"),
    (("139.162.0.0", "139.162.255.255"), "Linode Global"),
    (("151.236.0.0", "151.236.31.255"), "Linode London"),
    (("172.104.0.0", "172.104.255.255"), "Linode Global"),
    (("173.230.0.0", "173.230.31.255"), "Linode Fremont"),
    (("173.255.0.0", "173.255.31.255"), "Linode New York"),
    (("176.58.0.0", "176.58.127.255"), "Linode London"),
    (("185.19.28.0", "185.19.31.255"), "Linode Frankfurt"),
    (("192.155.0.0", "192.155.127.255"), "Linode Global"),
    (("192.237.0.0", "192.237.31.255"), "Linode Atlanta"),
]

OBJECT_STORAGE_URLS = [
    "https://{name}.us-east-1.linodeobjects.com",
    "https://{name}.eu-central-1.linodeobjects.com",
    "https://{name}.ap-south-1.linodeobjects.com",
    "https://{name}.us-southeast-1.linodeobjects.com",
]

DNS_MANAGER_NS = ["ns1.linode.com", "ns2.linode.com", "ns3.linode.com", "ns4.linode.com", "ns5.linode.com"]

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
    for (s, e), region in LINODE_IPS:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(make_finding(
                    entity=f"Linode {region}",
                    type="Linode IP Range Match",
                    source="LinodeCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} falls in Linode range {s}-{e} ({region})",
                    tags=["cloud", "linode", "ip-range"]
                ))
                break
        except Exception:
            continue
    for region, ranges in LINODE_REGIONS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(make_finding(
                        entity=f"Linode Region: {region}",
                        type="Linode Region Detected (IP)",
                        source="LinodeCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to Linode region {region}",
                        tags=["cloud", "linode", "region", region]
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
                for svc, patterns in LINODE_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=f"Linode {svc}",
                                type="Linode Service (CNAME)",
                                source="LinodeCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches Linode {svc} pattern '{pat}'",
                                tags=["cloud", "linode", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                if ns in DNS_MANAGER_NS or "linode" in ns:
                    findings.append(make_finding(
                        entity="Linode DNS Manager",
                        type="Linode DNS Service (NS)",
                        source="LinodeCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS record {ns} indicates Linode DNS Manager",
                        tags=["cloud", "linode", "dns"]
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

        if "linode" in server or "linode" in all_vals:
            findings.append(make_finding(
                entity="Linode (Server Header)",
                type="Linode Infrastructure",
                source="LinodeCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server header indicates Linode: {server}",
                tags=["cloud", "linode"]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "linode" in html or "linodeusercontent" in html:
            findings.append(make_finding(
                entity="Linode (HTML Indicator)",
                type="Linode Cloud (HTML)",
                source="LinodeCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="Linode-related content in HTML",
                tags=["cloud", "linode"]
            ))
    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Linode Scan Error",
            source="LinodeCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_linode_object_storage(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    suffixes = ["", "-data", "-assets", "-backup", "-storage", "-files", "-media", "-public", "-bucket"]
    for s in suffixes:
        name = f"{base}{s}" if s else base
        for url_tmpl in OBJECT_STORAGE_URLS:
            url = url_tmpl.format(name=name)
            try:
                resp = await safe_fetch(client, url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text[:200]
                    is_listing = "ListBucketResult" in body or "<Contents>" in body
                    findings.append(make_finding(
                        entity=f"linode-obj://{name}",
                        type="Linode Object Storage (Public)",
                        source="LinodeCloudScanner",
                        confidence="High",
                        color="red" if is_listing else "orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical" if is_listing else "Medium",
                        status="Public" + (" + Listing" if is_listing else ""),
                        resolution=url,
                        raw_data=f"Linode Object Storage {name} is publicly accessible at {url}",
                        tags=["cloud", "linode", "object-storage"]
                    ))
                    break
                elif resp.status_code == 403:
                    findings.append(make_finding(
                        entity=f"linode-obj://{name}",
                        type="Linode Object Storage (Exists)",
                        source="LinodeCloudScanner",
                        confidence="High",
                        color="yellow",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Low",
                        status="Exists (Denied)",
                        resolution=url,
                        raw_data=f"Linode Object Storage {name} exists but access denied",
                        tags=["cloud", "linode", "object-storage"]
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="LinodeCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="LinodeCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_ip_ranges(ip))
    findings.extend(await _check_dns_services(target))
    findings.extend(await _analyze_headers(target, client))
    findings.extend(await _check_linode_object_storage(target, client))

    services = sum(1 for f in findings if "Linode Service" in f.type)
    linode_ip = sum(1 for f in findings if "Linode IP Range" in f.type)
    storage = sum(1 for f in findings if "Object Storage" in f.type or "linode-obj" in f.entity)

    findings.append(make_finding(entity=f"Linode services detected: {services}", type="Linode Service Count", source="LinodeCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["linode", "summary"]))
    findings.append(make_finding(entity=f"Linode IP match: {'Yes' if linode_ip else 'No'}", type="Linode Hosting Status", source="LinodeCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["linode", "summary"]))
    findings.append(make_finding(entity=f"Linode object storage: {storage}", type="Linode Storage Count", source="LinodeCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["linode", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="Linode Scan Target", source="LinodeCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["linode", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="Linode Resolved Address", source="LinodeCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["linode", "ip"]))
    findings.append(make_finding(entity=f"Total Linode findings: {len(findings)}", type="Linode Scan Summary", source="LinodeCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["linode", "summary"]))

    return findings
