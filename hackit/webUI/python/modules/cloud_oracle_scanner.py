import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

OCI_SERVICES = {
    "Compute": ["compute.oraclecloud.com", "oraclecloud.com", ".oci.oraclecloud"],
    "Object Storage": ["objectstorage.oraclecloud.com", "objectstorage.", "oraclecloud.com"],
    "Load Balancer": ["loadbalancer.oraclecloud.com", "lb.oraclecloud"],
    "WAF": ["waf.oraclecloud.com", "waf.oracle"],
    "DNS": ["dns.oraclecloud.com", "ocidns"],
    "MySQL": ["mysql.oraclecloud.com", "mysql.com"],
    "Autonomous DB": ["autonomous.oraclecloud.com", "adb.oraclecloud.com", "oraclecloud.com"],
    "Functions": ["functions.oraclecloud.com", "fn.oraclecloud"],
    "Container Engine": ["containerengine.oraclecloud.com", "oke.oraclecloud"],
    "Streaming": ["streaming.oraclecloud.com"],
    "Email": ["email.oraclecloud.com"],
    "API Gateway": ["apigateway.oraclecloud.com"],
    "Vault": ["vault.oraclecloud.com"],
    "IAM": ["identity.oraclecloud.com"],
}

OCI_REGIONS = {
    "us-phoenix-1": [("129.146.0.0", "129.146.31.255")],
    "us-ashburn-1": [("129.146.64.0", "129.146.95.255")],
    "eu-frankfurt-1": [("129.146.192.0", "129.146.223.255")],
    "uk-london-1": [("138.1.0.0", "138.1.255.255")],
    "ap-mumbai-1": [("129.146.160.0", "129.146.191.255")],
    "ap-sydney-1": [("129.146.128.0", "129.146.159.255")],
    "ap-tokyo-1": [("129.146.96.0", "129.146.127.255")],
    "sa-saopaulo-1": [("134.70.0.0", "134.70.255.255")],
}

OCI_IPS = [
    (("129.146.0.0", "129.146.255.255"), "OCI Global"),
    (("140.91.0.0", "140.91.255.255"), "OCI Global"),
    (("150.136.0.0", "150.136.255.255"), "OCI Global"),
    (("193.122.0.0", "193.122.255.255"), "OCI Global"),
    (("192.29.0.0", "192.29.255.255"), "OCI Global"),
    (("134.70.0.0", "134.70.255.255"), "OCI Global"),
    (("141.147.0.0", "141.147.255.255"), "OCI Global"),
    (("144.24.0.0", "144.24.255.255"), "OCI Global"),
    (("152.67.0.0", "152.67.255.255"), "OCI Global"),
    (("158.178.0.0", "158.178.255.255"), "OCI Global"),
]

OBJECT_STORAGE_URL = "https://objectstorage.{region}.oraclecloud.com/n/{name}/"
OCI_REGION_LIST = [
    "us-phoenix-1", "us-ashburn-1", "us-sanjose-1", "us-chicago-1",
    "eu-frankfurt-1", "uk-london-1", "eu-amsterdam-1", "eu-marseille-1",
    "eu-milan-1", "eu-paris-1", "eu-stockholm-1", "eu-zurich-1",
    "ap-mumbai-1", "ap-osaka-1", "ap-sydney-1", "ap-tokyo-1",
    "ap-seoul-1", "ap-hyderabad-1", "ap-chuncheon-1",
    "sa-saopaulo-1", "sa-santiago-1", "me-jeddah-1", "me-dubai-1",
    "me-abudhabi-1", "af-johannesburg-1",
]

WAF_HEADERS = ["x-oci-waf", "x-oracle-waf"]

LB_HEADERS = ["x-oci-lb", "x-oracle-lb"]

async def _resolve_target(target: str) -> tuple:
    try:
        socket.inet_aton(target)
        return target, True
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, False
    except Exception as e:
        return None, str(e)

async def _check_ip_ranges(ip: str) -> list:
    findings = []
    try:
        parts = ip.split(".")
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except Exception:
        return findings
    for (s, e), region in OCI_IPS:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(IntelligenceFinding(
                    entity=f"OCI {region}",
                    type="OCI IP Range Match",
                    source="OracleCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} falls in OCI range {s}-{e} ({region})",
                    tags=["cloud", "oci", "ip-range"]
                ))
                break
        except Exception:
            continue
    for region, ranges in OCI_REGIONS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(IntelligenceFinding(
                        entity=f"OCI Region: {region}",
                        type="OCI Region Detected (IP)",
                        source="OracleCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to OCI region {region}",
                        tags=["cloud", "oci", "region", region]
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
                for svc, patterns in OCI_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(IntelligenceFinding(
                                entity=f"OCI {svc}",
                                type="OCI Service (CNAME)",
                                source="OracleCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches OCI {svc} pattern '{pat}'",
                                tags=["cloud", "oci", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                if "dynect" in ns or "dyn.com" in ns or "oracle" in ns:
                    findings.append(IntelligenceFinding(
                        entity="Oracle Dyn DNS",
                        type="OCI DNS Service (NS)",
                        source="OracleCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS record {ns} indicates Oracle DNS",
                        tags=["cloud", "oci", "dns"]
                    ))
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                if "oracle" in txt or "oraclecloud" in txt or "_oracle" in txt:
                    findings.append(IntelligenceFinding(
                        entity="Oracle Cloud (TXT)",
                        type="OCI Service (TXT)",
                        source="OracleCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"OCI TXT record: {txt[:100]}",
                        tags=["cloud", "oci"]
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
        resp = await client.get(base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        if "oracle" in server or "oracle" in all_vals:
            findings.append(IntelligenceFinding(
                entity="Oracle Cloud (Server Header)",
                type="OCI Infrastructure",
                source="OracleCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server header indicates OCI: {server}",
                tags=["cloud", "oci"]
            ))
        if "x-oci-" in all_vals:
            findings.append(IntelligenceFinding(
                entity="OCI Headers Present",
                type="OCI Service (Header)",
                source="OracleCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-oci-* headers detected",
                tags=["cloud", "oci"]
            ))
        if "x-oci-request-id" in headers:
            findings.append(IntelligenceFinding(
                entity="OCI Request ID",
                type="OCI Service (Header)",
                source="OracleCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-oci-request-id header present",
                tags=["cloud", "oci"]
            ))
        if "x-oci-region" in headers:
            region = headers.get("x-oci-region", "")
            findings.append(IntelligenceFinding(
                entity=f"OCI Region: {region}",
                type="OCI Region (Header)",
                source="OracleCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=region,
                raw_data=f"OCI region from header: {region}",
                tags=["cloud", "oci", "region", region]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "oracle" in html or "oraclecloud" in html:
            findings.append(IntelligenceFinding(
                entity="OCI (HTML Indicator)",
                type="OCI Cloud (HTML)",
                source="OracleCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="OCI-related content in HTML",
                tags=["cloud", "oci"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="OCI Scan Error",
            source="OracleCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_oci_object_storage(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    suffixes = ["", "-data", "-assets", "-backup", "-storage", "-files", "-public", "-bucket"]
    for s in suffixes:
        name = f"{base}{s}" if s else base
        for region in OCI_REGION_LIST[:5]:
            url = OBJECT_STORAGE_URL.format(region=region, name=name)
            try:
                resp = await client.get(url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 or resp.status_code == 403:
                    status = "Public" if resp.status_code == 200 else "Exists (Denied)"
                    findings.append(IntelligenceFinding(
                        entity=f"oci://{name} ({region})",
                        type="OCI Object Storage",
                        source="OracleCloudScanner",
                        confidence="High",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Medium" if resp.status_code == 200 else "Low",
                        status=status,
                        resolution=url,
                        raw_data=f"OCI Object Storage bucket {name} in {region}: {status}",
                        tags=["cloud", "oci", "object-storage"]
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
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="OracleCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="OracleCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_ip_ranges(ip))
    findings.extend(await _check_dns_services(target))
    findings.extend(await _analyze_headers(target, client))
    findings.extend(await _check_oci_object_storage(target, client))

    services = sum(1 for f in findings if "OCI Service" in f.type or "OCI Infrastructure" in f.type)
    oci_ip = sum(1 for f in findings if "OCI IP Range" in f.type)
    storage = sum(1 for f in findings if "Object Storage" in f.type or "oci://" in f.entity)

    findings.append(IntelligenceFinding(entity=f"OCI services detected: {services}", type="OCI Service Count", source="OracleCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["oci", "summary"]))
    findings.append(IntelligenceFinding(entity=f"OCI IP match: {'Yes' if oci_ip else 'No'}", type="OCI Hosting Status", source="OracleCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["oci", "summary"]))
    findings.append(IntelligenceFinding(entity=f"OCI storage buckets: {storage}", type="OCI Storage Count", source="OracleCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["oci", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="OCI Scan Target", source="OracleCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["oci", "target"]))
    findings.append(IntelligenceFinding(entity=f"Resolved IP: {ip}", type="OCI Resolved Address", source="OracleCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["oci", "ip"]))
    findings.append(IntelligenceFinding(entity=f"Total OCI findings: {len(findings)}", type="OCI Scan Summary", source="OracleCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["oci", "summary"]))

    return findings
