import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

GCP_SERVICES = {
    "Compute Engine": ["compute.googleapis.com", "gce", ".compute."],
    "App Engine": ["appengine.google.com", "appspot.com", ".appspot."],
    "Cloud Run": ["run.app", "cloudrun", "run.googleapis.com"],
    "Cloud Functions": ["cloudfunctions.net", "cloudfunctions.googleapis.com"],
    "GKE": ["gke.googleapis.com", "container.googleapis.com", "gke"],
    "Cloud Storage": ["storage.googleapis.com", "storage.cloud.google.com"],
    "Cloud CDN": ["cloudcdn", "cdn.cloud.google"],
    "Cloud Load Balancing": ["loadbalancer", "lb.googleapis.com", "googleapis.com"],
    "Cloud SQL": ["sql.googleapis.com", "cloudsql"],
    "Firestore": ["firestore.googleapis.com", "firestore"],
    "BigQuery": ["bigquery.googleapis.com", "bigquery"],
    "Cloud DNS": ["dns.google", "dns.googleapis.com", "googledomains"],
    "Cloud KMS": ["kms.googleapis.com"],
    "Cloud Armor": ["armor.googleapis.com", "cloudarmor"],
    "Cloud Scheduler": ["scheduler.googleapis.com"],
    "Cloud Tasks": ["cloudtasks.googleapis.com"],
    "Cloud Memorystore": ["memorystore.googleapis.com"],
    "Cloud Spanner": ["spanner.googleapis.com"],
}

GCP_REGION_IPS = {
    "us-central1": [("34.0.0.0", "34.31.255.255")],
    "us-east1": [("34.64.0.0", "34.71.255.255")],
    "us-west1": [("34.72.0.0", "34.79.255.255")],
    "europe-west1": [("34.140.0.0", "34.147.255.255")],
    "europe-west2": [("35.188.0.0", "35.191.255.255")],
    "asia-east1": [("34.80.0.0", "34.87.255.255")],
    "asia-northeast1": [("34.88.0.0", "34.95.255.255")],
    "asia-southeast1": [("34.96.0.0", "34.103.255.255")],
}

GCP_HEADER_SIGS = ["gfe", "google", "google-cloud", "x-google-", "x-gfe-"]

GCP_STORAGE_URLS = [
    "https://storage.googleapis.com/{name}",
    "https://{name}.storage.googleapis.com",
    "https://storage.cloud.google.com/{name}",
]

COMMON_BUCKET_SUFFIXES = [
    "", "-data", "-assets", "-backup", "-storage", "-files", "-media",
    "-config", "-logs", "-public", "-private", "-app", "-web", "-bucket",
    "-resources", "-static", "-uploads", "-archive", "-cdn", "-db",
]

CLOUD_ARMOR_HEADERS = ["x-goog-armor", "x-cloud-armor", "x-gfe-"]

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
    gcp_ranges = [
        (("8.34.0.0", "8.35.255.255"), "GCP US"),
        (("23.236.0.0", "23.236.255.255"), "GCP US"),
        (("34.0.0.0", "34.255.255.255"), "GCP Global"),
        (("35.184.0.0", "35.255.255.255"), "GCP Global"),
        (("104.154.0.0", "104.199.255.255"), "GCP Global"),
        (("107.167.0.0", "107.167.255.255"), "GCP Global"),
        (("108.59.80.0", "108.59.95.255"), "GCP Global"),
        (("130.211.0.0", "130.211.255.255"), "GCP Global"),
        (("146.148.0.0", "146.148.255.255"), "GCP Global"),
        (("35.216.0.0", "35.255.255.255"), "GCP Global"),
    ]
    for (s, e), region in gcp_ranges:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(make_finding(
                    entity=f"GCP {region}",
                    type="GCP IP Range Match",
                    source="GCPCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} falls in GCP range {s}-{e} ({region})",
                    tags=["cloud", "gcp", "ip-range"]
                ))
                break
        except Exception:
            continue
    for region, ranges in GCP_REGION_IPS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(make_finding(
                        entity=f"GCP Region: {region}",
                        type="GCP Region Detected (IP)",
                        source="GCPCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to GCP region {region}",
                        tags=["cloud", "gcp", "region", region]
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
                for svc, patterns in GCP_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(make_finding(
                                entity=f"GCP {svc}",
                                type="GCP Service (CNAME)",
                                source="GCPCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches GCP {svc} pattern '{pat}'",
                                tags=["cloud", "gcp", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                if "google" in ns or "googledomains" in ns or "dns.google" in ns:
                    findings.append(make_finding(
                        entity="Google Cloud DNS",
                        type="GCP DNS Service (NS)",
                        source="GCPCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS record {ns} indicates Google Cloud DNS",
                        tags=["cloud", "gcp", "dns"]
                    ))
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                if "google-site-verification" in txt:
                    findings.append(make_finding(
                        entity="Google Workspace Verified",
                        type="GCP Service (TXT)",
                        source="GCPCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Verified",
                        raw_data=f"Google site verification TXT: {txt[:100]}",
                        tags=["cloud", "gcp", "workspace"]
                    ))
                if "_spf.google.com" in txt or "_spf.google.com" in txt:
                    findings.append(make_finding(
                        entity="Google Workspace (SPF)",
                        type="GCP Service (TXT)",
                        source="GCPCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Google Workspace SPF in TXT: {txt[:100]}",
                        tags=["cloud", "gcp", "workspace"]
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
        via = headers.get("via", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        if "gfe" in server or "gfe" in all_vals:
            findings.append(make_finding(
                entity="Google Front End (GFE)",
                type="GCP Service (Header)",
                source="GCPCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"Google Front End detected via header. Server: {server}",
                tags=["cloud", "gcp", "gfe"]
            ))
        if "google" in server or "google" in via:
            findings.append(make_finding(
                entity="Google Cloud (Server Header)",
                type="GCP Infrastructure",
                source="GCPCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server/Via header indicates Google: {server} / {via}",
                tags=["cloud", "gcp"]
            ))
        if "x-google-" in all_vals or "x-gfe-" in all_vals:
            findings.append(make_finding(
                entity="Google Cloud Headers Present",
                type="GCP Service (Header)",
                source="GCPCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-google-* or x-gfe-* headers detected",
                tags=["cloud", "gcp"]
            ))
        if "x-gfe-request-id" in headers:
            findings.append(make_finding(
                entity="GFE Request ID Present",
                type="GCP Service (Header)",
                source="GCPCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-gfe-request-id header present - Google Front End",
                tags=["cloud", "gcp"]
            ))
        if "x-cloud-trace-context" in headers:
            findings.append(make_finding(
                entity="Cloud Trace Context",
                type="GCP Service (Header)",
                source="GCPCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-cloud-trace-context header present - GCP Cloud Trace",
                tags=["cloud", "gcp", "cloud-trace"]
            ))
        if server in ("", "-") and "google" in via:
            findings.append(make_finding(
                entity="Google Cloud (Serverless)",
                type="GCP Serverless",
                source="GCPCloudScanner",
                confidence="Medium",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data=f"Empty server header with Google via: {via}",
                tags=["cloud", "gcp", "serverless"]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "googleapis" in html or "gstatic" in html or "googlecloud" in html:
            findings.append(make_finding(
                entity="GCP (HTML Indicator)",
                type="GCP Cloud (HTML)",
                source="GCPCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="GCP-related content in HTML source",
                tags=["cloud", "gcp"]
            ))
    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="GCP Scan Error",
            source="GCPCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_gcp_storage(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    buckets = [f"{base}{s}" for s in COMMON_BUCKET_SUFFIXES]
    for b in buckets:
        if not b or len(b) < 3:
            continue
        for tmpl in GCP_STORAGE_URLS:
            url = tmpl.format(name=b)
            try:
                resp = await safe_fetch(client, url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text[:300]
                    is_listing = "ListBucketResult" in body or "<Contents>" in body or "storage" in body.lower()
                    findings.append(make_finding(
                        entity=f"gcs://{b}",
                        type="GCP Storage Bucket (Public)",
                        source="GCPCloudScanner",
                        confidence="High",
                        color="red" if is_listing else "orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical" if is_listing else "Medium",
                        status="Public" + (" + Listing" if is_listing else ""),
                        resolution=url,
                        raw_data=f"GCS bucket {b} publicly accessible at {url}",
                        tags=["cloud", "gcp", "storage", "bucket"]
                    ))
                    break
                elif resp.status_code == 403:
                    body = resp.text[:200]
                    if "AccessDenied" in body or "access_denied" in body.lower():
                        findings.append(make_finding(
                            entity=f"gcs://{b}",
                            type="GCP Storage Bucket (Exists)",
                            source="GCPCloudScanner",
                            confidence="High",
                            color="yellow",
                            category="Cloud / Infrastructure OSINT",
                            threat_level="Low",
                            status="Exists (Denied)",
                            resolution=url,
                            raw_data=f"GCS bucket {b} exists but access denied",
                            tags=["cloud", "gcp", "storage", "bucket"]
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="GCPCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="GCPCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    ip_findings = await _check_ip_ranges(ip)
    findings.extend(ip_findings)

    dns_findings = await _check_dns_services(target)
    findings.extend(dns_findings)

    header_findings = await _analyze_headers(target, client)
    findings.extend(header_findings)

    storage_findings = await _check_gcp_storage(target, client)
    findings.extend(storage_findings)

    gcp_services = sum(1 for f in findings if "GCP Service" in f.type or "GCP Serverless" in f.type)
    gcp_infra = sum(1 for f in findings if "GCP Infrastructure" in f.type or "GCP IP Range" in f.type)
    gcp_storage = sum(1 for f in findings if "Storage" in f.entity or "gcs://" in f.entity)

    findings.append(make_finding(entity=f"GCP services detected: {gcp_services}", type="GCP Service Count", source="GCPCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["gcp", "summary"]))
    findings.append(make_finding(entity=f"GCP infrastructure indicators: {gcp_infra}", type="GCP Infrastructure Count", source="GCPCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["gcp", "summary"]))
    findings.append(make_finding(entity=f"GCP storage buckets: {gcp_storage}", type="GCP Storage Count", source="GCPCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["gcp", "summary"]))
    findings.append(make_finding(entity=f"GCP hosted: {'Yes' if any('GCP IP Range' in f.type for f in findings) else 'No'}", type="GCP Hosting Status", source="GCPCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["gcp", "summary"]))
    findings.append(make_finding(entity=f"Target: {target}", type="GCP Scan Target", source="GCPCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["gcp", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="GCP Resolved Address", source="GCPCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["gcp", "ip"]))
    findings.append(make_finding(entity=f"Total GCP findings: {len(findings)}", type="GCP Scan Summary", source="GCPCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["gcp", "summary"]))

    return findings
