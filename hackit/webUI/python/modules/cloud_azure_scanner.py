import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

AZURE_SERVICES = {
    "App Service": ["azurewebsites.net", "azurewebsites.", "appservice"],
    "VMs": [".cloudapp.net", "azure.com", "azure-api.net"],
    "Functions": ["azurewebsites.net", "azurefd.net", "functions"],
    "AKS": ["azmk8s.io", "aks-", "azmk8s"],
    "Blob Storage": ["blob.core.windows.net", "blob.core.usgovcloudapi.net"],
    "CDN": ["azureedge.net", "azurefd.net", "azureedge"],
    "Traffic Manager": ["trafficmanager.net"],
    "Front Door": ["azurefd.net", "frontdoor"],
    "API Management": ["azure-api.net", "apim", "management.azure.com"],
    "SQL Database": ["database.windows.net", "azure.com"],
    "Cosmos DB": ["documents.azure.com", "cosmos.azure"],
    "Redis Cache": ["redis.cache.windows.net"],
    "Service Bus": ["servicebus.windows.net"],
    "SignalR": ["signalr.net"],
    "Logic Apps": ["logic.azure.com"],
    "Event Grid": ["eventgrid.azure.net"],
    "Event Hubs": ["eventhub.net"],
    "Cognitive Services": ["cognitiveservices.azure.com"],
    "Key Vault": ["vault.azure.net"],
    "Search": ["search.windows.net"],
    "Batch": ["batch.azure.com"],
    "Data Lake": ["datalake.azure.net", "adls"],
    "Analysis Services": ["asazure.windows.net"],
}

AZURE_REGIONS = {
    "eastus": [("20.0.0.0", "20.31.255.255")],
    "westus": [("40.64.0.0", "40.79.255.255")],
    "westeurope": [("52.128.0.0", "52.143.255.255")],
    "northeurope": [("52.144.0.0", "52.159.255.255")],
    "southeastasia": [("52.160.0.0", "52.175.255.255")],
    "eastasia": [("52.176.0.0", "52.191.255.255")],
    "japaneast": [("52.192.0.0", "52.207.255.255")],
    "brazilsouth": [("52.64.0.0", "52.79.255.255")],
}

AZURE_HEADER_SIGS = ["x-ms-", "x-azure-", "azure", "kestrel"]

AZURE_BLOB_URLS = [
    "https://{name}.blob.core.windows.net",
    "https://{name}.blob.core.windows.net/?restype=container&comp=list",
    "https://{name}storage.blob.core.windows.net",
    "https://{name}data.blob.core.windows.net",
    "https://{name}assets.blob.core.windows.net",
    "https://{name}backup.blob.core.windows.net",
    "https://{name}logs.blob.core.windows.net",
    "https://{name}config.blob.core.windows.net",
]

WAF_HEADERS = ["x-azure-waf", "x-ms-waf", "application-gateway"]

FRONTDOOR_HEADERS = ["x-azure-fd", "x-azure-ref", "azurefd"]

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
    azure_ranges = [
        (("13.64.0.0", "13.107.255.255"), "Azure Global"),
        (("20.0.0.0", "20.255.255.255"), "Azure Global"),
        (("23.96.0.0", "23.99.255.255"), "Azure Global"),
        (("40.64.0.0", "40.127.255.255"), "Azure Global"),
        (("52.128.0.0", "52.255.255.255"), "Azure Global"),
        (("65.52.0.0", "65.55.255.255"), "Azure Global"),
        (("104.208.0.0", "104.215.255.255"), "Azure Global"),
        (("137.116.0.0", "137.135.255.255"), "Azure Global"),
        (("4.0.0.0", "4.255.255.255"), "Azure Global"),
        (("51.0.0.0", "51.255.255.255"), "Azure Global"),
        (("102.0.0.0", "102.255.255.255"), "Azure Global"),
        (("168.0.0.0", "168.255.255.255"), "Azure Global"),
    ]
    for (s, e), region in azure_ranges:
        try:
            sp = s.split("."); ep = e.split(".")
            si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
            ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
            if si <= ip_int <= ei:
                findings.append(IntelligenceFinding(
                    entity=f"Azure {region}",
                    type="Azure IP Range Match",
                    source="AzureCloudScanner",
                    confidence="High",
                    color="orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Verified",
                    resolution=ip,
                    raw_data=f"IP {ip} falls in Azure range {s}-{e} ({region})",
                    tags=["cloud", "azure", "ip-range"]
                ))
                break
        except Exception:
            continue
    for region, ranges in AZURE_REGIONS.items():
        for (s, e) in ranges:
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(IntelligenceFinding(
                        entity=f"Azure Region: {region}",
                        type="Azure Region Detected (IP)",
                        source="AzureCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ip,
                        raw_data=f"IP {ip} maps to Azure region {region}",
                        tags=["cloud", "azure", "region", region]
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
                for svc, patterns in AZURE_SERVICES.items():
                    for pat in patterns:
                        if pat in cname:
                            findings.append(IntelligenceFinding(
                                entity=f"Azure {svc}",
                                type="Azure Service (CNAME)",
                                source="AzureCloudScanner",
                                confidence="High",
                                color="purple",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME {cname} matches Azure {svc} pattern '{pat}'",
                                tags=["cloud", "azure", svc.lower().replace(" ", "-")]
                            ))
                            break
        except Exception:
            pass
        try:
            answers_ns = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
            for r in answers_ns:
                ns = str(r.target).rstrip('.').lower()
                if "azure-dns" in ns or "azure.com" in ns:
                    findings.append(IntelligenceFinding(
                        entity="Azure DNS",
                        type="Azure DNS Service (NS)",
                        source="AzureCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS record {ns} indicates Azure DNS",
                        tags=["cloud", "azure", "dns"]
                    ))
        except Exception:
            pass
        try:
            answers_txt = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'TXT'))
            for r in answers_txt:
                txt = str(r).lower()
                if "ms=" in txt or "microsoft" in txt or "outlook" in txt:
                    findings.append(IntelligenceFinding(
                        entity="Microsoft 365 / Azure (TXT)",
                        type="Azure Service (TXT)",
                        source="AzureCloudScanner",
                        confidence="High",
                        color="blue",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=f"Azure/M365 TXT record: {txt[:100]}",
                        tags=["cloud", "azure", "m365"]
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

        if "kestrel" in server:
            findings.append(IntelligenceFinding(
                entity="Azure App Service (Kestrel)",
                type="Azure Service (Header)",
                source="AzureCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Active",
                raw_data=f"Kestrel server header: {server}",
                tags=["cloud", "azure", "app-service"]
            ))
        if "azure" in server or "azure" in all_vals:
            findings.append(IntelligenceFinding(
                entity="Azure (Server Header)",
                type="Azure Infrastructure",
                source="AzureCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Server header indicates Azure: {server}",
                tags=["cloud", "azure"]
            ))
        if "x-ms-" in all_vals:
            findings.append(IntelligenceFinding(
                entity="Azure Headers Present",
                type="Azure Service (Header)",
                source="AzureCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-ms-* headers detected indicating Azure",
                tags=["cloud", "azure"]
            ))
        if "x-ms-request-id" in headers:
            findings.append(IntelligenceFinding(
                entity="Azure Request ID Present",
                type="Azure Service (Header)",
                source="AzureCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data="x-ms-request-id header present",
                tags=["cloud", "azure"]
            ))
        if "x-ms-region" in headers:
            region = headers.get("x-ms-region", "")
            findings.append(IntelligenceFinding(
                entity=f"Azure Region: {region}",
                type="Azure Region (Header)",
                source="AzureCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=region,
                raw_data=f"Azure region from header: {region}",
                tags=["cloud", "azure", "region", region]
            ))
        if "x-azure-ref" in headers:
            ref = headers.get("x-azure-ref", "")
            findings.append(IntelligenceFinding(
                entity=f"Azure Front Door Ref: {ref[:30]}",
                type="Azure Front Door",
                source="AzureCloudScanner",
                confidence="High",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=ref[:50],
                raw_data=f"Azure Front Door detected: {ref}",
                tags=["cloud", "azure", "front-door"]
            ))
        if "x-azure-fd" in headers:
            fd = headers.get("x-azure-fd", "")
            findings.append(IntelligenceFinding(
                entity=f"Azure Front Door Edge: {fd}",
                type="Azure Front Door Edge",
                source="AzureCloudScanner",
                confidence="High",
                color="blue",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=fd,
                raw_data=f"Azure Front Door edge location: {fd}",
                tags=["cloud", "azure", "front-door", "edge"]
            ))
        html = resp.text[:50000].lower() if hasattr(resp, "text") else ""
        if "azure" in html or "microsoft" in html or "msapplication" in html:
            findings.append(IntelligenceFinding(
                entity="Azure (HTML Indicator)",
                type="Azure Cloud (HTML)",
                source="AzureCloudScanner",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Suspected",
                raw_data="Azure-related content in HTML",
                tags=["cloud", "azure"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Azure Scan Error",
            source="AzureCloudScanner",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_azure_blob(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        return findings
    suffixes = ["", "storage", "data", "assets", "backup", "logs", "config", "media", "files", "public", "app", "web", "archive", "cdn", "db", "cache"]
    for s in suffixes:
        name = f"{base}{s}" if s else base
        if not name or len(name) < 3:
            continue
        for tmpl in AZURE_BLOB_URLS:
            url = tmpl.format(name=name)
            try:
                resp = await client.get(url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text[:300]
                    is_listing = "Blobs" in body or "EnumerationResults" in body or "Container" in body
                    findings.append(IntelligenceFinding(
                        entity=f"azure-blob://{name}",
                        type="Azure Blob Container (Public)",
                        source="AzureCloudScanner",
                        confidence="High",
                        color="red" if is_listing else "orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical" if is_listing else "Medium",
                        status="Public" + (" + Listing" if is_listing else ""),
                        resolution=url,
                        raw_data=f"Azure Blob {name} is publicly accessible at {url}",
                        tags=["cloud", "azure", "blob", "storage"]
                    ))
                    break
                elif resp.status_code == 403:
                    body = resp.text[:200]
                    if "AccessDenied" in body or "access_denied" in body.lower() or "ResourceNotFound" in body:
                        if "ResourceNotFound" not in body:
                            findings.append(IntelligenceFinding(
                                entity=f"azure-blob://{name}",
                                type="Azure Blob Container (Exists)",
                                source="AzureCloudScanner",
                                confidence="High",
                                color="yellow",
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Low",
                                status="Exists (Denied)",
                                resolution=url,
                                raw_data=f"Azure Blob {name} exists but access denied",
                                tags=["cloud", "azure", "blob", "storage"]
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
        findings.append(IntelligenceFinding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="AzureCloudScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(IntelligenceFinding(entity=f"{target} -> {ip}", type="DNS Resolution", source="AzureCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    ip_findings = await _check_ip_ranges(ip)
    findings.extend(ip_findings)

    dns_findings = await _check_dns_services(target)
    findings.extend(dns_findings)

    header_findings = await _analyze_headers(target, client)
    findings.extend(header_findings)

    blob_findings = await _check_azure_blob(target, client)
    findings.extend(blob_findings)

    services = sum(1 for f in findings if "Azure Service" in f.type)
    infra = sum(1 for f in findings if "Azure Infrastructure" in f.type or "Azure IP Range" in f.type)
    blobs = sum(1 for f in findings if "Blob" in f.type or "azure-blob" in f.entity)

    findings.append(IntelligenceFinding(entity=f"Azure services detected: {services}", type="Azure Service Count", source="AzureCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["azure", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Azure infrastructure indicators: {infra}", type="Azure Infrastructure Count", source="AzureCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["azure", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Azure Blob containers: {blobs}", type="Azure Blob Count", source="AzureCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["azure", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Azure hosted: {'Yes' if any('Azure IP Range' in f.type for f in findings) else 'No'}", type="Azure Hosting Status", source="AzureCloudScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["azure", "summary"]))
    findings.append(IntelligenceFinding(entity=f"Target: {target}", type="Azure Scan Target", source="AzureCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["azure", "target"]))
    findings.append(IntelligenceFinding(entity=f"Resolved IP: {ip}", type="Azure Resolved Address", source="AzureCloudScanner", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["azure", "ip"]))
    findings.append(IntelligenceFinding(entity=f"Total Azure findings: {len(findings)}", type="Azure Scan Summary", source="AzureCloudScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["azure", "summary"]))

    return findings
