import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip, is_ip
from models import IntelligenceFinding

CDN_PROVIDERS = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-connecting-ip", "cf-request-id", "cf-wan", "cf-edge"],
        "server": ["cloudflare"],
        "cname": [".cloudflare.net", ".cloudflare.com"],
        "ip_ranges": [("104.16.0.0", "104.31.255.255"), ("172.64.0.0", "172.71.255.255"), ("141.101.0.0", "141.101.255.255")],
        "asn": ["AS13335"],
        "color": "orange"
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id", "x-akamai-request-id"],
        "server": ["akamai", "akamaighost"],
        "cname": [".akamaiedge.net", ".edgesuite.net", ".edgekey.net", ".akamaiedge-staging.net"],
        "ip_ranges": [("23.0.0.0", "23.79.255.255"), ("2.16.0.0", "2.23.255.255")],
        "asn": ["AS16625", "AS20940", "AS21342", "AS36183"],
        "color": "orange"
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "x-served-by", "x-cache-hits", "x-cache", "x-timer"],
        "server": ["fastly"],
        "cname": [".fastly.net", ".fastlylb.net", ".fastly-edge.com"],
        "ip_ranges": [("151.101.0.0", "151.101.255.255"), ("199.27.128.0", "199.27.159.255")],
        "asn": ["AS54113"],
        "color": "orange"
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-ip"],
        "server": ["cloudfront", "amazon"],
        "cname": [".cloudfront.net"],
        "ip_ranges": [("13.32.0.0", "13.35.255.255"), ("54.182.0.0", "54.182.255.255"), ("52.84.0.0", "52.87.255.255"), ("205.251.192.0", "205.251.255.255")],
        "asn": ["AS16509"],
        "color": "orange"
    },
    "Azure CDN": {
        "headers": ["x-azure-ref", "x-azure-fd"],
        "server": ["azure"],
        "cname": [".azureedge.net", ".azurefd.net", ".trafficmanager.net"],
        "ip_ranges": [("13.64.0.0", "13.107.255.255"), ("20.0.0.0", "20.255.255.255")],
        "asn": ["AS8075", "AS8068"],
        "color": "orange"
    },
    "GCP CDN": {
        "headers": ["x-gfe-", "x-google-"],
        "server": ["gfe", "google"],
        "cname": [".cdn.google", ".google.com"],
        "ip_ranges": [("34.0.0.0", "34.255.255.255"), ("35.184.0.0", "35.255.255.255")],
        "asn": ["AS15169"],
        "color": "orange"
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache", "x-vercel-request-id"],
        "server": ["vercel"],
        "cname": [".vercel.app", ".now.sh"],
        "ip_ranges": [("76.76.21.0", "76.76.21.255")],
        "asn": [],
        "color": "orange"
    },
    "Netlify": {
        "headers": ["x-nf-request-id", "x-ns-server", "x-nf-route"],
        "server": ["netlify"],
        "cname": [".netlify.app", ".netlify.com"],
        "ip_ranges": [("75.2.0.0", "75.2.255.255"), ("99.83.0.0", "99.83.255.255")],
        "asn": [],
        "color": "orange"
    },
    "KeyCDN": {
        "headers": ["x-keycdn"],
        "server": ["keycdn"],
        "cname": [".kxcdn.com", ".keycdn.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "BunnyCDN": {
        "headers": ["x-bunnycdn"],
        "server": ["bunnycdn", "bunny"],
        "cname": [".b-cdn.net", ".bunnycdn.com", ".bunny.net"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "StackPath": {
        "headers": ["x-stackpath-id"],
        "server": ["stackpath"],
        "cname": [".stackpath.com", ".stackpathdns.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "CacheFly": {
        "headers": ["x-cachefly"],
        "server": ["cachefly"],
        "cname": [".cachefly.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "Section.io": {
        "headers": ["x-section"],
        "server": ["section"],
        "cname": [".section.io"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "BelugaCDN": {
        "headers": ["x-belugacdn"],
        "server": ["belugacdn"],
        "cname": [".belugacdn.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "Incapsula": {
        "headers": ["x-request-id", "x-iinfo", "x-cdn"],
        "server": ["incapsula"],
        "cname": [".incapsula.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "cname": [".sucuri.net"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "G-Core": {
        "headers": [],
        "server": ["gcore"],
        "cname": [".gcdn.co", ".gcore.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
    "OVH CDN": {
        "headers": [],
        "server": ["ovh"],
        "cname": [".ovh.net", ".ovh.com"],
        "ip_ranges": [],
        "asn": [],
        "color": "orange"
    },
}

async def _resolve_target(target: str) -> tuple:
    t = target.strip()
    if is_ip(t):
        return t, True
    ip = resolve_ip(t)
    if ip:
        return ip, False
    return None, "DNS resolution failed"

async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "").lower()
        all_vals = " ".join(str(v).lower() for v in headers.values())

        detected_cdns = []
        for name, config in CDN_PROVIDERS.items():
            found = False
            for h in config["headers"]:
                if h in headers:
                    found = True
                    break
            if not found and config["server"]:
                for s in config["server"]:
                    if s in server:
                        found = True
                        break
            if found:
                detected_cdns.append(name)
                findings.append(make_finding(
                    entity=name,
                    type="CDN Detected (Header)",
                    source="MultiCDNFinder",
                    confidence="High",
                    color=config["color"],
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"{name} CDN detected via headers. Server: {server}",
                    tags=["cdn", name.lower().replace(" ", "-")]
                ))

        if len(detected_cdns) > 1:
            findings.append(make_finding(
                entity=f"Multi-CDN detected: {', '.join(detected_cdns)}",
                type="Multi-CDN Configuration",
                source="MultiCDNFinder",
                confidence="High",
                color="purple",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"{len(detected_cdns)} CDNs detected: {', '.join(detected_cdns)}",
                tags=["cdn", "multi-cdn"]
            ))

        if "via" in headers:
            via = headers["via"]
            findings.append(make_finding(
                entity=f"Via: {via[:200]}",
                type="CDN Hop (Via Header)",
                source="MultiCDNFinder",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Via header: {via}",
                tags=["cdn", "via", "hop"]
            ))

        if "x-cache" in headers:
            xcache = headers["x-cache"]
            findings.append(make_finding(
                entity=f"X-Cache: {xcache}",
                type="CDN Cache Status",
                source="MultiCDNFinder",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Cache status: {xcache}",
                tags=["cdn", "cache"]
            ))

        if "x-served-by" in headers:
            served = headers["x-served-by"]
            findings.append(make_finding(
                entity=f"Served-By: {served}",
                type="CDN Edge Node",
                source="MultiCDNFinder",
                confidence="Medium",
                color="slate",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Detected",
                resolution=served,
                raw_data=f"Edge node: {served}",
                tags=["cdn", "edge"]
            ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="CDN Scan Error",
            source="MultiCDNFinder",
            confidence="Low",
            color="red",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings

async def _check_dns_cname(target: str) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for name, config in CDN_PROVIDERS.items():
                    for cname_pat in config.get("cname", []):
                        if cname_pat in cname:
                            findings.append(make_finding(
                                entity=f"{name} (CNAME: {cname})",
                                type="CDN Detected (CNAME)",
                                source="MultiCDNFinder",
                                confidence="High",
                                color=config["color"],
                                category="Cloud / Infrastructure OSINT",
                                threat_level="Informational",
                                status="Verified",
                                resolution=cname,
                                raw_data=f"CNAME chain: {target} -> {cname} ({name})",
                                tags=["cdn", name.lower().replace(" ", "-"), "cname"]
                            ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

async def _check_ip_range(ip: str) -> list:
    findings = []
    try:
        parts = ip.split(".")
        ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except Exception:
        return findings
    for name, config in CDN_PROVIDERS.items():
        for (s, e) in config.get("ip_ranges", []):
            try:
                sp = s.split("."); ep = e.split(".")
                si = (int(sp[0])<<24)+(int(sp[1])<<16)+(int(sp[2])<<8)+int(sp[3])
                ei = (int(ep[0])<<24)+(int(ep[1])<<16)+(int(ep[2])<<8)+int(ep[3])
                if si <= ip_int <= ei:
                    findings.append(make_finding(
                        entity=f"{name} (IP Range)",
                        type="CDN Detected (IP Range)",
                        source="MultiCDNFinder",
                        confidence="High",
                        color="orange",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Informational",
                        status="Verified",
                        resolution=ip,
                        raw_data=f"IP {ip} falls within {name} range",
                        tags=["cdn", name.lower().replace(" ", "-"), "ip-range"]
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
        findings.append(make_finding(entity=f"DNS resolution failed: {target}", type="DNS Error", source="MultiCDNFinder", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", raw_data=str(is_ip)[:200], tags=["error"]))
        return findings

    if not is_ip:
        findings.append(make_finding(entity=f"{target} -> {ip}", type="DNS Resolution", source="MultiCDNFinder", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Resolved", resolution=ip, tags=["dns", "resolution"]))

    findings.extend(await _check_ip_range(ip))
    findings.extend(await _check_dns_cname(target))
    findings.extend(await _analyze_headers(target, client))

    cdns_found = set(f.entity for f in findings if f.type in ("CDN Detected (Header)", "CDN Detected (CNAME)", "CDN Detected (IP Range)"))
    primary_cdn = cdns_found.pop() if cdns_found else "None detected"
    if cdns_found:
        cdns_found.add(primary_cdn)

    findings.append(make_finding(entity=f"Primary CDN: {primary_cdn}", type="CDN: Primary", source="MultiCDNFinder", confidence="High", color="purple", category="Cloud / Infrastructure OSINT", threat_level="Informational", status="Identified", tags=["cdn", "primary"]))
    findings.append(make_finding(entity=f"Total CDNs detected: {len(cdns_found)}", type="CDN: Total Count", source="MultiCDNFinder", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["cdn", "count"]))
    findings.append(make_finding(entity=f"Target: {target}", type="CDN Scan Target", source="MultiCDNFinder", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["cdn", "target"]))
    findings.append(make_finding(entity=f"Resolved IP: {ip}", type="CDN Resolved IP", source="MultiCDNFinder", confidence="High", color="slate", category="Cloud / Infrastructure OSINT", tags=["cdn", "ip"]))
    findings.append(make_finding(entity=f"Total CDN findings: {len(findings)}", type="CDN Scan Summary", source="MultiCDNFinder", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["cdn", "summary"]))

    return findings
