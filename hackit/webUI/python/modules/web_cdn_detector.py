import re
import asyncio
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

CDN_HEADERS = {
    "via": "Generic CDN",
    "x-cache": "Generic CDN",
    "x-cache-hits": "Generic CDN",
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "cf-request-id": "Cloudflare",
    "server": "Generic CDN",
    "x-served-by": "Generic CDN",
    "x-amz-cf-pop": "CloudFront",
    "x-amz-cf-id": "CloudFront",
    "x-amzn-trace-id": "CloudFront",
    "x-akamai-request-id": "Akamai",
    "akamai-request-id": "Akamai",
    "x-akamai-transformed": "Akamai",
    "x-edge-request-id": "CloudFront",
    "x-edge-location": "CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-sucuri-id": "Sucuri/StackPath",
    "x-sucuri-cache": "Sucuri/StackPath",
    "x-azure-ref": "Azure CDN",
    "x-cdn": "Generic CDN",
    "cdn-loop": "Generic CDN",
    "true-client-ip": "Cloudflare",
    "x-forwarded-for": "Generic Proxy",
    "x-real-ip": "Generic Proxy",
    "x-bunny-cdn": "Bunny CDN",
    "x-pull": "Bunny CDN",
    "x-q-quic": "QUIC.cloud",
    "x-litespeed-cache": "LiteSpeed Cache",
    "x-proxy-cache": "Proxy Cache",
}

CDN_CNAME_PATTERNS = [
    (r"\.cloudflare\.net$", "Cloudflare"),
    (r"\.cloudfront\.net$", "CloudFront"),
    (r"\.akamai(edge|tech|hd)\.net$", "Akamai"),
    (r"\.akadns\.net$", "Akamai"),
    (r"\.fastly\.net$", "Fastly"),
    (r"\.azureedge\.net$", "Azure CDN"),
    (r"\.azurefd\.net$", "Azure Front Door"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager"),
    (r"\.cdn\.cloud\.net$", "GCP CDN"),
    (r"\.cdn77\.(net|org)$", "CDN77"),
    (r"\.bunnycdn\.(com|net)$", "Bunny CDN"),
    (r"\.keycdn\.com$", "KeyCDN"),
    (r"\.cachefly\.net$", "CacheFly"),
    (r"\.edgesuite\.net$", "Akamai"),
    (r"\.edgekey\.net$", "Akamai"),
    (r"\.sucuri\.net$", "Sucuri/StackPath"),
    (r"\.stackpathdns\.com$", "StackPath"),
    (r"\.stackpathcdn\.com$", "StackPath"),
    (r"\.rscdn\.net$", "Rackspace CDN"),
    (r"\.incapdns\.net$", "Incapsula"),
    (r"\.impervadns\.net$", "Imperva"),
    (r"\.belugacdn\.(com|net)$", "BelugaCDN"),
    (r"\.pantheon\.io$", "Pantheon"),
    (r"\.pantheonsite\.io$", "Pantheon"),
    (r"\.wpengine\.com$", "WP Engine"),
    (r"\.wpeproxy\.com$", "WP Engine"),
    (r"\.kinsta\.(com|net)$", "Kinsta"),
    (r"\.nexcess\.net$", "Nexcess"),
    (r"\.hwcdn\.net$", "Highwinds/CDNetworks"),
    (r"\.cdngc\.net$", "CDNetworks"),
    (r"\.gccdn\.net$", "CDNetworks"),
    (r"\.llnwd\.net$", "Limelight"),
    (r"\.lldns\.net$", "Limelight"),
    (r"\.footprint\.net$", "Level 3 / CenturyLink"),
    (r"\.frank\.io$", "Edgecast/Yahoo"),
    (r"\.yahooapis\.com$", "Yahoo CDN"),
    (r"\.yimg\.com$", "Yahoo CDN"),
    (r"\.a\.msedge\.net$", "Microsoft Edge CDN"),
    (r"\.msecnd\.net$", "Microsoft CDN"),
    (r"\.vo\.msecnd\.net$", "Microsoft CDN"),
    (r"\.ssl-on9\.net$", "OnApp CDN"),
    (r"\.clients\.turbobytes\.net$", "TurboBytes"),
    (r"\.turbobytescdn\.com$", "TurboBytes"),
    (r"\.swiftcdn\.com$", "SwiftCDN"),
    (r"\.cdx\.cloudflare\.com$", "Cloudflare"),
    (r"\.cdn\.google\.com$", "Google Cloud CDN"),
    (r"\.cdn\.instagram\.com$", "Instagram CDN"),
    (r"\.fbcdn\.net$", "Facebook CDN"),
    (r"\.twimg\.com$", "Twitter CDN"),
    (r"\.cdninstagram\.com$", "Instagram CDN"),
    (r"\.p-cdn\.net$", "P-CDN"),
    (r"\.res\.cloudinary\.com$", "Cloudinary"),
]

CDN_IP_RANGES = {
    "Cloudflare": ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"],
    "CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "13.249.0.0/16", "18.154.0.0/15", "18.200.0.0/16", "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "54.240.128.0/18", "70.132.0.0/18", "71.152.0.0/17", "143.204.0.0/16", "150.222.81.0/24", "204.246.164.0/22", "204.246.168.0/22", "205.251.192.0/19", "216.137.32.0/19"],
    "Fastly": ["23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "104.156.80.0/20", "130.61.91.0/24", "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18", "167.82.32.0/22", "167.82.36.0/22", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"],
    "Akamai": ["2.16.0.0/13", "2.21.0.0/13", "2.22.0.0/15", "23.0.0.0/12", "23.32.0.0/11", "23.192.0.0/11", "23.224.0.0/12", "63.145.0.0/16", "63.208.0.0/14", "64.29.0.0/14", "64.191.0.0/16", "65.200.0.0/14", "66.205.0.0/16", "69.40.0.0/14", "69.164.0.0/16", "69.192.0.0/16", "69.197.0.0/16", "69.200.0.0/16", "72.246.0.0/16", "80.67.64.0/20", "80.67.72.0/21", "80.239.128.0/17", "84.53.0.0/16"],
    "Azure CDN": ["13.69.188.0/22", "13.71.199.0/24", "13.73.240.0/22", "13.74.112.0/21", "13.75.120.0/21", "13.77.56.0/21", "13.78.184.0/21", "13.82.128.0/23", "13.86.101.0/24", "13.86.102.0/23", "13.87.8.0/21", "13.89.176.0/21", "13.90.152.0/21", "40.69.104.0/21", "40.74.24.0/21", "40.117.16.0/21", "40.118.0.0/17", "40.122.48.0/22"],
    "GCP CDN": ["34.96.64.0/18", "34.96.128.0/17", "34.97.0.0/16", "34.104.0.0/16", "34.105.0.0/16", "34.106.0.0/15", "34.108.0.0/16", "34.110.128.0/17", "34.111.0.0/16", "34.112.0.0/16", "34.116.0.0/16", "34.117.0.0/16", "34.118.0.0/16", "34.120.0.0/16", "34.122.0.0/15"],
    "StackPath": ["45.60.0.0/16", "45.64.32.0/19", "45.128.128.0/18", "63.141.128.0/19", "66.115.0.0/19", "69.167.128.0/19", "74.63.64.0/19", "99.83.128.0/19", "99.192.128.0/19", "108.161.128.0/19", "108.163.128.0/19", "146.66.128.0/19", "151.139.128.0/19", "162.211.128.0/19", "172.245.128.0/19"],
    "Bunny CDN": ["31.24.24.0/21", "45.14.144.0/22", "89.187.160.0/20", "91.230.92.0/24", "102.165.16.0/20", "105.224.160.0/21", "116.202.96.0/21", "138.199.0.0/17", "141.0.176.0/20", "151.139.128.0/18", "156.238.112.0/21", "167.86.96.0/20", "168.100.4.0/22", "172.96.72.0/22", "178.18.24.0/21"],
    "KeyCDN": ["37.235.52.0/24", "47.90.0.0/20", "62.210.128.0/24", "64.139.79.0/24", "82.117.224.0/20", "84.200.96.0/20", "89.38.96.0/20", "94.102.56.0/21", "104.238.144.0/21", "104.238.152.0/21", "136.243.96.0/20", "159.8.144.0/20", "167.114.96.0/20", "168.100.0.0/18", "192.145.120.0/21"],
    "CacheFly": ["5.62.56.0/22", "5.248.0.0/16", "5.249.0.0/17", "12.34.56.0/22", "54.39.0.0/16", "66.115.0.0/19", "70.33.0.0/17", "74.121.248.0/21", "78.39.0.0/15", "89.38.96.0/20", "91.218.184.0/21", "103.27.80.0/22", "103.244.48.0/22", "107.155.96.0/20", "138.128.128.0/18"],
    "Edgecast": ["68.67.128.0/17", "72.21.81.0/24", "72.21.91.0/24", "74.222.0.0/17", "93.184.220.0/23", "98.137.0.0/16", "151.139.240.0/21", "192.16.32.0/21", "192.16.40.0/21", "192.16.48.0/21", "192.16.56.0/21", "199.47.88.0/21", "199.47.96.0/21", "216.21.0.0/24"],
    "CDN77": ["31.222.64.0/19", "37.139.32.0/21", "38.54.80.0/21", "45.86.36.0/22", "45.129.144.0/22", "45.142.196.0/22", "46.29.208.0/21", "62.204.140.0/22", "77.73.64.0/19", "79.110.48.0/20", "80.92.120.0/21", "82.204.96.0/19", "89.40.112.0/20", "91.210.184.0/22", "92.223.84.0/22"],
}

def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        import ipaddress
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False)
    except Exception:
        return False

async def resolve_dns(domain: str) -> list:
    return resolve_ip(domain)

async def get_cname(domain: str) -> str:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CNAME")
        for a in answers:
            return str(a.target).rstrip(".")
    except Exception:
        return ""

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ips = await resolve_dns(domain)
    cname = await get_cname(domain)

    found_cdns = set()

    for ip in ips:
        for cdn_name, ranges in CDN_IP_RANGES.items():
            for cidr in ranges:
                if ip_in_cidr(ip, cidr):
                    if cdn_name not in found_cdns:
                        found_cdns.add(cdn_name)
                        findings.append(make_finding(
                            entity=f"CDN detected via IP range: {cdn_name} ({ip})",
                            ftype="CDN: IP Range Match",
                            source="CDNDetector",
                            confidence="High",
                            color="blue",
                            threat_level="Informational",
                            raw_data=f"ip={ip}, cdn={cdn_name}, cidr={cidr}",
                            tags=["cdn", "ip-range", cdn_name.lower().replace(" ", "-")]
                        ))

    if cname:
        for pattern, cdn_name in CDN_CNAME_PATTERNS:
            if re.search(pattern, cname, re.I):
                if cdn_name not in found_cdns:
                    found_cdns.add(cdn_name)
                    findings.append(make_finding(
                        entity=f"CDN detected via CNAME: {cdn_name} ({cname})",
                        ftype="CDN: CNAME Match",
                        source="CDNDetector",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        raw_data=f"cname={cname}, cdn={cdn_name}",
                        tags=["cdn", "cname", cdn_name.lower().replace(" ", "-")]
                    ))

    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}

            for hdr_name, cdn_name in CDN_HEADERS.items():
                if hdr_name in hdrs:
                    hdr_val = hdrs[hdr_name]
                    actual_cdn = cdn_name
                    if hdr_name == "server" and "cloudflare" in hdr_val.lower():
                        actual_cdn = "Cloudflare"
                    elif hdr_name == "server" and "cloudfront" in hdr_val.lower():
                        actual_cdn = "CloudFront"
                    elif hdr_name == "server" and "akamai" in hdr_val.lower():
                        actual_cdn = "Akamai"
                    elif hdr_name == "x-cache":
                        if "cloudfront" in hdr_val.lower():
                            actual_cdn = "CloudFront"
                        elif "fastly" in hdr_val.lower():
                            actual_cdn = "Fastly"

                    if actual_cdn not in found_cdns:
                        found_cdns.add(actual_cdn)
                        findings.append(make_finding(
                            entity=f"CDN detected via header: {actual_cdn} ({hdr_name}: {hdr_val[:60]})",
                            ftype="CDN: Header Detection",
                            source="CDNDetector",
                            confidence="High" if actual_cdn != "Generic CDN" else "Medium",
                            color="blue",
                            threat_level="Informational",
                            raw_data=f"header={hdr_name}, value={hdr_val[:200]}, cdn={actual_cdn}",
                            tags=["cdn", "header", actual_cdn.lower().replace(" ", "-")]
                        ))

            if resp.status_code == 200:
                findings.append(make_finding(
                    entity=f"HTTP {resp.status_code} - Site is reachable via {proto.upper()}",
                    ftype="CDN: Reachability",
                    source="CDNDetector",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["cdn", "reachability"]
                ))
            break
        except Exception:
            continue

    if not found_cdns:
        findings.append(make_finding(
            entity=f"No CDN detected for {domain}",
            ftype="CDN: No CDN Found",
            source="CDNDetector",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["cdn", "no-cdn"]
        ))
    elif len(found_cdns) > 1:
        findings.append(make_finding(
            entity=f"Multi-CDN detected: {', '.join(found_cdns)} ({len(found_cdns)} CDNs)",
            ftype="CDN: Multi-CDN",
            source="CDNDetector",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"CDNs: {', '.join(found_cdns)}",
            tags=["cdn", "multi-cdn"]
        ))

    findings.append(make_finding(
        entity=f"CDN Analysis: {len(found_cdns)} CDN(s) detected | IPs: {len(ips)} | CNAME: {cname or 'None'}",
        ftype="CDN: Summary",
        source="CDNDetector",
        confidence="High",
        color="blue" if found_cdns else "slate",
        threat_level="Informational",
        raw_data=f"cdns={len(found_cdns)}, ips={len(ips)}, cname={cname or 'None'}",
        tags=["cdn", "summary"]
    ))

    return findings
