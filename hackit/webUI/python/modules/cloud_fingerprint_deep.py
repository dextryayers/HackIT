import httpx
import socket
import asyncio
import re
from models import IntelligenceFinding

CLOUD_METADATA_ENDPOINTS = {
    "AWS": {
        "urls": ["http://169.254.169.254/latest/meta-data/",
                 "http://169.254.169.254/latest/dynamic/instance-identity/document"],
        "headers": {"X-aws-ec2": "true"},
    },
    "GCP": {
        "urls": ["http://metadata.google.internal/computeMetadata/v1/",
                 "http://169.254.169.254/computeMetadata/v1/"],
        "headers": {"Metadata-Flavor": "Google"},
    },
    "Azure": {
        "urls": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
        "headers": {"Metadata": "true"},
    },
    "DigitalOcean": {
        "urls": ["http://169.254.169.254/metadata/v1.json"],
        "headers": {},
    },
}

CLOUD_IP_RANGES_URLS = {
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP": "https://www.gstatic.com/ipranges/cloud.json",
    "Azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250331.json",
    "Oracle": "",
    "DigitalOcean": "",
    "Linode": "",
    "Vultr": "",
}

CLOUD_CDN_HEADERS = {
    "cloudflare": {"name": "Cloudflare", "header": "cf-ray", "color": "orange"},
    "akamai": {"name": "Akamai", "header": "x-akamai-transformed", "color": "orange"},
    "fastly": {"name": "Fastly", "header": "x-fastly-request-id", "color": "orange"},
    "cloudfront": {"name": "CloudFront", "header": "x-amz-cf-id", "color": "orange"},
    "incapsula": {"name": "Incapsula", "header": "x-request-id", "color": "orange"},
    "sucuri": {"name": "Sucuri", "header": "x-sucuri-id", "color": "orange"},
    "stackpath": {"name": "StackPath", "header": "x-stackpath-id", "color": "orange"},
}

CLOUD_SERVER_HEADERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "cloudfront": "CloudFront",
    "amazon": "AWS",
    "amazon.com": "AWS",
    "azure": "Azure",
    "azurewebsites": "Azure App Service",
    "azureedge": "Azure CDN",
    "google": "Google Cloud",
    "gce": "Google Compute Engine",
    "gcp": "Google Cloud Platform",
    "googlecloud": "Google Cloud",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
    "vultr": "Vultr",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "heroku": "Heroku",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "railway": "Railway",
    "render": "Render",
    "fly": "Fly.io",
    "ibm": "IBM Cloud",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
    "tencent": "Tencent Cloud",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "keycdn": "KeyCDN",
    "bunnycdn": "BunnyCDN",
}

CLOUD_STORAGE_PATTERNS = {
    "s3.amazonaws.com": "AWS S3",
    "s3.us-east-1.amazonaws.com": "AWS S3 (us-east-1)",
    "s3-us-west-1.amazonaws.com": "AWS S3 (us-west-1)",
    "s3-us-west-2.amazonaws.com": "AWS S3 (us-west-2)",
    "s3-eu-west-1.amazonaws.com": "AWS S3 (eu-west-1)",
    "s3-eu-central-1.amazonaws.com": "AWS S3 (eu-central-1)",
    "blob.core.windows.net": "Azure Blob Storage",
    "storage.googleapis.com": "GCP Cloud Storage",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "storage.bunnycdn.com": "BunnyCDN Storage",
    "wasabisys.com": "Wasabi Cloud Storage",
    "backblazeb2.com": "Backblaze B2",
    "linodeobjects.com": "Linode Object Storage",
    "vultrobjects.com": "Vultr Object Storage",
}

CLOUD_PROVIDER_IP_RANGES = {
    "AWS": [
        (("54.0.0.0", "54.255.255.255"), "AWS Global"),
        (("13.0.0.0", "13.255.255.255"), "AWS Global"),
        (("15.0.0.0", "15.255.255.255"), "AWS Global"),
        (("16.0.0.0", "16.255.255.255"), "AWS Global"),
        (("18.0.0.0", "18.255.255.255"), "AWS Global"),
        (("35.0.0.0", "35.255.255.255"), "AWS Global"),
        (("44.192.0.0", "44.255.255.255"), "AWS Global"),
        (("52.0.0.0", "52.255.255.255"), "AWS Global"),
    ],
    "Azure": [
        (("13.64.0.0", "13.107.255.255"), "Azure Global"),
        (("20.0.0.0", "20.255.255.255"), "Azure Global"),
        (("23.96.0.0", "23.99.255.255"), "Azure Global"),
        (("40.64.0.0", "40.127.255.255"), "Azure Global"),
        (("52.128.0.0", "52.255.255.255"), "Azure Global"),
        (("65.52.0.0", "65.55.255.255"), "Azure Global"),
        (("104.208.0.0", "104.215.255.255"), "Azure Global"),
        (("137.116.0.0", "137.135.255.255"), "Azure Global"),
    ],
    "GCP": [
        (("8.34.0.0", "8.35.255.255"), "GCP US"),
        (("23.236.0.0", "23.236.255.255"), "GCP US"),
        (("23.251.0.0", "23.251.255.255"), "GCP US"),
        (("34.0.0.0", "34.255.255.255"), "GCP Global"),
        (("35.184.0.0", "35.255.255.255"), "GCP Global"),
        (("104.154.0.0", "104.199.255.255"), "GCP Global"),
        (("107.167.0.0", "107.167.255.255"), "GCP Global"),
        (("108.59.80.0", "108.59.95.255"), "GCP Global"),
    ],
    "DigitalOcean": [
        (("104.131.0.0", "104.131.255.255"), "DO NYC"),
        (("104.236.0.0", "104.236.255.255"), "DO SFO"),
        (("107.170.0.0", "107.170.255.255"), "DO SFO"),
        (("128.199.0.0", "128.199.255.255"), "DO SGP"),
        (("138.68.0.0", "138.68.255.255"), "DO FRA"),
        (("138.197.0.0", "138.197.255.255"), "DO NYC"),
        (("139.59.0.0", "139.59.255.255"), "DO BLR"),
        (("143.110.0.0", "143.110.255.255"), "DO Global"),
        (("146.185.0.0", "146.185.255.255"), "DO LON"),
        (("157.230.0.0", "157.230.255.255"), "DO NYC"),
        (("159.65.0.0", "159.65.255.255"), "DO SFO"),
        (("161.35.0.0", "161.35.255.255"), "DO FRA"),
        (("162.243.0.0", "162.243.255.255"), "DO NYC"),
        (("164.90.0.0", "164.90.255.255"), "DO Global"),
        (("165.22.0.0", "165.22.255.255"), "DO SGP"),
        (("167.71.0.0", "167.71.255.255"), "DO SFO"),
        (("167.99.0.0", "167.99.255.255"), "DO FRA"),
        (("174.138.0.0", "174.138.255.255"), "DO SFO"),
        (("178.62.0.0", "178.62.255.255"), "DO LON"),
        (("188.166.0.0", "188.166.255.255"), "DO AMS"),
        (("188.226.0.0", "188.226.255.255"), "DO AMS"),
        (("192.241.0.0", "192.241.255.255"), "DO NYC"),
        (("198.199.0.0", "198.199.255.255"), "DO NYC"),
        (("206.189.0.0", "206.189.255.255"), "DO SFO"),
        (("209.97.0.0", "209.97.255.255"), "DO AMS"),
    ],
    "Oracle": [
        (("129.146.0.0", "129.146.255.255"), "Oracle US-ASHBURN"),
        (("130.35.0.0", "130.35.255.255"), "Oracle US-PHOENIX"),
        (("134.70.0.0", "134.70.255.255"), "Oracle Global"),
        (("137.26.0.0", "137.26.255.255"), "Oracle US-PHOENIX"),
        (("140.91.0.0", "140.91.255.255"), "Oracle Global"),
        (("141.147.0.0", "141.147.255.255"), "Oracle Global"),
        (("144.24.0.0", "144.24.255.255"), "Oracle Global"),
        (("144.25.0.0", "144.25.255.255"), "Oracle Global"),
        (("147.154.0.0", "147.154.255.255"), "Oracle Global"),
        (("150.136.0.0", "150.136.255.255"), "Oracle Global"),
        (("152.67.0.0", "152.67.255.255"), "Oracle Global"),
        (("158.178.0.0", "158.178.255.255"), "Oracle Global"),
        (("192.29.0.0", "192.29.255.255"), "Oracle Global"),
        (("193.122.0.0", "193.122.255.255"), "Oracle Global"),
        (("205.147.0.0", "205.147.255.255"), "Oracle Global"),
        (("207.211.0.0", "207.211.255.255"), "Oracle Global"),
    ],
    "Linode": [
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
        (("185.19.0.0", "185.19.31.255"), "Linode Frankfurt"),
        (("192.155.0.0", "192.155.127.255"), "Linode Global"),
        (("192.237.0.0", "192.237.31.255"), "Linode Atlanta"),
        (("192.81.0.0", "192.81.31.255"), "Linode Dallas"),
    ],
    "Vultr": [
        (("23.90.0.0", "23.90.31.255"), "Vultr New Jersey"),
        (("45.32.0.0", "45.32.255.255"), "Vultr Global"),
        (("45.63.0.0", "45.63.127.255"), "Vultr New Jersey"),
        (("45.76.0.0", "45.76.255.255"), "Vultr Global"),
        (("45.77.0.0", "45.77.255.255"), "Vultr Global"),
        (("66.42.0.0", "66.42.127.255"), "Vultr Chicago"),
        (("104.156.0.0", "104.156.255.255"), "Vultr Global"),
        (("104.207.0.0", "104.207.255.255"), "Vultr Global"),
        (("104.238.0.0", "104.238.127.255"), "Vultr Los Angeles"),
        (("107.191.0.0", "107.191.127.255"), "Vultr Atlanta"),
        (("108.61.0.0", "108.61.255.255"), "Vultr Global"),
        (("136.244.0.0", "136.244.255.255"), "Vultr Global"),
        (("141.255.0.0", "141.255.255.255"), "Vultr Global"),
        (("146.0.32.0", "146.0.63.255"), "Vultr Sydney"),
        (("149.28.0.0", "149.28.255.255"), "Vultr Global"),
        (("149.248.0.0", "149.248.127.255"), "Vultr Global"),
        (("155.138.0.0", "155.138.255.255"), "Vultr Global"),
        (("158.247.0.0", "158.247.255.255"), "Vultr Global"),
        (("192.248.0.0", "192.248.127.255"), "Vultr Global"),
        (("198.13.0.0", "198.13.127.255"), "Vultr Global"),
        (("207.148.0.0", "207.148.127.255"), "Vultr Seattle"),
        (("208.167.0.0", "208.167.255.255"), "Vultr Global"),
        (("216.238.0.0", "216.238.127.255"), "Vultr Amsterdam"),
    ],
    "Hetzner": [
        (("49.12.0.0", "49.12.255.255"), "Hetzner Nuremberg"),
        (("49.13.0.0", "49.13.255.255"), "Hetzner Nuremberg"),
        (("65.21.0.0", "65.21.255.255"), "Hetzner Helsinki"),
        (("78.46.0.0", "78.46.255.255"), "Hetzner Nuremberg"),
        (("88.198.0.0", "88.198.255.255"), "Hetzner Nuremberg"),
        (("91.190.0.0", "91.190.255.255"), "Hetzner Nuremberg"),
        (("94.130.0.0", "94.130.255.255"), "Hetzner Global"),
        (("95.216.0.0", "95.216.255.255"), "Hetzner Global"),
        (("116.202.0.0", "116.202.255.255"), "Hetzner Global"),
        (("116.203.0.0", "116.203.255.255"), "Hetzner Global"),
        (("128.140.0.0", "128.140.255.255"), "Hetzner Global"),
        (("135.181.0.0", "135.181.255.255"), "Hetzner Helsinki"),
        (("136.243.0.0", "136.243.255.255"), "Hetzner Nuremberg"),
        (("138.201.0.0", "138.201.255.255"), "Hetzner Nuremberg"),
        (("142.132.0.0", "142.132.255.255"), "Hetzner Global"),
        (("144.76.0.0", "144.76.255.255"), "Hetzner Nuremberg"),
        (("148.251.0.0", "148.251.255.255"), "Hetzner Nuremberg"),
        (("157.90.0.0", "157.90.255.255"), "Hetzner Global"),
        (("159.69.0.0", "159.69.255.255"), "Hetzner Global"),
        (("162.55.0.0", "162.55.255.255"), "Hetzner Global"),
        (("167.235.0.0", "167.235.255.255"), "Hetzner Global"),
        (("168.119.0.0", "168.119.255.255"), "Hetzner Global"),
        (("176.9.0.0", "176.9.255.255"), "Hetzner Nuremberg"),
        (("178.63.0.0", "178.63.255.255"), "Hetzner Nuremberg"),
        (("188.40.0.0", "188.40.255.255"), "Hetzner Nuremberg"),
        (("195.201.0.0", "195.201.255.255"), "Hetzner Global"),
    ],
}


def _ip_to_int(ip_str: str) -> int:
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def _check_ip_in_ranges(ip_str: str) -> list:
    try:
        ip_int = _ip_to_int(ip_str)
    except Exception:
        return []
    results = []
    for provider, ranges in CLOUD_PROVIDER_IP_RANGES.items():
        for (start_str, end_str), region in ranges:
            try:
                start_int = _ip_to_int(start_str)
                end_int = _ip_to_int(end_str)
                if start_int <= ip_int <= end_int:
                    results.append((provider, region))
                    break
            except Exception:
                continue
    return results


async def _fetch_cloud_ip_ranges(target_ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    providers_found = _check_ip_in_ranges(target_ip)
    seen = set()
    for provider, region in providers_found:
        key = f"{provider}-{region}"
        if key not in seen:
            seen.add(key)
            findings.append(IntelligenceFinding(
                entity=f"{provider} ({region})",
                type="Cloud Provider (IP Range)",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Verified",
                resolution=target_ip,
                raw_data=f"IP {target_ip} is in {provider} range ({region})",
                tags=["cloud", provider.lower().replace(" ", "-")]
            ))
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    is_ip = False
    target_ip = target

    if target.startswith("http"):
        from urllib.parse import urlparse
        netloc = urlparse(target).netloc
        target = netloc.split(":")[0]

    try:
        import ipaddress
        ipaddress.ip_address(target)
        is_ip = True
        target_ip = target
    except ValueError:
        is_ip = False
        try:
            loop = asyncio.get_event_loop()
            target_ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
            findings.append(IntelligenceFinding(
                entity=target_ip,
                type="IP Resolution",
                source="CloudFingerprintDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                resolution=target_ip,
                raw_data=f"{target} resolves to {target_ip}",
                tags=["dns", "resolution"]
            ))
        except Exception as e:
            findings.append(IntelligenceFinding(
                entity=f"DNS resolution failed: {target}",
                type="DNS Error",
                source="CloudFingerprintDeep",
                confidence="Low",
                color="red",
                threat_level="Informational",
                raw_data=str(e)[:200],
                tags=["error"]
            ))
            return findings

    ip_range_findings = await _fetch_cloud_ip_ranges(target_ip, client)
    findings.extend(ip_range_findings)

    base = f"https://{target}"
    try:
        resp = await client.get(base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = (headers.get("server") or "").lower()
        via = (headers.get("via") or "").lower()
        cf_ray = headers.get("cf-ray", "")
        amz_cf = headers.get("x-amz-cf-id", "")
        fastly = headers.get("x-fastly-request-id", "")
        x_powered = (headers.get("x-powered-by") or "").lower()

        all_header_vals = " ".join(str(v).lower() for v in headers.values())

        for sig, provider_name in CLOUD_SERVER_HEADERS.items():
            if sig in server or sig in via or sig in all_header_vals or sig in x_powered:
                if any(f.type == "Cloud Provider (Header)" and f.entity.startswith(provider_name) for f in findings):
                    continue
                findings.append(IntelligenceFinding(
                    entity=f"{provider_name}",
                    type="Cloud Provider (Header)",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Server/Via header contains '{sig}' -> {provider_name}",
                    tags=["cloud", provider_name.lower().replace(" ", "-")]
                ))

        if cf_ray:
            findings.append(IntelligenceFinding(
                entity="Cloudflare",
                type="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                resolution=f"cf-ray: {cf_ray}",
                raw_data=f"Cloudflare CDN detected via cf-ray header: {cf_ray}",
                tags=["cdn", "cloudflare"]
            ))

        if amz_cf:
            findings.append(IntelligenceFinding(
                entity="AWS CloudFront",
                type="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                resolution=f"x-amz-cf-id: {amz_cf}",
                raw_data="AWS CloudFront CDN detected",
                tags=["cdn", "aws", "cloudfront"]
            ))

        if fastly:
            findings.append(IntelligenceFinding(
                entity="Fastly",
                type="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                raw_data="Fastly CDN detected",
                tags=["cdn", "fastly"]
            ))

        for cdn_key, cdn_info in CLOUD_CDN_HEADERS.items():
            if cdn_info["header"] in headers:
                findings.append(IntelligenceFinding(
                    entity=cdn_info["name"],
                    type="CDN Detected",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color=cdn_info["color"],
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"{cdn_info['name']} CDN detected via {cdn_info['header']} header",
                    tags=["cdn", cdn_key]
                ))

        x_robots = headers.get("x-robots-tag", "")
        if x_robots:
            findings.append(IntelligenceFinding(
                entity=f"X-Robots-Tag: {x_robots[:100]}",
                type="Cloud Response Header",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=x_robots[:500],
                tags=["header"]
            ))

        if "x-amz-" in all_header_vals or "aws" in all_header_vals:
            findings.append(IntelligenceFinding(
                entity="AWS",
                type="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="AWS-specific headers detected",
                tags=["cloud", "aws"]
            ))

        if "google" in all_header_vals or "gfe" in server:
            findings.append(IntelligenceFinding(
                entity="Google Cloud / GFE",
                type="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="Google Cloud / GFE detected",
                tags=["cloud", "gcp"]
            ))

        if "azure" in all_header_vals or "x-ms-" in all_header_vals:
            findings.append(IntelligenceFinding(
                entity="Microsoft Azure",
                type="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="Azure-specific headers detected",
                tags=["cloud", "azure"]
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Cloud Fingerprint Error",
            source="CloudFingerprintDeep",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))

    try:
        txt_records = []
        loop = asyncio.get_event_loop()
        import dns.resolver
        try:
            resp_txt = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'TXT'))
            txt_records = [str(r) for r in resp_txt]
        except Exception:
            pass

        txt_combined = " ".join(txt_records).lower()
        for provider_key, provider_name in [("google-site-verification", "Google Cloud"),
                                              ("ms=ms", "Microsoft"),
                                              ("atlassian-domain-verification", "Atlassian/Cloud"),
                                              ("cloudflare-verification", "Cloudflare"),
                                              ("mailru-verification", "Mail.ru"),
                                              ("yandex-verification", "Yandex"),
                                              ("facebook-domain-verification", "Facebook"),
                                              ("amazonses", "AWS SES"),
                                              ("spf", "Email Security"),
                                              ("_globalsign", "GlobalSign"),
                                              ("docusign", "DocuSign"),
                                              ("stripe", "Stripe"),
                                              ("heroku", "Heroku")]:
            if provider_key in txt_combined:
                findings.append(IntelligenceFinding(
                    entity=f"{provider_name}",
                    type="Cloud Provider (DNS TXT)",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Verified",
                    raw_data=f"DNS TXT record contains '{provider_key}'",
                    tags=["cloud", "dns", provider_name.lower().replace(" ", "-")]
                ))

        try:
            resp_spf = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'TXT'))
            for r in resp_spf:
                txt = str(r)
                if "include:" in txt:
                    includes = re.findall(r'include:(\S+)', txt)
                    for inc in includes:
                        inc_lower = inc.lower()
                        for cloud_key, cloud_name in [("spf.protection.outlook.com", "Microsoft 365"),
                                                       ("aspmx.p01.dynect.net", "Oracle Cloud"),
                                                       ("_spf.google.com", "Google Workspace"),
                                                       ("servers.mcsv.net", "Mailchimp"),
                                                       ("spf.mtasv.net", "Mailgun"),
                                                       ("spf.sendgrid.net", "SendGrid"),
                                                       ("spf.mandrillapp.com", "Mandrill"),
                                                       ("amazonses.com", "AWS"),
                                                       ("mail.zendesk.com", "Zendesk"),
                                                       ("spf.ess.barracudanetworks.com", "Barracuda"),
                                                       ("spf.proofpoint.com", "Proofpoint")]:
                            if cloud_key in inc_lower:
                                findings.append(IntelligenceFinding(
                                    entity=f"{cloud_name}",
                                    type="Cloud Service (SPF Include)",
                                    source="CloudFingerprintDeep",
                                    confidence="High",
                                    color="blue",
                                    threat_level="Informational",
                                    status="Verified",
                                    raw_data=f"SPF include: {inc}",
                                    tags=["cloud", "email", cloud_name.lower().replace(" ", "-")]
                                ))
        except Exception:
            pass

    except Exception:
        pass

    try:
        cname_targets = []
        try:
            resp_cname = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'CNAME'))
            cname_targets = [str(r.target).rstrip('.') for r in resp_cname]
        except Exception:
            pass

        for cname in cname_targets:
            cl = cname.lower()
            for pattern, provider_name in CLOUD_STORAGE_PATTERNS.items():
                if pattern in cl:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider_name}",
                        type="Cloud Storage (CNAME)",
                        source="CloudFingerprintDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Detected",
                        resolution=cname,
                        raw_data=f"CNAME target: {cname}",
                        tags=["cloud", "storage"]
                    ))

            for paas_pattern, paas_name in [("herokuapp.com", "Heroku"),
                                             ("vercel.app", "Vercel"),
                                             ("netlify.app", "Netlify"),
                                             ("onrender.com", "Render"),
                                             ("railway.app", "Railway"),
                                             ("fly.dev", "Fly.io"),
                                             ("pages.dev", "Cloudflare Pages"),
                                             ("azurewebsites.net", "Azure App Service"),
                                             ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
                                             ("firebaseapp.com", "Firebase"),
                                             ("withgoogle.com", "Google Cloud"),
                                             ("appspot.com", "Google App Engine"),
                                             ("compute.amazonaws.com", "AWS EC2"),
                                             ("amazonaws.com", "AWS")]:
                if paas_pattern in cl:
                    findings.append(IntelligenceFinding(
                        entity=f"{paas_name}",
                        type="PaaS Platform (CNAME)",
                        source="CloudFingerprintDeep",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        status="Detected",
                        resolution=cname,
                        raw_data=f"CNAME to {paas_name}: {cname}",
                        tags=["cloud", "paas", paas_name.lower().replace(" ", "-")]
                    ))
    except Exception:
        pass

    cloud_providers = set(f.entity for f in findings if "Cloud Provider" in f.type)
    cdns = set(f.entity for f in findings if f.type == "CDN Detected")
    if cloud_providers or cdns:
        providers_str = ", ".join(cloud_providers) if cloud_providers else "None"
        cdns_str = ", ".join(cdns) if cdns else "None"
        findings.append(IntelligenceFinding(
            entity=f"Cloud Providers: {providers_str} | CDNs: {cdns_str}",
            type="Cloud Fingerprint Summary",
            source="CloudFingerprintDeep",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            raw_data=f"Providers: {providers_str}, CDNs: {cdns_str}",
            tags=["cloud", "summary"]
        ))

    return findings
