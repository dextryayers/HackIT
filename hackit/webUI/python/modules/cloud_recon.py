import httpx
import asyncio
import socket
import re
from models import IntelligenceFinding

CDN_DETECTION = {
    "cloudflare": {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status", "cf-connecting-ip"], "color": "orange"},
    "cloudfront": {"name": "AWS CloudFront", "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-ip"], "color": "orange"},
    "akamai": {"name": "Akamai", "headers": ["x-akamai-transformed", "x-akamai-request-id"], "color": "orange"},
    "fastly": {"name": "Fastly", "headers": ["x-fastly-request-id", "x-served-by", "x-cache-hits"], "color": "orange"},
    "incapsula": {"name": "Incapsula", "headers": ["x-request-id", "x-cdn"], "color": "orange"},
    "sucuri": {"name": "Sucuri", "headers": ["x-sucuri-id", "x-sucuri-cache"], "color": "orange"},
    "stackpath": {"name": "StackPath", "headers": ["x-stackpath-id"], "color": "orange"},
    "keycdn": {"name": "KeyCDN", "headers": ["x-keycdn"], "color": "orange"},
    "bunnycdn": {"name": "BunnyCDN", "headers": ["x-bunnycdn"], "color": "orange"},
    "cachefly": {"name": "CacheFly", "headers": ["x-cachefly"], "color": "orange"},
    "section": {"name": "Section.io", "headers": ["x-section"], "color": "orange"},
    "belugacdn": {"name": "BelugaCDN", "headers": ["x-belugacdn"], "color": "orange"},
}

PAAS_PLATFORMS = {
    "herokuapp.com": "Heroku",
    "heroku.com": "Heroku",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "onrender.com": "Render",
    "railway.app": "Railway",
    "fly.dev": "Fly.io",
    "fly.io": "Fly.io",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "r2.dev": "Cloudflare R2",
    "azurewebsites.net": "Azure App Service",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door",
    "trafficmanager.net": "Azure Traffic Manager",
    "azure-api.net": "Azure API Management",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "amazonaws.com": "AWS",
    "compute.amazonaws.com": "AWS EC2",
    "rds.amazonaws.com": "AWS RDS",
    "elb.amazonaws.com": "AWS ELB",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "api-gateway.amazonaws.com": "AWS API Gateway",
    "execute-api": "AWS API Gateway",
    "lambda-url": "AWS Lambda",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase Hosting",
    "firebaseio.com": "Firebase Realtime DB",
    "appspot.com": "Google App Engine",
    "withgoogle.com": "Google Cloud",
    "cloudfunctions.net": "Google Cloud Functions",
    "run.app": "Google Cloud Run",
    "appengine.google.com": "Google App Engine",
    "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "digitalocean.com": "DigitalOcean",
    "ovhcloud.com": "OVHcloud",
    "hetzner.com": "Hetzner",
    "hetzner.cloud": "Hetzner Cloud",
    "linode.com": "Linode",
    "linodeobjects.com": "Linode Object Storage",
    "vultr.com": "Vultr",
    "vultrobjects.com": "Vultr Object Storage",
    "scw.cloud": "Scaleway",
    "scaleway.com": "Scaleway",
    "exoscale.com": "Exoscale",
    "upcloud.com": "UpCloud",
    "phoenixnap.com": "PhoenixNAP",
    "ionos.com": "IONOS",
    "contabo.com": "Contabo",
}

CLOUD_SERVER_HEADERS = {
    "cloudflare": "Cloudflare",
    "akamai": "AkamaiGHost",
    "cloudfront": "Amazon CloudFront",
    "amazons3": "Amazon S3",
    "AmazonS3": "Amazon S3",
    "amazon": "AWS",
    "Apache": "Standard Web Server",
    "nginx/": "Standard Web Server",
    "gunicorn": "Standard Web Server",
    "ECS": "AWS ECS",
    "gws": "Google Web Server",
    "gfe": "Google Front End",
    "Google Cloud": "Google Cloud",
    "azure": "Microsoft Azure",
}

CLOUD_INDICATORS_HTML = [
    (r"cloudflare", "Cloudflare"),
    (r"cdn-cgi", "Cloudflare"),
    (r"akamai", "Akamai"),
    (r"fastly", "Fastly"),
    (r"netlify", "Netlify"),
    (r"vercel", "Vercel"),
    (r"heroku", "Heroku"),
    (r"digitalocean", "DigitalOcean"),
    (r"linode", "Linode"),
    (r"vultr", "Vultr"),
    (r"ovh", "OVH"),
    (r"hetzner", "Hetzner"),
    (r"amazonaws", "AWS"),
    (r"s3\b", "AWS S3"),
    (r"cloudfront", "CloudFront"),
    (r"azure", "Azure"),
    (r"azureedge", "Azure"),
    (r"firebase", "Firebase"),
    (r"googleapis", "Google Cloud"),
    (r"gstatic", "Google Cloud"),
    (r"googlecloud", "Google Cloud"),
]


async def _check_paas_cname(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for pattern, platform in PAAS_PLATFORMS.items():
                    if pattern in cname:
                        if not any(f.entity == platform and f.type == "PaaS Platform" for f in findings):
                            findings.append(IntelligenceFinding(
                                entity=platform,
                                type="PaaS Platform",
                                source="CloudRecon",
                                confidence="High",
                                color="purple",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME: {cname} to {platform}",
                                tags=["cloud", "paas", platform.lower().replace(" ", "-")]
                            ))
        except Exception:
            pass

        try:
            answers_a = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'A'))
            for r in answers_a:
                ip_str = str(r)
                for pattern, platform in PAAS_PLATFORMS.items():
                    if pattern in ip_str:
                        findings.append(IntelligenceFinding(
                            entity=platform,
                            type="PaaS Platform (IP)",
                            source="CloudRecon",
                            confidence="Medium",
                            color="purple",
                            threat_level="Informational",
                            status="Suspected",
                            resolution=ip_str,
                            raw_data=f"IP {ip_str} associated with {platform}",
                            tags=["cloud", "paas"]
                        ))
        except Exception:
            pass

    except Exception:
        pass
    return findings


async def _check_ns_record(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
        ns_providers = {
            "awsdns": "AWS Route53",
            "cloudflare": "Cloudflare DNS",
            "azure-dns": "Azure DNS",
            "azure.com": "Azure DNS",
            "googledomains": "Google Cloud DNS",
            "google": "Google Cloud DNS",
            "dns.google": "Google Cloud DNS",
            "nsone": "NS1",
            "ultradns": "UltraDNS",
            "akamai": "Akamai DNS",
            "dynect": "Oracle Dyn DNS",
            "dyn.com": "Oracle Dyn DNS",
            "dnsmadeeasy": "DNS Made Easy",
            "constellix": "Constellix",
            "dnspod": "DNSPod (Tencent)",
            "alidns": "Alibaba Cloud DNS",
            "hichina": "HiChina (Alibaba)",
            "namecheap": "Namecheap FreeDNS",
            "digitalocean": "DigitalOcean DNS",
        }
        for r in answers:
            ns = str(r).lower()
            for key, provider in ns_providers.items():
                if key in ns:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider} ({ns})",
                        type="DNS Nameserver Provider",
                        source="CloudRecon",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS provider: {provider} via {ns}",
                        tags=["cloud", "dns", provider.lower().replace(" ", "-")]
                    ))
                    break
    except Exception:
        pass
    return findings


async def _check_mx_cloud(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'MX'))
        mx_patterns = {
            "google": "Google Workspace",
            "googlemail": "Google Workspace",
            "outlook": "Microsoft 365",
            "protection.outlook": "Microsoft 365",
            "mail.protection": "Microsoft 365",
            "microsoft": "Microsoft 365",
            "protonmail": "ProtonMail",
            "protonmail.ch": "ProtonMail",
            "zoho": "Zoho Mail",
            "mailgun": "Mailgun",
            "sendgrid": "SendGrid",
            "sparkpost": "SparkPost",
            "yandex": "Yandex Mail",
            "mail.ru": "Mail.ru",
            "gmx": "GMX Mail",
            "icloud": "iCloud Mail",
            "fastmail": "Fastmail",
            "rackspace": "Rackspace Email",
            "exchange": "Microsoft Exchange",
        }
        for r in answers:
            mx = str(r.exchange).lower()
            for key, provider in mx_patterns.items():
                if key in mx:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider} ({mx})",
                        type="Email Cloud Provider (MX)",
                        source="CloudRecon",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Detected",
                        resolution=mx,
                        raw_data=f"MX: {mx} -> {provider}",
                        tags=["cloud", "email", provider.lower().replace(" ", "-")]
                    ))
                    break
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
        server = headers.get("server", "")
        via = headers.get("via", "")
        x_powered = headers.get("x-powered-by", "")

        for cdn_key, cdn_info in CDN_DETECTION.items():
            for h in cdn_info["headers"]:
                if h in headers:
                    findings.append(IntelligenceFinding(
                        entity=cdn_info["name"],
                        type="CDN Service",
                        source="CloudRecon",
                        confidence="High",
                        color=cdn_info["color"],
                        threat_level="Informational",
                        status="Active",
                        raw_data=f"CDN: {cdn_info['name']} detected via {h} header",
                        tags=["cdn", cdn_key]
                    ))
                    break

        for sig, provider in CLOUD_SERVER_HEADERS.items():
            if sig.lower() in server.lower() or sig.lower() in via.lower():
                findings.append(IntelligenceFinding(
                    entity=provider,
                    type="Cloud Infrastructure (Header)",
                    source="CloudRecon",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Server header: {server}, Via: {via}, Signature: {sig}",
                    tags=["cloud", provider.lower().replace(" ", "-")]
                ))
                break

        if via:
            findings.append(IntelligenceFinding(
                entity=f"Via: {via[:200]}",
                type="Cloud Infrastructure (Via Header)",
                source="CloudRecon",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=f"Via: {via}",
                tags=["cloud", "header"]
            ))

        if x_powered:
            if any(cloud in x_powered.lower() for cloud in ["aws", "azure", "google", "cloud", "heroku"]):
                findings.append(IntelligenceFinding(
                    entity=f"X-Powered-By: {x_powered[:100]}",
                    type="Cloud Technology (Header)",
                    source="CloudRecon",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=x_powered,
                    tags=["cloud", "tech"]
                ))

        html = resp.text[:50000].lower() if hasattr(resp, 'text') else ""
        for pattern, provider in CLOUD_INDICATORS_HTML:
            if re.search(pattern, html):
                findings.append(IntelligenceFinding(
                    entity=provider,
                    type="Cloud Service (HTML Indicator)",
                    source="CloudRecon",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Suspected",
                    raw_data=f"HTML pattern '{pattern}' found indicating {provider}",
                    tags=["cloud", provider.lower().replace(" ", "-")]
                ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Cloud Recon Error",
            source="CloudRecon",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings


async def _check_ip_ranges(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            import ipaddress
            ipaddress.ip_address(target)
            target_ip = target
        except ValueError:
            target_ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))

        cloud_ranges = [
            (("34.0.0.0", "34.255.255.255"), "Google Cloud", "GCP"),
            (("35.184.0.0", "35.255.255.255"), "Google Cloud", "GCP"),
            (("8.34.0.0", "8.35.255.255"), "Google Cloud", "GCP"),
            (("13.0.0.0", "13.255.255.255"), "AWS", "AWS"),
            (("15.0.0.0", "15.255.255.255"), "AWS", "AWS"),
            (("16.0.0.0", "16.255.255.255"), "AWS", "AWS"),
            (("18.0.0.0", "18.255.255.255"), "AWS", "AWS"),
            (("35.0.0.0", "35.183.255.255"), "AWS", "AWS"),
            (("44.192.0.0", "44.255.255.255"), "AWS", "AWS"),
            (("52.0.0.0", "52.255.255.255"), "AWS", "AWS"),
            (("54.0.0.0", "54.255.255.255"), "AWS", "AWS"),
            (("20.0.0.0", "20.255.255.255"), "Azure", "Azure"),
            (("40.64.0.0", "40.127.255.255"), "Azure", "Azure"),
            (("52.128.0.0", "52.255.255.255"), "Azure", "Azure"),
            (("65.52.0.0", "65.55.255.255"), "Azure", "Azure"),
            (("104.208.0.0", "104.215.255.255"), "Azure", "Azure"),
            (("137.116.0.0", "137.135.255.255"), "Azure", "Azure"),
            (("104.131.0.0", "104.131.255.255"), "DigitalOcean", "DO"),
            (("159.65.0.0", "159.65.255.255"), "DigitalOcean", "DO"),
            (("167.99.0.0", "167.99.255.255"), "DigitalOcean", "DO"),
            (("139.162.0.0", "139.162.255.255"), "Linode", "Linode"),
            (("172.104.0.0", "172.104.255.255"), "Linode", "Linode"),
            (("45.32.0.0", "45.32.255.255"), "Vultr", "Vultr"),
            (("149.28.0.0", "149.28.255.255"), "Vultr", "Vultr"),
            (("49.12.0.0", "49.12.255.255"), "Hetzner", "Hetzner"),
            (("78.46.0.0", "78.46.255.255"), "Hetzner", "Hetzner"),
            (("88.198.0.0", "88.198.255.255"), "Hetzner", "Hetzner"),
            (("95.216.0.0", "95.216.255.255"), "Hetzner", "Hetzner"),
            (("129.146.0.0", "129.146.255.255"), "Oracle Cloud", "OCI"),
            (("140.91.0.0", "140.91.255.255"), "Oracle Cloud", "OCI"),
            (("150.136.0.0", "150.136.255.255"), "Oracle Cloud", "OCI"),
            (("193.122.0.0", "193.122.255.255"), "Oracle Cloud", "OCI"),
        ]

        def ip_to_int(ip_str):
            parts = ip_str.split(".")
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

        try:
            ip_int = ip_to_int(target_ip)
            for (start_str, end_str), provider, short in cloud_ranges:
                start_int = ip_to_int(start_str)
                end_int = ip_to_int(end_str)
                if start_int <= ip_int <= end_int:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider} (IP Range Match)",
                        type="Cloud Provider IP",
                        source="CloudRecon",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        status="Verified",
                        resolution=target_ip,
                        raw_data=f"IP {target_ip} falls in {provider} range {start_str}-{end_str}",
                        tags=["cloud", short.lower()]
                    ))
                    break
        except Exception:
            pass

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    cname_findings = await _check_paas_cname(target, client)
    findings.extend(cname_findings)

    ns_findings = await _check_ns_record(target, client)
    findings.extend(ns_findings)

    mx_findings = await _check_mx_cloud(target, client)
    findings.extend(mx_findings)

    header_findings = await _analyze_headers(target, client)
    findings.extend(header_findings)

    ip_findings = await _check_ip_ranges(target, client)
    findings.extend(ip_findings)

    paas_count = sum(1 for f in findings if f.type == "PaaS Platform")
    cdn_count = sum(1 for f in findings if f.type == "CDN Service")
    cloud_count = sum(1 for f in findings if "Cloud" in f.type and f.type not in ("CDN Service",))

    if paas_count > 0 or cdn_count > 0 or cloud_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"Cloud Recon Complete: {cloud_count} cloud, {cdn_count} CDN, {paas_count} PaaS",
            type="Cloud Recon Summary",
            source="CloudRecon",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{len(findings)} total findings",
            raw_data=f"Cloud: {cloud_count}, CDN: {cdn_count}, PaaS: {paas_count}",
            tags=["cloud", "recon", "summary"]
        ))

    return findings
