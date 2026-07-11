import httpx
import re
import json
import asyncio
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding
from models import IntelligenceFinding

CLOUD_CNAME_PATTERNS = {
    "Amazon Web Services": ["cloudfront.net", "elb.amazonaws.com", "s3-website", "s3.amazonaws.com", "compute.amazonaws.com", "elasticbeanstalk.com"],
    "Microsoft Azure": ["azureedge.net", "azurefd.net", "azurewebsites.net", "trafficmanager.net", "cloudapp.net", "azure-api.net"],
    "Google Cloud": ["cdn.cloudflare.net", "googleusercontent.com", "gcpcdn.", "appspot.com", "firebaseio.com", "firebaseapp.com"],
    "Cloudflare": ["cloudflare.net", "cloudflare.com"],
    "Akamai": ["akamaiedge.net", "akamaitechnologies.com", "edgesuite.net", "edgekey.net"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "DigitalOcean": ["digitaloceanspaces.com"],
    "Vercel": ["vercel.app", "vercel.com"],
    "Netlify": ["netlify.app", "netlify.com"],
    "Heroku": ["herokuapp.com", "herokudns.com"],
    "Alibaba Cloud": ["alicdn.com", "aliyuncs.com"],
    "OVH": ["ovh.net", "soyoustart.com"],
    "BunnyCDN": ["b-cdn.net", "bunnycdn.com"],
    "StackPath": ["stackpathcdn.com"],
    "KeyCDN": ["keycdn.com"],
}

CLOUD_WHOIS_ORG = {
    "amazon": "Amazon Web Services", "aws": "AWS", "google": "Google Cloud",
    "microsoft": "Microsoft Azure", "azure": "Microsoft Azure",
    "cloudflare": "Cloudflare", "digitalocean": "DigitalOcean",
    "linode": "Linode", "vultr": "Vultr", "ovh": "OVH SAS",
    "hetzner": "Hetzner", "oracle": "Oracle Cloud", "ibm": "IBM Cloud",
    "alibaba": "Alibaba Cloud", "rackspace": "Rackspace",
    "netlify": "Netlify", "heroku": "Heroku", "vercel": "Vercel",
}

TXT_VERIFICATION = {
    "google-site-verification": "Google Cloud / Workspace",
    "MS=": "Microsoft 365",
    "facebook-domain-verification": "Facebook / Meta",
    "zoom-domain-verification": "Zoom",
    "stripe-verification": "Stripe",
    "atlassian-domain-verification": "Atlassian",
    "github-verification": "GitHub",
    "twitter-domain-verification": "Twitter / X",
    "linkedin-domain-verification": "LinkedIn",
    "apple-domain-verification": "Apple",
    "dropbox-domain-verification": "Dropbox",
    "amazonses": "Amazon SES",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "spf.include": "SPF Email Provider",
    "v=spf": "SPF Record",
    "dkim": "DKIM",
}

async def _check_cname_patterns(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=CNAME",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 5:
                    cname = ans.get("data", "").lower()
                    findings.append(make_finding(
                        entity=f"CNAME: {cname}",
                        type="Cloud Detection - CNAME Record",
                        source="Passive Cloud Detection",
                        confidence="High",
                        color="slate",
                        status="Detected",
                        tags=["cloud", "cname"]
                    ))
                    for provider, patterns in CLOUD_CNAME_PATTERNS.items():
                        for pat in patterns:
                            if pat in cname:
                                findings.append(make_finding(
                                    entity=f"Cloud Provider: {provider} (via CNAME match: {pat})",
                                    type="Cloud Detection - CNAME Provider Match",
                                    source="Passive Cloud Detection",
                                    confidence="High",
                                    color="orange",
                                    status=f"Identified: {provider}",
                                    raw_data=f"CNAME {cname} matched pattern {pat}",
                                    tags=["cloud", provider.lower().replace(" ", "-")]
                                ))
    except Exception:
        pass
    return findings

async def _check_subdomains_for_cloud(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        ht_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if ht_resp.status_code == 200:
            for line in ht_resp.text.split("\n"):
                if "," in line:
                    sub, ip = line.split(",")
                    sub = sub.strip().lower()
                    for provider, patterns in CLOUD_CNAME_PATTERNS.items():
                        for pat in patterns:
                            if pat in sub:
                                findings.append(make_finding(
                                    entity=f"{sub} -> {provider} (via hostname: {pat})",
                                    type="Cloud Detection - Subdomain Pattern",
                                    source="Passive Cloud Detection",
                                    confidence="High",
                                    color="orange",
                                    status=f"Cloud: {provider}",
                                    tags=["cloud", provider.lower().replace(" ", "-")]
                                ))
    except Exception:
        pass
    return findings

async def _check_whois_cloud(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            whois_text = resp.text.lower()
            for keyword, provider in CLOUD_WHOIS_ORG.items():
                if keyword in whois_text:
                    findings.append(make_finding(
                        entity=f"WHOIS organization suggests {provider}",
                        type="Cloud Detection - WHOIS Organization",
                        source="Passive Cloud Detection",
                        confidence="Medium",
                        color="orange",
                        status=f"Cloud: {provider}",
                        raw_data=f"WHOIS matched '{keyword}' indicating {provider}",
                        tags=["cloud", "whois", provider.lower().replace(" ", "-")]
                    ))
    except Exception:
        pass
    return findings

async def _check_dns_txt_cloud(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    for pattern, service in TXT_VERIFICATION.items():
                        if pattern.lower() in txt:
                            findings.append(make_finding(
                                entity=f"TXT verification for {service} (pattern: {pattern})",
                                type="Cloud Detection - TXT Verification Record",
                                source="Passive Cloud Detection",
                                confidence="High",
                                color="orange",
                                status=f"Verified: {service}",
                                raw_data=f"TXT matched '{pattern}' indicates {service}",
                                tags=["cloud", "txt", service.lower().replace(" ", "-")]
                            ))
                    if "v=spf" in txt:
                        include_match = re.search(r'include:([\w.]+)', txt)
                        if include_match:
                            included = include_match.group(1)
                            for provider, patterns in CLOUD_CNAME_PATTERNS.items():
                                for pat in patterns:
                                    if pat in included:
                                        findings.append(make_finding(
                                            entity=f"SPF include: {included} -> {provider}",
                                            type="Cloud Detection - SPF Cloud Provider",
                                            source="Passive Cloud Detection",
                                            confidence="High",
                                            color="orange",
                                            raw_data=f"SPF include domain {included} matches cloud provider {provider}",
                                            tags=["cloud", "spf", provider.lower().replace(" ", "-")]
                                        ))
    except Exception:
        pass
    return findings

async def _check_mx_cloud(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    mx_providers = {
        "google": "Google Workspace (Gmail)",
        "googlemail": "Google Workspace (Gmail)",
        "outlook.com": "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "mail.protection": "Microsoft 365",
        "zoho": "Zoho Mail",
        "protonmail": "ProtonMail",
        "proton": "ProtonMail",
        "yandex": "Yandex Mail",
        "mailgun": "Mailgun",
        "sendgrid": "SendGrid",
        "fastmail": "FastMail",
        "rackspace": "Rackspace Email",
        "icloud": "Apple iCloud",
        "mx.cloudflare": "Cloudflare Email",
    }
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=MX",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            mx_servers = []
            for ans in answers:
                if ans.get("type") == 15:
                    mx_val = ans.get("data", "").lower()
                    mx_servers.append(mx_val)
                    for keyword, provider in mx_providers.items():
                        if keyword in mx_val:
                            findings.append(make_finding(
                                entity=f"MX: {mx_val} -> {provider}",
                                type="Cloud Detection - Email Provider (MX)",
                                source="Passive Cloud Detection",
                                confidence="High",
                                color="orange",
                                raw_data=f"MX server {mx_val} identifies as {provider}",
                                tags=["cloud", "email", provider.lower().replace(" ", "-")]
                            ))
    except Exception:
        pass
    return findings

async def _check_ssl_issuer_cloud(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    ssl_cloud_map = {
        "cloudflare": "Cloudflare",
        "amazon": "Amazon Web Services",
        "google trust": "Google Cloud",
        "microsoft": "Microsoft Azure",
        "digicert": "DigiCert (Multi-Cloud)",
        "lets encrypt": "Let's Encrypt (Multi-Cloud)",
        "sectigo": "Sectigo (Multi-Cloud)",
    }
    try:
        resp = await safe_fetch(client, 
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            seen_issuers = set()
            for cert in certs[:100]:
                issuer = str(cert.get("issuer_name", ""))
                if issuer in seen_issuers:
                    continue
                seen_issuers.add(issuer)
                for keyword, provider in ssl_cloud_map.items():
                    if keyword in issuer.lower():
                        findings.append(make_finding(
                            entity=f"SSL Issuer: {issuer[:100]} -> Cloud: {provider}",
                            type="Cloud Detection - SSL Issuer",
                            source="Passive Cloud Detection",
                            confidence="Medium",
                            color="slate",
                            raw_data=f"SSL certificate issued by {issuer[:200]}",
                            tags=["cloud", "ssl", provider.lower().replace(" ", "-")]
                        ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    cname_findings = await _check_cname_patterns(domain, client)
    findings.extend(cname_findings)

    sub_findings = await _check_subdomains_for_cloud(domain, client)
    findings.extend(sub_findings)

    whois_findings = await _check_whois_cloud(domain, client)
    findings.extend(whois_findings)

    txt_findings = await _check_dns_txt_cloud(domain, client)
    findings.extend(txt_findings)

    mx_findings = await _check_mx_cloud(domain, client)
    findings.extend(mx_findings)

    ssl_findings = await _check_ssl_issuer_cloud(domain, client)
    findings.extend(ssl_findings)

    if findings:
        cloud_providers = set()
        for f in findings:
            for t in f.tags:
                if t in ["cloud"] or any(c in t for c in ["aws", "azure", "gcp", "cloudflare"]):
                    cloud_providers.add(t)
        findings.append(make_finding(
            entity=f"Cloud detection complete: {len(findings)} findings across {len(cloud_providers)} provider indicators",
            type="Cloud Detection - Summary",
            source="Passive Cloud Detection",
            confidence="High", color="purple",
            status="Complete",
            tags=["cloud", "summary"]
        ))

    return findings
