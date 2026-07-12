import httpx
import asyncio
import re
from urllib.parse import urlparse
from datetime import datetime
from models import IntelligenceFinding
from osint_common import resolve_dns, get_all_dns_records, get_ssl_cert_info, parse_cert_to_dict
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

CONTENT_CATEGORIES = [
    ("adult|porn|xxx|sex|nsfw", "Adult"),
    ("business|enterprise|corporate|company|llc|inc", "Business"),
    ("tech|technology|software|developer|programming|code|api", "Technology"),
    ("news|media|press|journal|article|blog|magazine", "News/Media"),
    ("shop|store|buy|product|cart|ecommerce|retail|amazon", "E-Commerce"),
    ("bank|finance|invest|trade|capital|money|payment|pay", "Finance"),
    ("health|medical|doctor|hospital|clinic|pharma", "Healthcare"),
    ("gov|government|state|federal|agency|official", "Government"),
    ("edu|school|university|college|academy|learning|course", "Education"),
    ("social|forum|community|chat|group|network", "Social Network"),
    ("game|gaming|play|casino|bet|poker|sport|sports", "Gaming/Sports"),
    ("mail|email|inbox|message|contact", "Communication"),
    ("wiki|knowledge|docs|documentation|howto|tutorial", "Reference"),
    ("cdn|cloud|host|server|infra|vps|dedicated", "Hosting/Infrastructure"),
]

RISK_KEYWORDS = {
    "malware": -10, "phishing": -10, "spam": -8, "scam": -8, "fraud": -8,
    "hack": -6, "exploit": -6, "crack": -6, "warez": -6, "piracy": -6,
    "torrent": -4, "gambling": -3, "casino": -3, "adult": -2, "sex": -2,
}

TRUSTED_KEYWORDS = {
    "ssl": 2, "secure": 2, "privacy": 2, "official": 3, "verified": 3,
    "trust": 3, "safe": 1, "legal": 2, "compliance": 2, "audit": 2,
}

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "date", "men", "loan", "download", "review", "racing", "faith", "click", "rest", "country", "mom", "cricket"}

REGISTRAR_REPUTATION = {
    "namecheap": 3, "godaddy": 2, "cloudflare": 5, "google": 4,
    "aws": 4, "azure": 4, "name.com": 3, "ionos": 2, "ovh": 3,
    "gandi": 4, "porkbun": 4, "netlify": 3, "verisign": 5,
    "publicdomainregistry": 1, "pdr": 1, "rebel": 2,
    "enom": 2, "network solutions": 2, "tucows": 2,
    "wild west domains": 1, "fastdomain": 2,
}

EMAIL_HOSTING_PROVIDERS = [
    ("google.com", "googlemail.com", "Google Workspace"),
    ("outlook.com", "protection.outlook.com", "microsoft.com", "Microsoft 365"),
    ("zoho.com", "zohomail.com", "Zoho Mail"),
    ("protonmail.com", "protonmail.ch", "ProtonMail"),
    ("yandex.ru", "yandex.net", "Yandex Mail"),
    ("mailgun.org", "mg.", "Mailgun"),
    ("sendgrid.net", "sendgrid.com", "SendGrid"),
    ("fastmail.com", "fastmail.fm", "FastMail"),
    ("rackspace.com", "Rackspace Email"),
    ("icloud.com", "me.com", "Apple iCloud"),
    ("mxroute.com", "MXroute"),
    ("titan.email", "Titan Email"),
    ("migadu.com", "Migadu"),
]

WEB_HOSTING_PROVIDERS = [
    ("cloudflare", "cloudflare.net", "Cloudflare"),
    ("aws", "amazonaws.com", "amazonaws.com.cn", "AWS"),
    ("google", "googleapis.com", "googleusercontent.com", "Google Cloud"),
    ("azure", "azure.com", "azureedge.net", "azurefd.net", "Microsoft Azure"),
    ("akamai", "akamaiedge.net", "akamai.net", "Akamai"),
    ("fastly", "fastly.net", "Fastly"),
    ("cloudfront", "cloudfront.net", "CloudFront (AWS CDN)"),
    ("netlify", "netlify.app", "Netlify"),
    ("vercel", "vercel.app", "Vercel"),
    ("github", "github.io", "GitHub Pages"),
    ("heroku", "herokuapp.com", "Heroku"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode (Akamai)"),
    ("ovh", "OVHcloud"),
    ("hetzner", "Hetzner"),
    ("vultr", "Vultr"),
    ("namecheap", "Namecheap Hosting"),
    ("siteground", "SiteGround"),
    ("wpengine", "WP Engine"),
    ("wordpress", "WordPress.com"),
    ("shopify", "Shopify"),
    ("squarespace", "Squarespace"),
    ("wix", "Wix"),
    ("ionos", "IONOS (1&1)"),
    ("bluehost", "Bluehost"),
    ("hostgator", "HostGator"),
    ("dreamhost", "DreamHost"),
    ("godaddy", "GoDaddy Hosting"),
]

SOCIAL_MEDIA_PATTERNS = [
    (r"facebook\.com/[a-zA-Z0-9.]+", "Facebook"),
    (r"twitter\.com/[a-zA-Z0-9_]+", "Twitter/X"),
    (r"x\.com/[a-zA-Z0-9_]+", "X/Twitter"),
    (r"linkedin\.com/(company|in)/[a-zA-Z0-9-]+", "LinkedIn"),
    (r"github\.com/[a-zA-Z0-9_.-]+", "GitHub"),
    (r"instagram\.com/[a-zA-Z0-9_.]+", "Instagram"),
    (r"youtube\.com/@?[a-zA-Z0-9_.-]+", "YouTube"),
    (r"tiktok\.com/@[a-zA-Z0-9_.]+", "TikTok"),
    (r"discord\.gg/[a-zA-Z0-9]+", "Discord"),
    (r"t\.me/[a-zA-Z0-9_]+", "Telegram"),
    (r"medium\.com/@[a-zA-Z0-9_.]+", "Medium"),
    (r"reddit\.com/r/[a-zA-Z0-9_]+", "Reddit"),
]

RISKY_REGISTRARS = {
    "porkbun", "namecheap", "namesilo", "dynadot", "internet.bs",
    "sav", "spaceship", "hostinger", "bigrock", "resellerclub",
    "publicdomainregistry", "pdr", "rebely",
}

RISKY_HOSTING_NAMESERVERS = {
    "cloudflare.com": "Cloudflare (often used to hide origin)",
    "akamai.net": "Akamai (CDN)",
    "akamaiedge.net": "Akamai Edge (CDN)",
    "fastly.net": "Fastly (CDN)",
}


async def get_whois_data(domain: str) -> dict:
    result = {}
    try:
        loop = asyncio.get_event_loop()
        whois_server = "whois.verisign-grs.com"
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(whois_server, 43), timeout=10.0)
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), timeout=15.0)
        writer.close()
        text = data.decode("utf-8", errors="ignore")
        if "Creation Date" in text:
            m = re.search(r"Creation Date:\s*(.+)", text)
            if m: result["creation_date"] = m.group(1).strip()
        if "Registry Expiry Date" in text:
            m = re.search(r"Registry Expiry Date:\s*(.+)", text)
            if m: result["expiration_date"] = m.group(1).strip()
        if "Updated Date" in text:
            m = re.search(r"Updated Date:\s*(.+)", text)
            if m: result["updated_date"] = m.group(1).strip()
        if "Registrar" in text:
            m = re.search(r"Registrar:\s*(.+)", text)
            if m: result["registrar"] = m.group(1).strip()
        if "Name Server" in text:
            ns = re.findall(r"Name Server:\s*(.+)", text)
            if ns: result["nameservers"] = [n.strip() for n in ns]
        if "Domain Status" in text:
            statuses = re.findall(r"Domain Status:\s*(.+)", text)
            if statuses: result["statuses"] = [s.strip() for s in statuses]
        if "Registrant Organization" in text:
            m = re.search(r"Registrant Organization:\s*(.+)", text)
            if m: result["org"] = m.group(1).strip()
        if "Registrant Country" in text:
            m = re.search(r"Registrant Country:\s*(.+)", text)
            if m: result["country"] = m.group(1).strip()
        if "Registrant Email" in text:
            m = re.search(r"Registrant Email:\s*(.+)", text)
            if m: result["email"] = m.group(1).strip()
        result["raw"] = text[:3000]
    except:
        pass
    return result


async def check_http_service(domain: str, client: httpx.AsyncClient) -> dict:
    result = {}
    for scheme in ["https", "http"]:
        try:
            resp = await safe_fetch(client, f"{scheme}://{domain}", timeout=10.0, follow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            result[f"{scheme}_status"] = resp.status_code
            result[f"{scheme}_server"] = resp.headers.get("server", "")
            result[f"{scheme}_ctype"] = resp.headers.get("content-type", "")
            result[f"{scheme}_powered"] = resp.headers.get("x-powered-by", "")
            result[f"{scheme}_cf_ray"] = resp.headers.get("cf-ray", "")
            result[f"{scheme}_set_cookie"] = resp.headers.get("set-cookie", "")
            result[f"{scheme}_location"] = resp.headers.get("location", "")
            result[f"{scheme}_xframe"] = resp.headers.get("x-frame-options", "")
            result[f"{scheme}_csp"] = resp.headers.get("content-security-policy", "")
            result[f"{scheme}_hsts"] = resp.headers.get("strict-transport-security", "")
            result[f"{scheme}_title"] = ""
            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if m:
                result[f"{scheme}_title"] = m.group(1).strip()[:200]
            result[f"{scheme}_headers"] = dict(resp.headers)
            if scheme == "https":
                result["html_sample"] = resp.text[:5000]
            break
        except:
            continue
    return result


def categorize_content(domain: str, page_title: str, html_sample: str) -> list:
    matched = []
    text = f"{domain} {page_title} {html_sample or ''}".lower()
    for pattern, category in CONTENT_CATEGORIES:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(category)
    return matched or ["General/Unknown"]


def score_reputation(domain: str, categories: list, whois: dict, dns_records: dict) -> int:
    score = 50
    for kw, val in RISK_KEYWORDS.items():
        if kw in domain.lower():
            score += val
    for kw, val in TRUSTED_KEYWORDS.items():
        if kw in domain.lower():
            score += val
    if whois.get("creation_date"):
        score += 5
        try:
            cd = whois["creation_date"][:10]
            created = datetime.strptime(cd, "%Y-%m-%d")
            age_days = (datetime.now() - created).days
            if age_days > 365 * 3:
                score += 10
            elif age_days < 30:
                score -= 15
        except:
            pass
    if whois.get("registrar"):
        score += 3
        reg = whois["registrar"].lower()
        for rname, rscore in REGISTRAR_REPUTATION.items():
            if rname in reg:
                score += rscore
                break
    if dns_records.get("MX"):
        score += 5
    if dns_records.get("TXT"):
        score += 3
    for cat in categories:
        if cat in ("Finance", "Government", "Healthcare"):
            score += 5
        elif cat in ("Adult", "Gaming/Sports"):
            score -= 5
    return max(0, min(100, score))


async def _check_domain_age_risk(domain: str, whois_data: dict) -> list:
    findings = []
    if whois_data.get("creation_date"):
        try:
            cd = whois_data["creation_date"][:10]
            created = datetime.strptime(cd, "%Y-%m-%d")
            age_days = (datetime.now() - created).days
            age_years = age_days / 365.25
            findings.append(make_finding(
                entity=f"Domain Age: {age_years:.1f} years ({age_days} days)",
                type="Domain Age Analysis",
                source="DomainProfileDeep",
                confidence="High",
                color="emerald" if age_years > 3 else ("orange" if age_days > 30 else "red"),
                threat_level="Informational" if age_years > 3 else ("Standard Target" if age_days > 30 else "High Risk"),
                status="Established" if age_years > 3 else ("Mature" if age_days > 365 else "New"),
                raw_data=f"Created: {cd}, Age: {age_days} days",
                tags=["domain-age", "risk-assessment"]
            ))
            if age_days < 365:
                findings.append(make_finding(
                    entity="NEWLY REGISTERED DOMAIN - higher phishing/malware risk",
                    ftype="New Domain Risk Alert",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="New Domain",
                    raw_data=f"Domain registered {age_days} days ago",
                    tags=["new-domain", "freshly-registered"]
                ))
        except:
            pass
    else:
        findings.append(make_finding(
            entity="Creation date not available in WHOIS",
            ftype="Domain Age Analysis",
            source="DomainProfileDeep",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="Unknown",
            tags=["domain-age", "whois-gap"]
        ))
    return findings


async def _check_registrar_reputation(whois_data: dict) -> list:
    findings = []
    registrar = whois_data.get("registrar", "")
    if registrar:
        reg_lower = registrar.lower()
        rep_score = 0
        matched_reg = None
        for rname, rscore in REGISTRAR_REPUTATION.items():
            if rname in reg_lower:
                rep_score = rscore
                matched_reg = rname
                break
        if matched_reg:
            rep_level = "Trusted" if rep_score >= 4 else ("Standard" if rep_score >= 2 else "Low Trust")
            rep_color = "emerald" if rep_score >= 4 else ("slate" if rep_score >= 2 else "orange")
            findings.append(make_finding(
                entity=f"Registrar: {registrar} (Reputation: {matched_reg.title()} - {rep_level})",
                type="Registrar Reputation Analysis",
                source="DomainProfileDeep",
                confidence="High",
                color=rep_color,
                threat_level="Informational" if rep_score >= 4 else ("Standard Target" if rep_score >= 2 else "Elevated Risk"),
                status=f"Score: {rep_score}/5",
                raw_data=f"Registrar: {registrar}, Matched: {matched_reg}, Score: {rep_score}",
                tags=["registrar", "reputation"]
            ))
        for risky_reg in RISKY_REGISTRARS:
            if risky_reg in reg_lower:
                findings.append(make_finding(
                    entity=f"Registrar {registrar} known for risky/poor verification",
                    ftype="Risky Registrar Alert",
                    source="DomainProfileDeep",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Risky Registrar",
                    raw_data=f"Registrar {registrar} often associated with spam/malware domains",
                    tags=["risky-registrar", "abuse"]
                ))
                break
    return findings


async def _check_nameserver_hosting(dns_records: dict) -> list:
    findings = []
    ns_records = dns_records.get("NS", [])
    if ns_records:
        for ns in ns_records[:5]:
            ns_lower = ns.lower()
            provider = None
            if "awsdns" in ns_lower:
                provider = "AWS Route53"
            elif "cloudflare" in ns_lower:
                provider = "Cloudflare DNS"
            elif "google" in ns_lower or "googledomains" in ns_lower:
                provider = "Google Cloud DNS"
            elif "azure" in ns_lower:
                provider = "Azure DNS"
            elif "dnsmadeeasy" in ns_lower:
                provider = "DNS Made Easy"
            elif "ns1.com" in ns_lower:
                provider = "NS1"
            elif "ultradns" in ns_lower or "neustar" in ns_lower:
                provider = "UltraDNS (Neustar)"
            elif "akamai" in ns_lower:
                provider = "Akamai DNS"
            elif "domaincontrol" in ns_lower or "secureserver" in ns_lower:
                provider = "GoDaddy DNS"
            elif "registrar-servers" in ns_lower:
                provider = "Namecheap Free DNS"
            elif "name-services" in ns_lower:
                provider = "Name.com DNS"
            elif "xserver" in ns_lower:
                provider = "XServer DNS"
            elif "dns" in ns_lower and "hosting" in ns_lower:
                provider = "Custom Hosting DNS"
            if provider:
                findings.append(make_finding(
                    entity=f"NS: {ns} ({provider})",
                    type="Nameserver Provider Detection",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="emerald",
                    status=provider,
                    raw_data=f"Nameserver: {ns} -> {provider}",
                    tags=["nameserver", "provider", "dns-hosting"]
                ))
            else:
                findings.append(make_finding(
                    entity=ns,
                    ftype="Nameserver (DNS Record)",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="slate",
                    status="Unknown Provider",
                    raw_data=f"NS: {ns}",
                    tags=["nameserver"]
                ))
    return findings


async def _detect_email_hosting(dns_records: dict, client: httpx.AsyncClient) -> list:
    findings = []
    mx_records = dns_records.get("MX", [])
    if mx_records:
        detected_providers = set()
        for mx in mx_records:
            mx_str = str(mx).lower()
            for patterns in EMAIL_HOSTING_PROVIDERS:
                provider_name = patterns[-1]
                for pattern in patterns[:-1]:
                    if pattern in mx_str:
                        detected_providers.add(provider_name)
                        break
        if detected_providers:
            for provider in sorted(detected_providers):
                findings.append(make_finding(
                    entity=f"Email Hosting: {provider}",
                    ftype="Email Hosting Provider",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="emerald",
                    status="Detected",
                    raw_data=f"MX records indicate {provider} email hosting",
                    tags=["email", "hosting", "provider"]
                ))
        else:
            mx_strs = [str(mx) for mx in mx_records[:3]]
            findings.append(make_finding(
                entity=f"Custom/Unknown email hosting (MX: {', '.join(mx_strs)})",
                type="Email Hosting Provider",
                source="DomainProfileDeep",
                confidence="Medium",
                color="slate",
                status="Custom",
                raw_data=f"Unrecognized MX servers: {mx_strs}",
                tags=["email", "custom-hosting"]
            ))
    else:
        findings.append(make_finding(
            entity="No email hosting (no MX records)",
            type="Email Hosting Detection",
            source="DomainProfileDeep",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="No Email",
            raw_data="No MX records - domain cannot receive email",
            tags=["email", "no-email"]
        ))
    return findings


async def _detect_web_hosting(http_info: dict, dns_records: dict) -> list:
    findings = []
    server = http_info.get("https_server", http_info.get("http_server", ""))
    cf_ray = http_info.get("https_cf_ray", "")
    ns_records = dns_records.get("NS", [])
    ns_str = " ".join(str(ns).lower() for ns in ns_records)

    detected = set()
    if server:
        server_lower = server.lower()
        for patterns, provider_name in [(p[:-1], p[-1]) for p in WEB_HOSTING_PROVIDERS]:
            for pattern in patterns:
                if pattern in server_lower:
                    detected.add(provider_name)
                    break
    if cf_ray:
        detected.add("Cloudflare (CDN)")

    for patterns, provider_name in [(p[:-1], p[-1]) for p in WEB_HOSTING_PROVIDERS]:
        for pattern in patterns:
            if pattern in ns_str:
                detected.add(f"{provider_name} (DNS)")
                break

    if detected:
        for provider in sorted(detected):
            findings.append(make_finding(
                entity=f"Web Infrastructure: {provider}",
                ftype="Web Hosting/CDN Detection",
                source="DomainProfileDeep",
                confidence="High",
                color="purple",
                status="Detected",
                raw_data=f"Detected via headers/NS: {provider}",
                tags=["web-hosting", "cdn", "infrastructure"]
            ))
    return findings


async def _check_security_headers(http_info: dict) -> list:
    findings = []
    hsts = http_info.get("https_hsts", "")
    csp = http_info.get("https_csp", "")
    xframe = http_info.get("https_xframe", "")
    powered = http_info.get("https_powered", "")

    if hsts:
        findings.append(make_finding(
            entity=f"HTTP Strict Transport Security: Enabled ({hsts[:100]})",
            type="Security Header - HSTS",
            source="DomainProfileDeep",
            confidence="High",
            color="emerald",
            status="Secure",
            raw_data=f"HSTS: {hsts}",
            tags=["security-header", "hsts"]
        ))
    else:
        findings.append(make_finding(
            entity="HSTS not configured (Strict-Transport-Security missing)",
            type="Missing Security Header",
            source="DomainProfileDeep",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="Missing",
            raw_data="No HSTS header",
            tags=["security-header", "hsts-missing"]
        ))

    if xframe:
        findings.append(make_finding(
            entity=f"X-Frame-Options: {xframe}",
            ftype="Security Header - ClickJacking Protection",
            source="DomainProfileDeep",
            confidence="High",
            color="emerald",
            status="Protected",
            raw_data=f"X-Frame-Options: {xframe}",
            tags=["security-header", "clickjacking"]
        ))
    else:
        findings.append(make_finding(
            entity="X-Frame-Options not set - vulnerable to clickjacking",
            ftype="Missing Security Header",
            source="DomainProfileDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Vulnerable",
            raw_data="No X-Frame-Options header",
            tags=["security-header", "clickjacking"]
        ))

    if csp:
        findings.append(make_finding(
            entity=f"Content-Security-Policy: {csp[:200]}",
            ftype="Security Header - CSP",
            source="DomainProfileDeep",
            confidence="High",
            color="emerald",
            status="Configured",
            raw_data=f"CSP: {csp[:500]}",
            tags=["security-header", "csp"]
        ))
    if powered:
        findings.append(make_finding(
            entity=f"Technology: {powered}",
            ftype="Technology Detection (X-Powered-By)",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            status="Detected",
            raw_data=f"X-Powered-By: {powered}",
            tags=["technology", "fingerprinting"]
        ))
    return findings


async def _check_social_media(http_info: dict) -> list:
    findings = []
    html = http_info.get("html_sample", "")
    if not html:
        return findings
    detected = set()
    for pattern, platform in SOCIAL_MEDIA_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            detected.add(platform)
    for platform in sorted(detected):
        findings.append(make_finding(
            entity=f"Social Media Presence: {platform}",
            ftype="Social Media Discovery",
            source="DomainProfileDeep",
            confidence="Medium",
            color="purple",
            status="Found on page",
            raw_data=f"Linked to {platform} found in page content",
            tags=["social-media", "osint"]
        ))
    return findings


async def _check_tld_risk(domain: str) -> list:
    findings = []
    tld = domain.split(".")[-1].lower()
    if tld in RISKY_TLDS:
        findings.append(make_finding(
            entity=f"Risky TLD: .{tld} - frequently abused for spam/malware",
            ftype="TLD Risk Assessment",
            source="DomainProfileDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Risky TLD",
            raw_data=f"TLD .{tld} is in the list of known abused TLDs",
            tags=["tld", "risk", "abuse"]
        ))
    if len(domain) > 50:
        findings.append(make_finding(
            entity=f"Very long domain ({len(domain)} chars) - potential DGA or algorithmically generated",
            type="Domain Length Anomaly",
            source="DomainProfileDeep",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="Anomalous",
            raw_data=f"Domain length: {len(domain)} characters",
            tags=["dga", "algorithmic", "anomaly"]
        ))
    return findings


async def _check_dns_records_extended(dns_records: dict, domain: str) -> list:
    findings = []
    all_strs = set()
    for rtype, records in dns_records.items():
        for rec in records:
            all_strs.add(str(rec).lower())
    all_text = " ".join(all_strs)

    cname_targets = [str(r) for r in dns_records.get("CNAME", [])]
    if cname_targets:
        for cname in cname_targets[:3]:
            findings.append(make_finding(
                entity=f"CNAME: {domain} -> {cname}",
                ftype="CNAME Record Analysis",
                source="DomainProfileDeep",
                confidence="High",
                color="purple",
                status="Alias",
                raw_data=f"{domain} is a CNAME alias for {cname}",
                tags=["dns", "cname", "alias"]
            ))
            if "s3" in cname.lower() or "amazonaws" in cname.lower():
                findings.append(make_finding(
                    entity=f"CNAME points to AWS: {cname}",
                    ftype="AWS Service Detection",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="orange",
                    status="AWS S3/CloudFront",
                    raw_data=f"{domain} -> {cname} (AWS)",
                    tags=["aws", "s3", "cloud"]
                ))
            if "cloudfront" in cname.lower():
                findings.append(make_finding(
                    entity=f"CNAME points to CloudFront CDN",
                    ftype="CDN Detection via CNAME",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="emerald",
                    status="CloudFront CDN",
                    raw_data=f"CNAME target: {cname}",
                    tags=["cdn", "cloudfront"]
                ))

    a_records = [str(r) for r in dns_records.get("A", [])]
    if len(a_records) > 3:
        findings.append(make_finding(
            entity=f"Multiple A records ({len(a_records)}): {', '.join(a_records)}",
            type="Multiple A Records - Load Balancing",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Load Balanced",
            raw_data=f"A records: {a_records}",
            tags=["dns", "load-balancing", "multi-a"]
        ))
    return findings


async def _check_ssl_cert_info(domain: str) -> list:
    findings = []
    try:
        cert_info = await get_ssl_cert_info(domain)
        if cert_info and cert_info.get("cert"):
            parsed = parse_cert_to_dict(cert_info["cert"])
            if parsed.get("issuer"):
                org = parsed["issuer"].get("organizationName", "Unknown")
                cn = parsed["issuer"].get("commonName", "")
                findings.append(make_finding(
                    entity=f"{org} ({cn})" if cn else org,
                    type="SSL Certificate Authority",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Valid SSL",
                    resolution=f"Issuer: {org}",
                    tags=["ssl", "certificate"]
                ))
            if parsed.get("days_remaining") is not None:
                days = parsed["days_remaining"]
                color = "emerald" if days > 30 else ("orange" if days > 7 else "red")
                risk = "Informational" if days > 30 else ("Elevated Risk" if days > 7 else "High Risk")
                findings.append(make_finding(
                    entity=f"{days} days remaining ({parsed.get('valid_to', '')})",
                    type="SSL Expiry",
                    source="DomainProfileDeep",
                    confidence="High",
                    color=color,
                    threat_level=risk,
                    status="Expiring" if days < 30 else "Valid",
                    tags=["ssl", "certificate"]
                ))
            if parsed.get("is_expired"):
                findings.append(make_finding(
                    entity="SSL Certificate EXPIRED",
                    ftype="SSL Expired",
                    source="DomainProfileDeep",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Expired",
                    tags=["security", "ssl"]
                ))
            if parsed.get("subject_alt_names"):
                for san in parsed["subject_alt_names"][:8]:
                    findings.append(make_finding(
                        entity=san, ftype="SSL SAN", source="DomainProfileDeep",
                        confidence="High", color="blue", threat_level="Informational",
                        status="SAN", tags=["ssl", "san"]
                    ))
    except:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    whois_data = await get_whois_data(domain)
    dns_records = await get_all_dns_records(domain)
    http_info = await check_http_service(domain, client)

    for rtype, records in dns_records.items():
        for rec in records[:5]:
            findings.append(make_finding(
                entity=str(rec)[:200],
                type=f"DNS: {rtype} Record",
                source="DomainProfileDeep",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Resolved",
                resolution=f"DNS {rtype} lookup",
                tags=["dns", f"dns-{rtype.lower()}"]
            ))

    if whois_data.get("creation_date"):
        findings.append(make_finding(
            entity=whois_data["creation_date"],
            ftype="Domain Creation Date",
            source="DomainProfileDeep",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Domain created: {whois_data['creation_date']}",
            tags=["whois"]
        ))
    if whois_data.get("updated_date"):
        findings.append(make_finding(
            entity=whois_data["updated_date"],
            ftype="Domain Last Updated",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="WHOIS Data",
            raw_data=f"Last updated: {whois_data['updated_date']}",
            tags=["whois", "updated"]
        ))
    if whois_data.get("expiration_date"):
        findings.append(make_finding(
            entity=whois_data["expiration_date"],
            ftype="Domain Expiration Date",
            source="DomainProfileDeep",
            confidence="High",
            color="orange",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Domain expires: {whois_data['expiration_date']}",
            tags=["whois"]
        ))
    if whois_data.get("registrar"):
        findings.append(make_finding(
            entity=whois_data["registrar"],
            ftype="Domain Registrar",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="WHOIS Data",
            resolution=f"Registrar: {whois_data['registrar']}",
            tags=["whois"]
        ))
    if whois_data.get("org"):
        findings.append(make_finding(
            entity=whois_data["org"],
            ftype="Registrant Organization",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            status="WHOIS Data",
            tags=["whois", "organization"]
        ))
    if whois_data.get("country"):
        findings.append(make_finding(
            entity=f"Registrant Country: {whois_data['country']}",
            ftype="Registrant Geolocation",
            source="DomainProfileDeep",
            confidence="High",
            color="slate",
            status="WHOIS Data",
            tags=["whois", "geo"]
        ))
    if whois_data.get("email"):
        findings.append(make_finding(
            entity=whois_data["email"],
            ftype="Registrant Email Contact",
            source="DomainProfileDeep",
            confidence="High",
            color="orange",
            status="WHOIS Data",
            tags=["whois", "email"]
        ))
    if whois_data.get("statuses"):
        for st in whois_data["statuses"][:5]:
            findings.append(make_finding(
                entity=st,
                ftype="Domain Status",
                source="DomainProfileDeep",
                confidence="High",
                color="slate",
                status="WHOIS Status",
                tags=["whois", "domain-status"]
            ))

    if whois_data.get("nameservers"):
        for ns in whois_data["nameservers"][:5]:
            findings.append(make_finding(
                entity=ns,
                ftype="Name Server (WHOIS)",
                source="DomainProfileDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="WHOIS Data",
                tags=["whois", "nameserver"]
            ))

    https_title = http_info.get("https_title", "")
    html_sample = http_info.get("html_sample", "")
    categories = categorize_content(domain, https_title, html_sample)
    for cat in categories:
        findings.append(make_finding(
            entity=f"Content Category: {cat}",
            ftype="Domain Category",
            source="DomainProfileDeep",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Classified",
            tags=["classification"]
        ))

    for scheme in ["https", "http"]:
        status_key = f"{scheme}_status"
        server_key = f"{scheme}_server"
        if status_key in http_info:
            title_key = f"{scheme}_title"
            title_str = f" - {http_info.get(title_key, '')}" if http_info.get(title_key) else ""
            findings.append(make_finding(
                entity=f"{scheme.upper()} {http_info[status_key]}{title_str}",
                type=f"Web Service ({scheme.upper()})",
                source="DomainProfileDeep",
                confidence="High",
                color="emerald" if http_info[status_key] < 400 else "red",
                threat_level="Informational",
                status="Online" if http_info[status_key] < 400 else "Error",
                resolution=f"HTTP {http_info[status_key]}",
                tags=["web-service"]
            ))
        if server_key in http_info and http_info[server_key]:
            findings.append(make_finding(
                entity=http_info[server_key],
                ftype="Web Server",
                source="DomainProfileDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                tags=["web-server", "technology"]
            ))

    ssl_findings = await _check_ssl_cert_info(domain)
    findings.extend(ssl_findings)

    email_security = False
    if dns_records.get("MX"):
        for mx in dns_records["MX"][:5]:
            findings.append(make_finding(
                entity=str(mx), type="Mail Server (MX)", source="DomainProfileDeep",
                confidence="High", color="slate", threat_level="Informational",
                status="Resolved", tags=["email", "mx"]
            ))
        email_security = True
    if dns_records.get("TXT"):
        for txt in dns_records["TXT"]:
            txt_str = str(txt)
            if txt_str.startswith("v=spf1"):
                findings.append(make_finding(
                    entity=txt_str[:200], ftype="SPF Record", source="DomainProfileDeep",
                    confidence="High", color="emerald", threat_level="Informational",
                    status="Email Security", tags=["email-security"]
                ))
                email_security = True
            if "v=DMARC1" in txt_str or "dmarc" in txt_str.lower():
                continue
        try:
            loop = asyncio.get_event_loop()
            dmarc_records = await loop.run_in_executor(
                None, lambda: __import__("dns").resolver.resolve(f"_dmarc.{domain}", 'TXT'))
            for r in dmarc_records:
                dmarc = str(r)
                if "v=DMARC1" in dmarc:
                    findings.append(make_finding(
                        entity=dmarc[:200], ftype="DMARC Record", source="DomainProfileDeep",
                        confidence="High", color="emerald", threat_level="Informational",
                        status="Email Security", tags=["email-security"]
                    ))
                    email_security = True
                    if "p=reject" in dmarc:
                        findings.append(make_finding(
                            entity="DMARC Policy: Reject", ftype="DMARC Policy",
                            source="DomainProfileDeep", confidence="High", color="emerald",
                            threat_level="Informational", status="Strong", tags=["email-security"]
                        ))
                    elif "p=quarantine" in dmarc:
                        findings.append(make_finding(
                            entity="DMARC Policy: Quarantine", ftype="DMARC Policy",
                            source="DomainProfileDeep", confidence="High", color="emerald",
                            threat_level="Informational", status="Moderate", tags=["email-security"]
                        ))
                    elif "p=none" in dmarc:
                        findings.append(make_finding(
                            entity="DMARC Policy: None (no protection)", type="DMARC Weakness",
                            source="DomainProfileDeep", confidence="High", color="red",
                            threat_level="Elevated Risk", status="Weak", tags=["email-security"]
                        ))
        except:
            pass
    if not email_security:
        findings.append(make_finding(
            entity="No email security configured (SPF/DKIM/DMARC)",
            type="Missing Email Security",
            source="DomainProfileDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Vulnerable",
            tags=["email-security", "vulnerability"]
        ))

    age_findings = await _check_domain_age_risk(domain, whois_data)
    findings.extend(age_findings)

    reg_findings = await _check_registrar_reputation(whois_data)
    findings.extend(reg_findings)

    ns_findings = await _check_nameserver_hosting(dns_records)
    findings.extend(ns_findings)

    email_host_findings = await _detect_email_hosting(dns_records, client)
    findings.extend(email_host_findings)

    web_host_findings = await _detect_web_hosting(http_info, dns_records)
    findings.extend(web_host_findings)

    sec_header_findings = await _check_security_headers(http_info)
    findings.extend(sec_header_findings)

    social_findings = await _check_social_media(http_info)
    findings.extend(social_findings)

    tld_findings = await _check_tld_risk(domain)
    findings.extend(tld_findings)

    dns_extended = await _check_dns_records_extended(dns_records, domain)
    findings.extend(dns_extended)

    rep_score = score_reputation(domain, categories, whois_data, dns_records)
    rep_level = "Good" if rep_score >= 70 else ("Fair" if rep_score >= 40 else "Poor")
    rep_color = "emerald" if rep_score >= 70 else ("orange" if rep_score >= 40 else "red")
    findings.append(make_finding(
        entity=f"Domain Reputation Score: {rep_score}/100 ({rep_level})",
        type="Domain Reputation",
        source="DomainProfileDeep",
        confidence="High",
        color=rep_color,
        threat_level="Informational" if rep_score >= 70 else ("Standard Target" if rep_score >= 40 else "Elevated Risk"),
        status=rep_level,
        tags=["reputation", "summary"]
    ))

    findings.append(make_finding(
        entity=f"Domain profile complete: {len(dns_records)} DNS types, {len(categories)} categories, {len(whois_data)} WHOIS fields",
        type="Domain Profile Summary",
        source="DomainProfileDeep",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["summary"]
    ))

    return findings
