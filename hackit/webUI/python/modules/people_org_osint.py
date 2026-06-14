import httpx
import re
import asyncio
import json
from models import IntelligenceFinding
from urllib.parse import urlparse
from datetime import datetime


LEADERSHIP_TITLES = [
    "ceo", "cto", "cfo", "coo", "cmo", "cio", "ciso", "cso",
    "founder", "co-founder", "cofounder", "owner",
    "president", "vp", "vice president", "director",
    "head of", "lead", "chief", "principal",
]

DEPARTMENT_TITLES = [
    "engineering", "security", "product", "marketing", "sales",
    "hr", "human resources", "finance", "legal", "operations",
    "support", "devops", "infrastructure", "data",
]


async def extract_org_from_whois(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain = target.strip().lower()
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            text = resp.text
            org_keys = [
                "Registrant Organization", "OrgName", "org_name",
                "Organization", "company", "Company",
            ]
            email_keys = [
                "Registrant Email", "Tech Email", "Admin Email",
                "Abuse Email", "abuse-mailbox",
            ]
            for line in text.split("\n"):
                for key in org_keys:
                    if line.lower().startswith(key.lower()) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val and val != "N/A" and val != "None":
                            findings.append(IntelligenceFinding(
                                entity=val[:200],
                                type="WHOIS: Organization",
                                source="PeopleOrgOSINT (HackerTarget)",
                                confidence="High",
                                color="emerald",
                                threat_level="Informational",
                                status="Found in WHOIS",
                                raw_data=line[:500],
                                tags=["whois", "organization", val[:50].lower().replace(" ", "-")]
                            ))
                            break
                for key in email_keys:
                    if line.lower().startswith(key.lower()) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val and "@" in val:
                            findings.append(IntelligenceFinding(
                                entity=val[:200],
                                type="WHOIS: Contact Email",
                                source="PeopleOrgOSINT (HackerTarget)",
                                confidence="High",
                                color="cyan",
                                threat_level="Informational",
                                status="Found in WHOIS",
                                resolution=f"Role: {key}",
                                raw_data=line[:500],
                                tags=["whois", "email", "contact"]
                            ))
                            break
                if "Registrant Name" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if val and val != "N/A" and val != "None":
                        findings.append(IntelligenceFinding(
                            entity=val[:200],
                            type="WHOIS: Registrant Name",
                            source="PeopleOrgOSINT (HackerTarget)",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            tags=["whois", "person"]
                        ))
    except:
        pass
    return findings


async def extract_org_from_ssl(target: str) -> list:
    findings = []
    try:
        import ssl
        import socket
        from osint_common import get_ssl_cert_info, parse_cert_to_dict
        cert_info = await get_ssl_cert_info(target)
        if cert_info and cert_info.get("cert"):
            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)
            org = parsed.get("issuer", {}).get("organizationName", "")
            cn = parsed.get("issuer", {}).get("commonName", "")
            subj_org = parsed.get("subject", {}).get("organizationName", "")
            if org:
                findings.append(IntelligenceFinding(
                    entity=org[:200],
                    type="SSL: Issuer Organization",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Found in SSL cert",
                    tags=["ssl", "organization"]
                ))
            if subj_org and subj_org != org:
                findings.append(IntelligenceFinding(
                    entity=subj_org[:200],
                    type="SSL: Subject Organization",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["ssl", "organization", "subject"]
                ))
            if cn:
                findings.append(IntelligenceFinding(
                    entity=cn[:200],
                    type="SSL: Common Name",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "common-name"]
                ))
    except:
        pass
    return findings


async def extract_people_from_html(html: str, target: str) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target
    domain_upper = target.upper()

    # Extract team page links
    team_paths = re.findall(
        r'href=["\'](/?(?:team|about|company|people|leadership|staff|our-team|management|about-us)[^"\']*)["\']',
        html, re.IGNORECASE
    )
    for path in set(team_paths[:3]):
        findings.append(IntelligenceFinding(
            entity=f"https://{target}{path}",
            type="Team/About Page Link",
            source="PeopleOrgOSINT (HTML)",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Found",
            tags=["team-page", "about-page"]
        ))

    # Extract social links for company
    social_patterns = [
        (r'linkedin\.com/company/([a-zA-Z0-9_-]+)', "LinkedIn Company"),
        (r'linkedin\.com/in/([a-zA-Z0-9_-]+)', "LinkedIn Profile"),
        (r'github\.com/([a-zA-Z0-9_-]+)', "GitHub Profile"),
        (r'twitter\.com/([a-zA-Z0-9_]+)', "Twitter/X Profile"),
        (r'facebook\.com/([a-zA-Z0-9._-]+)', "Facebook Page"),
        (r'crunchbase\.com/organization/([a-zA-Z0-9_-]+)', "Crunchbase"),
        (r'angel\.co/([a-zA-Z0-9_-]+)', "AngelList"),
    ]
    for pattern, label in social_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:2]:
            findings.append(IntelligenceFinding(
                entity=m[:200],
                type=f"Social: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Found in HTML",
                tags=["social", label.lower().replace(" ", "-")]
            ))

    # Extract JSON-LD structured data
    ld_json = re.findall(
        r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL
    )
    for block in ld_json[:3]:
        try:
            data = json.loads(block)
            if isinstance(data, dict):
                for key in ["name", "legalName", "alternateName"]:
                    val = data.get(key, "")
                    if val:
                        findings.append(IntelligenceFinding(
                            entity=val[:200],
                            type="Schema.org: Organization Name",
                            source="PeopleOrgOSINT (JSON-LD)",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            tags=["json-ld", "schema", "organization"]
                        ))
                founder = data.get("founder", "")
                if isinstance(founder, dict) and founder.get("name"):
                    findings.append(IntelligenceFinding(
                        entity=founder["name"][:200],
                        type="Schema.org: Founder",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="cyan",
                        threat_level="Informational",
                        tags=["json-ld", "founder", "person"]
                    ))
                employees = data.get("numberOfEmployees", "")
                if employees:
                    findings.append(IntelligenceFinding(
                        entity=str(employees)[:100],
                        type="Schema.org: Employee Count",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["json-ld", "employees"]
                    ))
                same_as = data.get("sameAs", [])
                if isinstance(same_as, list):
                    for link in same_as:
                        findings.append(IntelligenceFinding(
                            entity=link[:200],
                            type="Schema.org: SameAs (Social)",
                            source="PeopleOrgOSINT (JSON-LD)",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            tags=["json-ld", "social-link"]
                        ))
        except:
            pass

    # Extract org name from Open Graph and meta tags
    for pattern, label, key_name in [
        (r'<meta\s+property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)["\']', "OG Site Name", "meta"),
        (r'<meta\s+name=["\']twitter:site["\'][^>]*content=["\']([^"\']+)["\']', "Twitter Site", "meta"),
        (r'<meta\s+name=["\']author["\'][^>]*content=["\']([^"\']+)["\']', "Meta Author", "meta"),
        (r'<meta\s+name=["\']application-name["\'][^>]*content=["\']([^"\']+)["\']', "App Name", "meta"),
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(IntelligenceFinding(
                entity=m.group(1)[:200],
                type=f"Meta: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["meta", label.lower().replace(" ", "-")]
            ))

    # Extract copyright notice
    copyright_match = re.search(
        r'(?:copyright|©)\s*(?:20\d\d\s*)?([^.\n]{5,80})',
        html, re.IGNORECASE
    )
    if copyright_match:
        entity = copyright_match.group(1).strip()
        if len(entity) > 3 and domain_short.lower() not in entity.lower():
            findings.append(IntelligenceFinding(
                entity=entity[:200],
                type="Copyright: Organization Name",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["copyright", "organization"]
            ))

    return findings


async def search_github_org(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target
    try:
        resp = await client.get(
            f"https://api.github.com/search/users?q={domain_short}+in:name+type:org",
            timeout=10.0,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/vnd.github.v3+json"
            }
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            for item in items[:3]:
                findings.append(IntelligenceFinding(
                    entity=item.get("login", "")[:200],
                    type="GitHub Organization Match",
                    source="PeopleOrgOSINT (GitHub)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    resolution=item.get("html_url", ""),
                    raw_data=f"GitHub: {item.get('login')} - {item.get('html_url')}",
                    tags=["github", "organization", f"github-{item.get('login', '')}"]
                ))
    except:
        pass
    return findings


async def search_security_contacts(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    paths = [
        "/.well-known/security.txt",
        "/security.txt",
        "/security.md",
        "/.well-known/vulnerability-disclosure-policy",
    ]
    for path in paths:
        try:
            resp = await client.get(
                f"https://{target}{path}",
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200 and len(resp.text) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"https://{target}{path}",
                    type="Security Contact File",
                    source="PeopleOrgOSINT",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Found",
                    raw_data=resp.text[:500],
                    tags=["security", "contact", path.split("/")[-1]]
                ))
                # Extract emails from security.txt
                emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', resp.text)
                for email in emails[:3]:
                    findings.append(IntelligenceFinding(
                        entity=email,
                        type="Security Contact Email",
                        source="PeopleOrgOSINT",
                        confidence="High",
                        color="cyan",
                        threat_level="Informational",
                        status="Found in security.txt",
                        resolution="Security contact",
                        tags=["security", "email", "contact"]
                    ))
        except:
            pass
    return findings


async def extract_emails_from_page(html: str, target: str) -> list:
    findings = []
    emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', html)
    domain_lower = target.lower()
    for email in set(emails):
        email_domain = email.split("@")[-1].lower()
        if email_domain == domain_lower or email_domain.endswith("." + domain_lower):
            findings.append(IntelligenceFinding(
                entity=email,
                type="Corporate Email Address",
                source="PeopleOrgOSINT (HTML)",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Found on website",
                tags=["email", "corporate"]
            ))
    return findings


async def extract_contact_page(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    contact_paths = ["/contact", "/contact-us", "/contactus", "/about", "/about-us"]
    for path in contact_paths:
        try:
            resp = await client.get(
                f"https://{target}{path}",
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0"},
                follow_redirects=True
            )
            if resp.status_code == 200 and len(resp.text) > 200:
                html = resp.text.lower()
                phones = re.findall(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]', html)
                for phone in phones[:2]:
                    findings.append(IntelligenceFinding(
                        entity=phone.strip()[:30],
                        type="Contact Phone Number",
                        source="PeopleOrgOSINT",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["contact", "phone"]
                    ))
                # Find location/address
                addr_markers = ["address", "street", "suite", "avenue", "boulevard", "drive", "lane", "road"]
                lines = html.split("\n")
                for line in lines:
                    line_clean = line.strip()
                    if any(m in line_clean for m in addr_markers) and len(line_clean) > 15 and len(line_clean) < 200:
                        findings.append(IntelligenceFinding(
                            entity=re.sub(r'<[^>]+>', '', line_clean).strip()[:200],
                            type="Office Address",
                            source="PeopleOrgOSINT",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            tags=["contact", "address", "location"]
                        ))
                        break
                break
        except:
            continue
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    try:
        resp = await client.get(
            f"https://{domain}",
            follow_redirects=True, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        html = resp.text[:200000] if hasattr(resp, 'text') else ""
    except:
        pass

    tasks = [
        extract_org_from_whois(domain, client),
        extract_org_from_ssl(domain),
        search_github_org(domain, client),
        search_security_contacts(domain, client),
        extract_contact_page(domain, client),
    ]

    if html:
        tasks.append(extract_people_from_html(html, domain))
        tasks.append(extract_emails_from_page(html, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    org_names = [f.entity for f in findings if "Organization" in f.type or "Org" in f.type]
    people_count = sum(1 for f in findings if "Email" in f.type or "Name" in f.type or "Founder" in f.type)
    social_count = sum(1 for f in findings if "Social" in f.type or "GitHub" in f.type)

    findings.append(IntelligenceFinding(
        entity=f"People & Org OSINT: {len(set(org_names))} orgs, {people_count} people/contacts, {social_count} social links",
        type="People & Org OSINT Summary",
        source="PeopleOrgOSINT",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{len(findings)} findings",
        tags=["people-osint", "org-osint", "summary"]
    ))

    return findings
