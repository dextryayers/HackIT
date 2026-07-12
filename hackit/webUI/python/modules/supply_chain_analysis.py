from urllib.parse import urlparse
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

THIRD_PARTY_CATEGORIES = {
    "CDN": ["cloudflare", "akamai", "fastly", "cloudfront", "cdn", "stackpath", "keycdn", "bunnycdn", "section.io"],
    "Analytics": ["google analytics", "gtag", "ga.js", "segment", "mixpanel", "hotjar", "amplitude", "fullstory", "heap"],
    "Email": ["sendgrid", "mailchimp", "mailgun", "postmark", "smtp", "ses.amazonaws", "sparkpost", "mailjet"],
    "DNS": ["route53", "cloudflare dns", "ns1", "dnsmadeeasy", "ultradns", "akamai dns", "neustar"],
    "Payments": ["stripe", "paypal", "braintree", "square", "authorize.net", "adyen", "shopify payments", "recurly"],
    "Monitoring": ["datadog", "new relic", "dynatrace", "sentry", "appdynamics", "grafana", "prometheus"],
    "Hosting": ["aws", "azure", "gcp", "google cloud", "digitalocean", "linode", "vultr", "heroku", "netlify", "vercel"],
    "Support": ["zendesk", "intercom", "freshdesk", "helpscout", "livechat", "crisp", "tawk.to"],
    "Marketing": ["hubspot", "marketo", "salesforce", "pardot", "mailchimp", "constant contact", "activecampaign"],
    "Security": ["cloudflare", "imperva", "incapsula", "sucuri", "akamai kona", "f5", "barracuda"],
}

SHADOW_IT_INDICATORS = [
    "free", "trial", "personal", "gmail.com", "yahoo.com", "outlook.com",
    "hotmail.com", "jira", "confluence", "slack.com", "trello", "asana",
    "notion.so", "miro", "figma", "canva", "dropbox", "wetransfer",
]

THIRD_PARTY_BREACHES = {
    "Cloudflare": ["Cloudflare 2024", "Cloudbleed 2017"],
    "AWS": ["Accidentally exposed S3 buckets"],
    "Azure": ["Azure AD compromise 2024"],
    "Okta": ["Okta breach 2022", "Okta support breach 2023"],
    "GitHub": ["GitHub OAuth breach"],
    "Slack": ["Slack GH token leak"],
    "Atlassian": ["Atlassian 2024 breach"],
    "Twilio": ["Twilio 2022 breach"],
    "Salesforce": ["Salesforce misconfig"],
    "Zendesk": ["Zendesk API exposure"],
}


async def identify_third_party_services(target: str, client: httpx.AsyncClient) -> dict:
    services_found = {}
    try:
        resp = await safe_fetch(client,
            f"https://{target}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
        )
        if resp.status_code == 200:
            text = resp.text.lower()
            headers_text = str(resp.headers).lower()
            combined = text + headers_text

            for category, indicators in THIRD_PARTY_CATEGORIES.items():
                found = [ind for ind in indicators if ind in combined]
                if found:
                    services_found[category] = found

            shadow_it_found = [ind for ind in SHADOW_IT_INDICATORS if ind in combined]
            if shadow_it_found:
                services_found["shadow_it"] = shadow_it_found

        dns_resp = await safe_fetch(client,
            f"https://dns.google/resolve?name={target}&ftype=MX",
            timeout=10.0,
        )
        if dns_resp.status_code == 200:
            mx_data = dns_resp.json()
            mx_records = [a.get("data", "") for a in mx_data.get("Answer", [])]
            for mx in mx_records:
                for cat, indicators in THIRD_PARTY_CATEGORIES.items():
                    for ind in indicators:
                        if ind in mx.lower():
                            if f"MX:{cat}" not in services_found:
                                services_found[f"MX:{cat}"] = []
                            services_found[f"MX:{cat}"].append(ind)
    except:
        pass
    return services_found


def check_single_points_of_failure(services: dict) -> list:
    spof = []
    critical_categories = ["CDN", "DNS", "Payments", "Hosting", "Email"]
    for cat in critical_categories:
        if cat in services or f"MX:{cat}" in services:
            spof.append(cat)
    return spof


def get_vendor_breach_history(services: dict) -> list:
    breaches = []
    for category, indicators in services.items():
        for indicator in indicators:
            if isinstance(indicator, str):
                for vendor, vendor_breaches in THIRD_PARTY_BREACHES.items():
                    if vendor.lower() in indicator.lower():
                        for b in vendor_breaches:
                            breaches.append({"vendor": vendor, "breach": b})
    return breaches


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    services = await identify_third_party_services(t)

    if services:
        for category, indicators in services.items():
            if category.startswith("MX:"):
                display_cat = category[3:]
            else:
                display_cat = category

            if display_cat == "shadow_it":
                findings.append(make_finding(
                    entity=f"Shadow IT indicators: {', '.join(indicators[:5])}",
                    ftype="SupplyChain: Shadow IT",
                    source="SupplyChainAnalysis",
                    confidence="Medium",
                    color="orange",
                    category="Supply Chain Intelligence",
                    threat_level="High Risk",
                    status="Detected",
                    resolution=t,
                    tags=["supply-chain", "shadow-it", "unsanctioned"],
                ))
            else:
                findings.append(make_finding(
                    entity=f"Third-party {display_cat}: {', '.join(indicators[:3])}",
                    ftype=f"SupplyChain: {display_cat}",
                    source="SupplyChainAnalysis",
                    confidence="High",
                    color="blue",
                    category="Supply Chain Intelligence",
                    threat_level="Informational",
                    status="Detected",
                    resolution=t,
                    tags=["supply-chain", display_cat.lower().replace(" ", "-"), "third-party"],
                ))

        spof = check_single_points_of_failure(services)
        if spof:
            findings.append(make_finding(
                entity=f"Critical single points of failure: {', '.join(spof)}",
                ftype="SupplyChain: SPOF Analysis",
                source="SupplyChainAnalysis",
                confidence="High",
                color="red",
                category="Supply Chain Intelligence",
                threat_level="Critical",
                status="SPOF Identified",
                resolution=t,
                tags=["supply-chain", "spof", "critical"] + [s.lower() for s in spof],
            ))

        vendor_breaches = get_vendor_breach_history(services)
        if vendor_breaches:
            for vb in vendor_breaches[:3]:
                findings.append(make_finding(
                    entity=f"Vendor breach: {vb['vendor']} - {vb['breach']}",
                    ftype="SupplyChain: Vendor Breach",
                    source="SupplyChainAnalysis",
                    confidence="Medium",
                    color="red",
                    category="Supply Chain Intelligence",
                    threat_level="Critical",
                    status="Vendor Breached",
                    resolution=t,
                    tags=["supply-chain", "vendor-breach", vb['vendor'].lower().replace(" ", "-")],
                ))

        total_services = sum(len(v) for v in services.values() if not v[0].startswith("MX:"))
        findings.append(make_finding(
            entity=f"Total third-party services detected: {total_services} in {len(services)} categories",
            ftype="SupplyChain: Service Map",
            source="SupplyChainAnalysis",
            confidence="High",
            color="slate",
            category="Supply Chain Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["supply-chain", "service-map", "inventory"],
        ))

        dependency_chain = ", ".join(list(services.keys())[:8])
        findings.append(make_finding(
            entity=f"Dependency chain: {dependency_chain}",
            ftype="SupplyChain: Dependency Map",
            source="SupplyChainAnalysis",
            confidence="Medium",
            color="slate",
            category="Supply Chain Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["supply-chain", "dependencies", "map"],
        ))
    else:
        findings.append(make_finding(
            entity="No external third-party services detected",
            ftype="SupplyChain: Scan Complete",
            source="SupplyChainAnalysis",
            confidence="Low",
            color="emerald",
            category="Supply Chain Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["supply-chain", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Supply chain scan complete for {t}",
        ftype="SupplyChain: Scan Summary",
        source="SupplyChainAnalysis",
        confidence="High",
        color="slate",
        category="Supply Chain Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["supply-chain", "summary"],
    ))

    return findings
