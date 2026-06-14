import httpx
import re
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse, quote

BUILTWITH_API = "https://api.builtwith.com/free1/api.json"
SIMILAR_WEB_CSS_PATTERNS = [
    (r'google-analytics\.com/ga\.js', "Google Analytics (Universal)"),
    (r'googletagmanager\.com/gtag/js', "Google Tag Manager"),
    (r'gtag\(\'config\'', "Google Analytics 4 (gtag)"),
    (r'fbq\(|\/facebook.*(?:pixel|tr)', "Facebook Pixel"),
    (r'snap\.licdn\.com', "LinkedIn Insight Tag"),
    (r'static\.ads-twitter\.com', "Twitter Conversion Tracking"),
    (r'pixel\.quantserve\.com', "Quantcast"),
    (r'scorecardresearch\.com', "ScorecardResearch"),
    (r'hotjar\.com', "Hotjar Analytics"),
    (r'cdn\.cookielaw\.org', "CookieLaw / OneTrust"),
    (r'doubleclick\.net', "DoubleClick / Google Ads"),
    (r'cdn\.taboola\.com', "Taboola"),
    (r'amazon-adsystem\.com', "Amazon Ads"),
    (r'criteo\.net', "Criteo"),
    (r'newrelic\.com', "New Relic"),
    (r'cdn\.mxpnl\.com', "Mixpanel"),
    (r'segment\.com|cdn\.segment\.(?:io|com)', "Segment"),
    (r'intercom\.io', "Intercom"),
    (r'zendesk\.com', "Zendesk"),
    (r'sentry\.(?:io|cdn)', "Sentry"),
    (r'datadog\.(?:com|eu)', "Datadog"),
]

EXPOSED_PATTERNS = [
    (r'["\'](?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}["\']', "Stripe API Key"),
    (r'["\']AIza[0-9A-Za-z_-]{35}["\']', "Google API Key"),
    (r'["\']AKIA[0-9A-Z]{16}["\']', "AWS Access Key"),
    (r'["\'](?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}["\']', "GitHub Token"),
    (r'["\'](?:xox[abpsr]|xapp|xoxe)-[A-Za-z0-9-]{10,}["\']', "Slack Token"),
    (r'["\']sk_live_[0-9a-zA-Z]{10,}["\']', "Stripe Secret Key"),
    (r'["\'](?:pk|sk)\.(?:test|live)\.[A-Za-z0-9]{10,}["\']', "Stripe Key (modern)"),
    (r'["\']SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}["\']', "SendGrid API Key"),
    (r'["\']key-[0-9a-zA-Z]{32}["\']', "Mailgun API Key"),
    (r'["\'](?:api|apikey|secret)["\']\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Generic API Key"),
]

CDN_JS_PATTERNS = [
    (r'(?:cdnjs|cdn)\.cloudflare\.com/ajax/libs/([^/]+)', "Cloudflare CDN (cdnjs)"),
    (r'ajax\.googleapis\.com/ajax/libs/([^/]+)', "Google CDN"),
    (r'cdn\.jsdelivr\.net/(?:npm|gh)/([^/]+)', "jsDelivr CDN"),
    (r'unpkg\.com/([^/]+)', "Unpkg CDN"),
    (r'maxcdn\.bootstrapcdn\.com/([^/]+)', "Bootstrap CDN (MaxCDN)"),
    (r'stackpath\.bootstrapcdn\.com/([^/]+)', "Bootstrap CDN (StackPath)"),
    (r'code\.jquery\.com/([^/]+)', "jQuery CDN"),
]

ANALYTICS_ID_PATTERNS = [
    (r'UA-\d{4,10}-\d{1,4}', "Google Analytics (UA)"),
    (r'G-[A-Z0-9]{10,}', "Google Analytics 4 (G- tag)"),
    (r'AW-\d{4,12}', "Google Ads"),
    (r'DC-\d{4,12}', "Google DoubleClick"),
    (r'GTM-[A-Z0-9]{5,10}', "Google Tag Manager"),
    (r'FB-\d{4,12}', "Facebook Pixel ID"),
    (r'pub-\d{16}', "Google AdSense Publisher"),
    (r'ca-pub-\d{16}', "Google AdSense Publisher"),
    (r'mc[as]id_[A-Za-z0-9_-]{10,}', "Mailchimp Account"),
]


async def scrape_publicwww(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        search_url = f"https://publicwww.com/websites/{quote(target)}/?export=csv"
        resp = await client.get(search_url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
        if resp.status_code == 200:
            text = resp.text
            count_match = re.search(r'(\d[\d,]*)\s+(?:result|pages?)', text, re.IGNORECASE)
            if count_match:
                count = count_match.group(1).replace(",", "")
                findings.append(IntelligenceFinding(
                    entity=f"{count} indexed pages on PublicWWW",
                    type="PublicWWW Index Count",
                    source="PublicWWW",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status=f"{count} results",
                    tags=["publicwww", "index-count"]
                ))
            snippet_matches = re.findall(
                r'<em>([^<]{20,})</em>',
                text
            )[:8]
            for snippet in snippet_matches:
                findings.append(IntelligenceFinding(
                    entity=snippet[:150],
                    type="PublicWWW Code Snippet",
                    source="PublicWWW",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    raw_data=snippet[:500],
                    tags=["publicwww", "snippet"]
                ))
        elif resp.status_code == 503 or resp.status_code == 429:
            findings.append(IntelligenceFinding(
                entity="PublicWWW: Rate limited or blocked",
                type="PublicWWW Status",
                source="PublicWWW",
                confidence="Low",
                color="orange",
                threat_level="Informational",
                status="Rate limited",
                tags=["publicwww", "rate-limit"]
            ))
    except:
        pass
    return findings


async def analyze_html(html: str, target: str) -> list:
    findings = []

    # Track third-party JS
    js_src = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    seen_domains = set()
    for src in js_src:
        try:
            parsed = urlparse(src)
            domain = parsed.netloc.lower()
            if domain and domain not in seen_domains and domain not in target:
                seen_domains.add(domain)
                findings.append(IntelligenceFinding(
                    entity=domain,
                    type="Third-Party JS Include",
                    source="PublicWWW (HTML)",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status=f"Served from {domain}",
                    raw_data=f"JS: {src[:200]}",
                    tags=["third-party", "javascript", domain.replace(".", "-")]
                ))
        except:
            pass

    # CDN libraries
    for pattern, label in CDN_JS_PATTERNS:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            lib = m.group(1)
            findings.append(IntelligenceFinding(
                entity=lib[:100],
                type=f"CDN Library: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=m.group(0)[:200],
                tags=["cdn", label.lower().replace(" ", "-")]
            ))

    # Analytics IDs
    for pattern, label in ANALYTICS_ID_PATTERNS:
        matches = re.findall(pattern, html)
        for m in set(matches[:3]):
            findings.append(IntelligenceFinding(
                entity=m[:50],
                type=f"Analytics ID: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["analytics", label.lower().replace(" ", "-"), m[:30]]
            ))

    # Third-party integrations
    for pattern, label in SIMILAR_WEB_CSS_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(IntelligenceFinding(
                entity=label,
                type="Third-Party Integration",
                source="PublicWWW (HTML)",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["integration", label.lower().replace(" ", "-")]
            ))

    return findings


async def check_inline_exposed_secrets(html: str, target: str) -> list:
    findings = []
    for pattern, label in EXPOSED_PATTERNS:
        matches = re.findall(pattern, html)
        for m in set(matches[:3]):
            findings.append(IntelligenceFinding(
                entity=f"{label}: {m[:30]}...",
                type=f"Exposed Secret/Key: {label}",
                source="PublicWWW (HTML)",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Exposed in source",
                raw_data=m[:200],
                tags=["secret-exposure", "security", label.lower().replace(" ", "-")]
            ))
    return findings


async def check_email_exposure(html: str, target: str) -> list:
    findings = []
    emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', html)
    domain = target.lower()
    for email in set(emails[:20]):
        email_domain = email.split("@")[-1].lower()
        if email_domain == domain:
            findings.append(IntelligenceFinding(
                entity=email,
                type="Public Email (Same Domain)",
                source="PublicWWW (HTML)",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Found in page source",
                tags=["email", "exposure"]
            ))
    unique_domains = set(e.split("@")[-1].lower() for e in emails if e.split("@")[-1].lower() != domain)
    for em_domain in unique_domains:
        if em_domain:
            findings.append(IntelligenceFinding(
                entity=em_domain,
                type="Email Domain (Third Party)",
                source="PublicWWW (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["email-domain", "third-party"]
            ))
    return findings


async def check_builtwith(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://api.builtwith.com/free1/api.json?LOOKUP={target}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            groups = data.get("groups", [])
            for group in groups:
                name = group.get("name", "")
                techs = group.get("technologies", [])
                if isinstance(techs, list):
                    for tech in techs[:3]:
                        t_name = tech.get("name") if isinstance(tech, dict) else str(tech)
                        findings.append(IntelligenceFinding(
                            entity=t_name[:200] if t_name else "",
                            type=f"Technology Stack: {name}",
                            source="PublicWWW (BuiltWith)",
                            confidence="Medium",
                            color="orange",
                            threat_level="Informational",
                            tags=["technology", name.lower().replace(" ", "-")]
                        ))
    except:
        pass
    return findings


async def check_comment_references(html: str, target: str) -> list:
    findings = []
    html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    for comment in html_comments[:15]:
        stripped = comment.strip()
        if len(stripped) > 5 and any(x in stripped.lower() for x in ["todo", "fixme", "hack", "bug", "temp", "note", "author", "developer"]):
            findings.append(IntelligenceFinding(
                entity=stripped[:150],
                type="HTML Comment with Context",
                source="PublicWWW (HTML)",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Interesting HTML comment",
                raw_data=stripped[:500],
                tags=["html-comment", "information-leak"]
            ))
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
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        )
        html = resp.text[:200000] if hasattr(resp, 'text') else ""
    except:
        pass

    tasks = [
        scrape_publicwww(domain, client),
        check_builtwith(domain, client),
    ]

    if html:
        tasks.append(analyze_html(html, domain))
        tasks.append(check_inline_exposed_secrets(html, domain))
        tasks.append(check_email_exposure(html, domain))
        tasks.append(check_comment_references(html, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    third_party = sum(1 for f in findings if "Third-Party" in f.type or "Integration" in f.type)
    analytics = sum(1 for f in findings if "Analytics" in f.type)
    secrets = sum(1 for f in findings if "Secret" in f.type or "Key" in f.type)
    tech = sum(1 for f in findings if "Technology" in f.type)

    findings.append(IntelligenceFinding(
        entity=f"Public Code Search: {third_party} integrations, {analytics} analytics, {secrets} secrets, {tech} tech",
        type="PublicWWW Summary",
        source="PublicWWW",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{len(findings)} findings",
        tags=["publicwww", "summary"]
    ))

    return findings
