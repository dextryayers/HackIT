import httpx
import re
import socket
import asyncio
import json
from models import IntelligenceFinding
from urllib.parse import urlparse
from urllib.parse import quote

ITUNES_SEARCH = "https://itunes.apple.com/search"
PLAY_STORE_SEARCH = "https://play.google.com/store/search"

MOBILE_FRAMEWORKS = {
    "react-native": ["reactnative", "react-native", "rctrootview"],
    "flutter": ["flutter", "flutter_sdk", "dart"],
    "swift": ["swift", "xcode"],
    "kotlin": ["kotlin", "jetpack"],
    "xamarin": ["xamarin", "mono"],
    "cordova": ["cordova", "phonegap", "gap://"],
    "capacitor": ["capacitor", "ionic"],
    "unity": ["unity3d", "unity"],
}

DEEP_LINK_PATTERNS = [
    (r'(?:https?://)?(?:www\.)?([a-zA-Z0-9_-]+)\.app\.(?:links|googl|page|link)', "Branch.io deep link"),
    (r'(?:fb|twitter|instagram|tg|viber|whatsapp)://[^\s"\'<>]+', "App deep link"),
    (r'intent://[^\s"\'<>]+#Intent', "Android Intent URL"),
    (r'applinks:\s*([^\s]+)', "iOS applinks domain association"),
    (r'apple-app-site-association', "iOS Universal Link"),
    (r'assetlinks\.json', "Android App Link"),
    (r'google\.app\.linking', "Firebase Dynamic Link"),
]


def extract_mobile_domains(html: str, domain: str) -> list:
    findings = []
    patterns = [
        ('(["\x27])https?://(?:m|mobile|app|amp)\\.' + re.escape(domain) + '([^"\\x27]*)\\2', "Mobile Subdomain"),
        ('(["\x27])https?://(?:play\\.google\\.com/store/apps/details\\?id=[^"\\x27]*)\\1', "Google Play URL"),
        ('(["\x27])https?://(?:apps\\.apple\\.com|itunes\\.apple\\.com)[^"\\x27]*\\1', "App Store URL"),
    ]
    for pattern, label in patterns:
        matches = re.findall(pattern, html)
        for m in matches[:3]:
            findings.append(IntelligenceFinding(
                entity=m.strip("\"'")[:200],
                type=f"Mobile: {label}",
                source="MobileRecon",
                confidence="Medium",
                color="cyan",
                threat_level="Informational",
                status="Found",
                tags=["mobile", label.lower().replace(" ", "-")]
            ))
    return findings


def detect_mobile_frameworks(html: str, headers: dict) -> list:
    findings = []
    html_lower = html.lower()
    for framework, signatures in MOBILE_FRAMEWORKS.items():
        found = [sig for sig in signatures if sig in html_lower]
        if found:
            findings.append(IntelligenceFinding(
                entity=f"{framework} detected ({len(found)} signatures)",
                type=f"Mobile Framework: {framework.title()}",
                source="MobileRecon",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Signatures: {', '.join(found)[:500]}",
                tags=["mobile-framework", framework.lower()]
            ))
    ua = headers.get("user-agent", "").lower()
    mobile_ua_patterns = [
        ("mobile", "Mobile Browser"),
        ("android", "Android Browser"),
        ("iphone", "iPhone Browser"),
        ("ipad", "iPad Browser"),
        ("ios", "iOS Browser"),
    ]
    for pattern, label in mobile_ua_patterns:
        if pattern in ua:
            findings.append(IntelligenceFinding(
                entity=label,
                type="Mobile User-Agent",
                source="MobileRecon",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["mobile", "user-agent"]
            ))
            break
    if "mobile" in html_lower and "viewport" in html_lower:
        findings.append(IntelligenceFinding(
            entity="Mobile-responsive design detected",
            type="Mobile Optimization",
            source="MobileRecon",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            tags=["mobile", "responsive"]
        ))
    return findings


def extract_app_store_ids(html: str) -> list:
    findings = []
    patterns = [
        ('https?://apps\\.apple\\.com/[a-z]{2}/app/[^/"]*/id(\\d+)', "Apple App", "iOS"),
        ('https?://itunes\\.apple\\.com/[a-z]{2}/app/[^/"]*/id(\\d+)', "Apple App", "iOS"),
        ('https?://play\\.google\\.com/store/apps/details\\?id=([a-zA-Z0-9._-]+)', "Google Play App", "Android"),
        ('https?://play\\.google\\.com/store/apps/details\\?id=([^&"]+)', "Google Play App", "Android"),
    ]
    for pattern, label, platform in patterns:
        matches = re.findall(pattern, html)
        for m in matches[:5]:
            app_id = m if isinstance(m, str) else m
            findings.append(IntelligenceFinding(
                entity=f"{app_id} ({platform})",
                type=f"Mobile App: {label}",
                source="MobileRecon",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Found",
                raw_data=f"App ID: {app_id}, Platform: {platform}",
                tags=["mobile-app", platform.lower(), app_id[:50]]
            ))
    return findings


async def check_mobile_dns(target: str) -> list:
    findings = []
    domain = target.strip().lower()
    records_to_check = [
        (f"_appitunes.{domain}", "TXT", "Apple App Association"),
        (f"_appstore.{domain}", "TXT", "App Store Association"),
    ]
    for name, rtype, label in records_to_check:
        try:
            loop = asyncio.get_event_loop()
            import dns.resolver
            answers = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(name, rtype)
            )
            for ans in answers:
                findings.append(IntelligenceFinding(
                    entity=str(ans)[:200],
                    type=f"Mobile DNS: {label}",
                    source="MobileRecon",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Found",
                    raw_data=f"{name} {rtype} = {ans}",
                    tags=["mobile-dns", "app-association"]
                ))
        except:
            pass

    # Check Apple App Site Association
    for path in ["/.well-known/apple-app-site-association", "/apple-app-site-association"]:
        try:
            async with httpx.AsyncClient(verify=False) as ac:
                resp = await ac.get(f"https://{domain}{path}", timeout=8.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 and len(resp.text) > 10:
                    findings.append(IntelligenceFinding(
                        entity=f"https://{domain}{path}",
                        type="iOS Universal Link (AASA)",
                        source="MobileRecon",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="Present",
                        raw_data=resp.text[:500],
                        tags=["mobile", "ios", "universal-link", "aasa"]
                    ))
        except:
            pass

    # Check Android Asset Links
    try:
        async with httpx.AsyncClient(verify=False) as ac:
            resp = await ac.get(f"https://{domain}/.well-known/assetlinks.json", timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and len(resp.text) > 10:
                findings.append(IntelligenceFinding(
                    entity=f"https://{domain}/.well-known/assetlinks.json",
                    type="Android App Link (Asset Links)",
                    source="MobileRecon",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Present",
                    raw_data=resp.text[:500],
                    tags=["mobile", "android", "app-link", "assetlinks"]
                ))
    except:
        pass

    return findings


async def search_mobile_clients(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target
    try:
        resp = await client.get(
            f"{ITUNES_SEARCH}?term={quote(domain_short)}&entity=software&limit=10",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            for app in results[:5]:
                findings.append(IntelligenceFinding(
                    entity=app.get("trackName", "")[:200],
                    type="iOS App Store Entry",
                    source="MobileRecon (iTunes)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    status="Found",
                    resolution=app.get("sellerName", ""),
                    raw_data=f"Bundle: {app.get('bundleId', '')}, "
                             f"Rating: {app.get('averageUserRating', 'N/A')}, "
                             f"Category: {app.get('primaryGenreName', '')}",
                    tags=["ios", "app-store", "mobile-app"]
                ))
    except:
        pass
    return findings


async def check_mobile_viewport_meta(html: str, target: str) -> list:
    findings = []
    viewport_match = re.search('<meta\\s+name=["\x27]viewport["\x27][^>]*>', html, re.IGNORECASE)
    apple_touch = re.findall('<link\\s+rel=["\x27]apple-touch-icon["\x27][^>]*>', html, re.IGNORECASE)
    status_bar = re.search('<meta\\s+name=["\x27]apple-mobile-web-app-status-bar-style["\x27]', html, re.IGNORECASE)
    webapp_capable = re.search('<meta\\s+name=["\x27]apple-mobile-web-app-capable["\x27]', html, re.IGNORECASE)

    if viewport_match:
        findings.append(IntelligenceFinding(
            entity="Mobile viewport meta tag present",
            type="Mobile Meta: Viewport",
            source="MobileRecon",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Present",
            tags=["mobile-meta", "viewport"]
        ))
    if apple_touch:
        findings.append(IntelligenceFinding(
            entity=f"{len(apple_touch)} apple-touch-icon link(s)",
            type="Mobile Meta: Apple Touch Icon",
            source="MobileRecon",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Present",
            tags=["mobile-meta", "apple-touch"]
        ))
    if status_bar:
        findings.append(IntelligenceFinding(
            entity="Apple status bar style defined",
            type="Mobile Meta: Status Bar",
            source="MobileRecon",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["mobile-meta", "status-bar"]
        ))
    if webapp_capable:
        findings.append(IntelligenceFinding(
            entity="PWA capable (apple-mobile-web-app-capable)",
            type="Mobile Meta: PWA",
            source="MobileRecon",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            tags=["mobile-meta", "pwa", "progressive-web-app"]
        ))

    manifest = re.search('<link\\s+rel=["\x27]manifest["\x27][^>]*href=["\x27]([^"\\x27]+)["\x27]', html, re.IGNORECASE)
    if manifest:
        findings.append(IntelligenceFinding(
            entity=f"Web App Manifest: {manifest.group(1)}",
            type="PWA Manifest",
            source="MobileRecon",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Present",
            tags=["pwa", "manifest", "progressive-web-app"]
        ))

    service_worker = re.search(r'navigator\s*\.\s*serviceWorker', html)
    if service_worker:
        findings.append(IntelligenceFinding(
            entity="Service Worker detected",
            type="PWA Service Worker",
            source="MobileRecon",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            status="Detected",
            tags=["pwa", "service-worker"]
        ))
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    html = ""
    headers = {}

    try:
        resp = await client.get(base_url, follow_redirects=True, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
        html = resp.text[:150000] if hasattr(resp, 'text') else ""
        headers = dict(resp.headers)
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"MobileRecon HTTP error: {str(e)[:100]}",
            type="MobileRecon Error",
            source="MobileRecon",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))

    if html:
        findings.extend(extract_mobile_domains(html, domain))
        findings.extend(detect_mobile_frameworks(html, headers))
        findings.extend(extract_app_store_ids(html))
        findings.extend(await check_mobile_viewport_meta(html, domain))

    tasks = [
        check_mobile_dns(domain),
        search_mobile_clients(domain, client),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    findings.append(IntelligenceFinding(
        entity=f"Mobile reconnaissance complete: {len(findings)} findings",
        type="Mobile Recon Summary",
        source="MobileRecon",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["mobile", "summary"]
    ))

    return findings
