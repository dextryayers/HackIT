import re
import httpx
from urllib.parse import urlparse
from models import IntelligenceFinding

TRACKER_PATTERNS = {
    "Google Analytics 4": [
        r"googletagmanager\.com/gtag/js", r"google-analytics\.com", r"analytics\.google\.com",
        r"gtag\(", r"ga4", r"G-[A-Z0-9]+",
    ],
    "Google Ads": [
        r"googleads\.g\.doubleclick\.net", r"adservice\.google\.com",
        r"pagead2\.googlesyndication\.com", r"googleadservices\.com",
    ],
    "Meta Pixel": [
        r"connect\.facebook\.net", r"facebook\.com/tr\b", r"fbq\(", r"\.fb\.me",
        r"pixel\.facebook\.com",
    ],
    "TikTok Pixel": [
        r"analytics\.tiktok\.com", r"ads\.tiktok\.com", r"ttq\.tiktok",
        r"tiktok\.com/api/v1/pixel",
    ],
    "LinkedIn Insight": [
        r"linkedin\.com/px", r"ads\.linkedin\.com", r"snap\.licdn\.com",
        r"linkedin_insight",
    ],
    "Twitter Pixel": [
        r"static\.ads-twitter\.com", r"analytics\.twitter\.com",
        r"twq\(", r"t\.co",
    ],
    "Pinterest Tag": [
        r"ct\.pinterest\.com", r"pinterest\.com/ct", r"pintrk\(",
    ],
    "Snapchat Pixel": [
        r"sc\.snapchat\.com", r"tr\.snapchat\.com", r"snap\.sc",
        r"snaptr\(",
    ],
    "Reddit Pixel": [
        r"ads\.reddit\.com", r"reddit\.com/static/pixel",
        r"rdt\(", r"reddit\.com/api/v1/pixel",
    ],
    "Quora Pixel": [
        r"q.quora.com", r"quora\.com/widget", r"qpx\(",
    ],
    "Bing Ads": [
        r"bat\.bing\.com", r"bing\.com/bat", r"uetq\(", r"ads\.bing\.com",
    ],
    "Hotjar": [
        r"hotjar\.com", r"static\.hotjar\.com", r"hj\(", r"_hjSettings",
    ],
    "FullStory": [
        r"fullstory\.com", r"rs\.fullstory\.com", r"FS\(\)",
        r"_fs_",
    ],
    "Amplitude": [
        r"amplitude\.com", r"api\.amplitude\.com", r"amplitudeInstance",
        r"analytics\.amplitude\.com",
    ],
    "Mixpanel": [
        r"mixpanel\.com", r"api-mixpanel\.com", r"mixpanel\(",
        r"mpq\(", r"_mp_",
    ],
    "Segment": [
        r"segment\.com", r"cdn\.segment\.com", r"analytics\.js",
        r"segmentio",
    ],
    "Heap": [
        r"heap\.com", r"heapanalytics\.com", r"heap\(",
        r"_heapid",
    ],
    "Kissmetrics": [
        r"kissmetrics\.com", r"kiss\(", r"_kmq",
    ],
    "CrazyEgg": [
        r"crazyegg\.com", r"script\.crazyegg\.com", r"CE\(\)",
    ],
    "LuckyOrange": [
        r"luckyorange\.com", r"luckyorange\.net", r"_loq",
    ],
    "VWO": [
        r"vwo\.com", r"dev\.visualwebsiteoptimizer\.com",
        r"vwoAnalytics", r"_vwo_",
    ],
    "Optimizely": [
        r"optimizely\.com", r"cdn\.optimizely\.com",
        r"optimizely\(", r"window\.optimizely",
    ],
    "The Trade Desk": [
        r"adsrvr\.org", r"thetradedesk\.com", r"insight\.adsrvr\.org",
        r"tdid",
    ],
    "Criteo": [
        r"criteo\.com", r"criteo\.net", r"static\.criteo\.net",
        r"criteoDirect",
    ],
    "AdRoll": [
        r"adroll\.com", r"d\.adroll\.com", r"adroll_",
    ],
    "Amazon Ads": [
        r"amazon-adsystem\.com", r"aax\.amazon-adsystem\.com",
        r"amazon_ad",
    ],
    "HubSpot": [
        r"hs-scripts\.com", r"hubspot\.com", r"hs-analytics",
        r"_hsq\(",
    ],
    "Salesforce": [
        r"salesforce\.com", r"sfmc", r"exacttarget\.com",
        r"marketingcloud",
    ],
    "Cloudflare Analytics": [
        r"cloudflare\.com/analytics", r"static\.cloudflareinsights\.com",
        r"__cf",
    ],
    "New Relic": [
        r"newrelic\.com", r"nr-data\.net", r"newrelic\(",
        r"NREUM",
    ],
    "Datadog RUM": [
        r"datadog\.com", r"dd-RUM", r"datadog-rum",
        r"logs\.datadoghq\.com",
    ],
    "Sentry": [
        r"sentry\.io", r"browser\.sentry-cdn\.com", r"Sentry\.init",
        r"_sentry",
    ],
}

CMP_PATTERNS = [
    (r"cookiebot\.com", "Cookiebot"),
    (r"onetrust\.com", "OneTrust"),
    (r"cookieconsent", "CookieConsent"),
    (r"consent\.google\.com", "Google Consent"),
    (r"cmp\.quantcast\.com", "Quantcast CMP"),
    (r"sourcepoint\.com", "Sourcepoint"),
    (r"didomi\.io", "Didomi"),
    (r"iubenda\.com", "Iubenda"),
    (r"cookiehub\.net", "CookieHub"),
    (r"cookiefirst\.com", "CookieFirst"),
    (r"osano\.com", "Osano"),
    (r"termly\.io", "Termly"),
    (r"consent\.trustarc\.com", "TrustArc"),
    (r"cmp\.usercentrics\.eu", "Usercentrics"),
]

FINGERPRINTING_PATTERNS = [
    (r"canvas\.toDataURL", "Canvas Fingerprinting"),
    (r"webgl", "WebGL Fingerprinting"),
    (r"AudioContext", "Audio Fingerprinting"),
    (r"Navigator\.", "Navigator API Probing"),
    (r"font.*detection|detect.*font", "Font Fingerprinting"),
    (r"screen\.width|screen\.height|screen\.avail", "Screen Resolution Probing"),
    (r"navigator\.hardwareConcurrency", "Hardware Concurrency"),
    (r"navigator\.deviceMemory", "Device Memory"),
    (r"navigator\.plugins", "Plugin Enumeration"),
    (r"navigator\.mediaDevices", "Media Devices Enumeration"),
    (r"navigator\.userAgent|navigator\.platform", "User Agent/Platform Probing"),
    (r"navigator\.language|navigator\.languages", "Language Probing"),
    (r"navigator\.timezone|Intl\.DateTimeFormat", "Timezone Detection"),
    (r"navigator\.webdriver", "WebDriver Detection"),
    (r"navigator\.maxTouchPoints", "Touch Support Detection"),
    (r"navigator\.mimeTypes", "MIME Type Enumeration"),
    (r"navigator\.permissions", "Permissions API Probing"),
    (r"navigator\.connection", "Network Connection Info"),
    (r"navigator\.storage", "Storage Probing"),
]

BEACON_PATTERNS = [
    r"navigator\.sendBeacon",
    r"new\s+Image\(\)",
    r"\/collect",
    r"\/beacon",
    r"\/pixel",
    r"\/pageview",
    r"\/track",
    r"\/analytics",
    r"\/telemetry",
]

SCRIPT_SRC_REGEX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
IFRAME_SRC_REGEX = re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
IMG_SRC_REGEX = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
BEACON_REGEX = re.compile(r'<img[^>]+src=["\'][^"\']*?(?:collect|beacon|pixel|track|analytics|telemetry)[^"\']*["\']', re.IGNORECASE)
INLINE_SCRIPT_REGEX = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text
        headers = dict(resp.headers)
        domain = urlparse(base_url).netloc

        all_third_party_srcs = []
        for m in SCRIPT_SRC_REGEX.finditer(html):
            all_third_party_srcs.append(m.group(1))
        for m in IFRAME_SRC_REGEX.finditer(html):
            all_third_party_srcs.append(m.group(1))
        for m in IMG_SRC_REGEX.finditer(html):
            all_third_party_srcs.append(m.group(1))

        trackers_found = {}
        for src in all_third_party_srcs:
            src_lower = src.lower()
            for tracker_name, patterns in TRACKER_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, src_lower, re.IGNORECASE):
                        if tracker_name not in trackers_found:
                            trackers_found[tracker_name] = []
                        parsed = urlparse(src if src.startswith("http") else "https:" + src)
                        netloc = parsed.netloc or src.split("/")[0]
                        if netloc not in trackers_found[tracker_name]:
                            trackers_found[tracker_name].append(netloc)
                        break

        for tracker_name, domains_found in sorted(trackers_found.items()):
            for dom in domains_found[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"{tracker_name} ({dom})",
                    type="Third-Party Tracker",
                    source="TrackerNetworkMapper",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Tracker: {tracker_name} | Domain: {dom}",
                    tags=["tracker", "third-party", tracker_name.lower().replace(" ", "-")]
                ))

        all_beacon_srcs = []
        for m in BEACON_REGEX.finditer(html):
            all_beacon_srcs.append(m.group(0))

        inline_scripts = INLINE_SCRIPT_REGEX.findall(html)
        for inline in inline_scripts:
            for pat in BEACON_PATTERNS:
                if re.search(pat, inline, re.IGNORECASE):
                    findings.append(IntelligenceFinding(
                        entity=f"Beacon pattern: {pat}",
                        type="Tracking Beacon",
                        source="TrackerNetworkMapper",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"Inline beacon: {pat}",
                        tags=["tracker", "beacon"]
                    ))
                    break

        for inline in inline_scripts:
            for pat, desc in FINGERPRINTING_PATTERNS:
                if re.search(pat, inline, re.IGNORECASE):
                    findings.append(IntelligenceFinding(
                        entity=desc,
                        type="Cookie-less Fingerprinting",
                        source="TrackerNetworkMapper",
                        confidence="Medium",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=f"Fingerprinting technique detected: {pat}",
                        tags=["fingerprinting", "privacy"]
                    ))
                    break

        for pat, name in CMP_PATTERNS:
            if re.search(pat, html, re.IGNORECASE):
                findings.append(IntelligenceFinding(
                    entity=f"CMP: {name}",
                    type="Consent Management Platform",
                    source="TrackerNetworkMapper",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"CMP detected: {name}",
                    tags=["cmp", "consent", "privacy"]
                ))

        cookie_flags = headers.get("set-cookie", "")
        if cookie_flags:
            tracking_cookies = re.findall(r'(?:_ga|_fbp|_gid|_gat|_gaq|_gac|_hj|_hjid|_hjs|_hp|_mk|_lr|_lr_|_scid|_shopify|_s|_sp|_uetsid|_uetvid|_uacct|_utm|__utm|__utma|__utmb|__utmc|__utmt|__utmz|__gads|__gpi|__eoi|__ar_v4|__s).*?(?:;|$)', cookie_flags, re.IGNORECASE)
            for tc in tracking_cookies[:10]:
                findings.append(IntelligenceFinding(
                    entity=tc[:100],
                    type="Tracking Cookie",
                    source="TrackerNetworkMapper",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Cookie: {tc[:200]}",
                    tags=["tracker", "cookie", "tracking-cookie"]
                ))

        tracker_count = len(trackers_found)
        fingerprint_count = sum(1 for f in findings if f.type == "Cookie-less Fingerprinting")
        beacon_count = sum(1 for f in findings if f.type == "Tracking Beacon")

        findings.append(IntelligenceFinding(
            entity=f"{tracker_count} trackers ({len(all_third_party_srcs)} third-party requests), {fingerprint_count} fingerprinting methods, {beacon_count} beacons",
            type="Tracker Network Summary",
            source="TrackerNetworkMapper",
            confidence="High",
            color="purple",
            threat_level="Elevated Risk" if tracker_count > 10 or fingerprint_count > 2 else "Informational",
            raw_data=f"Trackers: {tracker_count} | 3rd-party requests: {len(all_third_party_srcs)} | Fingerprinting: {fingerprint_count} | Beacons: {beacon_count}",
            tags=["tracker", "summary"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Tracker Network error: {str(e)[:100]}",
            type="Tracker Network Error",
            source="TrackerNetworkMapper",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
