import httpx
import re
import socket
import asyncio
import json
from models import IntelligenceFinding
from urllib.parse import urlparse
from urllib.parse import quote

ITUNES_SEARCH = "https://itunes.apple.com/search"
ITUNES_LOOKUP = "https://itunes.apple.com/lookup"
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
    "swiftui": ["swiftui", "scenephase", "windowgroup"],
    "jetpack-compose": ["jetpack compose", "compose.material", "androidx.compose"],
    "kotlin-multiplatform": ["kotlin multiplatform", "kotlin-multiplatform", "kmm"],
    "jquery-mobile": ["jquery mobile", "jquery.mobile", "jqm"],
    "sencha-touch": ["sencha touch", "ext.touch", "sencha-touch"],
    "kony": ["kony", "kony.sdk", "konyos"],
    "appcelerator": ["appcelerator", "titanium", "alloy"],
    "corona-sdk": ["corona sdk", "coronalabs", "corona_"],
    "phonegap-build": ["phonegap build", "pgb", "phonegap\\."],
    "ionic": ["ionic", "ionicframework", "ion-", "ionview", "ionic.bundle"],
    "native-script": ["nativescript", "tns-core-modules", "nativescript-"],
    "react-native-expo": ["expo", "expo-constants", "expo-modules", "expo-"],
    "framework7": ["framework7", "framework7-", "f7-ios", "f7-material"],
    "fuse-tools": ["fusetools", "fuse", "ux.markup"],
    "tap-application": ["tap", "tap-", "tap.applink"],
    "trigger-io": ["trigger.io", "forge", "trigger.io"],
    "smartface": ["smartface", "smartface.io", "smf"],
    "codename-one": ["codenameone", "codename one", "cn1"],
    "telerik-platform": ["telerik", "kendo", "telerik.appbuilder"],
    "xdk": ["intel xdk", "xdk", "intel.js"],
    "rad-studio": ["embarcadero", "firemonkey", "rad studio"],
    "rhodes": ["rhodes", "rhomobile", "rho_"],
    "widgetpad": ["widgetpad", "wipad"],
    "moai-sdk": ["moai", "moai-sdk", "moaicpp"],
    "defold": ["defold", "defold-", "builtwith-defold"],
    "gideros": ["gideros", "gideros-"],
}

MOBILE_SDKS = {
    "firebase-sdk": [
        "firebase", "firebaseapp", "firebaseio.com", "firebase.google.com",
        "firebase-messaging", "firebase-analytics", "firebase-config",
        "FIREBASE_API_KEY", "firebase.initializeapp", "firebase.database",
        "firebase.messaging"
    ],
    "google-mobile-ads": [
        "googleservices", "google-mobile-ads", "admob", "ca-app-pub-",
        "googletag", "doubleclick", "adsense", "gadget"
    ],
    "onesignal": [
        "onesignal", "OneSignalSDK", "OneSignal.push", "OneSignal.init",
        "onesignal.com/api", "OneSignalDefault"
    ],
    "branch-io": [
        "branch.io", "branch_key", "branch_app_id", "Branch.init",
        "BranchSDK"
    ],
    "appsflyer": [
        "appsflyer", "AppsFlyer", "appsflyer_id", "appsflyersdk",
        "onInstallConversionData"
    ],
    "adjust-sdk": [
        "adjust", "adjust.com", "adjust_key", "Adjust.init",
        "AdjustSDK", "adjust_app_token"
    ],
    "kochava": [
        "kochava", "kochava.com", "kochava-device",
        "KochavaTracker", "kochava_"
    ],
    "mixpanel": [
        "mixpanel", "mixpanel-", "Mixpanel.sharedInstance",
        "mixpanel.android", "mixpanel.iphone"
    ],
    "amplitude": [
        "amplitude", "amplitude.com", "Amplitude.init",
        "amplitude_instance", "amplitude.logevent"
    ],
    "clevertap": [
        "clevertap", "clevertap.com", "CleverTap",
        "clevertap_id", "clevertap.init"
    ],
    "leanplum": [
        "leanplum", "Leanplum", "leanplum.com",
        "leanplum_start", "leanplum.track"
    ],
    "localytics": [
        "localytics", "Localytics", "localytics.com",
        "localytics_session", "localytics.tag"
    ],
    "flurry": [
        "flurry", "flurry.com", "FlurryAgent",
        "flurry_session", "flurry.logevent"
    ],
    "countly": [
        "countly", "Countly", "countly.com",
        "countly_init", "countly.session"
    ],
    "mparticle": [
        "mparticle", "mParticle", "mparticle.com",
        "mparticle_init", "MParticleOptions"
    ],
    "segment": [
        "segment", "segment.io", "SEGMENT_WRITE_KEY",
        "analytics.track", "Analytics.Builder"
    ],
    "bugsnag": [
        "bugsnag", "Bugsnag", "bugsnag.com",
        "bugsnag_init", "Bugsnag.start"
    ],
    "sentry": [
        "sentry", "sentry.io", "SentrySDK",
        "sentry.init", "sentry.dsn"
    ],
    "craslytics": [
        "crashlytics", "Fabric", "crashlytics.com",
        "Crashlytics.init", "firebase.crashlytics"
    ],
    "datadog": [
        "datadog", "dd-sdk", "datadoghq.com",
        "Datadog.init", "ddlogger"
    ],
    "newrelic": [
        "newrelic", "newrelic.com", "NewRelic",
        "newrelic.start", "NewRelicAgent"
    ],
}

DEEP_LINK_PATTERNS = [
    (r'(?:https?://)?(?:www\.)?([a-zA-Z0-9_-]+)\.app\.(?:links|googl|page|link)', "Branch.io deep link"),
    (r'(?:fb|twitter|instagram|tg|viber|whatsapp)://[^\s"\'<>]+', "App deep link"),
    (r'intent://[^\s"\'<>]+#Intent', "Android Intent URL"),
    (r'applinks:\s*([^\s]+)', "iOS applinks domain association"),
    (r'apple-app-site-association', "iOS Universal Link"),
    (r'assetlinks\.json', "Android App Link"),
    (r'google\.app\.linking', "Firebase Dynamic Link"),
    (r'youtube://[^\s"\'<>]+', "YouTube deep link"),
    (r'vnd\.youtube://[^\s"\'<>]+', "YouTube deep link (vnd)"),
    (r'twitter://[^\s"\'<>]+', "Twitter deep link"),
    (r'twitterrific://[^\s"\'<>]+', "Twitterrific deep link"),
    (r'tweetbot://[^\s"\'<>]+', "Tweetbot deep link"),
    (r'fb://[^\s"\'<>]+', "Facebook deep link"),
    (r'fb-messenger://[^\s"\'<>]+', "Facebook Messenger deep link"),
    (r'instagram://[^\s"\'<>]+', "Instagram deep link"),
    (r'whatsapp://[^\s"\'<>]+', "WhatsApp deep link"),
    (r'tg://[^\s"\'<>]+', "Telegram deep link"),
    (r'viber://[^\s"\'<>]+', "Viber deep link"),
    (r'comgooglemaps://[^\s"\'<>]+', "Google Maps deep link"),
    (r'comgooglemaps-x-callback://[^\s"\'<>]+', "Google Maps x-callback deep link"),
    (r'itms://[^\s"\'<>]+', "Apple iTunes Link"),
    (r'itms-apps://[^\s"\'<>]+', "Apple App Store Link"),
    (r'shsh://[^\s"\'<>]+', "SHSH (jailbreak) deep link"),
    (r'cydia://[^\s"\'<>]+', "Cydia (jailbreak) deep link"),
    (r'tel://[^\s"\'<>]+', "Phone call deep link"),
    (r'sms://[^\s"\'<>]+', "SMS deep link"),
    (r'facetime://[^\s"\'<>]+', "FaceTime deep link"),
    (r'mailto://[^\s"\'<>]+', "Mailto deep link"),
    (r'signal://[^\s"\'<>]+', "Signal deep link"),
    (r'viber://[^\s"\'<>]+', "Viber deep link"),
    (r'teams://[^\s"\'<>]+', "Microsoft Teams deep link"),
    (r'skype://[^\s"\'<>]+', "Skype deep link"),
    (r'zoom.us://[^\s"\'<>]+', "Zoom deep link"),
    (r'googlemeet://[^\s"\'<>]+', "Google Meet deep link"),
    (r'gotomeeting://[^\s"\'<>]+', "GoToMeeting deep link"),
    (r'cisco://[^\s"\'<>]+', "Cisco Webex deep link"),
    (r'slack://[^\s"\'<>]+', "Slack deep link"),
    (r'discord://[^\s"\'<>]+', "Discord deep link"),
    (r'github://[^\s"\'<>]+', "GitHub deep link"),
    (r'gitlab://[^\s"\'<>]+', "GitLab deep link"),
    (r'bitbucket://[^\s"\'<>]+', "Bitbucket deep link"),
    (r'trello://[^\s"\'<>]+', "Trello deep link"),
    (r'jira://[^\s"\'<>]+', "Jira deep link"),
    (r'notion://[^\s"\'<>]+', "Notion deep link"),
    (r'evernote://[^\s"\'<>]+', "Evernote deep link"),
    (r'twitter://[^\s"\'<>]+', "Twitter deep link"),
    (r'fb://[^\s"\'<>]+', "Facebook deep link"),
    (r'instagram://[^\s"\'<>]+', "Instagram deep link"),
    (r'linkedin://[^\s"\'<>]+', "LinkedIn deep link"),
    (r'pinterest://[^\s"\'<>]+', "Pinterest deep link"),
    (r'tiktok://[^\s"\'<>]+', "TikTok deep link"),
    (r'snapchat://[^\s"\'<>]+', "Snapchat deep link"),
    (r'reddit://[^\s"\'<>]+', "Reddit deep link"),
    (r'whatsapp://[^\s"\'<>]+', "WhatsApp deep link"),
    (r'telegram://[^\s"\'<>]+', "Telegram deep link"),
    (r'signal://[^\s"\'<>]+', "Signal deep link"),
    (r'wire://[^\s"\'<>]+', "Wire deep link"),
    (r'session://[^\s"\'<>]+', "Session deep link"),
    (r'protonmail://[^\s"\'<>]+', "ProtonMail deep link"),
    (r'tutanota://[^\s"\'<>]+', "Tutanota deep link"),
    (r'amazon://[^\s"\'<>]+', "Amazon deep link"),
    (r'ebay://[^\s"\'<>]+', "eBay deep link"),
    (r'etsy://[^\s"\'<>]+', "Etsy deep link"),
    (r'paypal://[^\s"\'<>]+', "PayPal deep link"),
    (r'venmo://[^\s"\'<>]+', "Venmo deep link"),
    (r'uber://[^\s"\'<>]+', "Uber deep link"),
    (r'lyft://[^\s"\'<>]+', "Lyft deep link"),
    (r'doordash://[^\s"\'<>]+', "DoorDash deep link"),
    (r'ubereats://[^\s"\'<>]+', "Uber Eats deep link"),
    (r'googlepay://[^\s"\'<>]+', "Google Pay deep link"),
    (r'applepay://[^\s"\'<>]+', "Apple Pay deep link"),
    (r'nfc://[^\s"\'<>]+', "NFC deep link"),
    (r'qr_code://[^\s"\'<>]+', "QR code deep link"),
    (r'qr_codes?://[^\s"\'<>]+', "QR deep link variant"),
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


def detect_mobile_sdks(html: str, js_vars: dict) -> list:
    findings = []
    html_lower = html.lower()
    for sdk, signatures in MOBILE_SDKS.items():
        found = [sig for sig in signatures if sig.lower() in html_lower]
        if found:
            findings.append(IntelligenceFinding(
                entity=f"{sdk} detected ({len(found)} signatures)",
                type=f"Mobile SDK: {sdk}",
                source="MobileRecon",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Signatures: {', '.join(found)[:500]}",
                tags=["mobile-sdk", sdk]
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
                track_id = app.get("trackId")
                review_count = app.get("userRatingCount", "N/A")
                avg_rating = app.get("averageUserRating", "N/A")
                price = app.get("price", "N/A")
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
                             f"Rating: {avg_rating} ({review_count} reviews), "
                             f"Price: {price}, "
                             f"Category: {app.get('primaryGenreName', '')}",
                    tags=["ios", "app-store", "mobile-app"]
                ))

                if track_id:
                    try:
                        lookup = await client.get(
                            f"{ITUNES_LOOKUP}?id={track_id}&country=us",
                            timeout=8.0,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if lookup.status_code == 200:
                            ldata = lookup.json()
                            lresults = ldata.get("results", [])
                            if lresults:
                                details = lresults[0]
                                findings.append(IntelligenceFinding(
                                    entity=f"{details.get('trackName', '')} - Full Details",
                                    type="iOS App Store Detail",
                                    source="MobileRecon (iTunes)",
                                    confidence="Medium",
                                    color="purple",
                                    threat_level="Informational",
                                    status="Found",
                                    raw_data=json.dumps({
                                        "rating": details.get("averageUserRating"),
                                        "rating_count": details.get("userRatingCount"),
                                        "rating_count_current": details.get("userRatingCountForCurrentVersion"),
                                        "version": details.get("version"),
                                        "min_os": details.get("minimumOsVersion"),
                                        "size": details.get("fileSizeBytes"),
                                        "seller": details.get("sellerName"),
                                        "supported_devices": details.get("supportedDevices", [])[:5],
                                        "advisories": details.get("advisories", []),
                                        "release_notes": (details.get("releaseNotes") or "")[:300],
                                        "release_date": details.get("releaseDate"),
                                        "price": details.get("price"),
                                        "currency": details.get("currency"),
                                        "bundle_id": details.get("bundleId"),
                                        "genres": details.get("genres", []),
                                    })[:1500],
                                    tags=["ios", "app-store", "mobile-app", "app-detail"]
                                ))
                    except:
                        pass
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


def detect_deep_links(html: str) -> list:
    findings = []
    for pattern, label in DEEP_LINK_PATTERNS:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:5]:
            matched_str = m if isinstance(m, str) else m[0]
            findings.append(IntelligenceFinding(
                entity=matched_str[:200],
                type=f"Deep Link: {label}",
                source="MobileRecon",
                confidence="Medium",
                color="blue",
                threat_level="Informational",
                status="Found",
                tags=["deep-link", label.lower().replace(" ", "-").replace("(", "").replace(")", "")]
            ))
    return findings


def detect_sms_mms(html: str) -> list:
    findings = []
    sms_links = re.findall(r'sms:\+?[\d\s\-\+\(\)]{7,20}', html, re.IGNORECASE)
    tel_links = re.findall(r'tel:\+?[\d\s\-\+\(\)]{7,20}', html, re.IGNORECASE)
    phone_numbers = re.findall(
        r'(?:tel|sms|callto|wtai)[:=]"?\+?(\d[\d\s\-\+\(\)]{6,18}\d)',
        html, re.IGNORECASE
    )
    combined = set(sms_links[:5] + tel_links[:5] + [f"tel:{p}" for p in phone_numbers[:5]])
    for link in combined:
        findings.append(IntelligenceFinding(
            entity=link[:200],
            type="Mobile: SMS/Phone Link",
            source="MobileRecon",
            confidence="Medium",
            color="cyan",
            threat_level="Informational",
            status="Found",
            tags=["mobile", "sms", "phone-link"]
        ))
    return findings


def detect_qr_code(html: str, target: str) -> list:
    findings = []
    qr_patterns = [
        r'qr\s*cod(?:e|es?)\s*(?:url|img|image|src|api|endpoint|generator)',
        r'(?:api|generate|create|get)/qr[^"\'\s]*',
        r'qr[_-]?(?:cod(?:e|es?)|img|image|api|generator|server)',
        r'qrcode(?:\.(?:js|php|aspx|py|rb))?',
        r'[^"\']*\.(?:png|jpg|jpeg|gif|svg)[^"\']*(?:qr|qrcode)',
        r'(?:qr|qrcode)[^"\']*\.(?:png|jpg|jpeg|gif|svg)',
    ]
    for pattern in qr_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:3]:
            findings.append(IntelligenceFinding(
                entity=f"QR code reference: {m[:200]}",
                type="Mobile: QR Code",
                source="MobileRecon",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Found",
                tags=["mobile", "qr-code"]
            ))
    return findings


def detect_notification_config(html: str, target: str) -> list:
    findings = []
    html_lower = html.lower()

    firebase_patterns = [
        (r'firebase\.initializeapp\s*\(\s*\{[^}]*\}', "Firebase config inline"),
        (r'apiKey:\s*["\'][^"\']+["\']', "Firebase API Key in JS"),
        (r'authDomain:\s*["\'][^"\']+["\']', "Firebase Auth Domain"),
        (r'projectId:\s*["\'][^"\']+["\']', "Firebase Project ID"),
        (r'messagingSenderId:\s*["\'](\d+)["\']', "Firebase Messaging Sender ID"),
        (r'appId:\s*["\'][^"\']+["\']', "Firebase App ID"),
        (r'measurementId:\s*["\'][^"\']+["\']', "Firebase Measurement ID"),
        (r'FIREBASE_CONFIG\s*[:=]', "Firebase config variable"),
        (r'firebase-messaging-sw\.js', "Firebase Messaging Service Worker"),
        (r'firebase\.messaging\(\)', "Firebase Messaging instance"),
    ]
    for pattern, label in firebase_patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(IntelligenceFinding(
                entity=m.group(0)[:200] if m.group(0) else label,
                type=f"Push Notification: {label}",
                source="MobileRecon",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                tags=["push-notification", "firebase", "fcm"]
            ))

    onesignal_patterns = [
        (r'OneSignal\.init\s*\(\s*\{[^}]*\}', "OneSignal init config"),
        (r'appId:\s*["\'][^"\']+["\']', "OneSignal App ID"),
        (r'safari_web_id:\s*["\'][^"\']+["\']', "OneSignal Safari ID"),
        (r'OneSignalSDKWorker\.js', "OneSignal Service Worker"),
        (r'OneSignalSDKUpdaterWorker\.js', "OneSignal Updater Worker"),
        (r'OneSignal\s*=\s*OneSignal', "OneSignal global"),
    ]
    for pattern, label in onesignal_patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(IntelligenceFinding(
                entity=m.group(0)[:200] if m.group(0) else label,
                type=f"Push Notification: {label}",
                source="MobileRecon",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                tags=["push-notification", "onesignal"]
            ))

    service_worker_reg = re.search(r"navigator\.serviceWorker\.register\s*\(\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE)
    if service_worker_reg:
        sw_path = service_worker_reg.group(1)
        if "firebase" in sw_path.lower() or "onesignal" in sw_path.lower():
            findings.append(IntelligenceFinding(
                entity=f"Push-capable Service Worker: {sw_path}",
                type="Push Notification: Service Worker",
                source="MobileRecon",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                tags=["push-notification", "service-worker"]
            ))

    return findings


async def check_mobile_headers(target: str) -> list:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    mobile_uas = [
        ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36", "Android Chrome"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "iPhone Safari"),
        ("Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36", "Android Samsung Browser"),
        ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "iPad Safari"),
    ]

    try:
        desktop_resp = await httpx.AsyncClient(verify=False).get(
            f"https://{domain}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            follow_redirects=True
        )
        desktop_headers = dict(desktop_resp.headers)
        desktop_size = len(desktop_resp.text) if hasattr(desktop_resp, "text") else 0
        desktop_status = desktop_resp.status_code

        vary = desktop_headers.get("vary", "")
        if "user-agent" in vary.lower() or "user-agent" in vary.lower():
            findings.append(IntelligenceFinding(
                entity=f"Vary: User-Agent header present",
                type="Mobile Headers: Vary",
                source="MobileRecon",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Vary: {vary}",
                tags=["mobile-headers", "vary"]
            ))

        for ua, label in mobile_uas:
            try:
                mobile_resp = await httpx.AsyncClient(verify=False).get(
                    f"https://{domain}", timeout=10.0,
                    headers={"User-Agent": ua},
                    follow_redirects=True
                )
                mobile_size = len(mobile_resp.text) if hasattr(mobile_resp, "text") else 0
                mobile_status = mobile_resp.status_code

                diff_size = abs(mobile_size - desktop_size)
                content_differs = desktop_status != mobile_status or diff_size > 500

                if content_differs or mobile_status != desktop_status:
                    findings.append(IntelligenceFinding(
                        entity=f"Content differs for {label} UA",
                        type="Mobile Headers: UA Differentiation",
                        source="MobileRecon",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        status="Detected",
                        raw_data=(
                            f"Desktop: {desktop_status} ({desktop_size}b) | "
                            f"Mobile ({label}): {mobile_status} ({mobile_size}b)"
                        ),
                        tags=["mobile-headers", "ua-differentiation"]
                    ))

                mobile_vary = mobile_resp.headers.get("vary", "")
                if "user-agent" in mobile_vary.lower():
                    findings.append(IntelligenceFinding(
                        entity=f"Vary: User-Agent in mobile response ({label})",
                        type="Mobile Headers: Vary Mobile",
                        source="MobileRecon",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        status="Detected",
                        tags=["mobile-headers", "vary"]
                    ))
            except:
                pass
    except:
        pass

    return findings


def detect_developer_accounts(html: str, target: str) -> list:
    findings = []
    domain_lower = target.lower()

    dev_account_patterns = [
        (r'https?://play\.google\.com/store/apps/developer\?id=[^"\'<>\s]+', "Google Play Developer"),
        (r'https?://play\.google\.com/store/apps/dev\?id=[^"\'<>\s]+', "Google Play Developer"),
        (r'https?://apps\.apple\.com/[a-z]{2}/developer/[^"\'<>\s]+', "Apple Developer"),
        (r'https?://itunes\.apple\.com/[a-z]{2}/developer/[^"\'<>\s]+', "Apple Developer"),
        (r'Google Play (?:Console|Developer) (?:account|console|page)', "Google Play Console Reference"),
        (r'App Store Connect', "App Store Connect Reference"),
        (r'developer\.apple\.com/account', "Apple Developer Account"),
        (r'developer\.apple\.com/app-store', "Apple App Store Connect URL"),
    ]

    for pattern, label in dev_account_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:3]:
            findings.append(IntelligenceFinding(
                entity=m[:200] if isinstance(m, str) else label,
                type=f"Mobile Dev Account: {label}",
                source="MobileRecon",
                confidence="Low",
                color="purple",
                threat_level="Informational",
                status="Found",
                tags=["mobile", "developer-account", "app-store"]
            ))

    return findings


def detect_sdk_versions(html: str) -> list:
    findings = []
    version_patterns = [
        (r'(?:react[-.\s]*native)[\s:=]*["\'"]?(\d+\.\d+\.\d+)', "React Native"),
        (r'(?:flutter)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Flutter"),
        (r'(?:cordova|phonegap)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Cordova/PhoneGap"),
        (r'(?:xamarin)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Xamarin"),
        (r'(?:ionic)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Ionic"),
        (r'(?:capacitor)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Capacitor"),
        (r'(?:unity)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Unity"),
        (r'(?:firebase)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Firebase"),
        (r'(?:onesignal)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "OneSignal"),
        (r'(?:appsflyer)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "AppsFlyer"),
        (r'(?:branch)[:=/\s]*["\'"]?(\d+\.\d+\.\d+)', "Branch"),
        (r'@react-native(?:-cli)?[/=]?\s*["\'"]?(?:\^|~|>=)?\s*(\d+\.\d+\.\d+)', "React Native (package)"),
        (r'com\.google\.android\.gms\.play-services[-.](?:ads|base|analytics)[:=].*?(\d+\.\d+\.\d+)', "Google Play Services"),
    ]

    for pattern, sdk_name in version_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:3]:
            version = m if isinstance(m, str) else m[0]
            findings.append(IntelligenceFinding(
                entity=f"{sdk_name} v{version}",
                type=f"Mobile SDK Version: {sdk_name}",
                source="MobileRecon",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Detected",
                raw_data=f"{sdk_name}: {version}",
                tags=["mobile-sdk-version", sdk_name.lower().replace(" ", "-")]
            ))

    return findings


def compute_mobile_presence_score(findings: list) -> list:
    score = 0
    max_score = 100
    categories = {
        "app_store_presence": 0,
        "universal_links": 0,
        "pwa_support": 0,
        "mobile_frameworks": 0,
        "push_notifications": 0,
        "deep_links": 0,
        "mobile_optimization": 0,
        "mobile_sdks": 0,
    }

    for f in findings:
        ftype = f.type if hasattr(f, "type") else ""
        if any(x in ftype for x in ["App Store Entry", "Google Play App", "iOS App Store", "Apple App"]):
            categories["app_store_presence"] = min(categories["app_store_presence"] + 15, 20)
        if any(x in ftype for x in ["AASA", "Asset Links", "Universal Link", "App Link"]):
            categories["universal_links"] = min(categories["universal_links"] + 15, 15)
        if any(x in ftype for x in ["PWA", "Service Worker", "Manifest", "Viewport"]):
            categories["pwa_support"] = min(categories["pwa_support"] + 10, 20)
        if "Framework" in ftype:
            categories["mobile_frameworks"] = min(categories["mobile_frameworks"] + 10, 15)
        if "Notification" in ftype or "OneSignal" in ftype or "Firebase" in ftype:
            categories["push_notifications"] = min(categories["push_notifications"] + 10, 10)
        if "Deep Link" in ftype:
            categories["deep_links"] = min(categories["deep_links"] + 5, 10)
        if any(x in ftype for x in ["Mobile Optimization", "Mobile Meta", "Mobile User-Agent"]):
            categories["mobile_optimization"] = min(categories["mobile_optimization"] + 5, 5)
        if "SDK:" in ftype or "SDK Version" in ftype:
            categories["mobile_sdks"] = min(categories["mobile_sdks"] + 5, 5)

    score = sum(categories.values())
    score = min(score, max_score)

    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(categories.items()))

    if score >= 80:
        color = "emerald"
        level = "Strong"
    elif score >= 50:
        color = "yellow"
        level = "Moderate"
    elif score >= 20:
        color = "orange"
        level = "Weak"
    else:
        color = "red"
        level = "Minimal"

    return [IntelligenceFinding(
        entity=f"Mobile Presence Score: {score}/{max_score} ({level})",
        type="Mobile Presence Score",
        source="MobileRecon",
        confidence="High",
        color=color,
        threat_level="Informational",
        status="Complete",
        raw_data=f"Score: {score}/{max_score} | Category breakdown: {breakdown}",
        tags=["mobile", "presence-score", level.lower()]
    )]


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
        findings.extend(detect_mobile_sdks(html, {}))
        findings.extend(extract_app_store_ids(html))
        findings.extend(await check_mobile_viewport_meta(html, domain))
        findings.extend(detect_deep_links(html))
        findings.extend(detect_sms_mms(html))
        findings.extend(detect_qr_code(html, domain))
        findings.extend(detect_notification_config(html, domain))
        findings.extend(detect_developer_accounts(html, domain))
        findings.extend(detect_sdk_versions(html))

    tasks = [
        check_mobile_dns(domain),
        search_mobile_clients(domain, client),
        check_mobile_headers(domain),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    findings.extend(compute_mobile_presence_score(findings))

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
