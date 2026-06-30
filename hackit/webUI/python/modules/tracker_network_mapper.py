import re
import httpx
from urllib.parse import urlparse, parse_qs
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
    "Mouseflow": [r"mouseflow\.com", r"mouseflow", r"/mouseflow/"],
    "Clicktale": [r"clicktale\.com", r"clicktale", r"/clicktale/"],
    "SmartLook": [r"smartlook\.com", r"smartlook"],
    "LogRocket": [r"logrocket\.com", r"logrocket"],
    "PostHog": [r"posthog\.com", r"posthog"],
    "Plausible": [r"plausible\.io", r"plausible"],
    "Fathom": [r"usefathom\.com", r"fathom"],
    "Simple Analytics": [r"simpleanalytics\.com", r"simpleanalytics"],
    "Umami": [r"umami\.is", r"umami"],
    "Matomo": [r"matomo\.org", r"piwik", r"matomo\.js"],
    "OpenReplay": [r"openreplay\.com", r"openreplay"],
    "RudderStack": [r"rudderstack\.com", r"rudderanalytics"],
    "Snowplow": [r"snowplow\.io", r"snowplow"],
    "Adobe Analytics": [r"adobe\.com/analytics", r"adobedtm", r"dpm\.demdex\.net", r"omtrdc\.net"],
    "Yandex Metrica": [r"mc\.yandex\.ru", r"yandexmetrica", r"yandex\.com/metrika"],
    "Baidu Tongji": [r"hm\.baidu\.com", r"tongji\.baidu"],
    "Mailchimp": [r"mailchimp\.com", r"list-manage\.com"],
    "ConvertKit": [r"convertkit\.com", r"convertkit"],
    "ActiveCampaign": [r"activecampaign\.net", r"activecampaign"],
    "SendGrid": [r"sendgrid\.net", r"sendgrid\.com"],
    "Mailgun": [r"mailgun\.net", r"mailgun"],
    "Postmark": [r"postmarkapp\.com", r"postmark"],
    "Intercom": [r"intercom\.io", r"intercomcdn"],
    "Drift": [r"drift\.com", r"drift"],
    "Crisp": [r"crisp\.chat", r"crisp"],
    "Tawk.to": [r"tawk\.to", r"tawk"],
    "LiveChat": [r"livechat\.com", r"livechat"],
    "Zendesk Chat": [r"zopim\.com", r"zendesk_chat", r"zendesk\.com/chat"],
    "Freshchat": [r"freshchat\.com", r"freshchat"],
    "Olark": [r"olark\.com", r"olark"],
    "Qualaroo": [r"qualaroo\.com", r"qualaroo"],
    "SurveyMonkey": [r"surveymonkey\.com", r"surveymonkey"],
    "Typeform": [r"typeform\.com", r"typeform"],
    "Google Tag Manager": [r"googletagmanager\.com", r"gtm\.js"],
    "Google Optimize": [r"optimize\.googleapis\.com", r"googleoptimize"],
    "Branch.io": [r"branch\.io", r"branchio"],
    "Adjust": [r"adjust\.com", r"adjust"],
    "AppsFlyer": [r"appsflyer\.com", r"appsflyer"],
    "Firebase Analytics": [r"firebase\.google\.com", r"firebase-analytics"],
    "AppDynamics": [r"appdynamics\.com", r"appdynamics"],
    "Dynatrace": [r"dynatrace\.com", r"dtagent"],
    "Akamai mPulse": [r"akamai\.com/mpulse", r"mpulse"],
    "Pingdom": [r"pingdom\.com", r"pingdom"],
    "StatusCake": [r"statuscake\.com", r"statuscake"],
    "Better Uptime": [r"betteruptime\.com", r"better-uptime"],
    "Ahrefs": [r"ahrefs\.com", r"ahrefs"],
    "Moz": [r"moz\.com", r"moz"],
    "Semrush": [r"semrush\.com", r"semrush"],
    "SimilarWeb": [r"similarweb\.com", r"similarweb"],
    "Alexa": [r"alexa\.com", r"alexa"],
    "Quantcast": [r"quantcast\.com", r"quantcast"],
    "comScore": [r"comscore\.com", r"comscore"],
    "Nielsen": [r"nielsen\.com", r"nielsen"],
    "Chartbeat": [r"chartbeat\.com", r"chartbeat"],
    "Parse.ly": [r"parsely\.com", r"parsely"],
    "CrowdTangle": [r"crowdtangle\.com", r"crowdtangle"],
    "Talkwalker": [r"talkwalker\.com", r"talkwalker"],
    "Brandwatch": [r"brandwatch\.com", r"brandwatch"],
    "Meltwater": [r"meltwater\.com", r"meltwater"],
    "Sprout Social": [r"sproutsocial\.com", r"sprout-social"],
    "Hootsuite": [r"hootsuite\.com", r"hootsuite"],
    "Buffer": [r"buffer\.com", r"buffer"],
    "CoSchedule": [r"coschedule\.com", r"coschedule"],
    "Proofpoint": [r"proofpoint\.com", r"proofpoint"],
    "Mimecast": [r"mimecast\.com", r"mimecast"],
    "CloudFlare SSL": [r"cloudflare\.com/ssl", r"cloudflare-ssl"],
    "Cloudinary": [r"cloudinary\.com", r"res\.cloudinary"],
    "Imgix": [r"imgix\.net", r"imgix"],
    "Fastly Images": [r"fastly\.com/images", r"fastly-image"],
    "Stripe": [r"stripe\.com", r"js\.stripe\.com"],
    "PayPal": [r"paypal\.com", r"paypalobjects"],
    "Braintree": [r"braintreegateway\.com", r"braintree"],
    "Square": [r"square\.com", r"squareup\.com"],
    "Shopify": [r"shopify\.com", r"myshopify\.com", r"cdn\.shopify"],
    "WooCommerce": [r"woocommerce", r"woocommerce"],
    "Magento": [r"magento", r"mage"],
    "BigCommerce": [r"bigcommerce\.com", r"bigcommerce"],
    "Squarespace": [r"squarespace\.com", r"static1\.squarespace"],
    "Wix": [r"wix\.com", r"wixstatic"],
    "Webflow": [r"webflow\.com", r"webflow"],
    "Drupal": [r"drupal\.org", r"drupal"],
    "WordPress": [r"wordpress\.org", r"wp-content", r"wp-includes"],
    "Joomla": [r"joomla\.org", r"joomla"],
    "phpMyAdmin": [r"phpmyadmin", r"phpmyadmin\.net"],
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
    (r"cookieinformation\.com", "CookieInformation"),
    (r"consentmanager\.net", "ConsentManager"),
    (r"cookieyes\.com", "CookieYes"),
    (r"cookie-script\.com", "CookieScript"),
    (r"cookiepro\.com", "CookiePro"),
    (r"consentu\.com", "ConsentU"),
    (r"enormo\.eu", "Enormo"),
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
    (r"navigator\.keyboard", "Keyboard Layout Detection"),
    (r"navigator\.pdfViewerEnabled", "PDF Viewer Detection"),
    (r"navigator\.bluetooth", "Bluetooth API Probing"),
    (r"navigator\.usb", "USB API Probing"),
    (r"navigator\.hid", "HID API Probing"),
    (r"navigator\.serial", "Serial API Probing"),
    (r"navigator\.wakeLock", "Wake Lock API Probing"),
    (r"navigator\.xr", "WebXR Detection"),
    (r"navigator\.credentials", "Credentials API Probing"),
    (r"navigator\.clipboard", "Clipboard API Probing"),
    (r"navigator\.presentation", "Presentation API Probing"),
    (r"navigator\.mediaSession", "Media Session API Probing"),
    (r"navigator\.geolocation", "Geolocation API Probing"),
    (r"navigator\.vibrate", "Vibration API Probing"),
    (r"navigator\.battery", "Battery API Probing"),
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
    r"\/ingest",
    r"\/logging",
    r"\/events",
    r"\/impression",
    r"\/visit",
    r"\/session",
    r"\/activity",
    r"\/count",
    r"\/stat",
    r"\/metrics",
    r"\/monitor",
    r"\/report",
    r"\/pageview.gif",
    r"\/pixel.gif",
    r"\/tracking",
    r"\/log",
    r"\/audit",
]

TRACKING_PARAM_PATTERNS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_cid", "utm_reader", "utm_viz_id", "utm_pubreferrer",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "twclid", "igshid", "mc_cid", "mc_eid",
    "yclid", "wickedid", "_ga", "_gl",
    "ref", "referrer", "source", "medium", "campaign",
    "term", "content", "placement", "adgroup",
    "adid", "device", "matchtype", "network",
    "target", "keyword", "creative", "loc",
    "url", "redirect_uri", "redirect_url",
    "return_url", "return_to", "next", "return",
    "track", "tracking", "trk", "trk_p",
    "hsa_cam", "hsa_grp", "hsa_mt", "hsa_src", "hsa_ad", "hsa_acc",
    "hsa_net", "hsa_ver", "hsa_la", "hsa_ol",
    "s_kwcid", "ef_id", "s_cid",
    "oly_anon_id", "oly_enc_id", "_openstat",
    "mtm_source", "mtm_medium", "mtm_campaign", "mtm_keyword", "mtm_content",
    "pk_source", "pk_medium", "pk_campaign", "pk_keyword", "pk_content",
    "piwik_source", "piwik_medium", "piwik_campaign",
    "wt_mc", "wt_zmc", "wt_zs", "wt_ni",
    "vero_conv", "vero_id",
    "mkt_tok", "imm_mid",
    "cm_mmc", "cm_guid",
    "as_cam", "as_chl", "as_chnl", "as_pt", "as_id",
]

THIRD_PARTY_CATEGORIES = {
    "google-analytics.com": {"category": "Analytics", "company": "Google", "privacy_impact": 7},
    "googletagmanager.com": {"category": "Analytics/Tag Manager", "company": "Google", "privacy_impact": 8},
    "doubleclick.net": {"category": "Advertising", "company": "Google", "privacy_impact": 9},
    "facebook.com": {"category": "Social/Tracking", "company": "Meta", "privacy_impact": 9},
    "connect.facebook.net": {"category": "Social/Tracking", "company": "Meta", "privacy_impact": 8},
    "fbcdn.net": {"category": "CDN", "company": "Meta", "privacy_impact": 5},
    "ads-twitter.com": {"category": "Advertising", "company": "Twitter/X", "privacy_impact": 8},
    "analytics.twitter.com": {"category": "Analytics", "company": "Twitter/X", "privacy_impact": 7},
    "linkedin.com": {"category": "Social", "company": "LinkedIn", "privacy_impact": 7},
    "ads.linkedin.com": {"category": "Advertising", "company": "LinkedIn", "privacy_impact": 8},
    "bat.bing.com": {"category": "Advertising", "company": "Microsoft", "privacy_impact": 8},
    "pinterest.com": {"category": "Social/Marketing", "company": "Pinterest", "privacy_impact": 7},
    "reddit.com": {"category": "Social", "company": "Reddit", "privacy_impact": 7},
    "snapchat.com": {"category": "Social", "company": "Snapchat", "privacy_impact": 7},
    "tiktok.com": {"category": "Social", "company": "TikTok", "privacy_impact": 8},
    "hotjar.com": {"category": "Analytics/Heatmap", "company": "Hotjar", "privacy_impact": 8},
    "fullstory.com": {"category": "Analytics/Session Replay", "company": "FullStory", "privacy_impact": 9},
    "amplitude.com": {"category": "Analytics", "company": "Amplitude", "privacy_impact": 7},
    "mixpanel.com": {"category": "Analytics", "company": "Mixpanel", "privacy_impact": 7},
    "segment.com": {"category": "Analytics/CDP", "company": "Segment", "privacy_impact": 8},
    "cloudflare.com": {"category": "CDN/Security", "company": "Cloudflare", "privacy_impact": 4},
    "cloudfront.net": {"category": "CDN", "company": "AWS", "privacy_impact": 3},
    "akamai.com": {"category": "CDN", "company": "Akamai", "privacy_impact": 3},
    "fastly.net": {"category": "CDN", "company": "Fastly", "privacy_impact": 3},
    "jsdelivr.net": {"category": "CDN", "company": "jsDelivr", "privacy_impact": 2},
    "cdnjs.cloudflare.com": {"category": "CDN", "company": "Cloudflare", "privacy_impact": 2},
    "unpkg.com": {"category": "CDN", "company": "npm", "privacy_impact": 2},
    "stripe.com": {"category": "Payment", "company": "Stripe", "privacy_impact": 6},
    "paypal.com": {"category": "Payment", "company": "PayPal", "privacy_impact": 6},
    "sentry.io": {"category": "Monitoring", "company": "Sentry", "privacy_impact": 6},
    "newrelic.com": {"category": "Monitoring", "company": "New Relic", "privacy_impact": 6},
    "datadoghq.com": {"category": "Monitoring", "company": "Datadog", "privacy_impact": 6},
    "zendesk.com": {"category": "Support", "company": "Zendesk", "privacy_impact": 5},
    "intercom.io": {"category": "Support/Chat", "company": "Intercom", "privacy_impact": 7},
    "crisp.chat": {"category": "Support/Chat", "company": "Crisp", "privacy_impact": 6},
    "tawk.to": {"category": "Support/Chat", "company": "Tawk.to", "privacy_impact": 6},
    "livechat.com": {"category": "Support/Chat", "company": "LiveChat", "privacy_impact": 5},
    "hubspot.com": {"category": "Marketing/CRM", "company": "HubSpot", "privacy_impact": 8},
    "salesforce.com": {"category": "CRM", "company": "Salesforce", "privacy_impact": 7},
    "mailchimp.com": {"category": "Email Marketing", "company": "Mailchimp", "privacy_impact": 6},
    "sendgrid.net": {"category": "Email", "company": "SendGrid", "privacy_impact": 5},
    "optimizely.com": {"category": "A/B Testing", "company": "Optimizely", "privacy_impact": 7},
    "vwo.com": {"category": "A/B Testing", "company": "VWO", "privacy_impact": 7},
    "mouseflow.com": {"category": "Session Replay", "company": "Mouseflow", "privacy_impact": 9},
    "clicktale.com": {"category": "Session Replay", "company": "Clicktale", "privacy_impact": 8},
    "smartlook.com": {"category": "Session Replay", "company": "Smartlook", "privacy_impact": 8},
    "logrocket.com": {"category": "Session Replay", "company": "LogRocket", "privacy_impact": 9},
    "posthog.com": {"category": "Analytics", "company": "PostHog", "privacy_impact": 6},
    "plausible.io": {"category": "Analytics", "company": "Plausible", "privacy_impact": 2},
    "matomo.org": {"category": "Analytics", "company": "Matomo", "privacy_impact": 3},
}

SCRIPT_SRC_REGEX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
IFRAME_SRC_REGEX = re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
IMG_SRC_REGEX = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_HREF_REGEX = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
BEACON_REGEX = re.compile(r'<img[^>]+src=["\'][^"\']*?(?:collect|beacon|pixel|track|analytics|telemetry|ingest|logging|events|impression|visit|session|activity|count|stat|metrics|monitor|report|pageview|tracking|log|audit)[^"\']*["\']', re.IGNORECASE)
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
        for m in LINK_HREF_REGEX.finditer(html):
            if ".css" in m.group(1).lower() or "font" in m.group(1).lower():
                all_third_party_srcs.append(m.group(1))

        trackers_found = {}
        third_party_domains = set()
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
                            third_party_domains.add(netloc)
                        break
                else:
                    continue
                break

        for src in all_third_party_srcs:
            parsed = urlparse(src if src.startswith("http") else "https:" + src)
            netloc = parsed.netloc or src.split("/")[0]
            if netloc and netloc != domain:
                third_party_domains.add(netloc)

        for domain_name in third_party_domains:
            domain_lower = domain_name.lower()
            for tp_domain, info in THIRD_PARTY_CATEGORIES.items():
                if tp_domain in domain_lower:
                    privacy_impact = info.get("privacy_impact", 5)
                    color = "red" if privacy_impact >= 8 else ("orange" if privacy_impact >= 5 else "slate")
                    findings.append(IntelligenceFinding(
                        entity=f"{domain_name} - {info['category']} ({info['company']})",
                        type=f"Third-Party: {info['category']}",
                        source="TrackerNetworkMapper",
                        confidence="High",
                        color=color,
                        threat_level="Elevated Risk" if privacy_impact >= 7 else "Informational",
                        raw_data=f"Domain: {domain_name} | Category: {info['category']} | Company: {info['company']} | Privacy Impact: {privacy_impact}/10",
                        tags=["third-party", info["category"].lower().replace(" ", "-").replace("/", "-"), info["company"].lower().replace(" ", "-")]
                    ))
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

        url_params = parse_qs(urlparse(base_url).query)
        for param in url_params:
            for tp_param in TRACKING_PARAM_PATTERNS:
                if param.lower() == tp_param:
                    findings.append(IntelligenceFinding(
                        entity=f"Tracking parameter in URL: {param}={url_params[param][0][:50]}",
                        type="Tracking URL Parameter",
                        source="TrackerNetworkMapper",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        tags=["tracker", "url-parameter", param]
                    ))
                    break

        tracker_count = len(trackers_found)
        fingerprint_count = sum(1 for f in findings if f.type == "Cookie-less Fingerprinting")
        beacon_count = sum(1 for f in findings if f.type == "Tracking Beacon")
        third_party_count = len(third_party_domains)
        high_privacy = sum(1 for f in findings if "Privacy Impact" in (f.raw_data or "") and "7" in (f.raw_data or ""))
        privacy_score = max(0, 100 - (tracker_count * 5 + fingerprint_count * 8 + beacon_count * 3 + third_party_count * 4))
        privacy_score = min(100, privacy_score)

        findings.append(IntelligenceFinding(
            entity=f"{tracker_count} trackers, {third_party_count} 3rd-party domains, {fingerprint_count} fingerprints, {beacon_count} beacons [Privacy: {privacy_score}/100]",
            type="Tracker Network Summary",
            source="TrackerNetworkMapper",
            confidence="High",
            color="red" if privacy_score < 50 else ("orange" if privacy_score < 70 else "purple"),
            threat_level="High Risk" if privacy_score < 50 else ("Elevated Risk" if privacy_score < 70 else "Informational"),
            raw_data=f"Trackers: {tracker_count} | 3rd-party requests: {third_party_count} | Fingerprinting: {fingerprint_count} | Beacons: {beacon_count} | Privacy Score: {privacy_score}/100",
            tags=["tracker", "summary", "privacy"]
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
