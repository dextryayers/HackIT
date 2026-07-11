import re
import httpx
from urllib.parse import urlparse, parse_qs
from module_common import safe_fetch, make_finding
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
        resp = await safe_fetch(client, base_url, follow_redirects=True,
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
                    findings.append(make_finding(
                        entity=f"{domain_name} - {info['category']} ({info['company']})",
                        ftype=f"Third-Party: {info['category']}",
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
                findings.append(make_finding(
                    entity=f"{tracker_name} ({dom})",
                    ftype="Third-Party Tracker",
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
                    findings.append(make_finding(
                        entity=f"Beacon pattern: {pat}",
                        ftype="Tracking Beacon",
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
                    findings.append(make_finding(
                        entity=desc,
                        ftype="Cookie-less Fingerprinting",
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
                findings.append(make_finding(
                    entity=f"CMP: {name}",
                    ftype="Consent Management Platform",
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
                findings.append(make_finding(
                    entity=tc[:100],
                    ftype="Tracking Cookie",
                    source="TrackerNetworkMapper",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"Cookie: {tc[:200]}",
                    tags=["tracker", "cookie", "tracking-cookie"]
                ))

        csp_data = await extract_csp_from_headers(headers)
        for directive_name, directive_info in csp_data.items():
            findings.append(make_finding(
                entity=f"CSP {directive_name}: {directive_info['value'][:100]}",
                ftype=f"CSP Directive: {directive_info['label']}",
                source="TrackerNetworkMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Directive: {directive_name} = {directive_info['value'][:300]}",
                tags=["csp", "security", directive_name]
            ))

        for inline in inline_scripts:
            for ev_pat, ev_desc in EVENT_LISTENER_PATTERNS:
                if re.search(ev_pat, inline, re.IGNORECASE):
                    findings.append(make_finding(
                        entity=ev_desc,
                        ftype="Event Listener Tracking",
                        source="TrackerNetworkMapper",
                        confidence="Low",
                        color="orange",
                        threat_level="Informational",
                        tags=["tracker", "event-listener", "privacy"]
                    ))
                    break

        tracker_stats = detect_cookie_tracking_vs_fingerprinting(inline_scripts)
        if tracker_stats["cookie_tracking"] > 0:
            findings.append(make_finding(
                entity=f"Cookie-based tracking detected ({tracker_stats['cookie_tracking']} signals)",
                ftype="Cookie Tracking Detection",
                source="TrackerNetworkMapper",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                tags=["tracker", "cookie-tracking", "privacy"]
            ))
        if tracker_stats["pixel_tracking"] > 0:
            findings.append(make_finding(
                entity=f"Pixel/web beacon tracking detected ({tracker_stats['pixel_tracking']} signals)",
                ftype="Pixel Tracking Detection",
                source="TrackerNetworkMapper",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                tags=["tracker", "pixel-tracking", "privacy"]
            ))

        url_params = parse_qs(urlparse(base_url).query)
        for param in url_params:
            for tp_param in TRACKING_PARAM_PATTERNS:
                if param.lower() == tp_param:
                    findings.append(make_finding(
                        entity=f"Tracking parameter in URL: {param}={url_params[param][0][:50]}",
                        ftype="Tracking URL Parameter",
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

        findings.append(make_finding(
            entity=f"{tracker_count} trackers, {third_party_count} 3rd-party domains, {fingerprint_count} fingerprints, {beacon_count} beacons [Privacy: {privacy_score}/100]",
            ftype="Tracker Network Summary",
            source="TrackerNetworkMapper",
            confidence="High",
            color="red" if privacy_score < 50 else ("orange" if privacy_score < 70 else "purple"),
            threat_level="High Risk" if privacy_score < 50 else ("Elevated Risk" if privacy_score < 70 else "Informational"),
            raw_data=f"Trackers: {tracker_count} | 3rd-party requests: {third_party_count} | Fingerprinting: {fingerprint_count} | Beacons: {beacon_count} | Privacy Score: {privacy_score}/100",
            tags=["tracker", "summary", "privacy"]
        ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Tracker Network error: {str(e)[:100]}",
            ftype="Tracker Network Error",
            source="TrackerNetworkMapper",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings

# === EXTENDED UPGRADE: 200+ tracker domains, CSP extraction, more categories ===

MORE_TRACKER_PATTERNS = {
    "Taboola": [r"taboola\.com", r"trc\.taboola", r"taboola"],
    "Outbrain": [r"outbrain\.com", r"traffic\.outbrain", r"obWidget"],
    "Revcontent": [r"revcontent\.com", r"revcontent"],
    "MGID": [r"mgid\.com", r"mgid"],
    "AdRecover": [r"adrecover\.com"],
    "PropellerAds": [r"propellerads\.com", r"propeller\.media"],
    "PopAds": [r"popads\.net", r"popadscdn"],
    "AdCash": [r"adcash\.com", r"adcash"],
    "AdMaven": [r"admaven\.com"],
    "AdThrive": [r"adthrive\.com", r"adthrive"],
    "Media.net": [r"media\.net", r"media\.net"],
    "Infolinks": [r"infolinks\.com", r"infolinks"],
    "Chitika": [r"chitika\.net", r"chitika"],
    "Kontera": [r"kontera\.com", r"kontera"],
    "VibrantMedia": [r"vibrantmedia\.com", r"intellitxt"],
    "Sovrn": [r"sovrn\.com", r"widget\.sovrn"],
    "OpenX": [r"openx\.com", r"openx\.net", r"openx"],
    "PubMatic": [r"pubmatic\.com", r"pubmatic"],
    "Rubicon": [r"rubiconproject\.com", r"rubicon"],
    "AppNexus": [r"appnexus\.com", r"adnxs\.com", r"appnexus"],
    "Index Exchange": [r"indexexchange\.com", r"casalemedia"],
    "ShareThrough": [r"sharethrough\.com", r"sharethrough"],
    "TripleLift": [r"triplelift\.com", r"triplelift"],
    "Teads": [r"teads\.com", r"teads\.tv", r"teads"],
    "VideoAmp": [r"videoamp\.com", r"videoamp"],
    "TheTradeDesk": [r"adsrvr\.org", r"thetradedesk"],
    "Lotame": [r"lotame\.com", r"lotame"],
    "Neustar": [r"neustar\.biz", r"adadvisor"],
    "Liveramp": [r"liveramp\.com", r"liveramp"],
    "Tapad": [r"tapad\.com", r"tapad"],
    "Drawbridge": [r"drawbridge\.com", r"drawbridge"],
    "CrossPixel": [r"crosspixel\.net", r"crosspixel"],
    "BlueKai": [r"bluekai\.com", r"bluekai"],
    "DemandBase": [r"demandbase\.com", r"demandbase"],
    "Bombora": [r"bombora\.com", r"bombora"],
    "6sense": [r"6sense\.com", r"6sense"],
    "RollWorks": [r"rollworks\.com", r"rollworks"],
    "ZoomInfo": [r"zoominfo\.com", r"zoominfo"],
    "Clearbit": [r"clearbit\.com", r"clearbit"],
    "FullContact": [r"fullcontact\.com", r"fullcontact"],
    "Pipl": [r"pipl\.com", r"pipl"],
    "Experian": [r"experian\.com", r"experian"],
    "Acxiom": [r"acxiom\.com", r"acxiom"],
    "Oracle Data Cloud": [r"oracle\.com/data", r"addthis"],
    "Salesforce DMP": [r"salesforce\.com/dmp", r"krxd\.net"],
    "Adobe Audience Manager": [r"demdex\.net", r"adobe\.com/audience"],
    "MediaMath": [r"mediamath\.com", r"mathtag"],
    "RocketFuel": [r"rocketfuel\.com", r"rfihub"],
    "ConversionLogic": [r"conversionlogic\.com"],
    "C3 Metrics": [r"c3metrics\.com", r"c3tag"],
    "EffectiveMeasure": [r"effectivemeasure\.com", r"effectivemeasure"],
    "Moat": [r"moat\.com", r"moatads"],
    "DoubleVerify": [r"doubleverify\.com", r"doubleverify"],
    "Integral Ad Science": [r"integralads\.com", r"ias\.ds"],
    "Pixalate": [r"pixalate\.com", r"pixalate"],
    "WhiteOps": [r"whiteops\.com", r"whiteops"],
    "Human Security": [r"humansecurity\.com", r"humansecurity"],
    "DataDome": [r"datadome\.co", r"datadome"],
    "PerimeterX": [r"perimeterx\.com", r"px-cdn"],
    "Akamai Bot Manager": [r"akamai\.com/bot", r"akamai/bot"],
    "Cloudflare Bot Management": [r"cloudflare\.com/bot", r"cf-bot"],
    "reCAPTCHA": [r"recaptcha\.net", r"google\.com/recaptcha", r"recaptcha/api"],
    "hCaptcha": [r"hcaptcha\.com", r"hcaptcha"],
    "Turnstile": [r"cloudflare\.com/turnstile", r"challenges\.cloudflare"],
    "Arkose Labs": [r"arkoselabs\.com", r"funcaptcha"],
    "GeoEdge": [r"geoedge\.com", r"geoedge"],
    "Confiant": [r"confiant\.com", r"confiant"],
    "AdGuard": [r"adguard\.com", r"adguard"],
    "uBlock Origin": [r"ublockorigin\.com", r"ublock"],
    "Ghostery": [r"ghostery\.com", r"ghostery"],
    "Privacy Badger": [r"privacybadger\.org", r"eff\.org/privacy"],
    "Disconnect": [r"disconnect\.me", r"disconnect"],
    "NoScript": [r"noscript\.net", r"noscript"],
    "DuckDuckGo": [r"duckduckgo\.com", r"duckduckgo"],
    "Brave": [r"brave\.com", r"brave"],
    "Cloudflare Warp": [r"cloudflarewarp\.com", r"warp"],
    "1.1.1.1": [r"one\.one\.one\.one", r"1\.1\.1\.1"],
    "NextDNS": [r"nextdns\.io", r"nextdns"],
    "ControlD": [r"controld\.com", r"controld"],
    "AdBlock": [r"adblock\.pl", r"adblock"],
    "AdBlock Plus": [r"adblockplus\.org", r"adblockplus"],
    "Malwarebytes": [r"malwarebytes\.com", r"malwarebytes"],
    "Bitdefender": [r"bitdefender\.com", r"bitdefender"],
    "Kaspersky": [r"kaspersky\.com", r"kaspersky"],
    "Norton": [r"norton\.com", r"norton"],
    "McAfee": [r"mcafee\.com", r"mcafee"],
    "Avast": [r"avast\.com", r"avast"],
    "AVG": [r"avg\.com", r"avg"],
    "ESET": [r"eset\.com", r"eset"],
    "Trend Micro": [r"trendmicro\.com", r"trendmicro"],
    "Sophos": [r"sophos\.com", r"sophos"],
    "Palo Alto Networks": [r"paloaltonetworks\.com", r"paloaltonetworks"],
    "Fortinet": [r"fortinet\.com", r"fortinet"],
    "Cisco": [r"cisco\.com", r"cisco"],
    "Check Point": [r"checkpoint\.com", r"checkpoint"],
    "Zscaler": [r"zscaler\.com", r"zscaler"],
    "Mimecast": [r"mimecast\.com", r"mimecast"],
    "Proofpoint": [r"proofpoint\.com", r"proofpoint"],
    "Barracuda": [r"barracuda\.com", r"barracuda"],
    "Trustwave": [r"trustwave\.com", r"trustwave"],
    "F5": [r"f5\.com", r"f5"],
    "Imperva": [r"imperva\.com", r"incapsula"],
    "Akamai": [r"akamai\.com", r"akamaihd"],
    "Fastly": [r"fastly\.com", r"fastly"],
    "Amazon CloudFront": [r"cloudfront\.net", r"amazonaws"],
    "Azure CDN": [r"azureedge\.net", r"azurefd"],
    "Google Cloud CDN": [r"cdn\.google", r"gcpcdn"],
    "Cloudflare": [r"cloudflare\.com", r"cloudflare"],
    "StackPath": [r"stackpathcdn\.com", r"stackpath"],
    "KeyCDN": [r"keycdn\.com", r"kxcdn"],
    "BunnyCDN": [r"bunnycdn\.com", r"bunny\.net"],
    "CDN77": [r"cdn77\.com", r"cdn77"],
    "CacheFly": [r"cachefly\.com", r"cachefly"],
    "OVH CDN": [r"ovh\.net", r"ovh"],
    "Quantil": [r"quantil\.com", r"quantil"],
    "G-Core CDN": [r"gcore\.com", r"gcore"],
    "BelugaCDN": [r"belugacdn\.com", r"belugacdn"],
    "CDNVideo": [r"cdnvideo\.ru", r"cdnvideo"],
    "EdgeCast": [r"edgecastcdn\.net", r"edgecast"],
    "Section.io": [r"section\.io", r"section"],
    "ArvanCloud": [r"arvancloud\.com", r"arvancloud"],
    "MyraCloud": [r"myracloud\.com", r"myracloud"],
    "Sucuri": [r"sucuri\.net", r"sucuri"],
    "Reblaze": [r"reblaze\.com", r"reblaze"],
    "DDoS Guard": [r"ddos-guard\.net", r"ddosguard"],
}

MORE_THIRD_PARTY_CATEGORIES = {
    "adsrvr.org": {"category": "Advertising/DSP", "company": "The Trade Desk", "privacy_impact": 9},
    "adnxs.com": {"category": "Ad Exchange", "company": "AppNexus/Xandr", "privacy_impact": 9},
    "rubiconproject.com": {"category": "Ad Exchange", "company": "Rubicon Project", "privacy_impact": 8},
    "openx.net": {"category": "Ad Exchange", "company": "OpenX", "privacy_impact": 8},
    "pubmatic.com": {"category": "Ad Exchange", "company": "PubMatic", "privacy_impact": 8},
    "casalemedia.com": {"category": "Ad Exchange", "company": "Index Exchange", "privacy_impact": 8},
    "moatads.com": {"category": "Ad Verification", "company": "Moat/Oracle", "privacy_impact": 8},
    "scorecardresearch.com": {"category": "Analytics", "company": "comScore", "privacy_impact": 7},
    "quantserve.com": {"category": "Analytics", "company": "Quantcast", "privacy_impact": 7},
    "krxd.net": {"category": "DMP", "company": "Salesforce/Krux", "privacy_impact": 8},
    "demdex.net": {"category": "DMP", "company": "Adobe Audience Manager", "privacy_impact": 8},
    "bluekai.com": {"category": "DMP", "company": "Oracle BlueKai", "privacy_impact": 8},
    "addthis.com": {"category": "Social/Sharing", "company": "Oracle AddThis", "privacy_impact": 7},
    "sharethis.com": {"category": "Social/Sharing", "company": "ShareThis", "privacy_impact": 7},
    "disqus.com": {"category": "Comments", "company": "Disqus", "privacy_impact": 6},
    "taboola.com": {"category": "Content Recommendation", "company": "Taboola", "privacy_impact": 7},
    "outbrain.com": {"category": "Content Recommendation", "company": "Outbrain", "privacy_impact": 7},
    "revcontent.com": {"category": "Content Recommendation", "company": "Revcontent", "privacy_impact": 7},
    "mgid.com": {"category": "Content Recommendation", "company": "MGID", "privacy_impact": 7},
    "criteo.com": {"category": "Retargeting", "company": "Criteo", "privacy_impact": 9},
    "criteo.net": {"category": "Retargeting", "company": "Criteo", "privacy_impact": 9},
    "adroll.com": {"category": "Retargeting", "company": "AdRoll", "privacy_impact": 8},
    "amazon-adsystem.com": {"category": "Advertising", "company": "Amazon", "privacy_impact": 9},
    "aax.amazon-adsystem.com": {"category": "Advertising", "company": "Amazon Ads", "privacy_impact": 9},
    "rlcdn.com": {"category": "Identity", "company": "LiveRamp", "privacy_impact": 9},
    "idsync.rlcdn.com": {"category": "Identity Resolution", "company": "LiveRamp", "privacy_impact": 9},
    "tapad.com": {"category": "Identity Resolution", "company": "Tapad", "privacy_impact": 9},
    "drawbridge.com": {"category": "Identity Resolution", "company": "Drawbridge", "privacy_impact": 8},
    "crosspixel.net": {"category": "Cross-Device", "company": "CrossPixel", "privacy_impact": 8},
    "agkn.com": {"category": "DMP", "company": "Neustar", "privacy_impact": 8},
    "2o7.net": {"category": "Analytics", "company": "Adobe Omniture", "privacy_impact": 7},
    "omtrdc.net": {"category": "Analytics", "company": "Adobe Analytics", "privacy_impact": 7},
    "demandbase.com": {"category": "ABM", "company": "Demandbase", "privacy_impact": 8},
    "bombora.com": {"category": "Intent Data", "company": "Bombora", "privacy_impact": 8},
    "6sense.com": {"category": "ABM/Intent", "company": "6sense", "privacy_impact": 8},
    "zoominfo.com": {"category": "B2B Data", "company": "ZoomInfo", "privacy_impact": 8},
    "clearbit.com": {"category": "B2B Data", "company": "Clearbit", "privacy_impact": 7},
    "fullcontact.com": {"category": "Identity", "company": "FullContact", "privacy_impact": 8},
    "pipl.com": {"category": "Identity", "company": "Pipl", "privacy_impact": 8},
    "experian.com": {"category": "Credit/Data", "company": "Experian", "privacy_impact": 9},
    "acxiom.com": {"category": "Data Broker", "company": "Acxiom", "privacy_impact": 9},
    "oracle.com": {"category": "Cloud/Data", "company": "Oracle", "privacy_impact": 7},
    "mediamath.com": {"category": "DSP", "company": "MediaMath", "privacy_impact": 8},
    "mathtag.com": {"category": "DSP", "company": "MediaMath", "privacy_impact": 8},
    "rfihub.com": {"category": "DSP", "company": "RocketFuel", "privacy_impact": 8},
    "effectivemeasure.com": {"category": "Web Analytics", "company": "Effective Measure", "privacy_impact": 7},
    "conviva.com": {"category": "Streaming Analytics", "company": "Conviva", "privacy_impact": 6},
    "mux.com": {"category": "Video Analytics", "company": "Mux", "privacy_impact": 6},
    "wistia.com": {"category": "Video Hosting", "company": "Wistia", "privacy_impact": 5},
    "vimeo.com": {"category": "Video Hosting", "company": "Vimeo", "privacy_impact": 5},
    "youtube.com": {"category": "Video Hosting", "company": "Google/YouTube", "privacy_impact": 7},
    "brightcove.com": {"category": "Video Hosting", "company": "Brightcove", "privacy_impact": 5},
    "jwplayer.com": {"category": "Video Player", "company": "JW Player", "privacy_impact": 5},
    "cdn.ampproject.org": {"category": "CDN/AMP", "company": "Google", "privacy_impact": 4},
    "cdn.jsdelivr.net": {"category": "CDN", "company": "jsDelivr", "privacy_impact": 2},
    "cdnjs.cloudflare.com": {"category": "CDN", "company": "Cloudflare/cdnjs", "privacy_impact": 2},
    "unpkg.com": {"category": "CDN", "company": "npm", "privacy_impact": 2},
    "polyfill.io": {"category": "Polyfill", "company": "Polyfill.io", "privacy_impact": 3},
    "code.jquery.com": {"category": "CDN", "company": "jQuery Foundation", "privacy_impact": 2},
    "stackpath.bootstrapcdn.com": {"category": "CDN", "company": "BootstrapCDN", "privacy_impact": 2},
    "netdna.bootstrapcdn.com": {"category": "CDN", "company": "BootstrapCDN (MaxCDN)", "privacy_impact": 2},
    "maxcdn.bootstrapcdn.com": {"category": "CDN", "company": "BootstrapCDN (MaxCDN)", "privacy_impact": 2},
    "c.speedcurve.com": {"category": "Performance Monitoring", "company": "SpeedCurve", "privacy_impact": 5},
    "rum.perfops.net": {"category": "Performance Monitoring", "company": "PerfOps", "privacy_impact": 5},
    "cdn.launchdarkly.com": {"category": "Feature Flags", "company": "LaunchDarkly", "privacy_impact": 5},
    "cdn.split.io": {"category": "Feature Flags", "company": "Split.io", "privacy_impact": 5},
    "cdn.auth0.com": {"category": "Auth/CDN", "company": "Auth0", "privacy_impact": 6},
    "cdn.sanity.io": {"category": "CMS/CDN", "company": "Sanity", "privacy_impact": 3},
    "cdn.contentful.com": {"category": "CMS/CDN", "company": "Contentful", "privacy_impact": 3},
    "images.ctfassets.net": {"category": "CMS/CDN", "company": "Contentful", "privacy_impact": 3},
    "cdn.storyblok.com": {"category": "CMS/CDN", "company": "Storyblok", "privacy_impact": 3},
    "cdn.builder.io": {"category": "CMS/CDN", "company": "Builder.io", "privacy_impact": 3},
    "ghost.org": {"category": "CMS", "company": "Ghost", "privacy_impact": 3},
    "prismic.io": {"category": "CMS", "company": "Prismic", "privacy_impact": 3},
    "cdn.shopify.com": {"category": "E-commerce/CDN", "company": "Shopify", "privacy_impact": 4},
    "squarecdn.com": {"category": "E-commerce/CDN", "company": "Square", "privacy_impact": 4},
    "cdn.woocommerce.com": {"category": "E-commerce", "company": "WooCommerce", "privacy_impact": 3},
    "js.braintreegateway.com": {"category": "Payments", "company": "Braintree/PayPal", "privacy_impact": 6},
    "js.stripe.com": {"category": "Payments", "company": "Stripe", "privacy_impact": 6},
    "www.paypalobjects.com": {"category": "Payments", "company": "PayPal", "privacy_impact": 6},
    "checkoutshopper-live.adyen.com": {"category": "Payments", "company": "Adyen", "privacy_impact": 6},
    "js.squareup.com": {"category": "Payments", "company": "Square", "privacy_impact": 6},
    "d3v27wwd40f0xu.cloudfront.net": {"category": "E-commerce", "company": "Shopify", "privacy_impact": 3},
}

CSP_DIRECTIVES = {
    "default-src": "Default source",
    "script-src": "Script sources",
    "style-src": "Style sources",
    "img-src": "Image sources",
    "connect-src": "Connection/XHR sources",
    "font-src": "Font sources",
    "frame-src": "Frame sources",
    "media-src": "Media sources",
    "object-src": "Object/plugin sources",
    "manifest-src": "Manifest sources",
    "worker-src": "Web Worker sources",
    "base-uri": "Base URL",
    "form-action": "Form action targets",
    "frame-ancestors": "Frame ancestors (clickjacking)",
    "block-all-mixed-content": "Mixed content blocking",
    "upgrade-insecure-requests": "HTTPS upgrade",
    "navigate-to": "Navigation targets",
    "report-uri": "CSP report URI",
    "report-to": "CSP reporting endpoint",
    "require-sri-for": "SRI requirement",
    "trusted-types": "Trusted types policy",
    "webrtc": "WebRTC sources",
}

EVENT_LISTENER_PATTERNS = [
    (r"addEventListener\(['\"]?(scroll|resize|mousemove|click|touch)", "UI Event Tracking"),
    (r"addEventListener\(['\"]?(beforeunload|unload|pagehide)", "Page Exit Tracking"),
    (r"addEventListener\(['\"]?(focus|blur)", "Focus/Blur Tracking"),
    (r"addEventListener\(['\"]?(copy|paste|cut)", "Clipboard Tracking"),
    (r"addEventListener\(['\"]?(visibilitychange|pageshow)", "Visibility/Page Tracking"),
]

async def extract_csp_from_headers(headers):
    csp_data = {}
    try:
        csp = headers.get("content-security-policy", "")
        if csp:
            directives = csp.split(";")
            for directive in directives:
                directive = directive.strip()
                parts = directive.split(maxsplit=1)
                if len(parts) >= 1:
                    name = parts[0]
                    value = parts[1] if len(parts) > 1 else ""
                    label = CSP_DIRECTIVES.get(name, name)
                    csp_data[name] = {"label": label, "value": value[:200]}
    except Exception:
        pass
    return csp_data

def detect_utm_parameters(url_params):
    findings_list = []
    try:
        all_utm = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                   "utm_id", "utm_cid", "utm_reader", "utm_viz_id", "utm_pubreferrer",
                   "utm_social", "utm_social-type",
                   "utm_affiliate", "utm_partner", "utm_brand",
                   "utm_placement", "utm_device", "utm_network",
                   "utm_target", "utm_keyword", "utm_adgroup",
                   "utm_region", "utm_country", "utm_city",
                   "utm_language", "utm_audience",
                   "utm_segment", "utm_user", "utm_account"]
        for param in url_params:
            for utm in all_utm:
                if param.lower() == utm:
                    findings_list.append(param)
    except Exception:
        pass
    return findings_list

def analyze_privacy_impact(trackers, fingerprints, beacons):
    score = 100
    try:
        score -= len(trackers) * 4
        score -= fingerprints * 7
        score -= beacons * 2
        if len(trackers) > 10:
            score -= 15
        if fingerprints > 5:
            score -= 10
    except Exception:
        pass
    return max(0, min(100, score))

def detect_cookie_tracking_vs_fingerprinting(inline_scripts):
    result = {"cookie_tracking": 0, "fingerprinting": 0, "pixel_tracking": 0}
    try:
        for inline in inline_scripts:
            if re.search(r'document\.cookie|setCookie|getCookie', inline, re.IGNORECASE):
                result["cookie_tracking"] += 1
            if re.search(r'canvas\.toDataURL|navigator\.|screen\.|webgl', inline, re.IGNORECASE):
                result["fingerprinting"] += 1
            if re.search(r'new Image\(\)|\.src\s*=|navigator\.sendBeacon', inline, re.IGNORECASE):
                result["pixel_tracking"] += 1
    except Exception:
        pass
    return result
