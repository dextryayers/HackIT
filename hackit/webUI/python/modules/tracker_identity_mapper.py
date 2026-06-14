import httpx
import re
import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from models import IntelligenceFinding

TRACKER_SIGNATURES = [
    (r'google-analytics\.com/(ga|analytics|collect|g\b)', "Google Analytics", "analytics"),
    (r'googletagmanager\.com/gtm\.js', "Google Tag Manager", "tag-manager"),
    (r'googletagmanager\.com/ns\.html', "Google Tag Manager (noscript)", "tag-manager"),
    (r'googleadservices\.com/pagead', "Google Ads", "advertising"),
    (r'googlesyndication\.com', "Google AdSense", "advertising"),
    (r'doubleclick\.net', "DoubleClick", "advertising"),
    (r'facebook\.com/tr\b', "Facebook Pixel", "social"),
    (r'facebook\.com/events\b', "Facebook Events", "social"),
    (r'connect\.facebook\.net', "Facebook Connect", "social"),
    (r'fbq\s*\(', "Facebook Pixel (fbq)", "social"),
    (r'fbq\.call\b', "Facebook Pixel (fbq.call)", "social"),
    (r'linkedin\.com/trk', "LinkedIn Insight", "social"),
    (r'linkedin\.com/analytics', "LinkedIn Analytics", "social"),
    (r'ads\.linkedin\.com', "LinkedIn Ads", "advertising"),
    (r'snap\.licdn\.com', "LinkedIn Pixel", "social"),
    (r'twitter\.com/oct.js', "Twitter Analytics", "social"),
    (r'static\.ads-twitter\.com', "Twitter Ads", "advertising"),
    (r't.co\b', "Twitter t.co", "social"),
    (r'tiktok\.com/analytics', "TikTok Analytics", "social"),
    (r'tiktok\.com/pixel', "TikTok Pixel", "social"),
    (r'analytics\.tiktok\.com', "TikTok Analytics SDK", "social"),
    (r'pinterest\.com/ct/', "Pinterest Tag", "social"),
    (r'ct\.pinterest\.com', "Pinterest Conversion Tag", "social"),
    (r'pinit\.js', "Pinterest Save Button", "social"),
    (r'snapchat\.com/ads', "Snapchat Ads", "social"),
    (r'snapchat\.com/ct/', "Snapchat Pixel", "social"),
    (r'analytics\.snapchat\.com', "Snapchat Analytics", "social"),
    (r'reddit\.com/static/pixel\.js', "Reddit Pixel", "social"),
    (r'alb\.reddit\.com', "Reddit Ads", "advertising"),
    (r'ads\.reddit\.com', "Reddit Ads Platform", "advertising"),
    (r'quora\.com/pixel', "Quora Pixel", "social"),
    (r'qpx\.quora\.com', "Quora Pixel (qpx)", "social"),
    (r'bat\.bing\.com', "Bing UET", "advertising"),
    (r'bing\.com/analytics', "Bing Analytics", "analytics"),
    (r'c\.bing\.com', "Bing Ads", "advertising"),
    (r'hotjar\.com', "Hotjar", "analytics"),
    (r'static\.hotjar\.com', "Hotjar Static", "analytics"),
    (r'mouseflow\.com', "Mouseflow", "analytics"),
    (r'fullstory\.com', "FullStory", "analytics"),
    (r'clarity\.ms', "Microsoft Clarity", "analytics"),
    (r'clarity-s\.ms', "Microsoft Clarity (session)", "analytics"),
    (r'mixpanel\.com', "Mixpanel", "analytics"),
    (r'cdn\.mixpanel\.com', "Mixpanel CDN", "analytics"),
    (r'amplitude\.com', "Amplitude", "analytics"),
    (r'api\.amplitude\.com', "Amplitude API", "analytics"),
    (r'segment\.com/analytics\.js', "Segment", "analytics"),
    (r'cdn\.segment\.com', "Segment CDN", "analytics"),
    (r'api\.segment\.io', "Segment API", "analytics"),
    (r'heap\.com', "Heap Analytics", "analytics"),
    (r'heapanalytics\.com', "Heap Analytics (direct)", "analytics"),
    (r'kissmetrics\.com', "Kissmetrics", "analytics"),
    (r'crazyegg\.com', "CrazyEgg", "analytics"),
    (r'luckyorange\.com', "LuckyOrange", "analytics"),
    (r'luckyorange\.net', "LuckyOrange (net)", "analytics"),
    (r'inspectlet\.com', "Inspectlet", "analytics"),
    (r'smartlook\.com', "Smartlook", "analytics"),
    (r'sessioncam\.com', "SessionCam", "analytics"),
    (r'vwo\.com', "VWO (Visual Website Optimizer)", "analytics"),
    (r'optimizely\.com', "Optimizely", "analytics"),
    (r'cdn\.optimizely\.com', "Optimizely CDN", "analytics"),
    (r'convert\.com', "Convert Experiences", "analytics"),
    (r'convertexperiments\.com', "Convert Experiments", "analytics"),
    (r'googleoptimize\.com', "Google Optimize", "analytics"),
    (r'unbounce\.com', "Unbounce", "marketing"),
    (r'leadpages\.net', "Leadpages", "marketing"),
    (r'intercom\.io', "Intercom", "crm"),
    (r'widget\.intercom\.io', "Intercom Widget", "crm"),
    (r'api\.intercom\.io', "Intercom API", "crm"),
    (r'drift\.com', "Drift", "crm"),
    (r'driftt\.com', "Drift (driftt)", "crm"),
    (r'crisp\.chat', "Crisp Chat", "crm"),
    (r'client\.crisp\.chat', "Crisp Chat Client", "crm"),
    (r'livechat\.com', "LiveChat", "crm"),
    (r'livechatinc\.com', "LiveChat Inc", "crm"),
    (r'zendesk\.com', "Zendesk", "crm"),
    (r'zopim\.com', "Zendesk Chat (Zopim)", "crm"),
    (r'freshworks\.com', "Freshworks", "crm"),
    (r'freshdesk\.com', "Freshdesk", "crm"),
    (r'freshchat\.com', "Freshchat", "crm"),
    (r'hubspot\.com', "HubSpot", "marketing"),
    (r'js\.hs-scripts\.com', "HubSpot Scripts", "marketing"),
    (r'hs-analytics\.net', "HubSpot Analytics", "analytics"),
    (r'hs-banner\.com', "HubSpot Banner", "marketing"),
    (r'marketo\.com', "Marketo", "marketing"),
    (r'mkto-response\.com', "Marketo Response", "marketing"),
    (r'pardot\.com', "Pardot", "marketing"),
    (r'pi\.pardot\.com', "Pardot PI", "marketing"),
    (r'eloqua\.com', "Eloqua", "marketing"),
    (r'c\.eloqua\.com', "Eloqua CDN", "marketing"),
    (r'salesforce\.com', "Salesforce", "crm"),
    (r'sfdc\.com', "Salesforce (sfdc)", "crm"),
    (r'force\.com', "Salesforce (force)", "crm"),
    (r'mailchimp\.com', "Mailchimp", "email"),
    (r'chimpstatic\.com', "Mailchimp Static", "email"),
    (r'list-manage\.com', "Mailchimp List", "email"),
    (r'constantcontact\.com', "Constant Contact", "email"),
    (r'activecampaign\.net', "ActiveCampaign", "email"),
    (r'activehosted\.com', "ActiveCampaign (hosted)", "email"),
    (r'sendgrid\.com', "SendGrid", "email"),
    (r'sendgrid\.net', "SendGrid (net)", "email"),
    (r'mailgun\.net', "Mailgun", "email"),
    (r'mailgun\.org', "Mailgun (org)", "email"),
    (r'postmark\.com', "Postmark", "email"),
    (r'api\.postmarkapp\.com', "Postmark API", "email"),
    (r'amazonaws\.com/ses', "Amazon SES", "email"),
    (r'email-us-amazon\.com', "Amazon SES (us)", "email"),
    (r'mandrill\.com', "Mandrill", "email"),
    (r'sparkpost\.com', "SparkPost", "email"),
    (r'convertkit\.com', "ConvertKit", "email"),
    (r'drip\.co', "Drip", "email"),
    (r'customer\.io', "Customer.io", "email"),
    (r'zoho\.com', "Zoho", "crm"),
    (r'crm\.zoho\.com', "Zoho CRM", "crm"),
    (r'zohosettings\.com', "Zoho Settings", "crm"),
    (r'monday\.com', "Monday.com", "crm"),
    (r'monday\.co', "Monday.com (co)", "crm"),
    (r'asana\.com', "Asana", "crm"),
    (r'app\.asana\.com', "Asana App", "crm"),
    (r'trello\.com', "Trello", "crm"),
    (r'jira\.com', "Jira", "crm"),
    (r'atlassian\.net', "Atlassian", "crm"),
    (r'notion\.so', "Notion", "crm"),
    (r'notion-static\.com', "Notion Static", "crm"),
    (r'airtable\.com', "Airtable", "crm"),
    (r'airtable\.co', "Airtable (co)", "crm"),
    (r'tableau\.com', "Tableau", "analytics"),
    (r'looker\.com', "Looker", "analytics"),
    (r'metabase\.com', "Metabase", "analytics"),
    (r'datadog\.com', "Datadog", "analytics"),
    (r'datadoghq\.com', "Datadog (dq)", "analytics"),
    (r'newrelic\.com', "New Relic", "analytics"),
    (r'newrelic\.net', "New Relic (net)", "analytics"),
    (r'nr-data\.net', "New Relic Data", "analytics"),
    (r'splunk\.com', "Splunk", "analytics"),
    (r'rollbar\.com', "Rollbar", "analytics"),
    (r'sentry\.io', "Sentry", "analytics"),
    (r'sentry-cdn\.com', "Sentry CDN", "analytics"),
    (r'logrocket\.com', "LogRocket", "analytics"),
    (r'bugsnag\.com', "Bugsnag", "analytics"),
    (r'exceptionless\.io', "Exceptionless", "analytics"),
]

TRACKING_ID_PATTERNS = [
    (r'UA-\d{4,10}-\d{1,4}', "Google Analytics UA ID"),
    (r'G-[A-Z0-9]{5,15}', "Google Analytics 4 ID"),
    (r'AW-\d{4,15}', "Google Ads ID"),
    (r'DC-\d{4,15}', "DoubleClick ID"),
    (r'GTM-[A-Z0-9]{4,10}', "Google Tag Manager ID"),
    (r'FB-\d{4,15}', "Facebook Pixel ID"),
    (r'fbid=\d{4,20}', "Facebook ID (fbid)"),
    (r'li_fat_id=[a-f0-9-]{30,}', "LinkedIn Insight ID"),
    (r'tt_pixel_id=[a-f0-9-]{10,}', "TikTok Pixel ID"),
    (r'pin_[a-f0-9]{10,}', "Pinterest Tag ID"),
    (r'snap_pixel_id=[a-f0-9-]{10,}', "Snapchat Pixel ID"),
    (r'uetq\s*=\s*new\s+uetq\b', "Bing UET ID"),
    (r'hotjar-\d{4,10}', "Hotjar ID"),
    (r'hjid\s*=\s*\d{4,10}', "Hotjar hjid"),
    (r'FS\w{5,15}', "FullStory ID"),
    (r'clarity\s*:\s*["\']?[a-f0-9-]{20,}', "Microsoft Clarity ID"),
    (r'mixpanel.*token["\':\s]+["\']([a-f0-9]{20,})["\']', "Mixpanel Token"),
    (r'amplitude.*api_key["\':\s]+["\']([a-f0-9]{20,})["\']', "Amplitude API Key"),
    (r'segment.*write_key["\':\s]+["\']([a-f0-9]{20,})["\']', "Segment Write Key"),
    (r'heap\s*:\s*["\']?\d{4,15}', "Heap App ID"),
    (r'intercom.*app_id["\':\s]+["\']([a-f0-9-]{10,})["\']', "Intercom App ID"),
    (r'drift.*driftId["\':\s]+["\']([a-f0-9-]{10,})["\']', "Drift ID"),
    (r'crisp.*website_id["\':\s]+["\']([a-f0-9-]{30,})["\']', "Crisp Website ID"),
    (r'zendesk.*widget_id["\':\s]+["\']([a-f0-9-]{10,})["\']', "Zendesk Widget ID"),
    (r'hubspot.*portalId["\':\s]+["\']?(\d{4,10})["\']?', "HubSpot Portal ID"),
    (r'mkto.*mktoId\s*=\s*(\d{4,10})', "Marketo Munchkin ID"),
    (r'pardot.*piAId["\':\s]+["\']?(\d{4,15})["\']?', "Pardot Account ID"),
    (r'eloqua.*siteID["\':\s]+["\']?(\d{4,10})["\']?', "Eloqua Site ID"),
    (r'mailchimp.*u\s*=\s*["\']?([a-f0-9]{10,})["\']?', "Mailchimp User ID"),
    (r'sendgrid.*api_key["\':\s]+["\'](SG\.[a-zA-Z0-9.-]+)["\']', "SendGrid API Key"),
    (r'vwo.*accountId["\':\s]+["\']?(\d{4,10})["\']?', "VWO Account ID"),
    (r'optimizely.*projectId["\':\s]+["\']?(\d{4,10})["\']?', "Optimizely Project ID"),
    (r'optimizely.*accountId["\':\s]+["\']?(\d{4,10})["\']?', "Optimizely Account ID"),
    (r'crazyegg.*accountNumber["\':\s]+["\']?(\d{4,10})["\']?', "CrazyEgg Account ID"),
]

DATA_SHARING_DOMAINS = {
    "crashlytics.com": "Firebase Crashlytics",
    "firebaseio.com": "Firebase Realtime DB",
    "firebaseremoteconfig.com": "Firebase Remote Config",
    "app.link": "Branch.io Deep Linking",
    "branch.io": "Branch.io",
    "adjust.com": "Adjust SDK",
    "appsflyer.com": "AppsFlyer",
    "amplitude.com": "Amplitude",
    "mixpanel.com": "Mixpanel",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "mparticle.com": "mParticle",
    "kochava.com": "Kochava",
    "tapjoy.com": "Tapjoy",
    "unity3d.com": "Unity Ads",
    "vungle.com": "Vungle",
    "applovin.com": "AppLovin",
    "chartboost.com": "Chartboost",
    "ironsrc.com": "ironSource",
    "fyber.com": "Fyber",
    "axept.io": "Axeptio (CMP)",
    "cookiebot.com": "Cookiebot (CMP)",
    "onetrust.com": "OneTrust (CMP)",
    "termly.io": "Termly (CMP)",
    "cookielaw.org": "CookieLaw",
    "trustarc.com": "TrustArc (CMP)",
    "quantcast.com": "Quantcast (CMP)",
    "sovrn.com": "Sovrn",
    "indexexchange.com": "Index Exchange",
    "openx.net": "OpenX",
    "pubmatic.com": "PubMatic",
    "criteo.com": "Criteo",
    "criteo.net": "Criteo (net)",
    "casalemedia.com": "Casale Media",
    "rubiconproject.com": "Rubicon Project",
    "magnite.com": "Magnite",
    "thetradedesk.com": "The Trade Desk",
    "adnxs.com": "AppNexus",
    "adsafeprotected.com": "Adsafe Protected",
    "moatads.com": "Moat Ads",
    "doubleverify.com": "DoubleVerify",
    "integralads.com": "Integral Ads",
}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        url = f"https://{domain}"
        resp = await client.get(url, timeout=15.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        html = resp.text

        found_trackers = defaultdict(list)
        for pattern, tracker_name, category in TRACKER_SIGNATURES:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                found_trackers[category].append(tracker_name)

        for tracker_name in found_trackers.get("analytics", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Analytics / Tracking",
                source="TrackerMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "analytics"],
            ))
        for tracker_name in found_trackers.get("tag-manager", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Tag Manager",
                source="TrackerMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "tag-manager"],
            ))
        for tracker_name in found_trackers.get("advertising", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Advertising / Ad Tech",
                source="TrackerMapper",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "advertising"],
            ))
        for tracker_name in found_trackers.get("social", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Social Media Tracking",
                source="TrackerMapper",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "social"],
            ))
        for tracker_name in found_trackers.get("marketing", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Marketing Automation",
                source="TrackerMapper",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "marketing"],
            ))
        for tracker_name in found_trackers.get("crm", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="CRM / Customer Platform",
                source="TrackerMapper",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "crm"],
            ))
        for tracker_name in found_trackers.get("email", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Email Marketing",
                source="TrackerMapper",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "email"],
            ))

        for pattern, id_name in TRACKING_ID_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for mid in matches[:3]:
                fid = mid if isinstance(mid, str) else mid[0]
                findings.append(IntelligenceFinding(
                    entity=f"{id_name}: {fid[:60]}",
                    type="Tracking ID",
                    source="TrackerMapper",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="ID Extracted",
                    resolution=id_name,
                    raw_data=fid[:200],
                    tags=["tracking-id", "pii"],
                ))

        sharing_domains_found = []
        for sdom, sname in DATA_SHARING_DOMAINS.items():
            if sdom in html.lower():
                sharing_domains_found.append(sname)
        if sharing_domains_found:
            for sname in sharing_domains_found:
                findings.append(IntelligenceFinding(
                    entity=sname,
                    type="Data Sharing / Third-Party",
                    source="TrackerMapper",
                    confidence="High",
                    color="yellow",
                    threat_level="Informational",
                    status="Data Shared",
                    resolution="Third-party data sharing detected",
                    tags=["data-sharing", "third-party"],
                ))

        cookie_names = re.findall(r'document\.cookie\s*[=].*?["\']([^"\'=;]+)', html, re.IGNORECASE)
        cookie_names.extend(re.findall(r'Set-Cookie:\s*([^=;]+)', str(resp.headers), re.IGNORECASE))
        cookie_names.extend(re.findall(r'["\']([\w]+_utm[a-z]+)["\']', html, re.IGNORECASE))
        if cookie_names:
            unique_cookies = list(set(cookie_names))[:10]
            findings.append(IntelligenceFinding(
                entity=f"Cookies: {', '.join(unique_cookies)}",
                type="Tracking Cookies",
                source="TrackerMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Detected",
                resolution=f"{len(unique_cookies)} tracking cookies",
                raw_data=", ".join(unique_cookies),
                tags=["cookies", "tracking"],
            ))

        consent_platforms = []
        consent_patterns = [
            (r'cmp\s*:|cmp\.|"cmp"', "CMP (Consent Management Platform)"),
            (r'cookiebot|Cookiebot', "Cookiebot"),
            (r'OnetrustActiveGroups', "OneTrust"),
            (r'OptanonWrapper', "OneTrust Wrapper"),
            (r'__tcfapi', "IAB TCF API"),
            (r'__cmp', "IAB CMP API"),
            (r'grvConsent|gravitec', "Gravitec Consent"),
            (r'axeptio', "Axeptio"),
        ]
        for cpat, cname in consent_patterns:
            if re.search(cpat, html, re.IGNORECASE):
                consent_platforms.append(cname)
        if consent_platforms:
            for cname in consent_platforms:
                findings.append(IntelligenceFinding(
                    entity=cname,
                    type="Consent Management",
                    source="TrackerMapper",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Detected",
                    tags=["consent", "privacy"],
                ))

        total_trackers = len(found_trackers)
        total_ids = sum(1 for f in findings if f.type == "Tracking ID")
        total_sharing = len(sharing_domains_found)

        if total_trackers > 0 or total_ids > 0:
            findings.append(IntelligenceFinding(
                entity=f"{domain}: {total_trackers} trackers, {total_ids} tracking IDs, {total_sharing} data-sharing partners",
                type="Tracker Summary",
                source="TrackerMapper",
                confidence="High",
                color="purple",
                threat_level="Elevated Risk" if total_trackers > 10 else "Informational",
                status="Complete",
                resolution=f"Categories: {', '.join(f'{k}={len(v)}' for k, v in found_trackers.items())}",
                raw_data=f"Total trackers: {total_trackers}, IDs: {total_ids}, Sharing: {total_sharing}",
                tags=["summary"],
            ))

    except Exception:
        pass
    return findings
