import httpx
import re
import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict, Counter
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
    (r'cookieyes\.com', "CookieYes", "consent"),
    (r'cookiebot\.com', "Cookiebot", "consent"),
    (r'consent\.cookiebot\.com', "Cookiebot CDN", "consent"),
    (r'osano\.com', "Osano", "consent"),
    (r'fides\.js|fides\.privacy', "Fides (Ethyca)", "consent"),
    (r'didomi\.io', "Didomi", "consent"),
    (r'sdk\.didomi\.io', "Didomi SDK", "consent"),
    (r'sourcepoint\.(com|org)', "Sourcepoint", "consent"),
    (r'usercentrics\.eu', "Usercentrics", "consent"),
    (r'consentmanager\.net', "Consentmanager", "consent"),
    (r'cookielaw\.org', "CookieLaw", "consent"),
    (r'decibel\.com|decibelinsight', "Decibel", "analytics"),
    (r'contentsquare\.(com|net)', "ContentSquare", "analytics"),
    (r'walkme\.com', "WalkMe", "analytics"),
    (r'appcues\.com', "Appcues", "analytics"),
    (r'userpilot\.com', "Userpilot", "analytics"),
    (r'cloudflare\.com', "Cloudflare", "cdn"),
    (r'cdn\.cloudflare\.com', "Cloudflare CDN", "cdn"),
    (r'ajax\.cloudflare\.com', "Cloudflare AJAX", "cdn"),
    (r'fastly\.net', "Fastly", "cdn"),
    (r'fastly\.com', "Fastly CDN", "cdn"),
    (r'akamai\.(com|net)', "Akamai", "cdn"),
    (r'akamaiedge\.net', "Akamai Edge", "cdn"),
    (r'akamaihd\.net', "Akamai HD", "cdn"),
    (r'keycdn\.com', "KeyCDN", "cdn"),
    (r'kc\.keycdn\.com', "KeyCDN (kc)", "cdn"),
    (r'unpkg\.com', "unpkg", "cdn"),
    (r'cdn\.jsdelivr\.net', "jsDelivr", "cdn"),
    (r'cdnjs\.cloudflare\.com', "cdnjs", "cdn"),
    (r'skypack\.dev', "Skypack", "cdn"),
    (r'kameleoon\.com', "Kameleoon", "analytics"),
    (r'kameleoon\.io', "Kameleoon (io)", "analytics"),
    (r'abtasty\.com', "AB Tasty", "analytics"),
    (r'cdn\.abtasty\.com', "AB Tasty CDN", "analytics"),
    (r'dynamicyield\.com', "Dynamic Yield", "analytics"),
    (r'cdn\.dynamicyield\.com', "Dynamic Yield CDN", "analytics"),
    (r'evergage\.com', "Evergage (Salesforce)", "analytics"),
    (r'monetate\.(com|net)', "Monetate", "analytics"),
    (r'certona\.com', "Certona", "analytics"),
    (r'salesforce\.com/.*/interaction', "Salesforce Interaction Studio", "crm"),
    (r'optimove\.net', "Optimove", "marketing"),
    (r'optimove\.com', "Optimove (com)", "marketing"),
    (r'richrelevance\.com', "RichRelevance", "marketing"),
    (r'strands\.com', "Strands", "marketing"),
    (r'cognitivescale\.com', "CognitiveScale", "marketing"),
    (r'olark\.com', "Olark", "crm"),
    (r'static\.olark\.com', "Olark Static", "crm"),
    (r'tawk\.to', "Tawk.to", "crm"),
    (r'embed\.tawk\.to', "Tawk.to Embed", "crm"),
    (r'chatra\.(com|io)', "Chatra", "crm"),
    (r'smartsuppchat\.com', "Smartsupp", "crm"),
    (r'smartsupp\.com', "Smartsupp CDN", "crm"),
    (r'tidio\.co', "Tidio", "crm"),
    (r'code\.tidio\.co', "Tidio Code", "crm"),
    (r'gorgias\.chat', "Gorgias", "crm"),
    (r'helpscout\.net', "Help Scout", "crm"),
    (r'cdn\.helpscout\.net', "Help Scout CDN", "crm"),
    (r'reamaze\.com', "Re:Amaze", "crm"),
    (r'rudderstack\.com', "RudderStack", "analytics"),
    (r'freshpaint\.io', "Freshpaint", "analytics"),
    (r'plausible\.io', "Plausible Analytics", "analytics"),
    (r'plausible\.com', "Plausible (com)", "analytics"),
    (r'cdn\.plausible\.io', "Plausible CDN", "analytics"),
    (r'usefathom\.com', "Fathom Analytics", "analytics"),
    (r'cdn\.usefathom\.com', "Fathom CDN", "analytics"),
    (r'umami\.(is|dev)', "Umami Analytics", "analytics"),
    (r'matomo\.org', "Matomo", "analytics"),
    (r'matomo\.cloud', "Matomo Cloud", "analytics"),
    (r'cdn\.matomo\.cloud', "Matomo CDN", "analytics"),
    (r'pirsch\.io', "Pirsch Analytics", "analytics"),
    (r'pirsch\.com', "Pirsch (com)", "analytics"),
    (r'countly\.(com|org)', "Countly", "analytics"),
    (r'keen\.io', "Keen IO", "analytics"),
    (r'auth0\.com', "Auth0", "identity"),
    (r'cdn\.auth0\.com', "Auth0 CDN", "identity"),
    (r'okta\.com', "Okta", "identity"),
    (r'oktacdn\.com', "Okta CDN", "identity"),
    (r'okta\.(net|org)', "Okta (alt)", "identity"),
    (r'login\.okta\.com', "Okta Login", "identity"),
    (r'onelogin\.com', "OneLogin", "identity"),
    (r'pingidentity\.com', "Ping Identity", "identity"),
    (r'keycloak\.*\.(org|com)', "Keycloak", "identity"),
    (r'addthis\.com', "AddThis", "social"),
    (r's7\.addthis\.com', "AddThis CDN", "social"),
    (r'sharethis\.com', "ShareThis", "social"),
    (r'platform-api\.sharethis\.com', "ShareThis API", "social"),
    (r'addtoany\.com', "AddToAny", "social"),
    (r'shareaholic\.com', "Shareaholic", "social"),
    (r'juicer\.io', "Juicer", "social"),
    (r'recaptcha/api\.js', "reCAPTCHA", "security"),
    (r'www\.google\.com/recaptcha', "Google reCAPTCHA", "security"),
    (r'hcaptcha\.com/1/api\.js', "hCaptcha", "security"),
    (r'js\.hcaptcha\.com', "hCaptcha JS", "security"),
    (r'turnstile-challenge\.cloudflare\.com', "Cloudflare Turnstile", "security"),
    (r'challenges\.cloudflare\.com', "Cloudflare Challenge", "security"),
    (r'fingerprintjs\.com', "FingerprintJS", "security"),
    (r'cdn\.fingerprintjs\.com', "FingerprintJS CDN", "security"),
    (r'threatmetrix\.com', "ThreatMetrix", "security"),
    (r'online-metrix\.net', "ThreatMetrix (net)", "security"),
    (r'arkoselabs\.com', "Arkose Labs", "security"),
    (r'tnx\.arkoselabs\.com', "Arkose Labs TNX", "security"),
    (r'distilnetworks\.com', "Distil Networks", "security"),
    (r'shapesecurity\.com', "Shape Security", "security"),
    (r'js-agent\.newrelic\.com', "New Relic Agent", "analytics"),
    (r'browser\.sentry-cdn\.com', "Sentry Browser SDK", "analytics"),
    (r'cdn\.luckyorange\.com', "LuckyOrange CDN", "analytics"),
    (r'cdn\.smartlook\.com', "Smartlook CDN", "analytics"),
    (r'cdn\.mouseflow\.com', "Mouseflow CDN", "analytics"),
    (r'cdn\.fullstory\.com', "FullStory CDN", "analytics"),
    (r'cdn\.hotjar\.com', "Hotjar CDN", "analytics"),
    (r'cdn\.inspectlet\.com', "Inspectlet CDN", "analytics"),
    (r'cdn\.crazyegg\.com', "CrazyEgg CDN", "analytics"),
    (r'cdn\.kissmetrics\.com', "Kissmetrics CDN", "analytics"),
    (r'cdn\.decibelinsight\.com', "Decibel CDN", "analytics"),
    (r'cdn\.contentsquare\.com', "ContentSquare CDN", "analytics"),
    (r'cdn\.walkme\.com', "WalkMe CDN", "analytics"),
    (r'cdn\.appcues\.com', "Appcues CDN", "analytics"),
    (r'cdn\.userpilot\.com', "Userpilot CDN", "analytics"),
    (r'cdn\.vwo\.com', "VWO CDN", "analytics"),
    (r'cdn\.optimizely\.com', "Optimizely CDN", "analytics"),
    (r'cdn\.convert\.com', "Convert CDN", "analytics"),
    (r'cdn\.kameleoon\.com', "Kameleoon CDN", "analytics"),
    (r'cdn\.abtasty\.com', "AB Tasty CDN", "analytics"),
    (r'cdn\.monetate\.com', "Monetate CDN", "analytics"),
    (r'cdn\.certona\.com', "Certona CDN", "analytics"),
    (r'pendo\.io', "Pendo", "analytics"),
    (r'cdn\.pendo\.io', "Pendo CDN", "analytics"),
    (r'appcues\.com', "Appcues", "analytics"),
    (r'chameleon\.io', "Chameleon", "analytics"),
    (r'userlane\.com', "Userlane", "analytics"),
    (r'whatfix\.com', "Whatfix", "analytics"),
    (r'walkthrough\.com', "Walkthrough", "analytics"),
    (r'userflow\.com', "Userflow", "analytics"),
    (r'productboard\.com', "Productboard", "analytics"),
    (r'canny\.io', "Canny", "analytics"),
    (r'feedback\.fish', "Feedback Fish", "analytics"),
    (r'surveymonkey\.com', "SurveyMonkey", "analytics"),
    (r'typeform\.com', "Typeform", "analytics"),
    (r'jotform\.com', "JotForm", "analytics"),
    (r'formstack\.com', "Formstack", "analytics"),
    (r'wufoo\.com', "Wufoo", "analytics"),
    (r'google\.com/analytics', "Google Analytics (direct)", "analytics"),
    (r'region1\.google-analytics\.com', "Google Analytics Region 1", "analytics"),
    (r'region2\.google-analytics\.com', "Google Analytics Region 2", "analytics"),
    (r'www-googletagmanager\.com', "Google Tag Manager (www-)", "tag-manager"),
    (r'googletagservices\.com', "Google Tag Services", "tag-manager"),
    (r'partner\.googleadservices\.com', "Google Partner Ads", "advertising"),
    (r'cm\.g\.doubleclick\.net', "DoubleClick CM", "advertising"),
    (r'pubads\.g\.doubleclick\.net', "DoubleClick PubAds", "advertising"),
    (r'securepubads\.g\.doubleclick\.net', "DoubleClick Secure PubAds", "advertising"),
    (r'tpc\.googlesyndication\.com', "Google AdSense TPC", "advertising"),
    (r'pagead2\.googlesyndication\.com', "Google AdSense PageAd", "advertising"),
    (r'fundingchoices\.google\.com', "Google Funding Choices", "consent"),
    (r'consent\.google\.com', "Google Consent", "consent"),
    (r'quantcount\.com', "QuantCount", "advertising"),
    (r'quantserve\.com', "QuantServe", "advertising"),
    (r'pixel\.quantserve\.com', "Quantcast Pixel", "advertising"),
    (r'quantserve\.com', "QuantServe", "advertising"),
    (r'pixel\.rubiconproject\.com', "Rubicon Pixel", "advertising"),
    (r'pixel\.adsafeprotected\.com', "AdSafe Pixel", "advertising"),
    (r'ads\.pinterest\.com', "Pinterest Ads", "advertising"),
    (r'analytics\.twitter\.com', "Twitter Analytics", "analytics"),
    (r'analytics\.pinterest\.com', "Pinterest Analytics", "analytics"),
    (r'analytics\.youtube\.com', "YouTube Analytics", "analytics"),
    (r'analytics\.crazyegg\.com', "CrazyEgg Analytics", "analytics"),
    (r'analytics\.hotjar\.com', "Hotjar Analytics", "analytics"),
    (r'analytics\.luckyorange\.com', "LuckyOrange Analytics", "analytics"),
]


TRACKING_ID_PATTERNS = [
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
    (r'gtag\s*\(\s*["\']config["\']\s*,\s*["\']([A-Z0-9-]+)["\']', "Google Tag (gtag config)"),
    (r'clarity\s*\(\s*["\']?([a-f0-9]+)["\']?\s*\)', "Microsoft Clarity Project ID"),
    (r'_paq\.push\(\[\s*["\']setTrackerUrl["\']', "Matomo Tracker URL"),
    (r'plausible\s*\(\s*["\']([^"\']+)["\']', "Plausible Event"),
    (r'fathom\.(track|identify)', "Fathom Analytics Call"),
    (r'recaptcha\/api\.js.*[?&]render=([^"&\s]+)', "reCAPTCHA Site Key"),
    (r'turnstile\.render\([^,]+,\s*["\']([^"\']+)', "Cloudflare Turnstile Site Key"),
    (r'FingerprintJS\.load\s*\(\s*["\']([a-zA-Z0-9_-]+)', "FingerprintJS Browser Key"),
    (r'auth0\.com\/[^"\']+client_id=([^"\']+)', "Auth0 Client ID"),
    (r'okta\.com\/oauth2\/[^"\']+client_id=([^"\']+)', "Okta Client ID"),
    (r'pk_(test|live)_[a-zA-Z0-9]+', "Stripe Publishable Key"),
    (r'AIzaSy[0-9A-Za-z_-]{30,}', "Google Maps API Key"),
    (r'[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com', "AWS API Gateway Endpoint"),
    (r'hotjar\.identify\s*\(', "Hotjar Identify Call"),
    (r'routing\.vwo\.com', "VWO Routing"),
    (r'didomi\.config\s*\(', "Didomi Config"),
    (r'usercentrics\.init\s*\(', "Usercentrics Init"),
    (r'osano\.(init|capture)', "Osano Init"),
    (r'cookieyes\.init\s*\(', "CookieYes Init"),
    (r'_cl\.js|clarity-s\.ms', "Microsoft Clarity Script"),
    (r'pendo\.validate|pendo\.initialize', "Pendo Init"),
    (r'rudderanalytics\.load\s*\(', "RudderStack Load"),
    (r'freshpaint\.init\s*\(', "Freshpaint Init"),
    (r'countly\.init\s*\(', "Countly Init"),
    (r'keen\.io.*projectId["\':\s]+["\']([a-f0-9]{20,})["\']', "Keen IO Project ID"),
    (r'alpine.*token["\':\s]+["\']([a-f0-9]{20,})["\']', "Alpine Token"),
    (r'customer\.io.*site_id["\':\s]+["\']([a-f0-9-]{20,})["\']', "Customer.io Site ID"),
    (r'pirsch\.init\s*\(', "Pirsch Init"),
    (r'umami\.track\s*\(', "Umami Track Event"),
    (r'matomo\.tracker\.push\s*\(', "Matomo Tracker Push"),
    (r'_paq\.push\s*\(', "Matomo/piwik Push"),
    (r'plausible\.track\s*\(', "Plausible Track Event"),
    (r'fathom\.trackEvent\s*\(', "Fathom Track Event"),
    (r'luckyorange\.settings\s*\(', "LuckyOrange Settings"),
    (r'smartlook\.(init|record|start)\s*\(', "Smartlook Init"),
    (r'sessioncam\.init\s*\(', "SessionCam Init"),
    (r'crazyegg\.init\s*\(', "CrazyEgg Init"),
    (r'vwo\s*=\s*\{\s*accountId["\':\s]+["\']?(\d{4,10})["\']?', "VWO Account ID (object)"),
    (r'optimizely\.push\s*\(', "Optimizely Push"),
    (r'_learnq=\["\']([a-f0-9]+)["\']', "Klaviyo Site ID"),
    (r'klaviyo\.push\s*\(', "Klaviyo Push"),
    (r'gtag\s*\(["\']config["\'],\s*["\'](G-[A-Z0-9]+)["\']', "Google Analytics 4 Measurement ID"),
    (r'gtag\s*\(["\']config["\'],\s*["\'](AW-[0-9]+)["\']', "Google Ads Conversion ID"),
    (r'fbq\s*\(["\']init["\'],\s*["\'](\d+)["\']', "Facebook Pixel ID (fbq init)"),
    (r'ttq\s*=\s*["\']([a-f0-9]+)["\']', "TikTok Pixel ID (ttq)"),
    (r'_linkedin_partner_id\s*=\s*["\']?(\d+)["\']?', "LinkedIn Partner ID"),
    (r'rdStation|rdstation', "RD Station"),
    (r'_rdntrk\s*=\s*(\d+)', "RD Station Tracking ID"),
    (r'hotjar\.settings\s*=\s*\{[\s\S]*?hjid\s*:\s*(\d+)', "Hotjar hjid (settings)"),
    (r'ls\.api\-email\.com', "LiveIntent Identity"),
    (r'_lr_site_id\s*=\s*(\d+)', "LogRocket Site ID"),
    (r'lr\.init\s*\(', "LogRocket Init"),
    (r'cdn\.fullstory\.com/s/fs\.js', "FullStory Script Load"),
    (r'sentry\.init\s*\(', "Sentry Init"),
    (r'BugSnag\.start\s*\(', "Bugsnag Start"),
    (r'rollbar\.init\s*\(', "Rollbar Init"),
    (r'stripe.*publishableKey["\':\s]+["\'](pk_(?:test|live)_[a-zA-Z0-9]+)["\']', "Stripe Publishable Key (named)"),
    (r'square\.id\s*=\s*["\']?([a-zA-Z0-9_-]+)["\']?', "Square Application ID"),
    (r'braintree\.setup\s*\(["\']?([a-zA-Z0-9_-]+)["\']?', "Braintree Setup Token"),
    (r'chargebee\.init\s*\(["\']?([a-zA-Z0-9_-]+)["\']?', "Chargebee Site Name"),
    (r'recaptcha\.render\s*\(["\']?([a-zA-Z0-9_-]+)["\']?', "reCAPTCHA Site Key (render)"),
    (r'grecaptcha\.render\s*\(', "reCAPTCHA Render Call"),
    (r'hcaptcha\.render\s*\(', "hCaptcha Render Call"),
    (r'turnstile\.render\s*\(', "Cloudflare Turnstile Render"),
    (r'maps\.google\.com/maps\?.*key=([a-zA-Z0-9_-]+)', "Google Maps API Key (alt)"),
    (r'GOOGLE_MAPS_API_KEY\s*[:=]\s*["\']([^"\']+)["\']', "Google Maps API Key (env)"),
    (r'AIza[0-9A-Za-z_-]{30,}', "Google API Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Access Token"),
    (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Access Token"),
    (r'ghs_[a-zA-Z0-9]{36}', "GitHub SSH Key"),
    (r'sk_live_[a-zA-Z0-9]+', "Stripe Secret Key (LIVE)"),
    (r'sk_test_[a-zA-Z0-9]+', "Stripe Secret Key (TEST)"),
    (r'xox[abposr]-[a-zA-Z0-9-]{10,}', "Slack Token"),
    (r'SK[a-z0-9]{32}', "Twilio API Key"),
    (r'AC[a-z0-9]{32}', "Twilio Account SID"),
    (r'rk_live_[a-zA-Z0-9]+', "Stripe Restricted Key"),
    (r'sq0[a-z]{3}-[a-zA-Z0-9]{22}', "Square Access Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'da2-[a-z0-9]{26}', "AWS AppSync API Key"),
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
    "cloudflare.com": "Cloudflare CDN",
    "fastly.net": "Fastly CDN",
    "akamaiedge.net": "Akamai Edge CDN",
    "cloudfront.net": "AWS CloudFront CDN",
    "stackpathcdn.com": "StackPath CDN",
    "fonts.googleapis.com": "Google Fonts API",
    "fonts.gstatic.com": "Google Fonts Static",
    "use.typekit.net": "Adobe Typekit Fonts",
    "fast.fonts.net": "Monotype Fonts",
    "stripe.com": "Stripe Payments",
    "paypal.com": "PayPal Payments",
    "braintreepayments.com": "Braintree Payments",
    "square.com": "Square Payments",
    "checkoutsandbox.com": "Checkout.com Sandbox",
    "youtube.com": "YouTube Video",
    "vimeo.com": "Vimeo Video",
    "wistia.net": "Wistia Video",
    "brightcove.net": "Brightcove Video",
    "vidyard.com": "Vidyard Video",
    "maps.googleapis.com": "Google Maps",
    "maps.google.com": "Google Maps (alt)",
    "mapbox.com": "Mapbox",
    "openstreetmap.org": "OpenStreetMap",
    "platform.twitter.com": "Twitter Platform",
    "staticxx.facebook.com": "Facebook Static",
    "pbs.twimg.com": "Twitter Media",
    "greenhouse.io": "Greenhouse Jobs",
    "lever.co": "Lever Jobs",
    "workable.com": "Workable Jobs",
    "bambooohr.com": "BambooHR",
    "hcaptcha.com": "hCaptcha Security",
    "recaptcha.net": "reCAPTCHA Security",
    "turnstile-challenge.cloudflare.com": "Cloudflare Turnstile",
    "www.google.com/recaptcha": "Google reCAPTCHA",
    "js.hcaptcha.com": "hCaptcha JS",
    "doubleclick.net": "DoubleClick Ads",
    "googlesyndication.com": "Google AdSense",
    "googleadservices.com": "Google Ads",
    "googletagmanager.com": "Google Tag Manager",
    "google-analytics.com": "Google Analytics",
    "connect.facebook.net": "Facebook Connect",
    "platform.linkedin.com": "LinkedIn Platform",
    "bat.bing.com": "Bing UET",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify (custom)",
    "squarespace.com": "Squarespace",
    "wix.com": "Wix",
    "wordpress.org": "WordPress",
    "wordpress.com": "WordPress.com",
    "jsdelivr.net": "jsDelivr CDN",
    "cdnjs.cloudflare.com": "cdnjs CDN",
    "unpkg.com": "unpkg CDN",
    "auth0.com": "Auth0 Identity",
    "okta.com": "Okta Identity",
    "onelogin.com": "OneLogin Identity",
    "pingidentity.com": "Ping Identity",
    "keycloak.org": "Keycloak Identity",
    "sentry.io": "Sentry Error Tracking",
    "datadoghq.com": "Datadog Monitoring",
    "newrelic.com": "New Relic Monitoring",
    "logrocket.com": "LogRocket Session Replay",
    "fullstory.com": "FullStory Session Replay",
    "hotjar.com": "Hotjar Session Replay",
    "luckyorange.com": "LuckyOrange Session Replay",
    "mouseflow.com": "Mouseflow Session Replay",
    "smartlook.com": "Smartlook Session Replay",
    "contentsquare.com": "ContentSquare Analytics",
    "walkme.com": "WalkMe Guidance",
}

CATEGORY_WEIGHTS = {
    "analytics": 3,
    "tag-manager": 2,
    "advertising": 5,
    "social": 3,
    "marketing": 4,
    "crm": 2,
    "email": 2,
    "cdn": 1,
    "consent": 1,
    "identity": 3,
    "security": 2,
}

FINGERPRINT_PATTERNS = [
    (r'canvas\.toDataURL|\.toBlob\s*\(|getImageData\s*\(', "Canvas Fingerprinting", "canvas"),
    (r'getContext\s*\(\s*["\']webgl["\']', "WebGL Fingerprinting", "webgl"),
    (r'getExtension\s*\(\s*["\']WEBGL_debug_renderer_info["\']', "WebGL Renderer Info", "webgl"),
    (r'getParameter\s*\(\s*renderer\s*\)', "WebGL Parameter Enumerate", "webgl"),
    (r'OscillatorNode|createOscillator|createAnalyser|getFloatFrequencyData|audioContext|AudioContext', "Audio Fingerprinting", "audio"),
    (r'fonts\.(googleapis|gstatic)\.com/css\?family=|FontFace\s*\(|document\.fonts\.(ready|add|load)', "Font Detection", "font"),
    (r'navigator\.(platform|userAgent|language|languages|hardwareConcurrency|deviceMemory|maxTouchPoints)', "Browser Property Enumeration", "browser"),
    (r'NavigatorPlugins|navigator\.plugins|navigator\.mimeTypes', "Plugin Enumeration", "plugin"),
    (r'screen\.(width|height|availWidth|availHeight|colorDepth|pixelDepth)', "Screen Property Enumeration", "screen"),
    (r'MediaDevices|enumerateDevices|getUserMedia', "Media Device Enumeration", "media"),
    (r'performance\.(memory|timing|navigation|getEntriesByType)', "Performance API Enumeration", "performance"),
    (r'Date\.getTimezoneOffset|Intl\.DateTimeFormat|Intl\.NumberFormat', "Locale Fingerprinting", "locale"),
    (r'navigator\.connection|connection\.(downlink|rtt|effectiveType)', "Network Info API", "network"),
    (r'WebGLRenderingContext|WEBGL_debug_shaders|getSupportedExtensions', "WebGL Extensions Enumeration", "webgl"),
    (r'StorageManager|navigator\.storage\.estimate', "Storage API Enumeration", "storage"),
]

FINGERPRINT_WEIGHTS = {
    "canvas": 5,
    "webgl": 5,
    "audio": 5,
    "font": 3,
    "browser": 2,
    "plugin": 2,
    "screen": 2,
    "media": 2,
    "performance": 1,
    "locale": 1,
    "network": 2,
    "storage": 1,
}


def parse_csp_header(headers):
    csp_entries = {}
    csp_raw = headers.get("content-security-policy", "")
    if not csp_raw:
        return {}, []
    directives = {}
    for part in csp_raw.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].strip().lower()
        sources = [t.strip() for t in tokens[1:] if t.strip() and not t.strip().startswith("'")]
        if sources:
            directives[directive] = sources

    tracking_directives = {}
    tracking_domains = []
    tracking_keys = {"connect-src", "script-src", "img-src", "frame-src", "media-src", "font-src", "style-src"}
    for d, srcs in directives.items():
        if d in tracking_keys:
            tracking_directives[d] = srcs
            for src in srcs:
                parsed = urlparse(src)
                domain = parsed.netloc or parsed.path
                if domain:
                    tracking_domains.append(domain)
    return tracking_directives, tracking_domains


def detect_dom_storage(html):
    findings = []
    storage_patterns = [
        (r'localStorage\.(setItem|getItem|removeItem|clear|key)\s*\(', "localStorage Usage"),
        (r'sessionStorage\.(setItem|getItem|removeItem|clear|key)\s*\(', "sessionStorage Usage"),
        (r'__storage_test__|storageTest|testStorage', "Storage Availability Test"),
        (r'JSON\.parse\(.*localStorage|JSON\.stringify\(.*localStorage', "localStorage JSON Serialization"),
    ]
    for pat, name in storage_patterns:
        if re.search(pat, html, re.IGNORECASE):
            findings.append(name)
    return findings


def classify_cookies(html, headers):
    cookies = set()

    js_cookies = re.findall(r'document\.cookie\s*[=].*?["\']([^"\'=;]+)', html, re.IGNORECASE)
    for c in js_cookies:
        cookies.add(c.lower())

    set_cookie = headers.get("set-cookie", "")
    resp_cookies = re.findall(r'([^=;=]+)=', set_cookie)
    for c in resp_cookies:
        cookies.add(c.strip().lower())

    cookie_categories = defaultdict(list)
    essential_patterns = [r'(session|csrf|token|xcsrf|xsrf|__cfduid|_cfduid|laravel_session|PHPSESSID|JSESSIONID|ASPSESSIONID)']
    functional_patterns = [r'(lang|language|locale|region|currency|country|ship|zip|postal)']
    analytics_patterns = [r'(_ga|_gid|_gat|_utm[a-z]|__utm[a-z]|utm_)']
    advertising_patterns = [r'(_fbp|_fbc|fr\b|_gcl_|_gac_|IDE|test_cookie|NID)']
    social_patterns = [r'(_sp_id|_sp_ses|guest_id|personalization_id)']
    for c in cookies:
        categorized = False
        if re.search(essential_patterns[0], c, re.IGNORECASE):
            cookie_categories["essential"].append(c)
            categorized = True
        if re.search(functional_patterns[0], c, re.IGNORECASE):
            cookie_categories["functional"].append(c)
            categorized = True
        if re.search(analytics_patterns[0], c, re.IGNORECASE):
            cookie_categories["analytics"].append(c)
            categorized = True
        if re.search(advertising_patterns[0], c, re.IGNORECASE):
            cookie_categories["advertising"].append(c)
            categorized = True
        if re.search(social_patterns[0], c, re.IGNORECASE):
            cookie_categories["social_media"].append(c)
            categorized = True
        if not categorized:
            cookie_categories["uncategorized"].append(c)
    return dict(cookie_categories)


def compute_tracking_intensity(found_trackers, fingerprint_count, storage_count):
    score = 0
    category_counts = {}
    for cat, trackers in found_trackers.items():
        weight = CATEGORY_WEIGHTS.get(cat, 1)
        count = len(trackers)
        category_counts[cat] = count
        score += count * weight

    score += fingerprint_count * 5
    score += storage_count * 2

    if score <= 10:
        level = "Low"
    elif score <= 30:
        level = "Moderate"
    elif score <= 60:
        level = "High"
    else:
        level = "Very High"

    return score, level, category_counts


def estimate_privacy_compliance(consent_platforms, has_cmp, cookie_categories):
    score = 0
    max_score = 10
    details = []

    gdpr_platforms = {"Cookiebot", "OneTrust", "OneTrust Wrapper", "IAB TCF API", "IAB CMP API",
                      "Axeptio", "Consentmanager", "Usercentrics", "Didomi", "Sourcepoint", "Fides (Ethyca)", "Osano"}
    ccpa_platforms = {"Cookiebot", "OneTrust", "OneTrust Wrapper", "Sourcepoint", "CookieYes", "Termly (CMP)"}

    consent_names = set(consent_platforms)

    gdpr_found = consent_names & gdpr_platforms
    ccpa_found = consent_names & ccpa_platforms

    if gdpr_found:
        score += 3
        details.append(f"GDPR consent platforms: {', '.join(sorted(gdpr_found))}")
    if ccpa_found:
        score += 2
        details.append(f"CCPA consent platforms: {', '.join(sorted(ccpa_found))}")

    if has_cmp:
        score += 2
        details.append("General CMP detected")
    if "IAB TCF API" in consent_names or "IAB CMP API" in consent_names:
        score += 1
        details.append("IAB TCF/CMP framework active")

    cookie_cats = cookie_categories.keys()
    if "essential" in cookie_cats and len(cookie_categories.get("essential", [])) > 0:
        score += 1
        details.append("Essential cookies properly labeled")

    advertising_present = "advertising" in cookie_cats and len(cookie_categories.get("advertising", [])) > 0
    social_present = "social_media" in cookie_cats and len(cookie_categories.get("social_media", [])) > 0
    analytics_present = "analytics" in cookie_cats and len(cookie_categories.get("analytics", [])) > 0

    if advertising_present or social_present:
        if not gdpr_found and not ccpa_found:
            score -= 1
            details.append("Advertising/social cookies without consent framework (risk)")

    score = max(0, min(score, max_score))

    if score >= 8:
        compliance = "Strong"
    elif score >= 5:
        compliance = "Moderate"
    elif score >= 3:
        compliance = "Basic"
    else:
        compliance = "Weak / None Detected"

    return score, compliance, details


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

        tracker_network_edges = []

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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "analytics"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "tag-manager"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "advertising"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "social"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "marketing"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "crm"})
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
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "email"})
        for tracker_name in found_trackers.get("cdn", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="CDN / Performance",
                source="TrackerMapper",
                confidence="High",
                color="sky",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "cdn"],
            ))
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "cdn"})
        for tracker_name in found_trackers.get("consent", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Consent Management",
                source="TrackerMapper",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "consent"],
            ))
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "consent"})
        for tracker_name in found_trackers.get("identity", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Identity / SSO",
                source="TrackerMapper",
                confidence="High",
                color="violet",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "identity"],
            ))
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "identity"})
        for tracker_name in found_trackers.get("security", []):
            findings.append(IntelligenceFinding(
                entity=tracker_name,
                type="Security / Anti-Bot",
                source="TrackerMapper",
                confidence="High",
                color="red",
                threat_level="Informational",
                status="Detected",
                tags=["tracker", "security"],
            ))
            tracker_network_edges.append({"source": "page", "target": tracker_name, "relation": "security"})

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
                tracker_network_edges.append({"source": "page", "target": sname, "relation": "data-sharing"})

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
            (r'cookieyes', "CookieYes"),
            (r'osano', "Osano"),
            (r'fides', "Fides (Ethyca)"),
            (r'didomi', "Didomi"),
            (r'sourcepoint', "Sourcepoint"),
            (r'usercentrics', "Usercentrics"),
            (r'consentmanager', "Consentmanager"),
            (r'termly', "Termly"),
            (r'cookielaw', "CookieLaw"),
            (r'trustarc', "TrustArc"),
        ]
        for cpat, cname in consent_patterns:
            if re.search(cpat, html, re.IGNORECASE):
                consent_platforms.append(cname)
        if consent_platforms:
            seen = set()
            unique_consent = []
            for c in consent_platforms:
                if c not in seen:
                    seen.add(c)
                    unique_consent.append(c)
            for cname in unique_consent:
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

        csp_directives, csp_domains = parse_csp_header(resp.headers)
        if csp_domains:
            findings.append(IntelligenceFinding(
                entity=f"CSP: {len(csp_domains)} external domains allowed ({', '.join(sorted(set(csp_domains))[:8])})",
                type="CSP Header Analysis",
                source="TrackerMapper",
                confidence="High",
                color="sky",
                threat_level="Informational",
                status="Analyzed",
                resolution=f"Directives: {', '.join(csp_directives.keys())}",
                raw_data=json.dumps(csp_directives, indent=2)[:500],
                tags=["csp", "security-headers", "tracking"],
            ))
            for d in csp_domains[:10]:
                if not any(d in d2 for d2 in sharing_domains_found):
                    tracker_network_edges.append({"source": "csp", "target": d, "relation": "csp-allowed"})

        storage_usage = detect_dom_storage(html)
        if storage_usage:
            findings.append(IntelligenceFinding(
                entity=f"DOM Storage: {', '.join(storage_usage[:5])}",
                type="DOM Storage Detection",
                source="TrackerMapper",
                confidence="Medium",
                color="amber",
                threat_level="Informational",
                status="Detected",
                resolution=f"{len(storage_usage)} storage API calls detected",
                raw_data=", ".join(storage_usage),
                tags=["storage", "localstorage", "dom-storage"],
            ))

        cookie_categories = classify_cookies(html, resp.headers)
        if cookie_categories:
            cat_summary = {k: len(v) for k, v in cookie_categories.items() if v}
            findings.append(IntelligenceFinding(
                entity=f"Cookie Categories: {cat_summary}",
                type="Cookie Classification",
                source="TrackerMapper",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Classified",
                resolution=f"{sum(cat_summary.values())} total cookies across {len(cat_summary)} categories",
                raw_data=json.dumps(cookie_categories, indent=2)[:500],
                tags=["cookies", "classification", "privacy"],
            ))

        fingerprint_findings = []
        for fpat, fname, ftype in FINGERPRINT_PATTERNS:
            matches = re.findall(fpat, html, re.IGNORECASE)
            if matches:
                fingerprint_findings.append((fname, ftype))
        if fingerprint_findings:
            fp_by_type = defaultdict(list)
            for fname, ftype in fingerprint_findings:
                fp_by_type[ftype].append(fname)
            fp_summary = {t: len(v) for t, v in fp_by_type.items()}
            total_weight = sum(FINGERPRINT_WEIGHTS.get(t, 1) * len(v) for t, v in fp_by_type.items())
            fp_risk = "Low"
            if total_weight >= 20:
                fp_risk = "Very High"
            elif total_weight >= 12:
                fp_risk = "High"
            elif total_weight >= 5:
                fp_risk = "Moderate"

            findings.append(IntelligenceFinding(
                entity=f"Fingerprinting: {len(fingerprint_findings)} techniques across {len(fp_by_type)} categories",
                type="Browser Fingerprinting",
                source="TrackerMapper",
                confidence="High",
                color="red",
                threat_level=fp_risk if fp_risk in ("High", "Very High") else "Informational",
                status="Detected",
                resolution=f"Weight: {total_weight}, Risk: {fp_risk}",
                raw_data=json.dumps(fp_by_type, indent=2)[:500],
                tags=["fingerprinting", "privacy", "tracking"],
            ))
            for fname in list(dict.fromkeys([f[0] for f in fingerprint_findings]))[:5]:
                tracker_network_edges.append({"source": "page", "target": fname, "relation": "fingerprinting"})

        intensity_score, intensity_level, cat_counts = compute_tracking_intensity(
            found_trackers, len(fingerprint_findings), len(storage_usage)
        )

        findings.append(IntelligenceFinding(
            entity=f"Tracking Intensity: {intensity_score} ({intensity_level})",
            type="Tracker Intensity Score",
            source="TrackerMapper",
            confidence="High",
            color="red" if intensity_level in ("High", "Very High") else "amber" if intensity_level == "Moderate" else "slate",
            threat_level="Elevated Risk" if intensity_level in ("High", "Very High") else "Informational" if intensity_level == "Moderate" else "Informational",
            status="Computed",
            resolution=f"Score: {intensity_score}/100, Level: {intensity_level}",
            raw_data=json.dumps({"score": intensity_score, "level": intensity_level, "category_counts": cat_counts}, indent=2)[:500],
            tags=["tracking-intensity", "privacy", "summary"],
        ))

        has_cmp = bool(consent_platforms)
        compliance_score, compliance_level, compliance_details = estimate_privacy_compliance(
            consent_platforms, has_cmp, cookie_categories
        )

        findings.append(IntelligenceFinding(
            entity=f"Privacy Compliance: {compliance_level} ({compliance_score}/10)",
            type="Privacy Compliance Analysis",
            source="TrackerMapper",
            confidence="Medium",
            color="green" if compliance_level == "Strong" else "amber" if compliance_level == "Moderate" else "red",
            threat_level="Informational" if compliance_level == "Strong" else "Elevated Risk" if compliance_level == "Weak / None Detected" else "Informational",
            status="Analyzed",
            resolution=compliance_details[0] if compliance_details else "No compliance framework detected",
            raw_data=json.dumps({"score": compliance_score, "level": compliance_level, "details": compliance_details}, indent=2)[:500],
            tags=["compliance", "gdpr", "ccpa", "privacy"],
        ))
        if compliance_details:
            for detail in compliance_details:
                tracker_network_edges.append({"source": "privacy", "target": detail[:80], "relation": "compliance"})

        unique_edges = []
        seen_edges = set()
        for edge in tracker_network_edges:
            key = (edge["source"], edge["target"], edge["relation"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(edge)

        network_data = json.dumps({
            "nodes": list(set(
                [edge["source"] for edge in unique_edges] +
                [edge["target"] for edge in unique_edges]
            )),
            "edges": unique_edges,
            "total_trackers": sum(len(v) for v in found_trackers.values()),
            "category_breakdown": {k: len(v) for k, v in found_trackers.items()},
        }, indent=2)

        total_trackers = sum(len(v) for v in found_trackers.values())
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
                resolution=f"Tracking Intensity: {intensity_level}, Privacy Compliance: {compliance_level}",
                raw_data=network_data[:1000],
                tags=["summary", "network-graph"],
            ))

    except Exception:
        pass

    async def analyze_tracker_categories():
        all_trackers = {}
        for f in findings:
            if f.type in ("Analytics / Tracking", "Advertising / Ad Tech", "Social Media Tracking",
                          "Marketing Automation", "CRM / Customer Platform", "Email Marketing",
                          "CDN / Performance", "Consent Management", "Identity / SSO", "Security / Anti-Bot"):
                all_trackers[f.type] = all_trackers.get(f.type, 0) + 1
        if all_trackers:
            for ftype, count in sorted(all_trackers.items(), key=lambda x: -x[1])[:6]:
                findings.append(IntelligenceFinding(
                    entity=f"{ftype}: {count} tracker(s)",
                    type="Tracker Category Summary",
                    source="TrackerMapper", confidence="Medium",
                    color="slate", tags=["category-summary"]))

    async def analyze_tracking_ids():
        id_count = sum(1 for f in findings if f.type == "Tracking ID")
        findings.append(IntelligenceFinding(
            entity=f"Tracking IDs found: {id_count}",
            type="Tracking ID Summary",
            source="TrackerMapper", confidence="Medium",
            color="orange", tags=["ids"]))

    async def analyze_data_sharing():
        sharing_count = sum(1 for f in findings if f.type == "Data Sharing / Third-Party")
        if sharing_count:
            findings.append(IntelligenceFinding(
                entity=f"Third-party data sharing partners: {sharing_count}",
                type="Data Sharing Summary",
                source="TrackerMapper", confidence="Medium",
                color="yellow", tags=["data-sharing"]))

    async def analyze_privacy_impact():
        fp_count = sum(1 for f in findings if f.type == "Browser Fingerprinting")
        storage_count = sum(1 for f in findings if f.type == "DOM Storage Detection")
        if fp_count or storage_count:
            findings.append(IntelligenceFinding(
                entity=f"Privacy impact: {fp_count} fingerprinting techniques, {storage_count} storage methods, {len(cookie_categories) if 'cookie_categories' in dir() else 0} cookie categories",
                type="Privacy Impact Analysis",
                source="TrackerMapper", confidence="Medium",
                color="red" if fp_count > 0 else "orange",
                threat_level="Elevated Risk" if fp_count > 0 else "Informational",
                tags=["privacy"]))

    async def generate_privacy_recommendations():
        rec_map = {}
        for f in findings:
            if f.type in ("Analytics / Tracking", "Advertising / Ad Tech"):
                rec_map["trackers"] = rec_map.get("trackers", 0) + 1
            if f.type == "Browser Fingerprinting":
                rec_map["fingerprinting"] = True
            if f.type == "Data Sharing / Third-Party":
                rec_map["sharing"] = True
        recs = []
        if rec_map.get("trackers", 0) > 10:
            recs.append("High tracker count - consider using ad-blockers/anti-tracking extensions")
        if rec_map.get("fingerprinting"):
            recs.append("Browser fingerprinting detected - use anti-fingerprinting browser")
        if rec_map.get("sharing"):
            recs.append("Data shared with third parties - review privacy policy")
        if not recs:
            recs.append("Moderate tracking profile - review cookie settings")
        for i, r in enumerate(recs[:3]):
            findings.append(IntelligenceFinding(entity=f"Rec {i+1}: {r}", type="Privacy Recommendation", source="TrackerMapper", confidence="Medium", color="orange", tags=["recommendation"]))

    async def analyze_cookie_landscape():
        cookie_count = sum(1 for f in findings if f.type == "Cookie Consent / Banner")
        findings.append(IntelligenceFinding(entity=f"Cookie consent mechanisms: {cookie_count}", type="Cookie Analysis", source="TrackerMapper", confidence="Medium", color="slate", tags=["cookies"]))

    async def analyze_dom_storage():
        storage_count = sum(1 for f in findings if f.type == "DOM Storage Detection")
        if storage_count:
            findings.append(IntelligenceFinding(entity=f"DOM storage entries: {storage_count}", type="Storage Analysis", source="TrackerMapper", confidence="Medium", color="orange", tags=["storage"]))

    async def analyze_total_exposure():
        tracker_count = sum(1 for f in findings if f.type in ("Analytics / Tracking", "Advertising / Ad Tech", "Social Media Tracking", "Marketing Automation", "CRM / Customer Platform", "Email Marketing"))
        findings.append(IntelligenceFinding(entity=f"Total marketing/tracking services: {tracker_count}", type="Exposure Summary", source="TrackerMapper", confidence="Medium", color="purple", tags=["exposure"]))
        fingerprint_count = sum(1 for f in findings if f.type == "Browser Fingerprinting")
        findings.append(IntelligenceFinding(entity=f"Fingerprinting scripts: {fingerprint_count}", type="Fingerprinting Summary", source="TrackerMapper", confidence="Medium", color="red" if fingerprint_count else "emerald", tags=["exposure"]))

    async def analyze_consent_mechanisms():
        consent_count = sum(1 for f in findings if f.type == "Consent Management")
        findings.append(IntelligenceFinding(entity=f"Consent management platforms: {consent_count}", type="Consent Analysis", source="TrackerMapper", confidence="Medium", color="slate", tags=["consent"]))

    async def analyze_third_party_scope():
        third_party_count = sum(1 for f in findings if f.type == "Data Sharing / Third-Party")
        findings.append(IntelligenceFinding(entity=f"Third-party data recipients: {third_party_count}", type="Third-Party Scope", source="TrackerMapper", confidence="Medium", color="orange" if third_party_count else "emerald", tags=["third-party"]))
        findings.append(IntelligenceFinding(entity="Review data processing agreements with each third party", type="Compliance Recommendation", source="TrackerMapper", confidence="Medium", color="orange", tags=["recommendation"]))

    async def analyze_security_headers():
        security_findings = [f for f in findings if f.type == "Security / Anti-Bot"]
        findings.append(IntelligenceFinding(entity=f"Security/anti-bot services: {len(security_findings)}", type="Security Analysis", source="TrackerMapper", confidence="Medium", color="slate", tags=["security"]))

    async def analyze_tracker_velocity():
        tracker_names = set()
        for f in findings:
            if f.type in ("Analytics / Tracking", "Advertising / Ad Tech"):
                for t in f.tags:
                    tracker_names.add(t)
        findings.append(IntelligenceFinding(entity=f"Unique tracker technologies: {len(tracker_names)}", type="Tracker Velocity", source="TrackerMapper", confidence="Medium", color="slate", tags=["velocity"]))

    async def analyze_privacy_tier():
        all_findings_count = len(findings)
        findings.append(IntelligenceFinding(entity=f"Total tracking entries: {all_findings_count}", type="Privacy Tier", source="TrackerMapper", confidence="Medium", color="purple", tags=["privacy-tier"]))
        findings.append(IntelligenceFinding(entity="Review consent management platform for GDPR compliance", type="GDPR Recommendation", source="TrackerMapper", confidence="Medium", color="orange", tags=["privacy-tier"]))
        findings.append(IntelligenceFinding(entity="Use browser extensions to limit third-party tracking", type="Browser Recommendation", source="TrackerMapper", confidence="Medium", color="orange", tags=["privacy-tier"]))
        findings.append(IntelligenceFinding(entity="Audit third-party scripts regularly for privacy compliance", type="Audit Recommendation", source="TrackerMapper", confidence="Medium", color="orange", tags=["privacy-tier"]))

    await asyncio.gather(
        analyze_tracker_categories(),
        analyze_tracking_ids(),
        analyze_data_sharing(),
        analyze_privacy_impact(),
        generate_privacy_recommendations(),
        analyze_cookie_landscape(),
        analyze_dom_storage(),
        analyze_total_exposure(),
        analyze_consent_mechanisms(),
        analyze_third_party_scope(),
        analyze_security_headers(),
        analyze_tracker_velocity(),
        analyze_privacy_tier(),
    )

    return findings
