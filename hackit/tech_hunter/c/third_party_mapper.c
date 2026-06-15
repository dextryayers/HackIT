#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define OUT_SIZE 8192

typedef struct {
    const char* pattern;
    const char* category;
    const char* description;
    int severity;
} tp_entry;

static const tp_entry tp_db[] = {
    // Analytics
    {"google-analytics.com",        "Analytics", "Google Analytics", 0},
    {"googletagmanager.com",        "Analytics", "Google Tag Manager", 0},
    {"gtag",                        "Analytics", "Google Global Site Tag (gtag.js)", 0},
    {"ga('create'",                 "Analytics", "Google Analytics Universal", 0},
    {"gtag('config'",               "Analytics", "Google Analytics 4 (gtag)", 0},
    {"facebook.com/tr",             "Analytics", "Facebook Pixel", 0},
    {"fbq(",                        "Analytics", "Facebook Pixel (fbq)", 0},
    {"hotjar.com",                  "Analytics", "Hotjar (session recording)", 0},
    {"linkedin.com/analytics",      "Analytics", "LinkedIn Insight Tag", 0},
    {"adform.net",                  "Analytics", "Adform", 0},
    {"mixpanel.com",                "Analytics", "Mixpanel", 0},
    {"amplitude.com",               "Analytics", "Amplitude", 0},
    {"segment.io",                  "Analytics", "Segment", 0},
    {"segment.com",                 "Analytics", "Segment", 0},
    {"fullstory.com",               "Analytics", "FullStory (session replay)", 0},
    {"crazyegg.com",               "Analytics", "CrazyEgg (heatmap)", 0},
    {"mouseflow.com",              "Analytics", "Mouseflow", 0},
    {"heap.com",                   "Analytics", "Heap Analytics", 0},
    {"clicky.com",                 "Analytics", "Clicky", 0},
    {"matomo",                     "Analytics", "Matomo (self-hosted analytics)", 0},
    {"piwik",                      "Analytics", "Piwik/Matomo", 0},
    {"snowplow",                   "Analytics", "Snowplow Analytics", 0},
    {"hubspot.com/analytics",      "Analytics", "HubSpot Analytics", 0},

    // Advertising / Ad Networks
    {"doubleclick.net",            "Advertising", "Google DoubleClick (DART)", 1},
    {"googlesyndication.com",      "Advertising", "Google AdSense/Syndication", 1},
    {"adzerk.net",                 "Advertising", "Adzerk", 1},
    {"criteo.com",                 "Advertising", "Criteo (retargeting)", 1},
    {"criteo.net",                 "Advertising", "Criteo (retargeting)", 1},
    {"taboola.com",                "Advertising", "Taboola (native ads)", 1},
    {"outbrain.com",               "Advertising", "Outbrain (native ads)", 1},
    {"amazon-adsystem.com",        "Advertising", "Amazon Advertising", 1},
    {"adnxs.com",                  "Advertising", "AppNexus/Xandr", 1},
    {"rubiconproject.com",         "Advertising", "Rubicon Project", 1},
    {"pubmatic.com",               "Advertising", "PubMatic", 1},
    {"openx.net",                  "Advertising", "OpenX", 1},
    {"indexww.com",                "Advertising", "Index Exchange", 1},

    // Email Services
    {"google.com/a/",              "Email", "Google Workspace (G Suite)", 0},
    {"outlook.office.com",         "Email", "Microsoft 365 / Outlook", 0},
    {"office365.com",              "Email", "Microsoft 365", 0},
    {"amazonaws.com/ses",          "Email", "Amazon SES", 0},
    {"sendgrid.com",               "Email", "SendGrid", 0},
    {"sendgrid.net",               "Email", "SendGrid", 0},
    {"mailgun.com",                "Email", "Mailgun", 0},
    {"mailgun.org",                "Email", "Mailgun", 0},
    {"mailchimp.com",              "Email", "Mailchimp", 0},
    {"constantcontact.com",        "Email", "Constant Contact", 0},
    {"hubspot.com/email",          "Email", "HubSpot Email", 0},
    {"postmarkapp.com",            "Email", "Postmark", 0},
    {"sendinblue.com",             "Email", "Sendinblue", 0},
    {"customer.io",                "Email", "Customer.io", 0},
    {"intercom.io",                "Email", "Intercom", 0},
    {"intercom.com",               "Email", "Intercom", 0},

    // Payment Processors
    {"js.stripe.com",              "Payment", "Stripe", 2},
    {"stripe.com/billing",         "Payment", "Stripe Billing", 2},
    {"paypal.com/sdk",             "Payment", "PayPal SDK", 2},
    {"paypal",                     "Payment", "PayPal", 2},
    {"checkout.braintreegateway.com","Payment", "Braintree (PayPal)", 2},
    {"square.com",                 "Payment", "Square", 2},
    {"squarecdn.com",              "Payment", "Square CDN", 2},
    {"adyen.com",                  "Payment", "Adyen", 2},
    {"adyen.net",                  "Payment", "Adyen", 2},
    {"authorize.net",              "Payment", "Authorize.net", 2},
    {"worldpay.com",               "Payment", "Worldpay", 2},
    {"shopify.com/checkouts",      "Payment", "Shopify Checkout", 2},
    {"recurly.com",                "Payment", "Recurly", 2},
    {"chargebee.com",              "Payment", "Chargebee", 2},
    {"paddle.com",                 "Payment", "Paddle", 2},
    {"mollie.com",                 "Payment", "Mollie", 2},

    // Map Services
    {"maps.googleapis.com",        "Maps", "Google Maps API", 0},
    {"maps.google.com",            "Maps", "Google Maps", 0},
    {"api.mapbox.com",             "Maps", "Mapbox", 0},
    {"mapbox.com",                 "Maps", "Mapbox", 0},
    {"openstreetmap.org",          "Maps", "OpenStreetMap", 0},
    {"tile.openstreetmap",         "Maps", "OpenStreetMap Tiles", 0},
    {"leafletjs.com",              "Maps", "Leaflet.js (OSM)", 0},
    {"unpkg.com/leaflet",          "Maps", "Leaflet.js via CDN", 0},
    {"cdnjs.cloudflare.com/ajax/libs/leaflet","Maps", "Leaflet.js via Cloudflare", 0},
    {"maps.googleapis.com/maps/api/js","Maps", "Google Maps JavaScript API", 0},
    {"here.com",                   "Maps", "HERE Maps", 0},
    {"tomtom.com",                 "Maps", "TomTom Maps", 0},

    // Social Media
    {"platform.twitter.com",       "Social", "Twitter/X Widgets", 0},
    {"twitter.com/share",          "Social", "Twitter/X Share Button", 0},
    {"facebook.com/plugins",       "Social", "Facebook Plugins", 0},
    {"facebook.net",               "Social", "Facebook SDK", 0},
    {"connect.facebook.net",       "Social", "Facebook JavaScript SDK", 0},
    {"instagram.com/embed",        "Social", "Instagram Embed", 0},
    {"linkedin.com/embed",         "Social", "LinkedIn Embed", 0},
    {"linkedin.com/oauth",         "Social", "LinkedIn OAuth", 0},
    {"pinterest.com/pin",          "Social", "Pinterest Pin Widget", 0},
    {"reddit.com/embed",           "Social", "Reddit Embed", 0},
    {"tiktok.com/embed",           "Social", "TikTok Embed", 0},
    {"youtube.com/embed",          "Social", "YouTube Embed", 0},
    {"youtube-nocookie.com",       "Social", "YouTube Privacy-Enhanced", 0},

    // Comment Systems
    {"disqus.com/embed.js",        "Comments", "Disqus", 0},
    {"disqus.com",                 "Comments", "Disqus", 0},
    {"disquscdn.com",              "Comments", "Disqus CDN", 0},
    {"facebook.com/plugins/comments","Comments", "Facebook Comments", 0},
    {"commento.io",                "Comments", "Commento", 0},
    {" utterances",                "Comments", "Utterances (GitHub issues)", 0},
    {"giscus.app",                 "Comments", "Giscus (GitHub discussions)", 0},
    {"isso.comments",              "Comments", "Isso (self-hosted)", 0},

    // Support / Chat
    {"zendesk.com",                "Support", "Zendesk", 0},
    {"freshdesk.com",              "Support", "Freshdesk", 0},
    {"freshworks.com",             "Support", "Freshworks", 0},
    {"intercom.com/messenger",     "Support", "Intercom Messenger", 0},
    {"drift.com",                  "Support", "Drift", 0},
    {"drift.ai",                   "Support", "Drift AI", 0},
    {"olark.com",                  "Support", "Olark", 0},
    {"livechat.com",               "Support", "LiveChat", 0},
    {"tawk.to",                    "Support", "Tawk.to", 0},
    {"crisp.chat",                 "Support", "Crisp Chat", 0},
    {"helpcrunch.com",             "Support", "HelpCrunch", 0},
    {"user.com",                   "Support", "User.com", 0},
    {"chatwoot.com",               "Support", "Chatwoot", 0},
    {"helpscout.net",              "Support", "Help Scout", 0},

    // CDN / Cloud
    {"cloudfront.net",             "CDN", "AWS CloudFront", 0},
    {"akamaihd.net",               "CDN", "Akamai", 0},
    {"akamaized.net",              "CDN", "Akamai", 0},
    {"fastly.net",                 "CDN", "Fastly", 0},
    {"fastly.com",                 "CDN", "Fastly", 0},
    {"cloudflare.com",             "CDN", "Cloudflare", 0},
    {"cloudflare.net",             "CDN", "Cloudflare", 0},
    {"cloudflarecdn.com",          "CDN", "Cloudflare CDNJS", 0},
    {"cdnjs.cloudflare.com",       "CDN", "Cloudflare CDNJS", 0},
    {"stackpathdns.com",           "CDN", "StackPath", 0},
    {"stackpathcdn.com",           "CDN", "StackPath", 0},
    {"keycdn.com",                 "CDN", "KeyCDN", 0},
    {"bunnycdn.com",               "CDN", "BunnyCDN", 0},
    {"bunny.net",                  "CDN", "BunnyCDN", 0},
    {"jsdelivr.net",               "CDN", "jsDelivr", 0},
    {"unpkg.com",                  "CDN", "unpkg (npm CDN)", 0},

    // A/B Testing / Personalization
    {"optimizely.com",             "A/B Testing", "Optimizely", 0},
    {"vwo.com",                    "A/B Testing", "VWO (Visual Website Optimizer)", 0},
    {"googleoptimize.com",         "A/B Testing", "Google Optimize", 0},
    {"launchdarkly.com",           "A/B Testing", "LaunchDarkly (feature flags)", 0},
    {"split.io",                   "A/B Testing", "Split.io", 0},
    {"abtasty.com",                "A/B Testing", "AB Tasty", 0},
    {"kameleoon.com",              "A/B Testing", "Kameleoon", 0},

    // Fonts / UI
    {"fonts.googleapis.com",       "Fonts", "Google Fonts", 0},
    {"fonts.gstatic.com",          "Fonts", "Google Fonts (static)", 0},
    {"use.typekit.net",            "Fonts", "Adobe Typekit", 0},
    {"use.fontawesome.com",        "Fonts", "Font Awesome", 0},
    {"fontawesome.com",            "Fonts", "Font Awesome", 0},
    {"cdn.jsdelivr.net/npm/@fortawesome","Fonts", "Font Awesome via jsDelivr", 0},
    {"bootstrapcdn.com",           "Fonts", "Bootstrap CDN", 0},

    // ReCAPTCHA / Security
    {"google.com/recaptcha",       "Security", "Google reCAPTCHA", 0},
    {"recaptcha.net",              "Security", "Google reCAPTCHA", 0},
    {"hcaptcha.com",               "Security", "hCaptcha", 0},
    {"funcaptcha.com",             "Security", "Arkose Labs FunCaptcha", 0},
    {"cloudflare.com/email-protection","Security", "Cloudflare Email Protection", 0},

    // Video
    {"player.vimeo.com",           "Video", "Vimeo Player", 0},
    {"vimeocdn.com",               "Video", "Vimeo CDN", 0},
    {"wistia.com",                 "Video", "Wistia", 0},
    {"fast.wistia.net",            "Video", "Wistia CDN", 0},
    {"cdn.video",                  "Video", "Video hosting", 0},
    {"brightcove.net",             "Video", "Brightcove", 0},
    {"jwplayer.com",               "Video", "JW Player", 0},
    {"cdn.jwplayer.com",           "Video", "JW Player CDN", 0},

    // CRM
    {"hubspot.com",                "CRM", "HubSpot (CRM/Marketing)", 0},
    {"salesforce.com",             "CRM", "Salesforce", 0},
    {"force.com",                  "CRM", "Salesforce (Force.com)", 0},
    {"pardot.com",                 "CRM", "Salesforce Pardot", 0},
    {"marketo.com",                "CRM", "Marketo (Adobe)", 0},
    {"marketo.net",                "CRM", "Marketo", 0},
    {"zoho.com",                   "CRM", "Zoho", 0},

    // Error Tracking
    {"sentry.com",                 "Error Tracking", "Sentry", 0},
    {"sentry.io",                  "Error Tracking", "Sentry", 0},
    {"browser.sentry-cdn.com",     "Error Tracking", "Sentry CDN", 0},
    {"rollbar.com",                "Error Tracking", "Rollbar", 0},
    {"datadog.com",                "Error Tracking", "Datadog RUM", 0},
    {"datadoghq.com",              "Error Tracking", "Datadog", 0},
    {"newrelic.com",               "Error Tracking", "New Relic", 0},
    {"nr-data.net",                "Error Tracking", "New Relic CDN", 0},
    {"humio.com",                  "Error Tracking", "Humio (Logging)", 0},
    {"logrocket.com",              "Error Tracking", "LogRocket (session replay)", 0},

    // Tag Managers
    {"googletagmanager.com/gtm.js","Tag Manager", "Google Tag Manager", 0},
    {"googletagmanager.com/ns.html","Tag Manager", "Google Tag Manager (noscript)", 0},
    {"tagmanager.google.com",      "Tag Manager", "Google Tag Manager", 0},
    {"adobedtm.com",               "Tag Manager", "Adobe Dynamic Tag Management", 0},
    {"ensighten.com",              "Tag Manager", "Ensighten", 0},
    {"tealiumiq.com",              "Tag Manager", "Tealium iQ", 0},
    {"tiqcdn.com",                 "Tag Manager", "Tealium CDN", 0},
};

#define TP_DB_SIZE (sizeof(tp_db) / sizeof(tp_db[0]))

EXPORT const char* check_third_party(const char* body) {
    if (body == NULL) body = "";

    char* buf = (char*)malloc(OUT_SIZE);
    if (!buf) return NULL;
    buf[0] = '\0';

    int found_count = 0;
    int found_severe = 0;
    size_t used = 0;

    used = strlen(buf);
    snprintf(buf + used, OUT_SIZE - used, "Third-Party Services Detected:\n");
    used = strlen(buf);
    snprintf(buf + used, OUT_SIZE - used, "==============================\n");

    for (size_t i = 0; i < TP_DB_SIZE; i++) {
        if (strstr(body, tp_db[i].pattern)) {
            found_count++;
            if (tp_db[i].severity >= 2) found_severe++;
            used = strlen(buf);
            snprintf(buf + used, OUT_SIZE - used,
                     "  [%s] %s - %s\n",
                     tp_db[i].category, tp_db[i].description, tp_db[i].pattern);
        }
    }

    if (found_count == 0) {
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "  - No third-party services detected.\n");
    }

    // Summary
    used = strlen(buf);
    snprintf(buf + used, OUT_SIZE - used,
             "\nSummary:\n"
             "  Total third-party services: %d\n"
             "  High-severity (payment/auth): %d\n"
             "  Attack surface: %s\n",
             found_count, found_severe,
             found_count == 0 ? "Minimal" :
             found_severe > 0 ? "Elevated (sensitive integrations)" :
             "Moderate (tracking/content only)");

    // Risk assessment
    if (found_severe > 0) {
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "\nWARNING: Payment/Auth processors detected.\n");
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "  Review: PCI DSS compliance, PII exposure via third-party JS.\n");
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "  Risk: Magecart/Formjacking via compromised CDN/Script.\n");
    }

    if (found_count > 10) {
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "\nNOTE: High number of third-party integrations.\n");
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "  Impact: Increased attack surface, privacy concerns (GDPR).\n");
        used = strlen(buf);
        snprintf(buf + used, OUT_SIZE - used, "  Recommend: Audit SRI (Subresource Integrity) for all loaded scripts.\n");
    }

    return buf;
}

EXPORT void free_tp_string(char* s) {
    free(s);
}
