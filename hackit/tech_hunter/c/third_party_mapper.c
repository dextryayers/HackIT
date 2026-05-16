#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* check_third_party(const char* body) {
    char buf[2048] = {0};
    
    // Email Providers
    if (strstr(body, "google.com/a/")) strcat(buf, "  - Email provider : [Google Workspace]\n");
    if (strstr(body, "outlook.office.com")) strcat(buf, "  - Email provider : [Microsoft 365]\n");
    if (strstr(body, "amazonaws.com/ses")) strcat(buf, "  - Email provider : [Amazon SES]\n");

    // Payment Processors
    if (strstr(body, "js.stripe.com")) strcat(buf, "  - Payment processor : [Stripe keys in JS]\n");
    if (strstr(body, "paypal.com/sdk")) strcat(buf, "  - Payment processor : [PayPal]\n");

    // Map Services
    if (strstr(body, "maps.googleapis.com")) strcat(buf, "  - Map services : [Google Maps API key (found in JS)]\n");
    if (strstr(body, "api.mapbox.com")) strcat(buf, "  - Map services : [Mapbox]\n");

    // Comment Systems
    if (strstr(body, "disqus.com/embed.js")) strcat(buf, "  - Comment systems : [Disqus shortname]\n");

    // Support Platforms
    if (strstr(body, "zendesk.com")) strcat(buf, "  - Support platforms : [Zendesk]\n");
    if (strstr(body, "freshdesk.com")) strcat(buf, "  - Support platforms : [Freshdesk domain]\n");

    // CDN Distributions
    if (strstr(body, "cloudfront.net") || strstr(body, "akamaihd.net") || strstr(body, "fastly.net")) {
        strcat(buf, "  - CDN distributions for static assets : [Discovered CDN edge nodes]\n");
    }
    
    if (strlen(buf) == 0) {
        strcat(buf, "  - None discovered\n");
    }

    char* res = (char*)malloc(strlen(buf) + 1);
    strcpy(res, buf);
    return res;
}

EXPORT void free_tp_string(char* s) {
    free(s);
}
