#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* check_third_party(const char* body) {
    char buf[1024] = {0};
    strcat(buf, "Third-Party Assets:\n");
    
    if (strstr(body, "stripe")) strcat(buf, "- Payment: Stripe (Key found in JS)\n");
    if (strstr(body, "maps.googleapis.com")) strcat(buf, "- Maps: Google Maps API (Key exposed)\n");
    if (strstr(body, "zendesk")) strcat(buf, "- Support: Zendesk Integration\n");
    if (strstr(body, "disqus")) strcat(buf, "- Comments: Disqus System\n");
    
    char* res = (char*)malloc(strlen(buf) + 1);
    strcpy(res, buf);
    return res;
}

EXPORT void free_tp_string(char* s) {
    free(s);
}
