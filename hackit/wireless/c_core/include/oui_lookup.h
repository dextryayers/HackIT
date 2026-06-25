#ifndef HACKIT_OUI_LOOKUP_H
#define HACKIT_OUI_LOOKUP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OUI_VENDOR_MAX 48

typedef struct {
    uint8_t oui[3];
    char vendor[OUI_VENDOR_MAX];
} OUIEntry;

const char* oui_lookup(const uint8_t bssid[6]);
const char* oui_lookup_str(const char* mac_str);
int oui_lookup_all(OUIEntry* out, int max_count);

#ifdef __cplusplus
}
#endif

#endif
