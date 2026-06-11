#ifndef HACKIT_BANNER_GRABBER_H
#define HACKIT_BANNER_GRABBER_H

#include <stdint.h>
#include <stdbool.h>

int hackit_grab_banner_tcp(const char* host, int port, int timeout_ms,
                           char* banner, int banner_size);

int hackit_probe_service(const char* host, int port, int timeout_ms,
                         const char* probe_data, int probe_len,
                         char* response, int response_size);

void hackit_detect_version_from_banner(const char* service, const char* banner,
                                       char* product, int product_size,
                                       char* version, int version_size,
                                       char* os_hint, int os_hint_size);

const char* hackit_get_http_probe(void);
const char* hackit_get_redis_probe(void);

#endif
