#ifndef PORTSTORM_C_API_H
#define PORTSTORM_C_API_H

#ifdef __cplusplus
extern "C" {
#endif

int portstorm_c_dispatch(const char *scanner_name, int argc, char **argv);
const char **portstorm_c_list_scanners(void);
int portstorm_c_scanner_count(void);

#ifdef __cplusplus
}
#endif

#endif
