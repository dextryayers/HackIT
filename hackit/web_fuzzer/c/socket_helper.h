#ifndef SOCKET_HELPER_H
#define SOCKET_HELPER_H

#include <winsock2.h>

void init_ws();
void cleanup_ws();
SOCKET create_connection(const char* ip, int port);

#endif
