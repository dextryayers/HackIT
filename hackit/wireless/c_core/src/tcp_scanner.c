#include "tcp_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

static int is_valid_ip_or_host(const char* host) {
    if (!host || !host[0]) return 0;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    freeaddrinfo(res);
    return 1;
}

int hackit_parse_ports(const char* range, int* out, int max) {
    if (!range || !out || max <= 0) return 0;
    int count = 0;
    char buf[PORT_RANGE_STR_LEN];
    strncpy(buf, range, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char* token = strtok(buf, ",");
    while (token && count < max) {
        while (*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { *end = '\0'; end--; }
        char* dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = atoi(token);
            int end_val = atoi(dash + 1);
            if (start > 0 && end_val > 0 && start <= end_val && end_val <= 65535) {
                for (int i = start; i <= end_val && count < max; i++) {
                    out[count++] = i;
                }
            }
        } else {
            int p = atoi(token);
            if (p > 0 && p <= 65535) {
                out[count++] = p;
            }
        }
        token = strtok(NULL, ",");
    }
    return count;
}

static int connect_with_timeout(SOCKET fd, const struct sockaddr* addr, int addrlen, int timeout_ms) {
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
    int rc = connect(fd, addr, addrlen);
    if (rc == 0) {
#ifdef _WIN32
        mode = 0;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        fcntl(fd, F_SETFL, flags);
#endif
        return 0;
    }
#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
#else
    if (errno != EINPROGRESS) return -1;
#endif
    fd_set wset;
    struct timeval tv;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    rc = select((int)(fd + 1), NULL, &wset, NULL, &tv);
    if (rc <= 0) return -1;
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) return -1;
#ifdef _WIN32
    mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    fcntl(fd, F_SETFL, flags);
#endif
    return 0;
}

static SOCKET create_tcp_socket(void) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    return fd;
}

static void close_socket(SOCKET fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

static void send_http_probe(SOCKET fd, const char* host) {
    char req[512];
    snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    send(fd, req, (int)strlen(req), 0);
}

static void send_probe_by_port(SOCKET fd, int port, const char* host) {
    switch (port) {
        case 80:
        case 8080:
        case 8000:
        case 8888:
            send_http_probe(fd, host);
            break;
        case 25:
            send(fd, "EHLO hackit.local\r\n", 19, 0);
            break;
        case 21:
            break;
        case 22:
            break;
        case 110:
            send(fd, "CAPA\r\n", 6, 0);
            break;
        case 143:
            send(fd, "A1 CAPABILITY\r\n", 15, 0);
            break;
        case 443:
        case 993:
        case 995:
            break;
        case 6379:
            send(fd, "*1\r\n$4\r\nPING\r\n", 14, 0);
            break;
        case 3306:
            break;
        case 5432:
            break;
        default:
            break;
    }
}

static int recv_banner(SOCKET fd, char* banner, int banner_size, int timeout_ms) {
    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select((int)(fd + 1), &rset, NULL, NULL, &tv);
    if (rc <= 0) return 0;
    int total = 0;
    while (total < banner_size - 1) {
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        rc = select((int)(fd + 1), &rset, NULL, NULL, &tv);
        if (rc <= 0) break;
        int n = recv(fd, banner + total, banner_size - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    banner[total] = '\0';
    return total;
}

int hackit_scan_tcp_port(const char* host, int port, int timeout_ms, ScannerPortResult* result) {
    if (!host || !result) return -1;
    memset(result, 0, sizeof(ScannerPortResult));
    result->port = port;
    result->state = SCAN_STATE_CLOSED;
    strncpy(result->service, hackit_port_service_name(port), sizeof(result->service) - 1);
    if (!is_valid_ip_or_host(host)) return -1;
    SOCKET fd = create_tcp_socket();
    if (fd == INVALID_SOCKET) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    struct hostent* he = gethostbyname(host);
    if (!he) {
        addr.sin_addr.s_addr = inet_addr(host);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            close_socket(fd);
            return -1;
        }
    } else {
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    double t1 = 0.0, t2 = 0.0;
#ifdef _WIN32
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
#else
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
#endif
    int rc = connect_with_timeout(fd, (struct sockaddr*)&addr, sizeof(addr), timeout_ms);
#ifdef _WIN32
    QueryPerformanceCounter(&end);
    t1 = (double)start.QuadPart;
    t2 = (double)end.QuadPart;
    result->rtt_ms = ((t2 - t1) * 1000.0) / (double)freq.QuadPart;
#else
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    result->rtt_ms = (double)(ts2.tv_sec - ts1.tv_sec) * 1000.0 +
                     (double)(ts2.tv_nsec - ts1.tv_nsec) / 1000000.0;
#endif
    if (rc != 0) {
        close_socket(fd);
        result->state = SCAN_STATE_FILTERED;
        return 0;
    }
    result->state = SCAN_STATE_OPEN;
#ifdef _WIN32
    int opt_val = timeout_ms < 10000 ? timeout_ms : 10000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&opt_val, sizeof(opt_val));
#else
    struct timeval rcv_tv;
    rcv_tv.tv_sec = (timeout_ms < 10000 ? timeout_ms : 10000) / 1000;
    rcv_tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));
#endif
    send_probe_by_port(fd, port, host);
    recv_banner(fd, result->banner, MAX_SCANNER_BANNER, timeout_ms);
    if (result->banner[0]) {
        strncpy(result->product, result->banner, sizeof(result->product) - 1);
    }
    close_socket(fd);
    return 0;
}

#ifdef _WIN32
typedef struct {
    CRITICAL_SECTION lock;
    int* ports;
    int port_count;
    int current_index;
} WorkQueue;

typedef struct {
    const char* host;
    int timeout_ms;
    bool grab_banners;
    WorkQueue* queue;
    ScannerPortResult* results;
    int max_results;
    int* result_count;
    ScanProgressFn callback;
    int total;
} ThreadData;

static DWORD WINAPI worker_thread(LPVOID arg) {
    ThreadData* td = (ThreadData*)arg;
    while (1) {
        EnterCriticalSection(&td->queue->lock);
        int idx = td->queue->current_index++;
        LeaveCriticalSection(&td->queue->lock);
        if (idx >= td->queue->port_count) break;
        ScannerPortResult r;
        hackit_scan_tcp_port(td->host, td->queue->ports[idx], td->timeout_ms, &r);
        if (r.state == SCAN_STATE_OPEN || !td->grab_banners) {
            EnterCriticalSection(&td->queue->lock);
            if (*td->result_count < td->max_results) {
                td->results[*td->result_count] = r;
                (*td->result_count)++;
            }
            LeaveCriticalSection(&td->queue->lock);
        }
        if (td->callback) td->callback(idx + 1, td->total, &r);
    }
    return 0;
}
#else
typedef struct {
    pthread_mutex_t lock;
    int* ports;
    int port_count;
    int current_index;
} WorkQueue;

typedef struct {
    const char* host;
    int timeout_ms;
    bool grab_banners;
    WorkQueue* queue;
    ScannerPortResult* results;
    int max_results;
    int* result_count;
    ScanProgressFn callback;
    int total;
} ThreadData;

static void* worker_thread(void* arg) {
    ThreadData* td = (ThreadData*)arg;
    while (1) {
        pthread_mutex_lock(&td->queue->lock);
        int idx = td->queue->current_index++;
        pthread_mutex_unlock(&td->queue->lock);
        if (idx >= td->queue->port_count) break;
        ScannerPortResult r;
        hackit_scan_tcp_port(td->host, td->queue->ports[idx], td->timeout_ms, &r);
        if (r.state == SCAN_STATE_OPEN || !td->grab_banners) {
            pthread_mutex_lock(&td->queue->lock);
            if (*td->result_count < td->max_results) {
                td->results[*td->result_count] = r;
                (*td->result_count)++;
            }
            pthread_mutex_unlock(&td->queue->lock);
        }
        if (td->callback) td->callback(idx + 1, td->total, &r);
    }
    return NULL;
}
#endif

int hackit_scan_tcp_ports(const char* host, const int* ports, int port_count,
                          int timeout_ms, int threads, bool grab_banners,
                          ScannerPortResult* results, int max_results,
                          ScanProgressFn callback) {
    if (!host || !ports || port_count <= 0 || !results || max_results <= 0) return -1;
    if (threads < 1) threads = 1;
    if (threads > 256) threads = 256;
    WorkQueue queue;
#ifdef _WIN32
    InitializeCriticalSection(&queue.lock);
#else
    pthread_mutex_init(&queue.lock, NULL);
#endif
    queue.ports = (int*)ports;
    queue.port_count = port_count;
    queue.current_index = 0;
    int result_count = 0;
    ThreadData td;
    td.host = host;
    td.timeout_ms = timeout_ms;
    td.grab_banners = grab_banners;
    td.queue = &queue;
    td.results = results;
    td.max_results = max_results;
    td.result_count = &result_count;
    td.callback = callback;
    td.total = port_count;
#ifdef _WIN32
    HANDLE* handles = (HANDLE*)malloc(threads * sizeof(HANDLE));
    for (int i = 0; i < threads; i++) {
        handles[i] = CreateThread(NULL, 0, worker_thread, &td, 0, NULL);
    }
    WaitForMultipleObjects(threads, handles, TRUE, INFINITE);
    for (int i = 0; i < threads; i++) {
        CloseHandle(handles[i]);
    }
    free(handles);
    DeleteCriticalSection(&queue.lock);
#else
    pthread_t* handles = (pthread_t*)malloc(threads * sizeof(pthread_t));
    for (int i = 0; i < threads; i++) {
        pthread_create(&handles[i], NULL, worker_thread, &td);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    free(handles);
    pthread_mutex_destroy(&queue.lock);
#endif
    return result_count;
}

const char* hackit_port_service_name(int port) {
    static const struct { int port; const char* name; } services[] = {
        {1, "tcpmux"}, {5, "rje"}, {7, "echo"}, {9, "discard"}, {11, "systat"},
        {13, "daytime"}, {17, "qotd"}, {18, "msp"}, {19, "chargen"}, {20, "ftp-data"},
        {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {37, "time"},
        {39, "rlp"}, {42, "nameserver"}, {43, "nicname"}, {49, "tacacs"},
        {50, "re-mail-ck"}, {53, "dns"}, {63, "whois++"}, {67, "dhcp-server"},
        {68, "dhcp-client"}, {69, "tftp"}, {70, "gopher"}, {79, "finger"},
        {80, "http"}, {81, "http-alt"}, {88, "kerberos"}, {101, "hostname"},
        {102, "iso-tsap"}, {105, "csnet-ns"}, {107, "rtelnet"}, {109, "pop2"},
        {110, "pop3"}, {111, "rpcbind"}, {113, "ident"}, {115, "sftp"},
        {117, "uucp-path"}, {118, "sqlserv"}, {119, "nntp"}, {123, "ntp"},
        {126, "uniz"}, {135, "epmap"}, {137, "netbios-ns"}, {138, "netbios-dgm"},
        {139, "netbios-ssn"}, {143, "imap"}, {144, "news"}, {152, "bfs"},
        {153, "sgmp"}, {156, "sqlsvc"}, {158, "dmsp"}, {161, "snmp"},
        {162, "snmptrap"}, {170, "print-srv"}, {177, "xdmcp"}, {179, "bgp"},
        {190, "gacp"}, {194, "irc"}, {199, "smux"}, {201, "at-rtmp"},
        {209, "qmtp"}, {210, "z39.50"}, {213, "ipx"}, {220, "imap3"},
        {245, "link"}, {259, "esro-gen"}, {262, "arcisdms"}, {264, "bgmp"},
        {280, "http-mgmt"}, {300, "thinlinc"}, {311, "osx-admin"}, {312, "vcom"},
        {315, "dpsi"}, {318, "pkix-timestamp"}, {323, "rpki-rtr"},
        {350, "matip-type-b"}, {351, "matip-type-a"}, {356, "ndap"},
        {366, "odmr"}, {369, "rpc2portmap"}, {371, "netconf"}, {376, "nip"},
        {381, "hp-collector"}, {383, "hp-managed-node"}, {384, "hp-alarm-mgr"},
        {386, "asa"}, {387, "aurp"}, {389, "ldap"}, {399, "digex"},
        {401, "ups"}, {407, "timbuktu"}, {411, "rmt"}, {412, "synoptics-trap"},
        {413, "smsp"}, {414, "infoseek"}, {415, "bnet"}, {423, "opsec-cvp"},
        {424, "opsec-ufp"}, {425, "opsec-sam"}, {426, "opsec-lea"},
        {427, "svrloc"}, {434, "mobileip-agent"}, {435, "mobilip-mn"},
        {443, "https"}, {444, "snpp"}, {445, "microsoft-ds"}, {446, "ddm-rdb"},
        {448, "dds"}, {456, "macon-tcp"}, {458, "applequicktime"},
        {459, "ampr-rcmd"}, {460, "skronk"}, {461, "dps"}, {462, "datasurfsrv"},
        {463, "alpes"}, {464, "kpasswd"}, {465, "smtps"}, {466, "digital-vrc"},
        {467, "mylex-mapd"}, {468, "photuris"}, {469, "rcp"}, {470, "scx-proxy"},
        {471, "mondex"}, {472, "ljk-login"}, {473, "hybrid-pop"},
        {474, "tn-tl-w1"}, {475, "tcpnethaspsrv"}, {476, "tn-tl-fd1"},
        {477, "ss7ns"}, {478, "spsc"}, {479, "iafserver"}, {480, "iafdbase"},
        {481, "ph"}, {482, "bgs-nsi"}, {483, "ulpnet"}, {484, "integra-sme"},
        {485, "powerburst"}, {486, "sstats"}, {487, "saft"}, {488, "gss-http"},
        {489, "nest-protocol"}, {490, "micom-pfs"}, {491, "go-login"},
        {492, "ticf-1"}, {493, "ticf-2"}, {494, "pov-ray"}, {495, "intecourier"},
        {496, "pim-rp-disc"}, {497, "retrospect"}, {498, "siam"},
        {499, "iso-ill"}, {500, "isakmp"}, {501, "stmf"}, {502, "modbus"},
        {503, "asa-appl-proto"}, {504, "citadel"}, {505, " mailbox-lm"},
        {506, "ohimsrv"}, {507, "crs"}, {508, "xvt"}, {509, "snmp-tcp-port"},
        {510, "post-office"}, {511, "passgo"}, {512, "exec"}, {513, "login"},
        {514, "shell"}, {515, "printer"}, {516, "videotex"}, {517, "talk"},
        {518, "ntalk"}, {519, "utime"}, {520, "efs"}, {521, "ripng"},
        {522, "ulp"}, {523, "ibm-db2"}, {524, "ncp"}, {525, "timed"},
        {526, "tempo"}, {527, "stx"}, {528, "custix"}, {529, "irc-serv"},
        {530, "courier"}, {531, "chat"}, {532, "netnews"}, {533, "netwall"},
        {534, "mm-admin"}, {535, "iiop"}, {536, "opalis-rdv"}, {537, "nmsp"},
        {538, "gdomap"}, {539, "apertus-ldp"}, {540, "uucp"}, {541, "uucp-rlogin"},
        {542, "commerce"}, {543, "klogin"}, {544, "kshell"}, {545, "appleqtcsrvr"},
        {546, "dhcpv6-client"}, {547, "dhcpv6-server"}, {548, "afpovertcp"},
        {549, "idfp"}, {550, "new-rwho"}, {551, "cybercash"}, {552, "deviceshare"},
        {553, "pirp"}, {554, "rtsp"}, {555, "dsf"}, {556, "remotefs"},
        {557, "openvms-sysipc"}, {558, "sdnskmp"}, {559, "teamspeak"},
        {560, "rmonitor"}, {561, "monitor"}, {562, "chshell"}, {563, "nntps"},
        {564, "9pfs"}, {565, "whoami"}, {566, "streettalk"}, {567, "banyan-rpc"},
        {568, "ms-shuttle"}, {569, "ms-rome"}, {570, "meter"}, {571, "umeter"},
        {572, "sonar"}, {573, "banyan-vip"}, {574, "ftp-agent"},
        {575, "vemmi"}, {576, "ipcd"}, {577, "vnas"}, {578, "ipdd"},
        {579, "decbsrv"}, {580, "sntp-heartbeat"}, {581, "bdp"},
        {582, "scc-security"}, {583, "philips-vc"}, {584, "keyserver"},
        {586, "pwdgen"}, {587, "submission"}, {588, "cal"},
        {589, "eyelink"}, {590, "tns-cml"}, {591, "http-alt"},
        {592, "eudora-set"}, {593, "http-rpc-epmap"}, {594, "tpip"},
        {595, "cab-protocol"}, {596, "smsd"}, {597, "ptcnameservice"},
        {598, "sco-websrvrmg3"}, {599, "acp"}, {600, "ipcserver"},
        {601, "syslog-conn"}, {602, "xmlrpc-beep"}, {603, "idxp"},
        {604, "tunnel"}, {605, "soap-beep"}, {606, "urm"}, {607, "nqs"},
        {608, "sift-uft"}, {609, "npmp-trap"}, {610, "npmp-local"},
        {611, "npmp-gui"}, {612, "hmmp-ind"}, {613, "hmmp-op"},
        {614, "sshell"}, {615, "sco-inetmgr"}, {616, "sco-sysmgr"},
        {617, "sco-dtmgr"}, {618, "dei-icda"}, {619, "compaq-evm"},
        {620, "sco-websrvrmgr"}, {621, "escp-ip"}, {622, "collaborator"},
        {623, "asf-rmcp"}, {624, "cryptoadmin"}, {625, "apple-xsan"},
        {626, "serialnumberd"}, {627, "passgo-tivoli"}, {628, "qmqp"},
        {629, "3com-amp3"}, {630, "rda"}, {631, "ipp"}, {632, "bmpp"},
        {633, "servstat"}, {634, "ginad"}, {635, "rlzdbase"}, {636, "ldaps"},
        {637, "lanserver"}, {638, "mcns-sec"}, {639, "msdp"}, {640, "entrust-sps"},
        {641, "repcmd"}, {642, "esro-emsdp"}, {643, "sanity"}, {644, "dwr"},
        {645, "pssc"}, {646, "ldp"}, {647, "dhcp-failover"}, {648, "rrp"},
        {649, "cadview-3d"}, {650, "obex"}, {651, "ieee-mms"}, {652, "hello-port"},
        {653, "repscmd"}, {654, "aodv"}, {655, "tinc"}, {656, "spmp"},
        {657, "rmc"}, {658, "tenfold"}, {660, "mac-srvr-admin"},
        {661, "hap"}, {662, "pftp"}, {663, "purenoise"}, {664, "oob-ws-http"},
        {665, "sun-dr"}, {666, "doom"}, {667, "disclose"}, {668, "mecomm"},
        {669, "meregister"}, {670, "vacdsm-sws"}, {671, "vacdsm-app"},
        {672, "vpps-qua"}, {673, "cimplex"}, {674, "acap"}, {675, "dctp"},
        {676, "vpps-via"}, {677, "vpp"}, {678, "ggf-ncp"}, {679, "mrm"},
        {680, "entrust-aaas"}, {681, "entrust-aams"}, {682, "xfr"},
        {683, "corba-iiop"}, {684, "corba-iiop-ssl"}, {685, "mdc-portmapper"},
        {686, "hcp-wismar"}, {687, "asipregistry"}, {688, "realm-rusd"},
        {689, "nmap"}, {690, "vatp"}, {691, "msexch-routing"},
        {692, "hyperwave-isp"}, {693, "connendp"}, {694, "ha-cluster"},
        {695, "ieee-mms-ssl"}, {696, "rushd"}, {697, "uuidgen"}, {698, "olsr"},
        {699, "accessnetwork"}, {700, "epp"}, {701, "lmp"}, {702, "iris-beep"},
        {704, "elcsd"}, {705, "agentx"}, {706, "silc"}, {707, "borland-dsj"},
        {709, "entrust-kmsh"}, {710, "entrust-ash"}, {711, "cisco-tdp"},
        {712, "tbrpf"}, {713, "iris-xpc"}, {714, "iris-xpcs"},
        {715, "iris-lwz"}, {716, "pana"}, {729, "netviewdm1"},
        {730, "netviewdm2"}, {731, "netviewdm3"}, {741, "netgw"},
        {742, "netrcs"}, {743, "cisco-fna"}, {744, "cisco-tna"},
        {745, "cisco-sys"}, {746, "fdm-auth"}, {747, "su-mit-tg"},
        {748, "si-srv"}, {749, "kerberos-adm"}, {750, "kerberos-iv"},
        {751, "pump"}, {752, "qrh"}, {753, "rrh"}, {754, "tell"},
        {758, "nlogin"}, {759, "con"}, {760, "ns"}, {761, "rxe"},
        {762, "quotad"}, {763, "cycleserv"}, {764, "omserv"}, {765, "webster"},
        {767, "phonebook"}, {769, "vid"}, {770, "cadlock"}, {771, "rtip"},
        {772, "cycleserv2"}, {773, "submit"}, {774, "rpasswd"},
        {775, "entomb"}, {776, "wpages"}, {777, "multiling-http"},
        {780, "wpgs"}, {781, "hp-collector"}, {782, "hp-managed-node"},
        {783, "spamassassin"}, {786, "concert"}, {787, "qsc"},
        {788, "mdbs-daemon"}, {789, "device"}, {790, "mol"},
        {800, "mdbs-daemon"}, {801, "device"}, {802, "modem"},
        {808, "ccproxy-http"}, {810, "fcp-udp"}, {828, "itm-mcell-s"},
        {829, "pkix-3-ca-ra"}, {830, "netconf-ssh"}, {831, "netconf-beep"},
        {832, "netconfsoaphttp"}, {833, "netconfsoapbeep"},
        {843, "adobe-flash-policy"}, {844, "syncml"}, {845, "syncml-http"},
        {846, "dhcp-failover"}, {847, "dhcp-failover-2"}, {848, "gdoi"},
        {849, "gdoi-capability"}, {853, "dns-over-tls"}, {854, "dns-over-https"},
        {860, "iscsi"}, {861, "owamp-control"}, {862, "twamp-control"},
        {863, "turboprint"}, {864, "corbaloc"}, {865, "corbaloc-iiop"},
        {866, "gtpv0"}, {867, "gtpv1"}, {868, "gtpv2"}, {869, "gtpv3"},
        {870, "supv-tunnel"}, {871, "supv-udp-tunnel"}, {872, "rdmc"},
        {873, "rsync"}, {875, "nfs4-callback"}, {876, "nfs4-callback-udp"},
        {877, "nfs4-callback-tcp"}, {878, "nfs4-callback-sctp"},
        {879, "nfs4-callback-dccp"}, {880, "nfs4-callback-rdma"},
        {881, "nfs4-callback-rpc"}, {882, "nfs4-callback-rpc-udp"},
        {883, "nfs4-callback-rpc-tcp"}, {886, "iclcnet-locate"},
        {887, "iclcnet-svinfo"}, {888, "accessbuilder"}, {889, "cddbp"},
        {890, "cddbp-alt"}, {891, "clarmon"}, {892, "oerpc"}, {893, "h2g2"},
        {894, "sdo"}, {895, "sdo-tls"}, {896, "sdo-ssh"}, {897, "sdo-sctp"},
        {900, "sdo-locate"}, {901, "samba-swat"}, {902, "vmware-auth"},
        {903, "ideafarm-chat"}, {904, "ideafarm-catch"}, {905, "netutil"},
        {906, "netutil2"}, {907, "netutil3"}, {908, "netutil4"},
        {909, "netutil5"}, {910, "netutil6"}, {911, "netutil7"},
        {912, "netutil8"}, {913, "netutil9"}, {914, "netutil10"},
        {915, "netutil11"}, {916, "netutil12"}, {917, "netutil13"},
        {918, "netutil14"}, {919, "netutil15"}, {920, "netutil16"},
        {921, "netutil17"}, {922, "netutil18"}, {923, "netutil19"},
        {924, "netutil20"}, {925, "netutil21"}, {926, "netutil22"},
        {927, "netutil23"}, {928, "netutil24"}, {929, "netutil25"},
        {930, "netutil26"}, {931, "netutil27"}, {932, "netutil28"},
        {933, "netutil29"}, {934, "netutil30"}, {935, "netutil31"},
        {936, "netutil32"}, {937, "netutil33"}, {938, "netutil34"},
        {939, "netutil35"}, {940, "netutil36"}, {941, "netutil37"},
        {942, "netutil38"}, {943, "netutil39"}, {944, "netutil40"},
        {945, "netutil41"}, {946, "netutil42"}, {947, "netutil43"},
        {948, "netutil44"}, {949, "netutil45"}, {950, "netutil46"},
        {951, "netutil47"}, {952, "netutil48"}, {953, "netutil49"},
        {954, "netutil50"}, {955, "netutil51"}, {956, "netutil52"},
        {957, "netutil53"}, {958, "netutil54"}, {959, "netutil55"},
        {960, "netutil56"}, {961, "netutil57"}, {962, "netutil58"},
        {963, "netutil59"}, {964, "netutil60"}, {965, "netutil61"},
        {966, "netutil62"}, {967, "netutil63"}, {968, "netutil64"},
        {969, "netutil65"}, {970, "netutil66"}, {971, "netutil67"},
        {972, "netutil68"}, {973, "netutil69"}, {974, "netutil70"},
        {975, "netutil71"}, {976, "netutil72"}, {977, "netutil73"},
        {978, "netutil74"}, {979, "netutil75"}, {980, "netutil76"},
        {981, "netutil77"}, {982, "netutil78"}, {983, "netutil79"},
        {984, "netutil80"}, {985, "netutil81"}, {986, "netutil82"},
        {987, "netutil83"}, {988, "netutil84"}, {989, "netutil85"},
        {990, "netutil86"}, {991, "netutil87"}, {992, "netutil88"},
        {993, "imaps"}, {994, "ircs"}, {995, "pop3s"}, {996, "vsinet"},
        {997, "maitrd"}, {998, "puparp"}, {999, "applix"}, {1000, "cadlock2"},
        {1433, "mssql"}, {1521, "oracle"}, {1701, "l2tp"}, {1723, "pptp"},
        {1883, "mqtt"}, {2049, "nfs"}, {2082, "cpanel"}, {2083, "cpanels"},
        {2086, "whm"}, {2087, "whms"}, {2095, "cpanel-webmail"},
        {2096, "cpanel-webmails"}, {2181, "zookeeper"}, {2222, "directadmin"},
        {2375, "docker"}, {2376, "docker-tls"}, {2483, "oracle-db"},
        {2484, "oracle-dbs"}, {3000, "gitea"}, {3128, "squid"},
        {3306, "mysql"}, {3389, "rdp"}, {3690, "svn"}, {4000, "icq"},
        {4333, "ahsp"}, {4343, "unicall"}, {4443, "pharos"},
        {4444, "nvp"}, {4500, "ipsec-nat-t"}, {4567, "sinatra"},
        {4646, "eapol-relay"}, {4662, "edonkey"}, {4672, "edonkey-udp"},
        {4711, "pulseaudio"}, {4848, "glassfish"}, {4899, "radmin"},
        {5000, "upnp"}, {5001, "iperf"}, {5002, "iperf-udp"},
        {5003, "filemaker"}, {5004, "rtp-data"}, {5005, "rtp"},
        {5006, "wsm-server"}, {5007, "wsm-server-ssl"}, {5008, "synapsis-edge"},
        {5009, "winfs"}, {5010, "telepathstart"}, {5011, "telepathattack"},
        {5012, "telia"}, {5020, "zenginkyo-1"}, {5021, "zenginkyo-2"},
        {5022, "mice"}, {5023, "htuilsrv"}, {5024, "scpi-telnet"},
        {5025, "scpi-raw"}, {5026, "strexec-d"}, {5027, "strexec-s"},
        {5028, "qvr"}, {5029, "infobright"}, {5030, "surfpass"},
        {5031, "dmp"}, {5032, "signacert-agent"}, {5033, "jtnetd-server"},
        {5034, "jtnetd-status"}, {5035, "cma"}, {5036, "cma-udp"},
        {5037, "adb"}, {5040, "modbus-gateway"}, {5041, "modbus-gateway-udp"},
        {5042, "asnaacceleratordb"}, {5043, "asnaacceleratordb-udp"},
        {5044, "logstash"}, {5045, "smtp-bdx"}, {5046, "smtp-bdx-udp"},
        {5047, "traceroute"}, {5048, "traceroute-udp"}, {5049, "ivms"},
        {5050, "mmcc"}, {5051, "ita-agent"}, {5052, "ita-manager"},
        {5053, "rlm-admin"}, {5054, "rlm"}, {5055, "unot"}, {5056, "intecom-ps"},
        {5057, "intecom-ps2"}, {5058, "intecom-ps3"}, {5059, "sds"},
        {5060, "sip"}, {5061, "sips"}, {5062, "sip-tls"},
        {5063, "sip-tcp"}, {5064, "sip-udp"}, {5065, "sip-sctp"},
        {5066, "sip-dccp"}, {5067, "sip-sctp-tls"}, {5068, "sip-tcp-tls"},
        {5070, "sip-msrp"}, {5080, "sip-http"}, {5081, "sip-https"},
        {5082, "sip-qos"}, {5083, "sip-qos-udp"}, {5084, "sip-qos-tcp"},
        {5085, "sip-qos-sctp"}, {5090, "sip-qos-dccp"}, {5091, "sip-qos-tls"},
        {5092, "sip-qos-tls-udp"}, {5093, "sip-qos-tls-tcp"},
        {5094, "sip-qos-tls-sctp"}, {5095, "sip-qos-tls-dccp"},
        {5096, "sip-qos-ipsec"}, {5097, "sip-qos-ipsec-udp"},
        {5098, "sip-qos-ipsec-tcp"}, {5099, "sip-qos-ipsec-sctp"},
        {5222, "xmpp-client"}, {5223, "xmpp-client-ssl"}, {5269, "xmpp-server"},
        {5432, "postgresql"}, {5555, "android-adb"}, {5631, "pcanywhere"},
        {5666, "nrpe"}, {5672, "amqp"}, {5800, "vnc-http"}, {5900, "vnc"},
        {5901, "vnc-1"}, {5984, "couchdb"}, {5985, "winrm-http"},
        {5986, "winrm-https"}, {6000, "x11"}, {6001, "x11-1"},
        {6379, "redis"}, {6443, "https-alt"}, {6588, "analogx"},
        {6660, "irc-0"}, {6661, "irc-1"}, {6662, "irc-2"}, {6663, "irc-3"},
        {6664, "irc-4"}, {6665, "irc-5"}, {6666, "irc-6"}, {6667, "irc"},
        {6668, "irc-8"}, {6669, "irc-9"}, {6670, "irc-10"}, {6671, "irc-11"},
        {6672, "irc-12"}, {6673, "irc-13"}, {6674, "irc-14"}, {6675, "irc-15"},
        {6676, "irc-16"}, {6677, "irc-17"}, {6678, "irc-18"}, {6679, "irc-19"},
        {6680, "irc-20"}, {6681, "irc-21"}, {6682, "irc-22"}, {6683, "irc-23"},
        {6684, "irc-24"}, {6685, "irc-25"}, {6686, "irc-26"}, {6687, "irc-27"},
        {6688, "irc-28"}, {6689, "irc-29"}, {6690, "irc-30"},
        {6697, "ircs"}, {6881, "bittorrent"}, {6969, "bittorrent-tracker"},
        {7001, "weblogic"}, {7002, "weblogic-ssl"}, {7070, "realserver"},
        {7071, "realserver-ssl"}, {7777, "cbt"}, {7778, "cbt-udp"},
        {8000, "http-alt"}, {8001, "vcom"}, {8002, "vcom-udp"},
        {8003, "vcom-tls"}, {8004, "vcom-tls-udp"}, {8005, "vcom-tcp"},
        {8006, "vcom-tcp-udp"}, {8007, "vcom-sctp"}, {8008, "http-alt"},
        {8009, "ajp13"}, {8010, "xmp"}, {8011, "xmp-udp"}, {8012, "xmp-tls"},
        {8013, "xmp-tls-udp"}, {8014, "xmp-sctp"}, {8015, "xmp-sctp-udp"},
        {8016, "xmp-dccp"}, {8017, "xmp-dccp-udp"}, {8018, "xmp-ipsec"},
        {8019, "xmp-ipsec-udp"}, {8020, "xmp-ipsec-tcp"},
        {8021, "xmp-ipsec-tcp-udp"}, {8022, "xmp-ipsec-sctp"},
        {8023, "xmp-ipsec-sctp-udp"}, {8024, "xmp-ipsec-dccp"},
        {8025, "xmp-ipsec-dccp-udp"}, {8042, "opengear"},
        {8060, "apns-http"}, {8070, "apns-https"}, {8080, "http-proxy"},
        {8081, "blackice"}, {8082, "us-cli"}, {8083, "us-srv"},
        {8084, "websnp"}, {8085, "ddi-tcp-1"}, {8086, "ddi-tcp-2"},
        {8087, "ddi-tcp-3"}, {8088, "ddi-tcp-4"}, {8089, "ddi-tcp-5"},
        {8090, "ddi-tcp-6"}, {8091, "couchbase"}, {8092, "couchbase-api"},
        {8100, "xprint-server"}, {8118, "privoxy"}, {8123, "polipo"},
        {8200, "trivnet"}, {8201, "trivnet-udp"}, {8202, "trivnet-tls"},
        {8203, "trivnet-tls-udp"}, {8222, "vmware-vc"}, {8291, "mikrotik"},
        {8300, "tmi"}, {8301, "tmi-udp"}, {8302, "tmi-tls"},
        {8303, "tmi-tls-udp"}, {8332, "bitcoin"}, {8333, "bitcoin-testnet"},
        {8400, "cvd"}, {8401, "cvd-udp"}, {8402, "cvd-tls"},
        {8403, "cvd-tls-udp"}, {8443, "https-alt"}, {8500, "consul"},
        {8530, "dns-over-tls"}, {8531, "dns-over-tls-udp"},
        {8600, "asterisk"}, {8649, "ganglia"}, {8834, "nessus"},
        {8880, "cddbp-alt"}, {8888, "sun-answerbook"}, {8889, "ddi-vpl"},
        {8890, "ddi-vpl-udp"}, {8891, "ddi-vpl-tls"}, {8892, "ddi-vpl-tls-udp"},
        {8999, "bctp"}, {9000, "cslistener"}, {9001, "tor-orport"},
        {9002, "tor-dirport"}, {9003, "tor-control"}, {9004, "tor-dns"},
        {9005, "tor-transport"}, {9006, "tor-socks"}, {9007, "tor-extor"},
        {9008, "tor-bridge"}, {9009, "tor-obfs3"}, {9010, "tor-scramblesuit"},
        {9011, "tor-meek"}, {9012, "tor-fte"}, {9013, "tor-http"},
        {9014, "tor-https"}, {9015, "tor-dns-2"}, {9016, "tor-socks-2"},
        {9017, "tor-extor-2"}, {9018, "tor-bridge-2"}, {9019, "tor-obfs3-2"},
        {9020, "tor-scramblesuit-2"}, {9021, "tor-meek-2"},
        {9022, "tor-fte-2"}, {9040, "tor-unknown"}, {9041, "tor-unknown-2"},
        {9042, "tor-unknown-3"}, {9043, "tor-unknown-4"},
        {9044, "tor-unknown-5"}, {9045, "tor-unknown-6"},
        {9046, "tor-unknown-7"}, {9047, "tor-unknown-8"},
        {9048, "tor-unknown-9"}, {9049, "tor-unknown-10"},
        {9050, "tor-socks-3"}, {9051, "tor-control-2"},
        {9090, "websm"}, {9100, "jetdirect"}, {9200, "elasticsearch"},
        {9300, "elasticsearch-cluster"}, {9324, "elasticsearch-s3"},
        {9418, "git"}, {9443, "https-alt-2"}, {9500, "ismserver"},
        {9530, "dsmcc-config"}, {9531, "dsmcc-config-udp"},
        {9532, "dsmcc-session"}, {9533, "dsmcc-session-udp"},
        {9534, "dsmcc-llc"}, {9535, "dsmcc-llc-udp"}, {9536, "dsmcc-cc"},
        {9537, "dsmcc-cc-udp"}, {9538, "dsmcc-udp"}, {9539, "dsmcc-tcp"},
        {9540, "dsmcc-tls"}, {9541, "dsmcc-tls-udp"}, {9542, "dsmcc-sctp"},
        {9543, "dsmcc-sctp-udp"}, {9544, "dsmcc-dccp"},
        {9545, "dsmcc-dccp-udp"}, {9666, "zoom"}, {9876, "sd"},
        {9877, "sd-udp"}, {9878, "sd-tls"}, {9879, "sd-tls-udp"},
        {9880, "sd-sctp"}, {9881, "sd-sctp-udp"}, {9882, "sd-dccp"},
        {9883, "sd-dccp-udp"}, {9898, "monkeycom"}, {9900, "iua"},
        {9901, "iua-udp"}, {9902, "iua-tls"}, {9903, "iua-tls-udp"},
        {9904, "iua-sctp"}, {9905, "iua-sctp-udp"}, {9906, "iua-dccp"},
        {9907, "iua-dccp-udp"}, {9981, "pulseaudio"}, {9999, "abyss"},
        {10000, "ndmp"}, {10001, "scp-config"}, {10002, "scp-file"},
        {10003, "scp-lock"}, {10004, "scp-mgmt"}, {10005, "scp-session"},
        {10006, "scp-transport"}, {10007, "scp-unknown"}, {10008, "scp-unknown"},
        {10009, "scp-unknown"}, {10010, "scp-unknown"}, {10011, "scp-unknown"},
        {10012, "scp-unknown"}, {10013, "scp-unknown"}, {10014, "scp-unknown"},
        {10015, "scp-unknown"}, {10016, "scp-unknown"}, {10017, "scp-unknown"},
        {10018, "scp-unknown"}, {10019, "scp-unknown"}, {10020, "scp-unknown"},
        {10050, "zabbix-agent"}, {10051, "zabbix-trapper"},
        {10113, "netiq"}, {10114, "netiq-udp"}, {10115, "netiq-tls"},
        {10116, "netiq-tls-udp"}, {10117, "netiq-sctp"},
        {10118, "netiq-sctp-udp"}, {10119, "netiq-dccp"},
        {10120, "netiq-dccp-udp"}, {10121, "netiq-ipsec"},
        {10122, "netiq-ipsec-udp"}, {10123, "netiq-ipsec-tcp"},
        {10124, "netiq-ipsec-tcp-udp"}, {10125, "netiq-ipsec-sctp"},
        {10126, "netiq-ipsec-sctp-udp"}, {10127, "netiq-ipsec-dccp"},
        {10128, "netiq-ipsec-dccp-udp"}, {10202, "rhevm"},
        {10203, "rhevm-udp"}, {10204, "rhevm-tls"},
        {10205, "rhevm-tls-udp"}, {10206, "rhevm-sctp"},
        {10207, "rhevm-sctp-udp"}, {10208, "rhevm-dccp"},
        {10209, "rhevm-dccp-udp"}, {11000, "irc-extra"}, {11001, "irc-extra"},
        {11002, "irc-extra"}, {11003, "irc-extra"}, {11004, "irc-extra"},
        {11005, "irc-extra"}, {11006, "irc-extra"}, {11007, "irc-extra"},
        {11008, "irc-extra"}, {11009, "irc-extra"}, {11010, "irc-extra"},
        {11111, "vnc"}, {11211, "memcached"}, {11371, "pgp-keyserver"},
        {11444, "virgo"}, {12000, "scp"}, {12001, "scp-udp"},
        {12002, "scp-tls"}, {12003, "scp-tls-udp"}, {12004, "scp-sctp"},
        {12005, "scp-sctp-udp"}, {12006, "scp-dccp"},
        {12007, "scp-dccp-udp"}, {12008, "scp-ipsec"},
        {12009, "scp-ipsec-udp"}, {12010, "scp-ipsec-tcp"},
        {12011, "scp-ipsec-tcp-udp"}, {12012, "scp-ipsec-sctp"},
        {12013, "scp-ipsec-sctp-udp"}, {12014, "scp-ipsec-dccp"},
        {12015, "scp-ipsec-dccp-udp"}, {12345, "netbus"},
        {12346, "netbus-2"}, {12443, "https-alt-3"}, {13720, "symantec-pv"},
        {13721, "symantec-pv-udp"}, {13722, "symantec-pv-tls"},
        {13723, "symantec-pv-tls-udp"}, {13724, "symantec-mc"},
        {13725, "symantec-mc-udp"}, {13726, "symantec-mc-tls"},
        {13727, "symantec-mc-tls-udp"}, {13728, "symantec-sa"},
        {13729, "symantec-sa-udp"}, {13730, "symantec-sa-tls"},
        {13731, "symantec-sa-tls-udp"}, {13732, "symantec-sa-sctp"},
        {13733, "symantec-sa-sctp-udp"}, {13734, "symantec-sa-dccp"},
        {13735, "symantec-sa-dccp-udp"}, {13782, "netbackup"},
        {13783, "netbackup-udp"}, {13784, "netbackup-tls"},
        {13785, "netbackup-tls-udp"}, {13786, "netbackup-sctp"},
        {13787, "netbackup-sctp-udp"}, {13788, "netbackup-dccp"},
        {13789, "netbackup-dccp-udp"}, {13832, "ms-frs"},
        {13833, "ms-frs-udp"}, {13834, "ms-frs-tls"},
        {13835, "ms-frs-tls-udp"}, {13836, "ms-frs-sctp"},
        {13837, "ms-frs-sctp-udp"}, {13838, "ms-frs-dccp"},
        {13839, "ms-frs-dccp-udp"}, {13980, "cvr"}, {13981, "cvr-udp"},
        {13982, "cvr-tls"}, {13983, "cvr-tls-udp"}, {13984, "cvr-sctp"},
        {13985, "cvr-sctp-udp"}, {13986, "cvr-dccp"},
        {13987, "cvr-dccp-udp"}, {14000, "sua"}, {14001, "sua-udp"},
        {14002, "sua-tls"}, {14003, "sua-tls-udp"}, {14004, "sua-sctp"},
        {14005, "sua-sctp-udp"}, {14006, "sua-dccp"},
        {14007, "sua-dccp-udp"}, {16080, "ossec"}, {16180, "ossec-agent"},
        {16384, "sip-udp-alt"}, {16385, "sip-tcp-alt"},
        {16386, "sip-tls-alt"}, {16387, "sip-sctp-alt"},
        {16388, "sip-dccp-alt"}, {20000, "dnp"}, {20001, "dnp-udp"},
        {20002, "dnp-tls"}, {20003, "dnp-tls-udp"}, {20004, "dnp-sctp"},
        {20005, "dnp-sctp-udp"}, {20006, "dnp-dccp"},
        {20007, "dnp-dccp-udp"}, {24444, "netbeans-xmpp"},
        {25565, "minecraft"}, {26000, "quake"}, {27015, "steam"},
        {27016, "steam-2"}, {27017, "mongodb"}, {28017, "mongodb-http"},
        {30718, "lantronix"}, {31337, "backorifice"}, {32768, "filenet"},
        {32769, "filenet-udp"}, {32770, "filenet-tls"},
        {32771, "filenet-tls-udp"}, {32772, "filenet-sctp"},
        {32773, "filenet-sctp-udp"}, {32774, "filenet-dccp"},
        {32775, "filenet-dccp-udp"}, {33434, "traceroute"},
        {33435, "traceroute-udp"}, {33436, "traceroute-tcp"},
        {33437, "traceroute-tcp-udp"}, {33438, "traceroute-sctp"},
        {33439, "traceroute-sctp-udp"}, {33440, "traceroute-dccp"},
        {33441, "traceroute-dccp-udp"}, {33442, "traceroute-ipsec"},
        {33443, "traceroute-ipsec-udp"}, {33444, "traceroute-ipsec-tcp"},
        {33445, "traceroute-ipsec-tcp-udp"}, {33446, "traceroute-ipsec-sctp"},
        {33447, "traceroute-ipsec-sctp-udp"}, {33448, "traceroute-ipsec-dccp"},
        {33449, "traceroute-ipsec-dccp-udp"}, {40000, "safetyNET-p"},
        {40001, "safetyNET-p-udp"}, {40002, "safetyNET-p-tls"},
        {40003, "safetyNET-p-tls-udp"}, {40004, "safetyNET-p-sctp"},
        {40005, "safetyNET-p-sctp-udp"}, {40006, "safetyNET-p-dccp"},
        {40007, "safetyNET-p-dccp-udp"}, {50000, "db2"},
        {50001, "db2-udp"}, {50002, "db2-tls"}, {50003, "db2-tls-udp"},
        {50004, "db2-sctp"}, {50005, "db2-sctp-udp"}, {50006, "db2-dccp"},
        {50007, "db2-dccp-udp"}, {50070, "hdfs-namenode"},
        {50075, "hdfs-datanode"}, {50090, "hdfs-secondary"},
        {50100, "hdfs-journal"}, {50200, "hdfs-http"},
        {50201, "hdfs-https"}, {50202, "hdfs-http-alt"},
        {50203, "hdfs-https-alt"}, {51000, "scp2"}, {51001, "scp2-udp"},
        {51002, "scp2-tls"}, {51003, "scp2-tls-udp"}, {51004, "scp2-sctp"},
        {51005, "scp2-sctp-udp"}, {51006, "scp2-dccp"},
        {51007, "scp2-dccp-udp"}, {51008, "scp2-ipsec"},
        {51009, "scp2-ipsec-udp"}, {51010, "scp2-ipsec-tcp"},
        {51011, "scp2-ipsec-tcp-udp"}, {51012, "scp2-ipsec-sctp"},
        {51013, "scp2-ipsec-sctp-udp"}, {51014, "scp2-ipsec-dccp"},
        {51015, "scp2-ipsec-dccp-udp"}, {65535, "unknown"}
    };
    int n = sizeof(services) / sizeof(services[0]);
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (services[mid].port == port) return services[mid].name;
        if (services[mid].port < port) lo = mid + 1;
        else hi = mid - 1;
    }
    return "unknown";
}
