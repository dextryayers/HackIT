#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>

#include "optimize.h"

#define MAX_SOCKETS      32768
#define MAX_EVENTS       4096
#define MAX_WORKERS      128
#define MAX_PORTS        65536
#define BATCH_SIZE       1024
#define PROGRESS_INTERVAL 500

typedef struct {
    int         port;
    int         state;
    int         rtt_ms;
    char        service[64];
} ScanResult;

typedef struct {
    uint32_t    target_ip;
    int*        ports;
    int         port_count;
    int         timeout_ms;
    int         thread_count;
    int         completed;
    int         batch_start;
    int         batch_end;
    int         max_sock;
    atomic_int  next_batch;
    atomic_int  result_count;
    atomic_int  open_count;
    atomic_int  closed_count;
    atomic_int  filtered_count;
    atomic_int  active_connects;
    ScanResult  results[MAX_PORTS];
    long long   start_time;
    pthread_mutex_t epoll_lock;
    int         epoll_fd;
    int         cpu_count;
    bool        running;
} MassScanContext;

typedef struct {
    int         sock;
    int         port;
    bool        done;
} ConnEntry;

static const char* get_service(int port) {
    static const struct { int p; const char* n; } svc[] = {
        {7,"echo"},{9,"discard"},{13,"daytime"},{19,"chargen"},{21,"ftp"},
        {22,"ssh"},{23,"telnet"},{25,"smtp"},{37,"time"},{53,"dns"},
        {69,"tftp"},{70,"gopher"},{79,"finger"},{80,"http"},{81,"http-alt"},
        {88,"kerberos"},{109,"pop2"},{110,"pop3"},{111,"rpcbind"},{113,"ident"},
        {119,"nntp"},{123,"ntp"},{135,"msrpc"},{137,"netbios-ns"},{139,"netbios-ssn"},
        {143,"imap"},{161,"snmp"},{162,"snmptrap"},{179,"bgp"},{194,"irc"},
        {389,"ldap"},{427,"slp"},{443,"https"},{444,"snpp"},{445,"smb"},
        {465,"smtps"},{500,"isakmp"},{514,"syslog"},{515,"printer"},{520,"rip"},
        {543,"klogin"},{544,"kshell"},{546,"dhcpv6-c"},{547,"dhcpv6-s"},{548,"afp"},
        {554,"rtsp"},{563,"nntps"},{587,"submission"},{631,"ipp"},{636,"ldaps"},
        {646,"ldp"},{873,"rsync"},{989,"ftps-data"},{990,"ftps"},{992,"telnet-tls"},
        {993,"imaps"},{995,"pop3s"},{1025,"nfs-or-iis"},{1080,"socks"},
        {1110,"nfsd-status"},{1194,"openvpn"},{1352,"lotus-notes"},{1433,"mssql"},
        {1521,"oracle-db"},{1604,"citrix-ica"},{1723,"pptp"},{1812,"radius"},
        {1883,"mqtt"},{1900,"upnp"},{2000,"cisco-sccp"},{2049,"nfs"},
        {2082,"cpanel"},{2083,"cpanel-ssl"},{2086,"whm"},{2087,"whm-ssl"},
        {2095,"webmail"},{2096,"webmail-ssl"},{2181,"zookeeper"},{2222,"ssh-alt"},
        {2375,"docker"},{2376,"docker-tls"},{2379,"etcd"},{2380,"etcd-peer"},
        {2483,"oracle-db"},{2484,"oracle-db-ssl"},{2525,"smtp-alt"},
        {3000,"rails"},{3128,"squid"},{3260,"iscsi"},{3306,"mysql"},
        {3310,"clamav"},{3389,"rdp"},{3478,"stun"},{3540,"p2p"},{3689,"daap"},
        {3690,"svn"},{4000,"icq"},{4045,"nfs-lockd"},{4190,"sieve"},
        {4369,"erlang"},{4444,"blazefs"},{4500,"ipsec-nat"},{4567,"sinatra"},
        {4643,"openfire"},{4662,"edonkey"},{4672,"edonkey-udp"},{4899,"radmin"},
        {5000,"upnp"},{5001,"sahara"},{5002,"ssh-alt"},{5005,"glassfish"},
        {5006,"wsm"},{5007,"wsm-ssl"},{5050,"yahoo-messenger"},{5060,"sip"},
        {5061,"sip-tls"},{5070,"sip-alt"},{5104,"ibm-db2"},{5190,"aim"},
        {5222,"xmpp"},{5223,"xmpp-ssl"},{5269,"xmpp-server"},{5353,"mdns"},
        {5432,"postgresql"},{5445,"smbdirect"},{5454,"apc"},{5555,"adb"},
        {5601,"kibana"},{5631,"pcanywhere"},{5666,"nagios"},{5672,"amqp"},
        {5681,"amqps"},{5800,"vnc-http"},{5900,"vnc"},{5901,"vnc-1"},
        {5984,"couchdb"},{5985,"winrm-http"},{5986,"winrm-https"},
        {6000,"x11"},{6001,"x11-1"},{6379,"redis"},{6380,"redis-tls"},
        {6443,"kubernetes"},{6480,"ldap-ssl"},{6560,"imap-ssl"},{6580,"pop3-ssl"},
        {6665,"irc"},{6666,"irc"},{6667,"irc"},{6668,"irc"},{6669,"irc"},
        {6679,"irc-ssl"},{6697,"ircs"},{6881,"bt-tracker"},{6969,"bt-tracker"},
        {7001,"weblogic"},{7002,"weblogic-ssl"},{7070,"realserver"},{7071,"realserver"},
        {7077,"mesos"},{7199,"cassandra"},{7443,"https-alt"},{7474,"neo4j"},
        {7777,"oracle-xe"},{7778,"oracle-xe"},{8000,"http-alt"},{8001,"http-alt"},
        {8008,"http-alt"},{8009,"ajp13"},{8010,"http-alt"},{8042,"http-alt"},
        {8060,"http-alt"},{8070,"http-alt"},{8080,"http-alt"},{8081,"http-alt"},
        {8082,"http-alt"},{8083,"http-alt"},{8084,"http-alt"},{8085,"http-alt"},
        {8086,"influxdb"},{8087,"http-alt"},{8088,"http-alt"},{8089,"http-alt"},
        {8090,"http-alt"},{8091,"couchbase"},{8092,"couchbase"},{8096,"http-alt"},
        {8098,"riak"},{8100,"http-alt"},{8101,"http-alt"},{8118,"privoxy"},
        {8140,"puppet"},{8161,"activemq"},{8172,"iis-remote"},{8200,"http-alt"},
        {8222,"http-alt"},{8243,"https-alt"},{8280,"http-alt"},{8281,"http-alt"},
        {8300,"http-alt"},{8332,"bitcoin"},{8333,"bitcoin-test"},{8384,"syncthing"},
        {8400,"http-alt"},{8401,"http-alt"},{8402,"http-alt"},{8443,"https-alt"},
        {8444,"https-alt"},{8445,"https-alt"},{8463,"http-alt"},{8500,"consul"},
        {8530,"http-alt"},{8531,"http-alt"},{8600,"http-alt"},{8649,"ganglia"},
        {8679,"http-alt"},{8686,"http-alt"},{8765,"http-alt"},{8787,"http-alt"},
        {8800,"http-alt"},{8812,"http-alt"},{8834,"nessus"},{8843,"https-alt"},
        {8875,"http-alt"},{8880,"http-alt"},{8881,"http-alt"},{8882,"http-alt"},
        {8883,"mqtts"},{8888,"http-alt"},{8889,"http-alt"},{8900,"http-alt"},
        {8983,"solr"},{8990,"http-alt"},{8991,"http-alt"},{8992,"http-alt"},
        {8993,"http-alt"},{8994,"http-alt"},{8995,"http-alt"},{8996,"http-alt"},
        {8997,"http-alt"},{8998,"http-alt"},{8999,"http-alt"},{9000,"cso"},
        {9001,"cso-alt"},{9002,"cso-alt"},{9003,"cso-alt"},{9004,"cso-alt"},
        {9005,"cso-alt"},{9006,"cso-alt"},{9007,"cso-alt"},{9008,"cso-alt"},
        {9009,"cso-alt"},{9010,"cso-alt"},{9011,"cso-alt"},{9020,"cso-alt"},
        {9021,"cso-alt"},{9022,"cso-alt"},{9023,"cso-alt"},{9024,"cso-alt"},
        {9025,"cso-alt"},{9042,"cassandra"},{9050,"tor-socks"},{9060,"http-alt"},
        {9080,"http-alt"},{9090,"cockpit"},{9091,"cockpit-ssl"},{9092,"kafka"},
        {9100,"hp-jetdirect"},{9101,"bacula-dir"},{9102,"bacula-fd"},{9103,"bacula-sd"},
        {9110,"http-alt"},{9111,"http-alt"},{9150,"tor"},{9160,"cassandra-thrift"},
        {9191,"http-alt"},{9200,"elasticsearch"},{9210,"http-alt"},{9280,"http-alt"},
        {9290,"http-alt"},{9300,"elasticsearch"},{9310,"http-alt"},{9320,"http-alt"},
        {9330,"http-alt"},{9339,"http-alt"},{9340,"http-alt"},{9350,"http-alt"},
        {9360,"http-alt"},{9370,"http-alt"},{9380,"http-alt"},{9390,"http-alt"},
        {9392,"http-alt"},{9400,"http-alt"},{9410,"http-alt"},{9418,"git"},
        {9420,"http-alt"},{9430,"http-alt"},{9440,"http-alt"},{9443,"https-alt"},
        {9450,"http-alt"},{9460,"http-alt"},{9470,"http-alt"},{9480,"http-alt"},
        {9490,"http-alt"},{9500,"http-alt"},{9510,"http-alt"},{9520,"http-alt"},
        {9530,"http-alt"},{9540,"http-alt"},{9550,"http-alt"},{9560,"http-alt"},
        {9570,"http-alt"},{9580,"http-alt"},{9590,"http-alt"},{9600,"http-alt"},
        {9610,"http-alt"},{9620,"http-alt"},{9630,"http-alt"},{9640,"http-alt"},
        {9650,"http-alt"},{9660,"http-alt"},{9670,"http-alt"},{9680,"http-alt"},
        {9690,"http-alt"},{9700,"http-alt"},{9710,"http-alt"},{9720,"http-alt"},
        {9730,"http-alt"},{9740,"http-alt"},{9750,"http-alt"},{9760,"http-alt"},
        {9770,"http-alt"},{9780,"http-alt"},{9790,"http-alt"},{9800,"http-alt"},
        {9810,"http-alt"},{9820,"http-alt"},{9830,"http-alt"},{9840,"http-alt"},
        {9850,"http-alt"},{9860,"http-alt"},{9870,"http-alt"},{9880,"http-alt"},
        {9890,"http-alt"},{9900,"http-alt"},{9910,"http-alt"},{9920,"http-alt"},
        {9930,"http-alt"},{9940,"http-alt"},{9950,"http-alt"},{9960,"http-alt"},
        {9970,"http-alt"},{9980,"http-alt"},{9981,"http-alt"},{9990,"http-alt"},
        {9991,"http-alt"},{9992,"http-alt"},{9993,"http-alt"},{9994,"http-alt"},
        {9995,"http-alt"},{9996,"http-alt"},{9997,"splunk"},{9998,"http-alt"},
        {9999,"http-alt"},{10000,"webmin"},{10001,"http-alt"},{10002,"http-alt"},
        {10003,"http-alt"},{10004,"http-alt"},{10005,"http-alt"},{10006,"http-alt"},
        {10007,"http-alt"},{10008,"http-alt"},{10009,"http-alt"},{10010,"http-alt"},
        {10050,"zabbix-agent"},{10051,"zabbix-trapper"},{10113,"http-alt"},
        {10114,"http-alt"},{10115,"http-alt"},{10116,"http-alt"},{10117,"http-alt"},
        {10118,"http-alt"},{10119,"http-alt"},{10120,"http-alt"},{10121,"http-alt"},
        {10122,"http-alt"},{10123,"http-alt"},{10124,"http-alt"},{10125,"http-alt"},
        {10126,"http-alt"},{10127,"http-alt"},{10128,"http-alt"},{10129,"http-alt"},
        {10130,"http-alt"},{10131,"http-alt"},{10132,"http-alt"},{10133,"http-alt"},
        {10134,"http-alt"},{10135,"http-alt"},{10136,"http-alt"},{10137,"http-alt"},
        {10138,"http-alt"},{10139,"http-alt"},{10140,"http-alt"},{10240,"http-alt"},
        {11000,"http-alt"},{11211,"memcached"},{11214,"memcached"},{11215,"memcached"},
        {11371,"pgp-keyserver"},{12000,"http-alt"},{12001,"http-alt"},{12345,"netbus"},
        {13720,"veritas"},{13721,"veritas"},{13722,"veritas"},{13724,"veritas"},
        {13782,"veritas"},{13783,"veritas"},{13785,"veritas"},{13786,"veritas"},
        {13832,"http-alt"},{13833,"http-alt"},{13834,"http-alt"},{13835,"http-alt"},
        {13836,"http-alt"},{13837,"http-alt"},{13838,"http-alt"},{13839,"http-alt"},
        {13840,"http-alt"},{13841,"http-alt"},{13842,"http-alt"},{13843,"http-alt"},
        {13844,"http-alt"},{13845,"http-alt"},{13846,"http-alt"},{13847,"http-alt"},
        {13848,"http-alt"},{13849,"http-alt"},{13850,"http-alt"},{13851,"http-alt"},
        {13852,"http-alt"},{13853,"http-alt"},{13854,"http-alt"},{13855,"http-alt"},
        {13856,"http-alt"},{13857,"http-alt"},{13858,"http-alt"},{13859,"http-alt"},
        {13860,"http-alt"},{13861,"http-alt"},{13862,"http-alt"},{13863,"http-alt"},
        {13864,"http-alt"},{13865,"http-alt"},{13866,"http-alt"},{13867,"http-alt"},
        {13868,"http-alt"},{13869,"http-alt"},{13870,"http-alt"},{13871,"http-alt"},
        {13872,"http-alt"},{13873,"http-alt"},{13874,"http-alt"},{13875,"http-alt"},
        {13876,"http-alt"},{13877,"http-alt"},{13878,"http-alt"},{13879,"http-alt"},
        {13880,"http-alt"},{13881,"http-alt"},{13882,"http-alt"},{13883,"http-alt"},
        {13884,"http-alt"},{13885,"http-alt"},{13886,"http-alt"},{13887,"http-alt"},
        {13888,"http-alt"},{13889,"http-alt"},{13890,"http-alt"},{13891,"http-alt"},
        {13892,"http-alt"},{13893,"http-alt"},{13894,"http-alt"},{13895,"http-alt"},
        {13896,"http-alt"},{13897,"http-alt"},{13898,"http-alt"},{13899,"http-alt"},
        {13900,"http-alt"},{14000,"http-alt"},{14141,"http-alt"},{14238,"http-alt"},
        {14441,"http-alt"},{14442,"http-alt"},{15000,"http-alt"},{15001,"http-alt"},
        {15345,"xpilot"},{16000,"http-alt"},{16001,"http-alt"},{16161,"http-alt"},
        {16200,"http-alt"},{16250,"http-alt"},{16300,"http-alt"},{16350,"http-alt"},
        {16379,"redis-cluster"},{16400,"http-alt"},{16450,"http-alt"},{16500,"http-alt"},
        {16550,"http-alt"},{16600,"http-alt"},{16650,"http-alt"},{16700,"http-alt"},
        {16750,"http-alt"},{16800,"http-alt"},{16850,"http-alt"},{16900,"http-alt"},
        {16950,"http-alt"},{17000,"http-alt"},{17050,"http-alt"},{17100,"http-alt"},
        {17150,"http-alt"},{17200,"http-alt"},{17250,"http-alt"},{17300,"http-alt"},
        {17350,"http-alt"},{17400,"http-alt"},{17450,"http-alt"},{17500,"http-alt"},
        {17550,"http-alt"},{17600,"http-alt"},{17650,"http-alt"},{17700,"http-alt"},
        {17750,"http-alt"},{17800,"http-alt"},{17850,"http-alt"},{17900,"http-alt"},
        {17950,"http-alt"},{18000,"http-alt"},{18050,"http-alt"},{18100,"http-alt"},
        {18150,"http-alt"},{18200,"http-alt"},{18250,"http-alt"},{18300,"http-alt"},
        {18350,"http-alt"},{18400,"http-alt"},{18450,"http-alt"},{18500,"http-alt"},
        {18550,"http-alt"},{18600,"http-alt"},{18650,"http-alt"},{18700,"http-alt"},
        {18750,"http-alt"},{18800,"http-alt"},{18850,"http-alt"},{18900,"http-alt"},
        {18950,"http-alt"},{19000,"http-alt"},{19050,"http-alt"},{19100,"http-alt"},
        {19150,"http-alt"},{19200,"http-alt"},{19250,"http-alt"},{19300,"http-alt"},
        {19350,"http-alt"},{19400,"http-alt"},{19450,"http-alt"},{19500,"http-alt"},
        {19550,"http-alt"},{19600,"http-alt"},{19650,"http-alt"},{19700,"http-alt"},
        {19750,"http-alt"},{19800,"http-alt"},{19850,"http-alt"},{19900,"http-alt"},
        {19950,"http-alt"},{20000,"http-alt"},{20001,"http-alt"},
        {0,NULL}
    };
    for (int i = 0; svc[i].n; i++)
        if (svc[i].p == port) return svc[i].n;
    return "unknown";
}

static ALWAYS_INLINE int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

HOT static int setup_connect_socket(uint32_t ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (unlikely(sock < 0)) return -1;

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

    int syn_retries = 2;
    setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;

    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(sock); return -1; }

    return sock;
}

HOT static int batch_connect_epoll(MassScanContext* ctx, int batch_start, int batch_end) {
    int epfd = epoll_create1(0);
    if (unlikely(epfd < 0)) return 0;

    ConnEntry entries[MAX_SOCKETS];
    int nsocks = 0;

    long long connect_start = now_ms();

    for (int i = batch_start; i < batch_end && nsocks < MAX_SOCKETS; i++) {
        int sock = setup_connect_socket(ctx->target_ip, ctx->ports[i], ctx->timeout_ms);
        if (sock >= 0) {
            entries[nsocks].sock = sock;
            entries[nsocks].port = ctx->ports[i];
            entries[nsocks].done = false;

            struct epoll_event ev;
            ev.data.fd = sock;
            ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
            epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
            nsocks++;
        } else {
            int ri = atomic_fetch_add(&ctx->result_count, 1);
            if (ri < MAX_PORTS) {
                ctx->results[ri].port = ctx->ports[i];
                ctx->results[ri].state = 2;
                ctx->results[ri].rtt_ms = 0;
                atomic_fetch_add(&ctx->filtered_count, 1);
            }
        }
    }

    if (nsocks == 0) { close(epfd); return 0; }

    struct epoll_event events[MAX_EVENTS];
    int remaining = nsocks;
    int poll_timeout = ctx->timeout_ms;
    long long deadline = now_ms() + ctx->timeout_ms;

    while (remaining > 0 && poll_timeout > 0) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, poll_timeout);
        if (unlikely(nfds < 0)) {
            if (errno == EINTR) continue;
            break;
        }
        if (nfds == 0) break;

        for (int i = 0; i < nfds; i++) {
            int sock = events[i].data.fd;
            int idx = -1;
            for (int j = 0; j < nsocks; j++) {
                if (entries[j].sock == sock) { idx = j; break; }
            }
            if (idx < 0 || entries[idx].done) continue;

            int so_err = 0;
            socklen_t el = sizeof(so_err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);

            entries[idx].done = true;
            remaining--;

            int ri = atomic_fetch_add(&ctx->result_count, 1);
            if (ri < MAX_PORTS) {
                ctx->results[ri].port = entries[idx].port;
                ctx->results[ri].rtt_ms = (int)(now_ms() - connect_start);

                if (so_err == 0) {
                    ctx->results[ri].state = 1;
                    atomic_fetch_add(&ctx->open_count, 1);
                } else if (so_err == ECONNREFUSED || so_err == ECONNRESET) {
                    ctx->results[ri].state = 0;
                    atomic_fetch_add(&ctx->closed_count, 1);
                } else {
                    ctx->results[ri].state = 2;
                    atomic_fetch_add(&ctx->filtered_count, 1);
                }
            }
            epoll_ctl(epfd, EPOLL_CTL_DEL, sock, NULL);
            close(sock);
        }
        poll_timeout = (int)(deadline - now_ms());
    }

    for (int i = 0; i < nsocks; i++) {
        if (!entries[i].done) {
            int ri = atomic_fetch_add(&ctx->result_count, 1);
            if (ri < MAX_PORTS) {
                ctx->results[ri].port = entries[i].port;
                ctx->results[ri].state = 2;
                atomic_fetch_add(&ctx->filtered_count, 1);
            }
            close(entries[i].sock);
        }
    }
    close(epfd);
    return nsocks;
}

HOT static void* mass_scan_worker(void* arg) {
    MassScanContext* ctx = (MassScanContext*)arg;

    while (1) {
        int start = atomic_fetch_add(&ctx->next_batch, BATCH_SIZE);
        if (start >= ctx->port_count) break;

        int end = start + BATCH_SIZE;
        if (end > ctx->port_count) end = ctx->port_count;

        batch_connect_epoll(ctx, start, end);

        if (now_ms() - ctx->start_time > ctx->timeout_ms * 2) break;
    }
    return NULL;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <target> <port_range> [timeout_ms] [threads]\n", prog);
    fprintf(stderr, "  target      - IP or hostname\n");
    fprintf(stderr, "  port_range  - e.g. 80,443 or 1-1024 or all\n");
    fprintf(stderr, "  timeout_ms  - connection timeout (default: 1000)\n");
    fprintf(stderr, "  threads     - worker threads (default: auto = 4x CPU)\n");
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static int parse_ports(const char* spec, int** ports_out) {
    static int ports[65536];
    int count = 0;
    if (!spec) return 0;
    if (strcmp(spec, "all") == 0) {
        for (int p = 1; p <= 65535 && count < 65536; p++) ports[count++] = p;
        *ports_out = ports;
        return count;
    }
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char* t = strtok(buf, ",");
    while (t && count < 65536) {
        char* d = strchr(t, '-');
        if (d) {
            int s = atoi(t), e = atoi(d + 1);
            if (s < 1) s = 1;
            if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < 65536; p++) ports[count++] = p;
        } else {
            int p = atoi(t);
            if (p >= 1 && p <= 65535) ports[count++] = p;
        }
        t = strtok(NULL, ",");
    }
    *ports_out = ports;
    return count;
}

static int get_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 4;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    uint32_t target = resolve_ip(argv[1]);
    if (unlikely(target == 0)) {
        fprintf(stderr, "Failed to resolve: %s\n", argv[1]);
        return 1;
    }

    int* ports = NULL;
    int port_count = parse_ports(argv[2], &ports);
    if (port_count <= 0) {
        fprintf(stderr, "No valid ports\n");
        return 1;
    }

    int timeout_ms = argc > 3 ? atoi(argv[3]) : 1000;
    int cpu_count = get_cpu_count();
    int threads = argc > 4 ? atoi(argv[4]) : (cpu_count * 4);
    if (threads < 1) threads = 1;
    if (threads > MAX_WORKERS) threads = MAX_WORKERS;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < 65536) {
            rl.rlim_cur = 65536;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    MassScanContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_ip = target;
    ctx.ports = ports;
    ctx.port_count = port_count;
    ctx.timeout_ms = timeout_ms;
    ctx.thread_count = threads;
    ctx.cpu_count = cpu_count;
    ctx.start_time = now_ms();

    struct in_addr ia;
    ia.s_addr = target;
    fprintf(stderr, "MASS_SCAN target=%s ports=%d timeout=%dms threads=%d cpu=%d\n",
        inet_ntoa(ia), port_count, timeout_ms, threads, cpu_count);

    long long last_progress = now_ms();
    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < threads; i++)
        pthread_create(&workers[i], NULL, mass_scan_worker, &ctx);
    for (int i = 0; i < threads; i++)
        pthread_join(workers[i], NULL);

    long long elapsed = now_ms() - ctx.start_time;

    for (int i = 0; i < ctx.result_count; i++) {
        ScanResult* r = &ctx.results[i];
        if (r->state == 1) {
            const char* svc = get_service(r->port);
            printf("{\"port\":%d,\"state\":\"open\",\"service\":\"%s\",\"rtt_ms\":%d}\n",
                r->port, svc, r->rtt_ms);
        }
    }

    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"ports\":%d,\"open\":%d,\"closed\":%d,\"filtered\":%d,\"elapsed_ms\":%lld}\n",
        inet_ntoa(ia), port_count,
        (int)atomic_load(&ctx.open_count),
        (int)atomic_load(&ctx.closed_count),
        (int)atomic_load(&ctx.filtered_count), elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
