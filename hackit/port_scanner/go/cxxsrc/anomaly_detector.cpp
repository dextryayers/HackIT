#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <mutex>
#include <cmath>
#include <cctype>
#include <string_view>
#include <memory>
#include <unordered_map>


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct PortResult {
    std::string target;
    int port;
    std::string status;
    std::string service;
    std::string banner;
    int banner_length;
};

struct Anomaly {
    std::string type;
    std::string description;
    int port;
    double severity;
    double confidence;
};

class AnomalyDetector {
    std::unordered_map<int, std::string> known_ports;
    std::mutex mtx;

    void init_known_ports() noexcept {
        known_ports = {
            {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
            {25, "smtp"}, {53, "dns"}, {67, "dhcp"}, {68, "dhcp"},
            {69, "tftp"}, {80, "http"}, {81, "http"}, {88, "kerberos"},
            {110, "pop3"}, {111, "rpcbind"}, {113, "ident"}, {119, "nntp"},
            {123, "ntp"}, {135, "epmap"}, {137, "netbios-ns"}, {138, "netbios-dgm"},
            {139, "netbios-ssn"}, {143, "imap"}, {161, "snmp"}, {162, "snmptrap"},
            {179, "bgp"}, {194, "irc"}, {201, "at-rtmp"}, {210, "z39.50"},
            {213, "ipx"}, {220, "imap3"}, {256, "fw1"}, {257, "fw1"},
            {259, "esro-gen"}, {264, "bgmp"}, {265, "x-bone-ctl"},
            {311, "asip-webadmin"}, {350, "rtp"}, {363, "rsvp_tunnel"},
            {369, "rpc2portmap"}, {370, "codaauth2"}, {371, "clearcase"},
            {372, "ulistproc"}, {373, "legent-1"}, {374, "legent-2"},
            {389, "ldap"}, {427, "svrloc"}, {443, "https"}, {444, "snpp"},
            {445, "microsoft-ds"}, {464, "kpasswd"}, {465, "smtps"},
            {497, "dantz"}, {500, "isakmp"}, {512, "exec"}, {513, "login"},
            {514, "shell"}, {515, "printer"}, {520, "efs"}, {521, "ripng"},
            {523, "ibm-db2"}, {524, "ncp"}, {525, "timed"}, {526, "tempo"},
            {530, "courier"}, {531, "chat"}, {532, "netnews"}, {533, "netwall"},
            {534, "mm-admin"}, {540, "uucp"}, {543, "klogin"}, {544, "kshell"},
            {546, "dhcpv6"}, {547, "dhcpv6"}, {548, "afpovertcp"},
            {550, "new-rwho"}, {554, "rtsp"}, {556, "remotefs"},
            {560, "rmonitor"}, {561, "monitor"}, {563, "nntps"},
            {564, "9pfs"},             {585, "submission"}, {591, "filemaker"},
            {593, "http-rpc-epmap"}, {604, "tun"}, {623, "asf-rmcp"},
            {631, "ipp"}, {636, "ldaps"}, {639, "msdp"}, {646, "ldp"},
            {647, "dhcp-failover"}, {648, "rrp"}, {651, "odmr"},
            {653, "ieee-mms"}, {654, "ieee-mms-ssl"}, {655, "tinc"},
            {657, "rmc"}, {660, "mac-srvr-admin"}, {666, "doom"},
            {674, "acap"}, {688, "appleqtc"}, {690, "vmsvc"},
            {691, "res"}, {694, "ha-cluster"}, {695, "ieee-mms-ssl"},
            {698, "drmsmc"}, {699, "accessnetwork"}, {700, "buddy-talk"},
            {701, "lmp"}, {702, "iris-beep"}, {704, "elcsd"},
            {705, "agentx"}, {706, "silc"}, {707, "borland-dsj"},
            {709, "entrust-kmsh"}, {710, "entrust-ash"},
            {711, "cisco-tdp"}, {712, "tbrpf"}, {713, "iris-xpc"},
            {714, "iris-xpcs"}, {715, "iris-lwz"}, {729, "netviewdm1"},
            {730, "netviewdm2"}, {731, "netviewdm3"}, {741, "netgw"},
            {742, "netrcs"}, {743, "service"}, {744, "flexlm"},
            {747, "fujitsu-dev"}, {748, "ris-cm"}, {749, "kerberos-adm"},
            {750, "kerberos-iv"}, {751, "kerberos-master"},
            {752, "qrh"}, {753, "rrh"}, {754, "krb-prop"},
            {759, "ndl-aas"}, {760, "ndl-aas"}, {761, "ndl-aas"},
            {762, "quotad"}, {763, "cycleserv"}, {764, "omserv"},
            {765, "webster"}, {767, "phonebook"}, {769, "vid"},
            {770, "cadlock"}, {771, "rtip"}, {772, "cycleserv2"},
            {773, "notify"}, {774, "acmaint_dbd"}, {775, "acmaint_transd"},
            {776, "wpages"}, {777, "multiling-http"}, {780, "wpgs"},
            {781, "hp-collector"}, {782, "hp-managed-node"}, {783, "spamassassin"},
            {786, "concert"}, {787, "qsc"}, {788, "mdbs_daemon"},
            {800, "mdbs_daemon"}, {801, "device"}, {802, "mbap"},
            {808, "ccproxy-http"}, {843, "adobe-flash-policy"},
            {844, "adobe-flash-socket"}, {847, "dhcp-failover"},
            {848, "gdoi"}, {860, "iscsi"}, {861, "owamp-control"},
            {862, "twamp-control"}, {873, "rsync"}, {888, "cddbp"},
            {889, "ddp-via"}, {890, "ddp-frame"}, {891, "clcadmin"},
            {892, "clcadmin"}, {893, "unknown"}, {900, "sctp"},
            {901, "samba-swat"}, {902, "vmware-auth"}, {903, "vmware-auth-alt"},
            {904, "vmware-srv"}, {905, "vmware-srv"}, {908, "accel-csa"},
            {909, "accel-ccp"}, {910, "kink"}, {911, "xact-backup"},
            {912, "apex-mesh"}, {913, "apex-edge"}, {989, "ftps-data"},
            {990, "ftps"}, {991, "nas"}, {992, "telnet-ssl"},
            {993, "imaps"}, {994, "ircs"}, {995, "pop3s"},
            {1025, "nfs-or-iis"}, {1026, "win-rpc"}, {1027, "win-rpc"},
            {1028, "win-rpc"}, {1029, "win-rpc"}, {1030, "iad1"},
            {1080, "socks"}, {1099, "rmi"}, {1100, "mirc"},
            {1102, "adobeserver"}, {1110, "nfsd-status"}, {1111, "lmsocialserver"},
            {1112, "icl-mgf"}, {1113, "icp"}, {1114, "mini-sql"},
            {1115, "ardus-trns"}, {1116, "ardus-cntl"}, {1117, "ardus-mtrns"},
            {1121, "rmpp"}, {1122, "availant-mgr"}, {1123, "murray"},
            {1124, "hpvmmcontrol"}, {1125, "hpvmmagent"}, {1126, "hpvmmdata"},
            {1127, "supfiledbg"}, {1128, "sap"}, {1129, "sapv6"},
            {1130, "casp"}, {1131, "caspssl"}, {1132, "kvm-via-ip"},
            {1138, "autobuild"}, {1141, "mxomss"}, {1142, "edtools"},
            {1143, "imyx"}, {1144, "fuscript"}, {1145, "x9-icue"},
            {1146, "audit-transfer"}, {1147, "capioverlan"},
            {1148, "elfiq-repl"}, {1149, "bvtsonar"}, {1150, "blaze"},
            {1151, "unizensus"}, {1152, "winpoplanmess"}, {1153, "c1222-acse"},
            {1154, "resacommunity"}, {1155, "nfa"}, {1156, "iascontrol-om"},
            {1157, "iascontrol"}, {1158, "dbcontrol-om"}, {1159, "oracle-oms"},
            {1160, "olsv"}, {1161, "health-polling"}, {1162, "health-trap"},
            {1163, "sddp"}, {1164, "qsm-proxy"}, {1165, "qsm-gui"},
            {1166, "qsm-remote"}, {1167, "cisco-ipsla"}, {1168, "vchat"},
            {1169, "tripwire"}, {1170, "atc-lm"}, {1171, "atc-appserver"},
            {1172, "dnap"}, {1173, "d-cinema-rrp"}, {1174, "fnet-remote-ui"},
            {1175, "dossier"}, {1176, "indigo-server"}, {1177, "dkmessenger"},
            {1178, "sgi-storman"}, {1179, "b2n"}, {1180, "mc-client"},
            {1181, "3comnetman"}, {1182, "accelenet"}, {1183, "llsurfup-http"},
            {1184, "llsurfup-https"}, {1185, "catchpole"}, {1186, "mysql-cluster"},
            {1187, "alias"}, {1188, "hp-webadmin"}, {1189, "unet"},
            {1190, "commlinx-avl"}, {1191, "gpfs"}, {1192, "caids-sensor"},
            {1193, "fiveacross"}, {1194, "openvpn"}, {1195, "rsf-1"},
            {1196, "netmagic"}, {1197, "carrius-rshell"}, {1198, "cajo-discovery"},
            {1199, "dmidi"}, {1200, "scol"}, {1201, "nucleus-sand"},
            {1202, "caiccipc"}, {1203, "ssslic-mgr"}, {1204, "ssslog-mgr"},
            {1205, "accord-mgc"}, {1206, "anthony-data"}, {1207, "metasage"},
            {1208, "seagull-ais"}, {1209, "ipcd3"}, {1210, "eoss"},
            {1211, "groove-dpp"}, {1212, "lupa"}, {1213, "mpc-lifenet"},
            {1214, "kazaa"}, {1215, "scanstat-1"}, {1216, "etebac5"},
            {1217, "hpss-ndapi"}, {1218, "aeroflight-ads"}, {1219, "aeroflight-ret"},
            {1220, "qt-serveradmin"}, {1221, "sweetware-apps"}, {1222, "nerv"},
            {1223, "tgp"}, {1224, "glass"}, {1225, "slinkysearch"},
            {1226, "grisbia"}, {1227, "dns2go"}, {1228, "nsws"},
            {1229, "opentest"}, {1230, "periscope"}, {1231, "menandmice-lm"},
            {1232, "first-defense"}, {1233, "univ-appserver"},
            {1433, "mssql"}, {1434, "ms-sql-m"}, {1521, "oracle"},
            {1701, "l2tp"}, {1723, "pptp"}, {1883, "mqtt"},
            {1900, "upnp"}, {2000, "cisco-sccp"}, {2049, "nfs"},
            {2082, "cpanel"}, {2083, "cpane-ssl"}, {2086, "whm"},
            {2087, "whm-ssl"}, {2100, "amqp"}, {2181, "zookeeper"},
            {2222, "directadmin"}, {2375, "docker"}, {2376, "docker-ssl"},
            {2443, "oracle-https"}, {2483, "oracle-db"}, {2484, "oracle-db-ssl"},
            {2628, "dict"}, {2947, "gpsd"}, {3000, "golang"},
            {3128, "squid"}, {3306, "mysql"}, {3389, "rdp"},
            {3690, "svn"}, {4000, "icq"}, {4040, "yocto-http"},
            {4045, "nfs-lock"}, {4222, "nats"}, {4333, "ahsp"},
            {4369, "epmd"}, {4443, "pharos"}, {4489, "alts-mgnt"},
            {4500, "ipsec-nat-t"}, {4567, "sinatra"}, {4569, "iax"},
            {4658, "playstation3"}, {4662, "edonkey"}, {4672, "edonkey"},
            {4711, "pulseaudio"}, {4730, "gearadmin"}, {4848, "glassfish"},
            {4899, "radmin"}, {4949, "munin"}, {5000, "docker-registry"},
            {5001, "plex"}, {5004, "rtp"}, {5005, "rtcp"},
            {5038, "asterisk"}, {5040, "asu"}, {5050, "sip"},
            {5051, "sip"}, {5060, "sip"}, {5061, "sip-tls"},
            {5070, "sip"}, {5080, "sip"}, {5090, "sip"},
            {5091, "sip"}, {5100, "sip"}, {5141, "aol"},
            {5150, "atmp"}, {5222, "xmpp-client"}, {5223, "xmpp-ssl"},
            {5269, "xmpp-server"}, {5280, "xmpp-bosh"}, {5298, "xmpp"},
            {5353, "mdns"}, {5432, "postgresql"}, {5445, "smbd"},
            {5450, "tiebreaker"}, {5454, "apc-5454"}, {5455, "apc-5455"},
            {5456, "apc-5456"}, {5481, "scard"}, {5500, "vnc"},
            {5501, "vnc"}, {5510, "sdlog"}, {5520, "sdlog"},
            {5530, "sdlog"}, {5540, "sdlog"}, {5550, "sdlog"},
            {5555, "adb"}, {5560, "sdlog"}, {5570, "sdlog"},
            {5580, "sdlog"}, {5590, "sdlog"}, {5591, "sdlog"},
            {5600, "esnm"}, {5601, "kibana"}, {5602, "aqualeg"},
            {5603, "aqualeg"}, {5604, "aqualeg"}, {5605, "aqualeg"},
            {5631, "pcanywhere"}, {5632, "pcanywhere"},
            {5666, "nagios-nrpe"}, {5667, "nagios-nsca"},
            {5672, "amqp"}, {5673, "amqp"}, {5674, "amqp"},
            {5675, "amqp"}, {5681, "ncx"}, {5682, "ncx"},
            {5683, "coap"}, {5684, "coaps"}, {5685, "coaps"},
            {5693, "nqs"}, {5701, "hazelcast"}, {5718, "microsoft-ds"},
            {5722, "dfs"}, {5723, "dfs"}, {5724, "dfs"},
            {5725, "dfs"}, {5741, "ida-discover"}, {5742, "ida-discover"},
            {5743, "ida-discover"}, {5744, "ida-discover"},
            {5800, "vnc-http"}, {5801, "vnc-http"}, {5802, "vnc-http"},
            {5803, "vnc-http"}, {5900, "vnc"}, {5901, "vnc"},
            {5984, "couchdb"}, {5985, "winrm"}, {5986, "winrm-ssl"},
            {6000, "x11"}, {6001, "x11"}, {6002, "x11"},
            {6379, "redis"}, {6380, "redis-ssl"}, {6443, "kubernetes"},
            {6480, "service"}, {6481, "service"}, {6666, "irc"},
            {6667, "irc"}, {6668, "irc"}, {6669, "irc"},
            {6670, "irc"}, {6697, "ircs"}, {6881, "bittorrent"},
            {6882, "bittorrent"}, {6883, "bittorrent"}, {6884, "bittorrent"},
            {6885, "bittorrent"}, {6886, "bittorrent"}, {6887, "bittorrent"},
            {6888, "bittorrent"}, {6889, "bittorrent"}, {6890, "bittorrent"},
            {6891, "bittorrent"}, {6900, "bittorrent"}, {6901, "bittorrent"},
            {6969, "bittorrent"}, {6970, "bittorrent"}, {7000, "afs3"},
            {7001, "afs3"}, {7002, "afs3"}, {7003, "afs3"},
            {7004, "afs3"}, {7005, "afs3"}, {7006, "afs3"},
            {7007, "afs3"}, {7008, "afs3"}, {7009, "afs3"},
            {7010, "afs3"}, {7070, "realserver"}, {7077, "nfs"},
            {7100, "x10"}, {7123, "snmp"}, {7171, "scp-config"},
            {7200, "nfs"}, {7201, "nfs"}, {7300, "swx"},
            {7301, "swx"}, {7302, "swx"}, {7303, "swx"},
            {7304, "swx"}, {7305, "swx"}, {7306, "swx"},
            {7307, "swx"}, {7308, "swx"}, {7309, "swx"},
            {7310, "swx"}, {7320, "swx"}, {7321, "swx"},
            {7322, "swx"}, {7323, "swx"}, {7324, "swx"},
            {7325, "swx"}, {7326, "swx"}, {7327, "swx"},
            {7328, "swx"}, {7329, "swx"}, {7330, "swx"},
            {7331, "swx"}, {7332, "swx"}, {7333, "swx"},
            {7334, "swx"}, {7335, "swx"}, {7336, "swx"},
            {7337, "swx"}, {7338, "swx"}, {7339, "swx"},
            {7340, "swx"}, {7341, "swx"}, {7342, "swx"},
            {7343, "swx"}, {7344, "swx"}, {7345, "swx"},
            {7346, "swx"}, {7347, "swx"}, {7348, "swx"},
            {7349, "swx"}, {7350, "swx"}, {7351, "swx"},
            {7352, "swx"}, {7353, "swx"}, {7354, "swx"},
            {7355, "swx"}, {7356, "swx"}, {7357, "swx"},
            {7358, "swx"}, {7359, "swx"}, {7360, "swx"},
            {7361, "swx"}, {7362, "swx"}, {7363, "swx"},
            {7364, "swx"}, {7365, "swx"}, {7366, "swx"},
            {7367, "swx"}, {7368, "swx"}, {7369, "swx"},
            {7370, "swx"}, {7371, "swx"}, {7372, "swx"},
            {7426, "opendesktop"}, {7427, "opendesktop"}, {7428, "opendesktop"},
            {7429, "opendesktop"}, {7430, "opendesktop"}, {7431, "opendesktop"},
            {7432, "opendesktop"}, {7433, "opendesktop"}, {7434, "opendesktop"},
            {7435, "opendesktop"}, {7436, "opendesktop"}, {7437, "opendesktop"},
            {7443, "oracle-https"}, {7474, "neo4j"}, {7547, "cwmp"},
            {7548, "cwmp"}, {7600, "couchdb"}, {7624, "instrument"},
            {7630, "instrument"}, {7654, "instrument"}, {7674, "instrument"},
            {7675, "instrument"}, {7676, "instrument"}, {7680, "pando"},
            {7687, "bolt"}, {7700, "p4p"}, {7701, "p4p"},
            {7702, "p4p"}, {7703, "p4p"}, {7704, "p4p"},
            {7705, "p4p"}, {7706, "p4p"}, {7707, "p4p"},
            {7708, "p4p"}, {7709, "p4p"}, {7710, "p4p"},
            {7711, "p4p"}, {7712, "p4p"}, {7713, "p4p"},
            {7714, "p4p"}, {7715, "p4p"}, {7716, "p4p"},
            {7717, "p4p"}, {7718, "p4p"}, {7719, "p4p"},
            {7720, "p4p"}, {7721, "p4p"}, {7722, "p4p"},
            {7723, "p4p"}, {7724, "p4p"}, {7725, "p4p"},
            {7726, "p4p"}, {7727, "p4p"}, {7728, "p4p"},
            {7729, "p4p"}, {7730, "p4p"}, {7731, "p4p"},
            {7732, "p4p"}, {7733, "p4p"}, {7734, "p4p"},
            {7735, "p4p"}, {7736, "p4p"}, {7737, "p4p"},
            {7738, "p4p"}, {7739, "p4p"}, {7740, "p4p"},
            {7741, "p4p"}, {7777, "cbt"}, {8000, "http-alt"},
            {8001, "http-alt"}, {8002, "http-alt"}, {8003, "http-alt"},
            {8004, "http-alt"}, {8005, "http-alt"}, {8006, "http-alt"},
            {8007, "http-alt"}, {8008, "http-alt"}, {8009, "ajp13"},
            {8010, "http-alt"}, {8080, "http-proxy"}, {8081, "http-proxy"},
            {8082, "http-proxy"}, {8083, "http-proxy"}, {8084, "http-proxy"},
            {8085, "http-proxy"}, {8086, "http-proxy"}, {8087, "http-proxy"},
            {8088, "http-proxy"}, {8089, "http-proxy"}, {8090, "http-proxy"},
            {8140, "puppet"}, {8172, "ms-web-deploy"}, {8181, "http-alt"},
            {8200, "tridion"}, {8222, "http-alt"}, {8243, "https-alt"},
            {8280, "http-alt"}, {8281, "http-alt"}, {8300, "tmi"},
            {8301, "tmi"}, {8312, "bloomberg"}, {8313, "bloomberg"},
            {8320, "tnp"}, {8321, "tnp"}, {8332, "bitcoin"},
            {8333, "bitcoin"}, {8350, "tnp"}, {8351, "tnp"},
            {8352, "tnp"}, {8353, "tnp"}, {8354, "tnp"},
            {8355, "tnp"}, {8384, "syncthing"}, {8400, "cvd"},
            {8401, "cvd"}, {8402, "cvd"}, {8403, "cvd"},
            {8404, "cvd"}, {8405, "cvd"}, {8416, "espeech"},
            {8417, "espeech"}, {8423, "aritts"}, {8442, "cybro-a-bus"},
            {8443, "https-alt"}, {8444, "https-alt"}, {8445, "https-alt"},
            {8450, "npmp"}, {8457, "nexentamv"},
            {8470, "cisco-avpair"}, {8471, "cisco-avpair"},
            {8472, "otv"}, {8473, "vp2p"}, {8474, "noteshare"},
            {8500, "http-alt"}, {8530, "http-alt"}, {8531, "http-alt"},
            {8554, "rtsp-alt"}, {8555, "rtsp-alt"}, {8560, "d-bus"},
            {8600, "asterisk"}, {8610, "canon-bjnp"}, {8611, "canon-bjnp"},
            {8612, "canon-bjnp"}, {8613, "canon-bjnp"}, {8614, "canon-bjnp"},
            {8615, "canon-bjnp"}, {8649, "ganglia"}, {8651, "ganglia"},
            {8652, "ganglia"}, {8654, "ganglia"}, {8675, "msi"},
            {8686, "sun-as"}, {8733, "ibm-ins"}, {8750, "dey-keyneg"},
            {8763, "mc-appserver"}, {8764, "mc-appserver"},
            {8765, "mc-appserver"}, {8766, "mc-appserver"},
            {8767, "mc-appserver"}, {8768, "mc-appserver"},
            {8769, "mc-appserver"}, {8770, "mc-appserver"},
            {8778, "uep"}, {8786, "msgclnt"}, {8787, "msgsrvr"},
            {8790, "sun-license"}, {8791, "sun-license"},
            {8792, "sun-license"}, {8793, "sun-license"},
            {8794, "sun-license"}, {8800, "http-alt"},
            {8810, "http-alt"}, {8820, "http-alt"}, {8830, "http-alt"},
            {8840, "http-alt"}, {8850, "http-alt"}, {8860, "http-alt"},
            {8870, "http-alt"}, {8873, "http-alt"}, {8880, "http-alt"},
            {8881, "http-alt"}, {8882, "http-alt"}, {8883, "mqtt-ssl"},
            {8888, "http-alt"}, {8889, "http-alt"}, {8890, "http-alt"},
            {8891, "http-alt"}, {8892, "http-alt"}, {8899, "http-alt"},
            {8900, "http-alt"}, {8910, "http-alt"}, {8920, "http-alt"},
            {8930, "http-alt"}, {8940, "http-alt"}, {8950, "http-alt"},
            {8960, "http-alt"}, {8970, "http-alt"}, {8980, "http-alt"},
            {8983, "solr"}, {8990, "http-alt"}, {8991, "http-alt"},
            {8992, "http-alt"}, {8993, "http-alt"}, {8994, "http-alt"},
            {8995, "http-alt"}, {8996, "http-alt"}, {8997, "http-alt"},
            {8998, "http-alt"}, {8999, "http-alt"}, {9000, "sonarr"},
            {9001, "tor"}, {9002, "tor"}, {9003, "tor"},
            {9004, "tor"}, {9005, "tor"}, {9006, "tor"},
            {9007, "tor"}, {9008, "tor"}, {9009, "tor"},
            {9010, "tor"}, {9042, "cassandra"}, {9043, "glassfish"},
            {9050, "tor"}, {9051, "tor"}, {9060, "tor"},
            {9080, "glrpc"}, {9090, "websm"}, {9091, "websm"},
            {9092, "kafka"}, {9093, "kafka-ssl"}, {9094, "kafka"},
            {9095, "kafka"}, {9100, "jetdirect"}, {9101, "jetdirect"},
            {9102, "jetdirect"}, {9103, "jetdirect"}, {9104, "jetdirect"},
            {9105, "jetdirect"}, {9106, "jetdirect"}, {9107, "jetdirect"},
            {9110, "http-alt"}, {9111, "http-alt"}, {9120, "http-alt"},
            {9121, "http-alt"}, {9122, "http-alt"}, {9123, "http-alt"},
            {9124, "http-alt"}, {9125, "http-alt"}, {9126, "http-alt"},
            {9130, "http-alt"}, {9140, "http-alt"}, {9150, "http-alt"},
            {9151, "http-alt"}, {9160, "http-alt"}, {9161, "http-alt"},
            {9170, "http-alt"}, {9180, "http-alt"}, {9190, "http-alt"},
            {9200, "elasticsearch"}, {9201, "elasticsearch"}, {9202, "elasticsearch"},
            {9210, "http-alt"}, {9220, "http-alt"}, {9229, "node-inspector"},
            {9230, "http-alt"}, {9240, "http-alt"}, {9250, "http-alt"},
            {9260, "http-alt"}, {9270, "http-alt"}, {9280, "http-alt"},
            {9290, "http-alt"}, {9292, "http-alt"}, {9293, "http-alt"},
            {9294, "http-alt"}, {9295, "http-alt"}, {9300, "elasticsearch"},
            {9301, "elasticsearch"}, {9302, "elasticsearch"}, {9303, "elasticsearch"},
            {9304, "elasticsearch"}, {9305, "elasticsearch"}, {9306, "elasticsearch"},
            {9307, "elasticsearch"}, {9308, "elasticsearch"}, {9309, "elasticsearch"},
            {9310, "elasticsearch"}, {9311, "elasticsearch"}, {9312, "elasticsearch"},
            {9313, "elasticsearch"}, {9314, "elasticsearch"}, {9315, "elasticsearch"},
            {9316, "elasticsearch"}, {9317, "elasticsearch"}, {9318, "elasticsearch"},
            {9319, "elasticsearch"}, {9320, "elasticsearch"}, {9418, "git"},
            {9443, "https-alt"}, {9444, "https-alt"}, {9500, "http-alt"},
            {9530, "http-alt"}, {9535, "http-alt"}, {9600, "http-alt"},
            {9675, "spdp"}, {9676, "spdp"}, {9696, "http-alt"},
            {9700, "http-alt"}, {9800, "http-alt"}, {9876, "sd"},
            {9877, "sd"}, {9878, "sd"}, {9898, "monkeycom"},
            {9900, "http-alt"}, {9981, "tvheadend"}, {9982, "tvheadend"},
            {9993, "zerotier"}, {9997, "splunk"}, {9998, "http-alt"},
            {9999, "http-alt"}, {10000, "ndmp"}, {10001, "scp-config"},
            {10002, "scp-config"}, {10003, "scp-config"}, {10004, "scp-config"},
            {10005, "scp-config"}, {10009, "dameware"}, {10010, "http-alt"},
            {10050, "zabbix-agent"}, {10051, "zabbix-trapper"},
            {10250, "kubelet"}, {10251, "kube-scheduler"},
            {10252, "kube-controller"}, {10255, "kubelet-readonly"},
            {11211, "memcached"}, {11214, "memcached-ssl"},
            {11215, "memcached-ssl"}, {11371, "hkp"},
            {12000, "http-alt"}, {12345, "netbus"}, {13720, "veritas"},
            {13721, "veritas"}, {13722, "veritas"}, {13724, "veritas"},
            {13782, "veritas"}, {13783, "veritas"}, {14000, "http-alt"},
            {16000, "http-alt"}, {16010, "http-alt"}, {16012, "http-alt"},
            {16016, "http-alt"}, {16113, "http-alt"}, {16384, "cisco-sccp"},
            {16385, "cisco-sccp"}, {16386, "cisco-sccp"},
            {16387, "cisco-sccp"}, {16388, "cisco-sccp"},
            {16389, "cisco-sccp"}, {16390, "cisco-sccp"},
            {16391, "cisco-sccp"}, {16392, "cisco-sccp"},
            {16393, "cisco-sccp"}, {16394, "cisco-sccp"},
            {16395, "cisco-sccp"}, {16396, "cisco-sccp"},
            {16397, "cisco-sccp"}, {16398, "cisco-sccp"},
            {16399, "cisco-sccp"}, {16400, "cisco-sccp"},
            {16401, "cisco-sccp"}, {16402, "cisco-sccp"},
            {16403, "cisco-sccp"}, {16404, "cisco-sccp"},
            {16405, "cisco-sccp"}, {16406, "cisco-sccp"},
            {16567, "cisco-sccp"}, {17000, "http-alt"},
            {18000, "http-alt"}, {18080, "http-alt"}, {18181, "http-alt"},
            {18200, "http-alt"}, {18201, "http-alt"}, {18202, "http-alt"},
            {18203, "http-alt"}, {18204, "http-alt"}, {18205, "http-alt"},
            {18206, "http-alt"}, {18207, "http-alt"}, {18208, "http-alt"},
            {18209, "http-alt"}, {18210, "http-alt"}, {18400, "http-alt"},
            {18901, "http-alt"}, {19000, "http-alt"}, {19001, "http-alt"},
            {19100, "http-alt"}, {19101, "http-alt"}, {19102, "http-alt"},
            {19103, "http-alt"}, {19104, "http-alt"}, {19105, "http-alt"},
            {19106, "http-alt"}, {19107, "http-alt"}, {19108, "http-alt"},
            {19109, "http-alt"}, {19110, "http-alt"}, {19111, "http-alt"},
            {19112, "http-alt"}, {19113, "http-alt"}, {19114, "http-alt"},
            {19115, "http-alt"}, {19116, "http-alt"}, {19117, "http-alt"},
            {19118, "http-alt"}, {19119, "http-alt"}, {19120, "http-alt"},
            {19121, "http-alt"}, {19122, "http-alt"}, {19123, "http-alt"},
            {19124, "http-alt"}, {19125, "http-alt"}, {19126, "http-alt"},
            {19127, "http-alt"}, {19128, "http-alt"}, {19129, "http-alt"},
            {19130, "http-alt"}, {19131, "http-alt"}, {19132, "http-alt"},
            {19133, "http-alt"}, {19134, "http-alt"}, {19135, "http-alt"},
            {19136, "http-alt"}, {19137, "http-alt"}, {19138, "http-alt"},
            {19139, "http-alt"}, {19140, "http-alt"}, {19141, "http-alt"},
            {19142, "http-alt"}, {19143, "http-alt"}, {19144, "http-alt"},
            {19145, "http-alt"}, {19146, "http-alt"}, {19147, "http-alt"},
            {19148, "http-alt"}, {19149, "http-alt"}, {19150, "http-alt"},
            {19151, "http-alt"}, {19152, "http-alt"}, {19153, "http-alt"},
            {19154, "http-alt"}, {19155, "http-alt"}, {19156, "http-alt"},
            {19157, "http-alt"}, {19158, "http-alt"}, {19159, "http-alt"},
            {19160, "http-alt"}, {19161, "http-alt"}, {19162, "http-alt"},
            {19163, "http-alt"}, {19164, "http-alt"}, {19165, "http-alt"},
            {19166, "http-alt"}, {19167, "http-alt"}, {19168, "http-alt"},
            {19169, "http-alt"}, {19170, "http-alt"}, {19171, "http-alt"},
            {19172, "http-alt"}, {19173, "http-alt"}, {19174, "http-alt"},
            {19175, "http-alt"}, {19176, "http-alt"}, {19177, "http-alt"},
            {19178, "http-alt"}, {19179, "http-alt"}, {19180, "http-alt"},
            {19181, "http-alt"}, {19182, "http-alt"}, {19183, "http-alt"},
            {19184, "http-alt"}, {19185, "http-alt"}, {19186, "http-alt"},
            {19187, "http-alt"}, {19188, "http-alt"}, {19189, "http-alt"},
            {19190, "http-alt"}, {19191, "http-alt"}, {19192, "http-alt"},
            {19193, "http-alt"}, {19194, "http-alt"}, {19195, "http-alt"},
            {19196, "http-alt"}, {19197, "http-alt"}, {19198, "http-alt"},
            {19199, "http-alt"}, {19200, "http-alt"}, {19201, "http-alt"},
            {19202, "http-alt"}, {19203, "http-alt"}, {19204, "http-alt"},
            {19205, "http-alt"}, {19206, "http-alt"}, {19207, "http-alt"},
            {19208, "http-alt"}, {19209, "http-alt"}, {19210, "http-alt"},
            {19211, "http-alt"}, {19212, "http-alt"}, {19213, "http-alt"},
            {19214, "http-alt"}, {19215, "http-alt"}, {19216, "http-alt"},
            {19217, "http-alt"}, {19218, "http-alt"}, {19219, "http-alt"},
            {19220, "http-alt"}, {19221, "http-alt"}, {19222, "http-alt"},
            {19223, "http-alt"}, {19224, "http-alt"}, {19225, "http-alt"},
            {19226, "http-alt"}, {19227, "http-alt"}, {19228, "http-alt"},
            {19229, "http-alt"}, {19230, "http-alt"}, {19231, "http-alt"},
            {19232, "http-alt"}, {19233, "http-alt"}, {19234, "http-alt"},
            {19235, "http-alt"}, {19236, "http-alt"}, {19237, "http-alt"},
            {19238, "http-alt"}, {19239, "http-alt"}, {19240, "http-alt"},
            {19241, "http-alt"}, {19242, "http-alt"}, {19243, "http-alt"},
            {19244, "http-alt"}, {19245, "http-alt"}, {19246, "http-alt"},
            {19247, "http-alt"}, {19248, "http-alt"}, {19249, "http-alt"},
            {19250, "http-alt"}, {19251, "http-alt"}, {19252, "http-alt"},
            {19253, "http-alt"}, {19254, "http-alt"}, {19255, "http-alt"},
            {19256, "http-alt"}, {19257, "http-alt"}, {19258, "http-alt"},
            {19259, "http-alt"}, {19260, "http-alt"}, {19261, "http-alt"},
            {19262, "http-alt"}, {19263, "http-alt"}, {19264, "http-alt"},
            {19265, "http-alt"}, {19266, "http-alt"}, {19267, "http-alt"},
            {19268, "http-alt"}, {19269, "http-alt"}, {19270, "http-alt"},
            {19271, "http-alt"}, {19272, "http-alt"}, {19273, "http-alt"},
            {19274, "http-alt"}, {19275, "http-alt"}, {19276, "http-alt"},
            {19277, "http-alt"}, {19278, "http-alt"}, {19279, "http-alt"},
            {19280, "http-alt"}, {19281, "http-alt"}, {19282, "http-alt"},
            {19283, "http-alt"}, {19284, "http-alt"}, {19285, "http-alt"},
            {19286, "http-alt"}, {19287, "http-alt"}, {19288, "http-alt"},
            {19289, "http-alt"}, {19290, "http-alt"}, {19291, "http-alt"},
            {19292, "http-alt"}, {19293, "http-alt"}, {19294, "http-alt"},
            {19295, "http-alt"}, {19296, "http-alt"}, {19297, "http-alt"},
            {19298, "http-alt"}, {19299, "http-alt"}, {19300, "http-alt"},
            {19301, "http-alt"}, {19302, "http-alt"}, {19303, "http-alt"},
            {19304, "http-alt"}, {19305, "http-alt"}, {19306, "http-alt"},
            {19307, "http-alt"}, {19308, "http-alt"}, {19309, "http-alt"},
            {19310, "http-alt"}, {19311, "http-alt"}, {19312, "http-alt"},
            {19313, "http-alt"}, {19314, "http-alt"}, {19315, "http-alt"},
            {19316, "http-alt"}, {19317, "http-alt"}, {19318, "http-alt"},
            {19319, "http-alt"}, {19320, "http-alt"}, {19321, "http-alt"},
            {19322, "http-alt"}, {19323, "http-alt"}, {19324, "http-alt"},
            {19325, "http-alt"}, {19326, "http-alt"}, {19327, "http-alt"},
            {19328, "http-alt"}, {19329, "http-alt"}, {19330, "http-alt"},
            {19331, "http-alt"}, {19332, "http-alt"}, {19333, "http-alt"},
            {19334, "http-alt"}, {19335, "http-alt"}, {19336, "http-alt"},
            {19337, "http-alt"}, {19338, "http-alt"}, {19339, "http-alt"},
            {19340, "http-alt"}, {19341, "http-alt"}, {19342, "http-alt"},
            {19343, "http-alt"}, {19344, "http-alt"}, {19345, "http-alt"},
            {19346, "http-alt"}, {19347, "http-alt"}, {19348, "http-alt"},
            {19349, "http-alt"}, {19350, "http-alt"}, {20000, "dicom"},
            {20001, "dicom"}, {20002, "dicom"}, {20003, "dicom"},
            {20004, "dicom"}, {20005, "dicom"}, {20006, "dicom"},
            {20007, "dicom"}, {20008, "dicom"}, {20009, "dicom"},
            {20010, "dicom"}, {20011, "dicom"}, {20012, "dicom"},
            {20013, "dicom"}, {20014, "dicom"}, {20015, "dicom"},
            {20016, "dicom"}, {20017, "dicom"}, {20018, "dicom"},
            {20019, "dicom"}, {20020, "dicom"}, {20021, "dicom"},
            {20022, "dicom"}, {20023, "dicom"}, {20024, "dicom"},
            {20025, "dicom"}, {20026, "dicom"}, {20027, "dicom"},
            {20028, "dicom"}, {20029, "dicom"}, {20030, "dicom"},
            {20031, "dicom"}, {20032, "dicom"}, {20033, "dicom"},
            {20034, "dicom"}, {20035, "dicom"}, {20036, "dicom"},
            {20037, "dicom"}, {20038, "dicom"}, {20039, "dicom"},
            {20040, "dicom"}, {20041, "dicom"}, {20042, "dicom"},
            {20043, "dicom"}, {20044, "dicom"}, {20045, "dicom"},
            {20046, "dicom"}, {20047, "dicom"}, {20048, "dicom"},
            {20049, "dicom"}, {20050, "dicom"}, {20051, "dicom"},
            {20052, "dicom"}, {20053, "dicom"}, {20054, "dicom"},
            {20055, "dicom"}, {20056, "dicom"}, {20057, "dicom"},
            {20058, "dicom"}, {20059, "dicom"}, {20060, "dicom"},
            {20061, "dicom"}, {20062, "dicom"}, {20063, "dicom"},
            {20064, "dicom"}, {20065, "dicom"}, {20066, "dicom"},
            {20067, "dicom"}, {20068, "dicom"}, {20069, "dicom"},
            {20070, "dicom"}, {20071, "dicom"}, {20072, "dicom"},
            {20073, "dicom"}, {20074, "dicom"}, {20075, "dicom"},
            {20076, "dicom"}, {20077, "dicom"}, {20078, "dicom"},
            {20079, "dicom"}, {20080, "dicom"}, {20081, "dicom"},
            {20082, "dicom"}, {20083, "dicom"}, {20084, "dicom"},
            {20085, "dicom"}, {20086, "dicom"}, {20087, "dicom"},
            {20088, "dicom"}, {20089, "dicom"}, {20090, "dicom"},
            {20091, "dicom"}, {20092, "dicom"}, {20093, "dicom"},
            {20094, "dicom"}, {20095, "dicom"}, {20096, "dicom"},
            {20097, "dicom"}, {20098, "dicom"}, {20099, "dicom"},
            {20100, "dicom"}, {21025, "tcp"}, {21320, "db2"},
            {21321, "db2"}, {21322, "db2"}, {21323, "db2"},
            {21324, "db2"}, {21325, "db2"}, {21326, "db2"},
            {21327, "db2"}, {21328, "db2"}, {21329, "db2"},
            {21330, "db2"}, {21509, "db2"}, {21510, "db2"},
            {21511, "db2"}, {21512, "db2"}, {21513, "db2"},
            {21514, "db2"}, {21515, "db2"}, {21516, "db2"},
            {21517, "db2"}, {21518, "db2"}, {21519, "db2"},
            {21520, "db2"}, {21521, "db2"}, {21522, "db2"},
            {21523, "db2"}, {21524, "db2"}, {21525, "db2"},
            {21526, "db2"}, {21527, "db2"}, {21528, "db2"},
            {21529, "db2"}, {21530, "db2"}, {21531, "db2"},
            {21532, "db2"}, {21533, "db2"}, {21534, "db2"},
            {21535, "db2"}, {21536, "db2"}, {21537, "db2"},
            {21538, "db2"}, {21539, "db2"}, {21540, "db2"},
            {21541, "db2"}, {21542, "db2"}, {21543, "db2"},
            {21544, "db2"}, {21545, "db2"}, {21546, "db2"},
            {21547, "db2"}, {21548, "db2"}, {21549, "db2"},
            {21550, "db2"}, {21551, "db2"}, {21552, "db2"},
            {21553, "db2"}, {21554, "db2"}, {21555, "db2"},
            {21556, "db2"}, {21557, "db2"}, {21558, "db2"},
            {21559, "db2"}, {21560, "db2"},
            {25565, "minecraft"}, {26257, "cockroachdb"}, {27017, "mongod"},
            {27018, "mongod"}, {27019, "mongod"}, {27020, "mongod"},
            {27021, "mongod"}, {27022, "mongod"}, {27023, "mongod"},
            {27024, "mongod"}, {27025, "mongod"}, {27026, "mongod"},
            {27027, "mongod"}, {27028, "mongod"}, {27029, "mongod"},
            {27030, "mongod"}, {27031, "mongod"}, {27032, "mongod"},
            {27033, "mongod"}, {27034, "mongod"}, {27035, "mongod"},
            {27036, "mongod"}, {27037, "mongod"}, {27038, "mongod"},
            {27039, "mongod"}, {27040, "mongod"}, {27117, "mongod"},
            {28015, "rethinkdb"}, {28017, "mongod-http"},
            {29015, "rethinkdb"}, {29016, "rethinkdb"},
            {30718, "lantronix"}, {31337, "backorifice"},
            {32400, "plex"}, {32764, "cisco-listen"}, {32768, "rpc"},
            {32769, "rpc"}, {32770, "rpc"}, {32771, "rpc"},
            {32772, "rpc"}, {32773, "rpc"}, {32774, "rpc"},
            {32775, "rpc"}, {32776, "rpc"}, {32777, "rpc"},
            {32778, "rpc"}, {32779, "rpc"}, {32780, "rpc"},
            {32781, "rpc"}, {32782, "rpc"}, {32783, "rpc"},
            {32784, "rpc"}, {32785, "rpc"}, {32786, "rpc"},
            {32787, "rpc"}, {32788, "rpc"}, {32789, "rpc"},
            {32790, "rpc"}, {32791, "rpc"}, {32792, "rpc"},
            {32793, "rpc"}, {32794, "rpc"}, {32795, "rpc"},
            {32796, "rpc"}, {32797, "rpc"}, {32798, "rpc"},
            {32799, "rpc"}, {32800, "rpc"}, {32801, "rpc"},
            {32802, "rpc"}, {32803, "rpc"}, {32804, "rpc"},
            {32805, "rpc"}, {32806, "rpc"}, {32807, "rpc"},
            {32808, "rpc"}, {32809, "rpc"}, {32810, "rpc"},
            {32811, "rpc"}, {32812, "rpc"}, {32813, "rpc"},
            {32814, "rpc"}, {32815, "rpc"}, {32816, "rpc"},
            {32817, "rpc"}, {32818, "rpc"}, {32819, "rpc"},
            {32820, "rpc"}, {32821, "rpc"}, {32822, "rpc"},
            {32823, "rpc"}, {32824, "rpc"}, {32825, "rpc"},
            {32826, "rpc"}, {32827, "rpc"}, {32828, "rpc"},
            {32829, "rpc"}, {32830, "rpc"}, {32831, "rpc"},
            {32832, "rpc"}, {32833, "rpc"}, {32834, "rpc"},
            {32835, "rpc"}, {32836, "rpc"}, {32837, "rpc"},
            {32838, "rpc"}, {32839, "rpc"}, {32840, "rpc"},
            {32841, "rpc"}, {32842, "rpc"}, {32843, "rpc"},
            {32844, "rpc"}, {32845, "rpc"}, {32846, "rpc"},
            {32847, "rpc"}, {32848, "rpc"}, {32849, "rpc"},
            {32850, "rpc"}, {32851, "rpc"}, {32852, "rpc"},
            {32853, "rpc"}, {32854, "rpc"}, {32855, "rpc"},
            {32856, "rpc"}, {32857, "rpc"}, {32858, "rpc"},
            {32859, "rpc"}, {32860, "rpc"}, {32861, "rpc"},
            {32862, "rpc"}, {32863, "rpc"}, {32864, "rpc"},
            {32865, "rpc"}, {32866, "rpc"}, {32867, "rpc"},
            {32868, "rpc"}, {32869, "rpc"}, {32870, "rpc"},
            {32871, "rpc"}, {32872, "rpc"}, {32873, "rpc"},
            {32874, "rpc"}, {32875, "rpc"}, {32876, "rpc"},
            {32877, "rpc"}, {32878, "rpc"}, {32879, "rpc"},
            {32880, "rpc"}, {32881, "rpc"}, {32882, "rpc"},
            {32883, "rpc"}, {32884, "rpc"}, {32885, "rpc"},
            {32886, "rpc"}, {32887, "rpc"}, {32888, "rpc"},
            {32889, "rpc"}, {32890, "rpc"}, {32891, "rpc"},
            {32892, "rpc"}, {32893, "rpc"}, {32894, "rpc"},
            {32895, "rpc"}, {32896, "rpc"}, {32897, "rpc"},
            {32898, "rpc"}, {32899, "rpc"}, {32900, "rpc"},
            {32901, "rpc"}, {32902, "rpc"}, {32903, "rpc"},
            {32904, "rpc"}, {32905, "rpc"}, {32906, "rpc"},
            {32907, "rpc"}, {32908, "rpc"}, {32909, "rpc"},
            {32910, "rpc"}, {32911, "rpc"}, {32912, "rpc"},
            {32913, "rpc"}, {32914, "rpc"}, {32915, "rpc"},
            {32916, "rpc"}, {32917, "rpc"}, {32918, "rpc"},
            {32919, "rpc"}, {32920, "rpc"}, {32921, "rpc"},
            {32922, "rpc"}, {32923, "rpc"}, {32924, "rpc"},
            {32925, "rpc"}, {32926, "rpc"}, {32927, "rpc"},
            {32928, "rpc"}, {32929, "rpc"}, {32930, "rpc"},
            {32931, "rpc"}, {32932, "rpc"}, {32933, "rpc"},
            {32934, "rpc"}, {32935, "rpc"}, {32936, "rpc"},
            {32937, "rpc"}, {32938, "rpc"}, {32939, "rpc"},
            {32940, "rpc"}, {32941, "rpc"}, {32942, "rpc"},
            {32943, "rpc"}, {32944, "rpc"}, {32945, "rpc"},
            {32946, "rpc"}, {32947, "rpc"}, {32948, "rpc"},
            {32949, "rpc"}, {32950, "rpc"}, {32951, "rpc"},
            {32952, "rpc"}, {32953, "rpc"}, {32954, "rpc"},
            {32955, "rpc"}, {32956, "rpc"}, {32957, "rpc"},
            {32958, "rpc"}, {32959, "rpc"}, {32960, "rpc"},
            {32961, "rpc"}, {32962, "rpc"}, {32963, "rpc"},
            {32964, "rpc"}, {32965, "rpc"}, {32966, "rpc"},
            {32967, "rpc"}, {32968, "rpc"}, {32969, "rpc"},
            {32970, "rpc"}, {32971, "rpc"}, {32972, "rpc"},
            {32973, "rpc"}, {32974, "rpc"}, {32975, "rpc"},
            {32976, "rpc"}, {32977, "rpc"}, {32978, "rpc"},
            {32979, "rpc"}, {32980, "rpc"}, {32981, "rpc"},
            {32982, "rpc"}, {32983, "rpc"}, {32984, "rpc"},
            {32985, "rpc"}, {32986, "rpc"}, {32987, "rpc"},
            {32988, "rpc"}, {32989, "rpc"}, {32990, "rpc"},
            {32991, "rpc"}, {32992, "rpc"}, {32993, "rpc"},
            {32994, "rpc"}, {32995, "rpc"}, {32996, "rpc"},
            {32997, "rpc"}, {32998, "rpc"}, {32999, "rpc"},
            {33000, "rpc"}, {33001, "rpc"}, {33002, "rpc"},
            {33003, "rpc"}, {33004, "rpc"}, {33005, "rpc"},
            {33006, "rpc"}, {33007, "rpc"}, {33008, "rpc"},
            {33009, "rpc"}, {33010, "rpc"}, {33011, "rpc"},
            {33012, "rpc"}, {33013, "rpc"}, {33014, "rpc"},
            {33015, "rpc"}, {33016, "rpc"}, {33017, "rpc"},
            {33018, "rpc"}, {33019, "rpc"}, {33020, "rpc"},
            {33021, "rpc"}, {33022, "rpc"}, {33023, "rpc"},
            {33024, "rpc"}, {33025, "rpc"}, {33026, "rpc"},
            {33027, "rpc"}, {33028, "rpc"}, {33029, "rpc"},
            {33030, "rpc"}, {33031, "rpc"}, {33032, "rpc"},
            {33033, "rpc"}, {33034, "rpc"}, {33035, "rpc"},
            {33036, "rpc"}, {33037, "rpc"}, {33038, "rpc"},
            {33039, "rpc"}, {33040, "rpc"}, {33041, "rpc"},
            {33042, "rpc"}, {33043, "rpc"}, {33044, "rpc"},
            {33045, "rpc"}, {33046, "rpc"}, {33047, "rpc"},
            {33048, "rpc"}, {33049, "rpc"}, {33050, "rpc"},
            {33051, "rpc"}, {33052, "rpc"}, {33053, "rpc"},
            {33054, "rpc"}, {33055, "rpc"}, {33056, "rpc"},
            {33057, "rpc"}, {33058, "rpc"}, {33059, "rpc"},
            {33060, "mysql-x"}, {33123, "aurora"}, {33333, "rpc"},
            {33334, "rpc"}, {33434, "traceroute"},
            {44818, "ethernetip"}, {47808, "bacnet"}, {49152, "rpc"},
            {49153, "rpc"}, {49154, "rpc"}, {49155, "rpc"},
            {49156, "rpc"}, {49157, "rpc"}, {49158, "rpc"},
            {49159, "rpc"}, {49160, "rpc"}, {49161, "rpc"},
            {49162, "rpc"}, {49163, "rpc"}, {49164, "rpc"},
            {49165, "rpc"}, {49166, "rpc"}, {49167, "rpc"},
            {49168, "rpc"}, {49169, "rpc"}, {49170, "rpc"},
            {49171, "rpc"}, {49172, "rpc"}, {49173, "rpc"},
            {49174, "rpc"}, {49175, "rpc"}, {49176, "rpc"},
            {49177, "rpc"}, {49178, "rpc"}, {49179, "rpc"},
            {49180, "rpc"}, {49181, "rpc"}, {49182, "rpc"},
            {49183, "rpc"}, {49184, "rpc"}, {49185, "rpc"},
            {49186, "rpc"}, {49187, "rpc"}, {49188, "rpc"},
            {49189, "rpc"}, {49190, "rpc"}, {49191, "rpc"},
            {49192, "rpc"}, {49193, "rpc"}, {49194, "rpc"},
            {49195, "rpc"}, {49196, "rpc"}, {49197, "rpc"},
            {49198, "rpc"}, {49199, "rpc"}, {49200, "rpc"},
            {49201, "rpc"}, {49202, "rpc"}, {49203, "rpc"},
            {49204, "rpc"}, {49205, "rpc"}, {49206, "rpc"},
            {49207, "rpc"}, {49208, "rpc"}, {49209, "rpc"},
            {49210, "rpc"}, {49211, "rpc"}, {49212, "rpc"},
            {49213, "rpc"}, {49214, "rpc"}, {49215, "rpc"},
            {49216, "rpc"}, {49217, "rpc"}, {49218, "rpc"},
            {49219, "rpc"}, {49220, "rpc"}, {49221, "rpc"},
            {49222, "rpc"}, {49223, "rpc"}, {49224, "rpc"},
            {49225, "rpc"}, {49226, "rpc"}, {49227, "rpc"},
            {49228, "rpc"}, {49229, "rpc"}, {49230, "rpc"},
            {49231, "rpc"}, {49232, "rpc"}, {49233, "rpc"},
            {49234, "rpc"}, {49235, "rpc"}, {49236, "rpc"},
            {49237, "rpc"}, {49238, "rpc"}, {49239, "rpc"},
            {49240, "rpc"}, {49241, "rpc"}, {49242, "rpc"},
            {49243, "rpc"}, {49244, "rpc"}, {49245, "rpc"},
            {49246, "rpc"}, {49247, "rpc"}, {49248, "rpc"},
            {49249, "rpc"}, {49250, "rpc"}, {49251, "rpc"},
            {49252, "rpc"}, {49253, "rpc"}, {49254, "rpc"},
            {49255, "rpc"}, {49256, "rpc"}, {49257, "rpc"},
            {49258, "rpc"}, {49259, "rpc"}, {49260, "rpc"},
            {49261, "rpc"}, {49262, "rpc"}, {49263, "rpc"},
            {49264, "rpc"}, {49265, "rpc"}, {49266, "rpc"},
            {49267, "rpc"}, {49268, "rpc"}, {49269, "rpc"},
            {49270, "rpc"}, {49271, "rpc"}, {49272, "rpc"},
            {49273, "rpc"}, {49274, "rpc"}, {49275, "rpc"},
            {49276, "rpc"}, {49277, "rpc"}, {49278, "rpc"},
            {49279, "rpc"}, {49280, "rpc"}, {49281, "rpc"},
            {49282, "rpc"}, {49283, "rpc"}, {49284, "rpc"},
            {49285, "rpc"}, {49286, "rpc"}, {49287, "rpc"},
            {49288, "rpc"}, {49289, "rpc"}, {49290, "rpc"},
            {49291, "rpc"}, {49292, "rpc"}, {49293, "rpc"},
            {49294, "rpc"}, {49295, "rpc"}, {49296, "rpc"},
            {49297, "rpc"}, {49298, "rpc"}, {49299, "rpc"},
            {49300, "rpc"}, {49301, "rpc"}, {49302, "rpc"},
            {49303, "rpc"}, {49304, "rpc"}, {49305, "rpc"},
            {49306, "rpc"}, {49307, "rpc"}, {49308, "rpc"},
            {49309, "rpc"}, {49310, "rpc"}, {49311, "rpc"},
            {49312, "rpc"}, {49313, "rpc"}, {49314, "rpc"},
            {49315, "rpc"}, {49316, "rpc"}, {49317, "rpc"},
            {49318, "rpc"}, {49319, "rpc"}, {49320, "rpc"},
            {49321, "rpc"}, {49322, "rpc"}, {49323, "rpc"},
            {49324, "rpc"}, {49325, "rpc"}, {49326, "rpc"},
            {49327, "rpc"}, {49328, "rpc"}, {49329, "rpc"},
            {49330, "rpc"}, {49331, "rpc"}, {49332, "rpc"},
            {49333, "rpc"}, {49334, "rpc"}, {49335, "rpc"},
            {49336, "rpc"}, {49337, "rpc"}, {49338, "rpc"},
            {49339, "rpc"}, {49340, "rpc"}, {49341, "rpc"},
            {49342, "rpc"}, {49343, "rpc"}, {49344, "rpc"},
            {49345, "rpc"}, {49346, "rpc"}, {49347, "rpc"},
            {49348, "rpc"}, {49349, "rpc"}, {49350, "rpc"},
            {49351, "rpc"}, {49352, "rpc"}, {49353, "rpc"},
            {49354, "rpc"}, {49355, "rpc"}, {49356, "rpc"},
            {49357, "rpc"}, {49358, "rpc"}, {49359, "rpc"},
            {49360, "rpc"}, {49361, "rpc"}, {49362, "rpc"},
            {49363, "rpc"}, {49364, "rpc"}, {49365, "rpc"},
            {49366, "rpc"}, {49367, "rpc"}, {49368, "rpc"},
            {49369, "rpc"}, {49370, "rpc"}, {49371, "rpc"},
            {49372, "rpc"}, {49373, "rpc"}, {49374, "rpc"},
            {49375, "rpc"}, {49376, "rpc"}, {49377, "rpc"},
            {49378, "rpc"}, {49379, "rpc"}, {49380, "rpc"},
            {49381, "rpc"}, {49382, "rpc"}, {49383, "rpc"},
            {49384, "rpc"}, {49385, "rpc"}, {49386, "rpc"},
            {49387, "rpc"}, {49388, "rpc"}, {49389, "rpc"},
            {49390, "rpc"}, {49391, "rpc"}, {49392, "rpc"},
            {49393, "rpc"}, {49394, "rpc"}, {49395, "rpc"},
            {49396, "rpc"}, {49397, "rpc"}, {49398, "rpc"},
            {49399, "rpc"}, {49400, "rpc"}, {50070, "hadoop-nn"},
            {50075, "hadoop-dn"}, {50090, "hadoop-nn-http"},
            {60000, "dynamo"}, {60020, "hbase-region"},
            {60030, "hbase-master"}, {61616, "activemq"},
            {61617, "activemq"}, {61618, "activemq"},
            {61619, "activemq"}, {61620, "activemq"},
            {61621, "activemq"}, {61622, "activemq"},
            {61623, "activemq"}, {61624, "activemq"},
            {61625, "activemq"}, {61626, "activemq"},
            {61627, "activemq"}, {61628, "activemq"},
            {61629, "activemq"}, {61630, "activemq"},
            {61631, "activemq"}, {61632, "activemq"},
            {61633, "activemq"}, {61634, "activemq"},
            {61635, "activemq"}, {61636, "activemq"},
            {64738, "mumble"}, {65535, "unknown"}
        };
    }

    std::string normalize_service(std::string_view s) {
        std::string n;
        for (char c : s) {
            n += std::tolower(static_cast<unsigned char>(c));
        }
        return n;
    }

public:
    AnomalyDetector() {
        init_known_ports();
    }

    std::vector<Anomaly> detect(const std::vector<PortResult>& port_results) {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Anomaly> anomalies;

        if (port_results.empty()) return anomalies;

        int total = port_results.size();
        int filtered_count = 0;
        int open_count = 0;
        std::vector<int> banner_lengths;
banner_lengths.reserve(256);
for (const auto& pr : port_results) {
            if (pr.status == "filtered" || pr.status == "closed") filtered_count++;
            if (pr.status == "open") {
                open_count++;
                banner_lengths.emplace_back(pr.banner_length);
            }
        }

        if (filtered_count == total && total > 0) {
            anomalies.push_back({"all_filtered",
                "All " + std::to_string(total) + " ports appear filtered - firewall detected",
                0, 0.9, 0.95});
        }

        for (const auto& pr : port_results) {
            if (pr.status == "open" && !pr.service.empty()) {
                auto it = known_ports.find(pr.port);
                if (it != known_ports.end()) {
                    std::string expected = normalize_service(it->second);
                    std::string detected = normalize_service(pr.service);
                    if (detected.find("http") != std::string::npos && expected.find("http") != std::string::npos) continue;
                    if (detected.find("rpc") != std::string::npos && expected.find("rpc") != std::string::npos) continue;
                    if (detected.find("alt") != std::string::npos) continue;
                    if (expected.find(detected) == std::string::npos && detected.find(expected) == std::string::npos) {
                        if (!expected.empty() && !detected.empty() && expected != detected) {
                            anomalies.push_back({"unexpected_service",
                                "Port " + std::to_string(pr.port) + " expected " + it->second + " but got " + pr.service,
                                pr.port, 0.6, 0.8});
                        }
                    }
                } else {
                    if (pr.port < 1024) {
                        anomalies.push_back({"unexpected_privileged_port",
                            "Unprivileged port " + std::to_string(pr.port) + " open with service " + pr.service,
                            pr.port, 0.5, 0.7});
                    }
                }
            }
        }

        if (banner_lengths.size() >= 3) {
            double sum = 0.0;
            for (int len : banner_lengths) sum += len;
            double mean = sum / banner_lengths.size();
            double sq_sum = 0.0;
            for (int len : banner_lengths) {
                double diff = len - mean;
                sq_sum += diff * diff;
            }
            double stddev = std::sqrt(sq_sum / banner_lengths.size());

            for (const auto& pr : port_results) {
                if (pr.status == "open" && pr.banner_length > 0) {
                    double z_score = (pr.banner_length - mean) / std::max(1.0, stddev);
                    if (std::abs(z_score) > 2.5) {
                        anomalies.push_back({"banner_length_outlier",
                            "Port " + std::to_string(pr.port) + " banner length " +
                            std::to_string(pr.banner_length) + " (z-score: " +
                            std::to_string(z_score).substr(0, 4) + ")",
                            pr.port, std::min(1.0, std::abs(z_score) / 5.0), 0.75});
                    }
                }
            }
        }

        std::set<int> open_ports_set;
        for (const auto& pr : port_results) {
            if (pr.status == "open") open_ports_set.insert(pr.port);
        }

        if (open_ports_set.size() >= 10) {
            anomalies.push_back({"many_open_ports",
                std::to_string(open_ports_set.size()) + " open ports detected - possible scanning detection",
                0, 0.4, 0.7});
        }

        std::sort(anomalies.begin(), anomalies.end(),
            [](const Anomaly& a, const Anomaly& b) {
                return a.severity > b.severity;
            });

        return anomalies;
    }

    void print_anomalies(const std::vector<Anomaly>& anomalies, std::string_view target) noexcept {
        for (const auto& a : anomalies) {
            std::cout << "RESULT:{\"target\":\"" << target
                      << "\",\"anomaly_type\":\"" << a.type
                      << "\",\"description\":\"" << a.description
                      << "\",\"port\":" << a.port
                      << ",\"severity\":" << std::fixed << std::setprecision(3) << a.severity
                      << ",\"confidence\":" << std::setprecision(3) << a.confidence
                      << "}" << '\n';
        }

        if (anomalies.empty()) {
            std::cout << "RESULT:{\"target\":\"" << target
                      << "\",\"anomaly_type\":\"none\",\"description\":\"No anomalies detected\""
                      << ",\"port\":0,\"severity\":0.0,\"confidence\":1.0}" << '\n';
        }

        std::cout << "FINAL:{\"target\":\"" << target
                  << "\",\"total_anomalies\":" << anomalies.size()
                  << ",\"max_severity\":" << std::fixed << std::setprecision(3)
                  << (anomalies.empty() ? 0.0 : anomalies[0].severity)
                  << "}" << '\n';
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target> [input from stdin]" << '\n';
        return 1;
    }

    std::string target = argv[1];
    std::vector<PortResult> port_results;

    std::string line;
    while (std::getline(std::cin, line)) {
        PortResult pr;
        pr.port = 0;
        pr.banner_length = 0;

        size_t start = line.find('{');
        if (start == std::string::npos) continue;
        std::string json = line.substr(start);

        auto extract = [&](std::string_view key) -> std::string {
            std::string s = "\"" + std::string(key) + "\":\"";
            size_t pos = json.find(s);
            if (pos == std::string::npos) {
                s = "\"" + std::string(key) + "\":";
                pos = json.find(s);
                if (pos == std::string::npos) return "";
                pos += s.size();
                size_t end = json.find_first_of(",}", pos);
                return (end != std::string::npos) ? json.substr(pos, end - pos) : "";
            }
            pos += s.size();
            size_t end = json.find('"', pos);
            return (end != std::string::npos) ? json.substr(pos, end - pos) : "";
        };

        pr.target = extract("target");
        std::string ps = extract("port");
        if (!ps.empty()) try { pr.port = std::stoi(ps); } catch (...) {}
        pr.status = extract("status");
        pr.service = extract("service");
        pr.banner = extract("banner");
        pr.banner_length = pr.banner.length();

        if (pr.port > 0) port_results.emplace_back(pr);
    }

    AnomalyDetector detector;
    auto anomalies = detector.detect(port_results);
    detector.print_anomalies(anomalies, target);

    return 0;
}
