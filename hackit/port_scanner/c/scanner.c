#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define CLOSE_SOCKET closesocket
#define SLEEP_MS(ms) Sleep(ms)
#define THREAD_RET unsigned int __stdcall
#define THREAD_HANDLE HANDLE
#define THREAD_CREATE(h,f,a) ((h=(HANDLE)_beginthreadex(NULL,0,f,a,0,NULL))!=NULL)
#define THREAD_JOIN(h) WaitForSingleObject(h,INFINITE)
#define THREAD_CLOSE(h) CloseHandle(h)
#define LOCK_T CRITICAL_SECTION
#define LOCK_INIT(m) InitializeCriticalSection(m)
#define LOCK_DESTROY(m) DeleteCriticalSection(m)
#define LOCK_ACQUIRE(m) EnterCriticalSection(m)
#define LOCK_RELEASE(m) LeaveCriticalSection(m)
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define SOCKET int
#define CLOSE_SOCKET(fd) close(fd)
#define SLEEP_MS(ms) usleep((ms)*1000)
#define THREAD_RET void*
#define THREAD_HANDLE pthread_t
#define THREAD_CREATE(h,f,a) (pthread_create(&h,NULL,f,a)==0)
#define THREAD_JOIN(h) pthread_join(h,NULL)
#define THREAD_CLOSE(h) ((void)0)
#define LOCK_T pthread_mutex_t
#define LOCK_INIT(m) pthread_mutex_init(m,NULL)
#define LOCK_DESTROY(m) pthread_mutex_destroy(m)
#define LOCK_ACQUIRE(m) pthread_mutex_lock(m)
#define LOCK_RELEASE(m) pthread_mutex_unlock(m)
#endif

#define MAX_PORTS 65536
#define MAX_THREADS 512
#define DEFAULT_TIMEOUT 2000
#define BANNER_SIZE 4096

typedef struct { int port; const char* name; } port_entry_t;

static const port_entry_t PORT_NAMES[] = {
    {1,"tcpmux"},
    {5,"rje"},
    {7,"echo"},
    {9,"discard"},
    {11,"systat"},
    {13,"daytime"},
    {17,"qotd"},
    {19,"chargen"},
    {20,"ftp-data"},
    {21,"ftp"},
    {22,"ssh"},
    {23,"telnet"},
    {25,"smtp"},
    {37,"time"},
    {39,"rlp"},
    {42,"nameserver"},
    {43,"whois"},
    {49,"tacacs"},
    {53,"dns"},
    {57,"mtp"},
    {67,"dhcp"},
    {68,"dhcp"},
    {69,"tftp"},
    {70,"gopher"},
    {79,"finger"},
    {80,"http"},
    {81,"http-alt"},
    {82,"http-alt"},
    {83,"http-alt"},
    {88,"kerberos"},
    {101,"hostname"},
    {102,"iso-tsap"},
    {107,"rtelnet"},
    {109,"pop2"},
    {110,"pop3"},
    {111,"rpcbind"},
    {113,"ident"},
    {115,"sftp"},
    {117,"uucp-path"},
    {118,"sqlserv"},
    {119,"nntp"},
    {123,"ntp"},
    {135,"epmap"},
    {137,"netbios-ns"},
    {138,"netbios-dgm"},
    {139,"netbios-ssn"},
    {143,"imap"},
    {144,"uma"},
    {152,"bftp"},
    {156,"sqlsrv"},
    {158,"dmsp"},
    {161,"snmp"},
    {162,"snmptrap"},
    {177,"xdmcp"},
    {179,"bgp"},
    {194,"irc"},
    {199,"smux"},
    {201,"appletalk"},
    {209,"qmtp"},
    {213,"ipx"},
    {220,"imap3"},
    {256,"rap"},
    {259,"esro"},
    {264,"bgmp"},
    {280,"http-mgmt"},
    {308,"novastor"},
    {311,"macosx-admin"},
    {319,"ptp-event"},
    {320,"ptp-general"},
    {350,"matip"},
    {363,"rsvp-tunnel"},
    {366,"odmr"},
    {369,"rpc2"},
    {370,"codaauth2"},
    {371,"clearcase"},
    {389,"ldap"},
    {401,"ups"},
    {406,"imsp"},
    {427,"svrloc"},
    {433,"nnsp"},
    {443,"https"},
    {444,"snpp"},
    {445,"microsoft-ds"},
    {464,"kpasswd"},
    {465,"smtps"},
    {468,"photuris"},
    {497,"retrospect"},
    {500,"isakmp"},
    {502,"modbus"},
    {504,"citadel"},
    {512,"exec"},
    {513,"login"},
    {514,"shell"},
    {515,"printer"},
    {517,"talk"},
    {518,"ntalk"},
    {520,"rip"},
    {521,"ripng"},
    {523,"ibm-db2"},
    {524,"ncp"},
    {525,"timed"},
    {526,"tempo"},
    {529,"irc-serv"},
    {530,"rpc"},
    {531,"irc"},
    {532,"netnews"},
    {533,"netwall"},
    {540,"uucp"},
    {541,"uucp-rlogin"},
    {543,"klogin"},
    {544,"kshell"},
    {546,"dhcpv6-client"},
    {547,"dhcpv6-server"},
    {548,"afp"},
    {554,"rtsp"},
    {556,"remotefs"},
    {560,"rmonitor"},
    {561,"rmonitor"},
    {563,"nntps"},
    {585,"imaps"},
    {587,"submission"},
    {591,"filemaker"},
    {593,"http-rpc-epmap"},
    {601,"syslog-conn"},
    {604,"tune"},
    {611,"npmp-gui"},
    {623,"ipmi"},
    {631,"ipp"},
    {635,"mountd"},
    {636,"ldaps"},
    {639,"msdp"},
    {646,"ldp"},
    {647,"dhcp-failover"},
    {648,"rrp"},
    {650,"obex"},
    {666,"doom"},
    {688,"appleqtc"},
    {694,"ha-cluster"},
    {698,"olsr"},
    {700,"epp"},
    {701,"lmp"},
    {706,"silex"},
    {711,"cisco-tdp"},
    {720,"smp"},
    {744,"flexlm"},
    {749,"kerberos-adm"},
    {750,"kerberos-iv"},
    {751,"pump"},
    {752,"qrh"},
    {753,"rrh"},
    {754,"tell"},
    {758,"nlogin"},
    {759,"con"},
    {760,"ns"},
    {761,"rxe"},
    {762,"quotad"},
    {763,"cycleserv"},
    {764,"omserv"},
    {765,"webster"},
    {767,"phone"},
    {769,"vid"},
    {770,"cadlock"},
    {771,"rtip"},
    {772,"cycleserv2"},
    {773,"submit"},
    {774,"rpasswd"},
    {775,"entomb"},
    {776,"wpages"},
    {780,"wpgs"},
    {781,"hp-collector"},
    {782,"hp-managed-node"},
    {783,"hp-alarm-mgr"},
    {786,"concert"},
    {787,"qsc"},
    {800,"mdbs-daemon"},
    {808,"ccproxy-http"},
    {829,"pkix-3-ca"},
    {843,"adobe-rtmfp"},
    {853,"dns-over-tls"},
    {860,"iscsi"},
    {865,"mqtt"},
    {873,"rsync"},
    {888,"accessbuilder"},
    {900,"sctp"},
    {901,"samba-swat"},
    {902,"ideafarm-door"},
    {953,"rndc"},
    {981,"soap-ssl"},
    {989,"ftps-data"},
    {990,"ftps"},
    {992,"telnets"},
    {993,"imaps"},
    {994,"ircs"},
    {995,"pop3s"},
    {1080,"socks"},
    {1099,"rmiregistry"},
    {1194,"openvpn"},
    {1214,"kazaa"},
    {1220,"quicktime"},
    {1241,"nessus"},
    {1310,"jabber"},
    {1337,"waste"},
    {1352,"lotusnotes"},
    {1394,"network-camera"},
    {1414,"mssql"},
    {1415,"db2"},
    {1433,"ms-sql-s"},
    {1434,"ms-sql-m"},
    {1494,"citrix-ica"},
    {1512,"wins"},
    {1521,"oracle-db"},
    {1522,"oracle-db"},
    {1524,"oracle-db"},
    {1526,"oracle-mgmt"},
    {1527,"oracle-java"},
    {1529,"oracle-tns"},
    {1540,"1c-server"},
    {1541,"1c-server"},
    {1547,"laplink"},
    {1645,"radius"},
    {1646,"radius-acct"},
    {1666,"perforce"},
    {1701,"l2tp"},
    {1719,"h323-ras"},
    {1720,"h323"},
    {1723,"pptp"},
    {1741,"directplay"},
    {1755,"wms"},
    {1801,"msmq"},
    {1812,"radius"},
    {1813,"radius-acct"},
    {1863,"msnp"},
    {1883,"mqtt"},
    {1900,"upnp"},
    {1935,"rtmp"},
    {1947,"sentinel"},
    {1984,"bbn-mmc"},
    {1985,"hsrp"},
    {2000,"cisco-sccp"},
    {2001,"dc"},
    {2005,"desknet"},
    {2013,"rip"},
    {2020,"xmpp"},
    {2030,"device2"},
    {2049,"nfs"},
    {2080,"autodesk"},
    {2082,"cpanel"},
    {2083,"cpanel-ssl"},
    {2086,"whm"},
    {2087,"whm-ssl"},
    {2095,"cpanel-webmail"},
    {2096,"cpanel-webmail"},
    {2100,"amiganet"},
    {2102,"zephyr"},
    {2103,"zephyr"},
    {2104,"zephyr"},
    {2105,"zephyr"},
    {2106,"zephyr"},
    {2107,"zephyr"},
    {2121,"ccproxy-ftp"},
    {2140,"deepthroat"},
    {2170,"microsoft-crm"},
    {2200,"tuxp"},
    {2222,"ad-tech"},
    {2273,"mysql"},
    {2300,"hp-dataprot"},
    {2301,"compaqdiag"},
    {2302,"games"},
    {2323,"photon"},
    {2375,"docker"},
    {2376,"docker-tls"},
    {2379,"etcd"},
    {2380,"etcd"},
    {2393,"ms-olap"},
    {2401,"cvs"},
    {2404,"cvs-pserver"},
    {2424,"orientdb"},
    {2425,"ravent"},
    {2447,"spring"},
    {2483,"oracle-db"},
    {2484,"oracle-db"},
    {2525,"smtp-alt"},
    {2556,"nicetec"},
    {2557,"nicetec"},
    {2558,"nicetec"},
    {2573,"ivr"},
    {2598,"citrix-xml"},
    {2628,"hp-stor"},
    {2700,"quicksilver"},
    {2710,"xbtracker"},
    {2727,"mgcp"},
    {2868,"nsstp"},
    {2869,"icslap"},
    {2947,"gpsd"},
    {2967,"symantec"},
    {2998,"real"},
    {3000,"goidap"},
    {3001,"oracle-rmi"},
    {3006,"exlm-agent"},
    {3017,"event"},
    {3030,"netra"},
    {3049,"cfs"},
    {3050,"gds-db"},
    {3074,"xbox-live"},
    {3128,"squid-http"},
    {3130,"squid-icp"},
    {3150,"deepthroat"},
    {3190,"svn"},
    {3225,"fcip"},
    {3260,"iscsi"},
    {3268,"ms-globalcat"},
    {3269,"ms-globalcat"},
    {3283,"netassistant"},
    {3300,"ceph"},
    {3306,"mysql"},
    {3307,"opsession"},
    {3308,"opsession"},
    {3310,"clamav"},
    {3333,"net-watch"},
    {3346,"trnsprnt"},
    {3351,"opsview"},
    {3372,"msdtc"},
    {3389,"ms-wbt-server"},
    {3391,"savant"},
    {3396,"efi-lm"},
    {3400,"csms"},
    {3421,"bmap"},
    {3455,"pdps"},
    {3478,"stun"},
    {3632,"distcc"},
    {3690,"svn"},
    {3702,"ws-discovery"},
    {3724,"wow"},
    {3784,"vctrl"},
    {3785,"vctrl"},
    {4000,"terabase"},
    {4001,"newoak"},
    {4045,"nrf"},
    {4111,"xgrid"},
    {4243,"docker-reg"},
    {4321,"rwhois"},
    {4444,"napster"},
    {4500,"ipsec-nat"},
    {4662,"edonkey"},
    {4672,"edonkey"},
    {4848,"appserver"},
    {4899,"radmin"},
    {5000,"upnp"},
    {5001,"commplex-link"},
    {5002,"fe-license"},
    {5003,"fmpro"},
    {5004,"rtp-data"},
    {5005,"rtp"},
    {5009,"airport"},
    {5010,"telepathstart"},
    {5011,"telepathattack"},
    {5020,"zenginkyo"},
    {5021,"zenginkyo-lic"},
    {5022,"zenginkyo"},
    {5030,"surfpass"},
    {5031,"surfpass"},
    {5050,"mmcc"},
    {5051,"ida-agent"},
    {5052,"ida-agent"},
    {5060,"sip"},
    {5061,"sip-tls"},
    {5093,"sentinel"},
    {5099,"sentinel"},
    {5100,"admd"},
    {5101,"admd"},
    {5102,"admd"},
    {5145,"rmonitor-secure"},
    {5150,"atmp"},
    {5151,"atmp"},
    {5152,"atmp"},
    {5154,"bzflag"},
    {5190,"icq"},
    {5191,"icq"},
    {5192,"icq"},
    {5193,"icq"},
    {5200,"targus"},
    {5201,"targus"},
    {5222,"xmpp-client"},
    {5223,"xmpp-server"},
    {5269,"xmpp-server"},
    {5298,"xmpp-bosh"},
    {5310,"outlaws"},
    {5311,"outlaws"},
    {5312,"outlaws"},
    {5313,"outlaws"},
    {5314,"outlaws"},
    {5315,"outlaws"},
    {5351,"nat-pmp"},
    {5353,"mdns"},
    {5405,"pc-support"},
    {5412,"thinkpoint"},
    {5413,"thinkpoint"},
    {5432,"postgresql"},
    {5445,"smbdirect"},
    {5450,"tiepie"},
    {5451,"tiepie"},
    {5495,"proliferc"},
    {5498,"hotline"},
    {5499,"hotline"},
    {5500,"hotline"},
    {5501,"hotline"},
    {5502,"hotline"},
    {5503,"hotline"},
    {5504,"hotline"},
    {5554,"sasser"},
    {5555,"freeciv"},
    {5556,"freeciv"},
    {5557,"freeciv"},
    {5558,"freeciv"},
    {5559,"freeciv"},
    {5560,"freeciv"},
    {5561,"freeciv"},
    {5562,"freeciv"},
    {5563,"freeciv"},
    {5564,"freeciv"},
    {5565,"freeciv"},
    {5566,"freeciv"},
    {5631,"pcanywhere"},
    {5632,"pcanywhere"},
    {5666,"nagios"},
    {5667,"nagios"},
    {5672,"amqp"},
    {5678,"murmur"},
    {5679,"murmur"},
    {5688,"ggz"},
    {5718,"dpm"},
    {5719,"dpm"},
    {5720,"dpm"},
    {5800,"vnc-http"},
    {5801,"vnc-http"},
    {5802,"vnc-http"},
    {5803,"vnc-http"},
    {5810,"icp"},
    {5811,"icp"},
    {5812,"icp"},
    {5813,"icp"},
    {5850,"wherehoo"},
    {5851,"wherehoo"},
    {5868,"dpm"},
    {5900,"vnc"},
    {5901,"vnc-1"},
    {5902,"vnc-2"},
    {5903,"vnc-3"},
    {5904,"vnc-4"},
    {5905,"vnc-5"},
    {5906,"vnc-6"},
    {5907,"vnc-7"},
    {5908,"vnc-8"},
    {5909,"vnc-9"},
    {5910,"vnc"},
    {5911,"vnc"},
    {5920,"vnc"},
    {5950,"vnc"},
    {5951,"vnc"},
    {5952,"vnc"},
    {5960,"vnc"},
    {5961,"vnc"},
    {5962,"vnc"},
    {5970,"vnc"},
    {5971,"vnc"},
    {5984,"couchdb"},
    {5985,"winrm-http"},
    {5986,"winrm-https"},
    {6000,"x11"},
    {6001,"x11"},
    {6002,"x11"},
    {6003,"x11"},
    {6004,"x11"},
    {6005,"x11"},
    {6006,"x11"},
    {6007,"x11"},
    {6008,"x11"},
    {6009,"x11"},
    {6010,"x11"},
    {6011,"x11"},
    {6012,"x11"},
    {6013,"x11"},
    {6014,"x11"},
    {6015,"x11"},
    {6016,"x11"},
    {6017,"x11"},
    {6018,"x11"},
    {6019,"x11"},
    {6020,"x11"},
    {6021,"x11"},
    {6022,"x11"},
    {6023,"x11"},
    {6024,"x11"},
    {6025,"x11"},
    {6026,"x11"},
    {6027,"x11"},
    {6028,"x11"},
    {6029,"x11"},
    {6030,"x11"},
    {6031,"x11"},
    {6032,"x11"},
    {6033,"x11"},
    {6034,"x11"},
    {6035,"x11"},
    {6036,"x11"},
    {6037,"x11"},
    {6038,"x11"},
    {6039,"x11"},
    {6040,"x11"},
    {6041,"x11"},
    {6042,"x11"},
    {6043,"x11"},
    {6044,"x11"},
    {6045,"x11"},
    {6046,"x11"},
    {6047,"x11"},
    {6048,"x11"},
    {6049,"x11"},
    {6050,"x11"},
    {6051,"x11"},
    {6052,"x11"},
    {6053,"x11"},
    {6054,"x11"},
    {6055,"x11"},
    {6056,"x11"},
    {6057,"x11"},
    {6058,"x11"},
    {6059,"x11"},
    {6060,"x11"},
    {6061,"x11"},
    {6062,"x11"},
    {6063,"x11"},
    {6064,"x11"},
    {6065,"x11"},
    {6066,"x11"},
    {6067,"x11"},
    {6068,"x11"},
    {6069,"x11"},
    {6070,"x11"},
    {6071,"x11"},
    {6072,"x11"},
    {6073,"x11"},
    {6074,"x11"},
    {6075,"x11"},
    {6076,"x11"},
    {6077,"x11"},
    {6078,"x11"},
    {6079,"x11"},
    {6080,"x11"},
    {6081,"x11"},
    {6082,"x11"},
    {6083,"x11"},
    {6084,"x11"},
    {6085,"x11"},
    {6086,"x11"},
    {6087,"x11"},
    {6088,"x11"},
    {6089,"x11"},
    {6090,"x11"},
    {6091,"x11"},
    {6092,"x11"},
    {6093,"x11"},
    {6094,"x11"},
    {6095,"x11"},
    {6096,"x11"},
    {6097,"x11"},
    {6098,"x11"},
    {6099,"x11"},
    {6100,"x11"},
    {6101,"x11"},
    {6102,"x11"},
    {6103,"x11"},
    {6104,"x11"},
    {6105,"x11"},
    {6106,"x11"},
    {6107,"x11"},
    {6108,"x11"},
    {6109,"x11"},
    {6110,"x11"},
    {6111,"x11"},
    {6112,"x11"},
    {6113,"x11"},
    {6114,"x11"},
    {6115,"x11"},
    {6116,"x11"},
    {6117,"x11"},
    {6118,"x11"},
    {6119,"x11"},
    {6120,"x11"},
    {6121,"x11"},
    {6122,"x11"},
    {6123,"x11"},
    {6124,"x11"},
    {6125,"x11"},
    {6126,"x11"},
    {6127,"x11"},
    {6128,"x11"},
    {6129,"x11"},
    {6130,"x11"},
    {6131,"x11"},
    {6132,"x11"},
    {6133,"x11"},
    {6134,"x11"},
    {6135,"x11"},
    {6136,"x11"},
    {6137,"x11"},
    {6138,"x11"},
    {6139,"x11"},
    {6140,"x11"},
    {6141,"x11"},
    {6142,"x11"},
    {6143,"x11"},
    {6144,"x11"},
    {6145,"x11"},
    {6146,"x11"},
    {6147,"x11"},
    {6148,"x11"},
    {6149,"x11"},
    {6150,"x11"},
    {6151,"x11"},
    {6152,"x11"},
    {6153,"x11"},
    {6154,"x11"},
    {6155,"x11"},
    {6156,"x11"},
    {6157,"x11"},
    {6158,"x11"},
    {6159,"x11"},
    {6160,"x11"},
    {6161,"x11"},
    {6162,"x11"},
    {6163,"x11"},
    {6164,"x11"},
    {6165,"x11"},
    {6166,"x11"},
    {6167,"x11"},
    {6168,"x11"},
    {6169,"x11"},
    {6170,"x11"},
    {6171,"x11"},
    {6172,"x11"},
    {6173,"x11"},
    {6174,"x11"},
    {6175,"x11"},
    {6176,"x11"},
    {6177,"x11"},
    {6346,"gnutella"},
    {6347,"gnutella"},
    {6379,"redis"},
    {6389,"redis"},
    {6480,"dns-sd"},
    {6481,"dns-sd"},
    {6502,"netop"},
    {6514,"syslog-tls"},
    {6515,"elipse"},
    {6566,"sane-port"},
    {6580,"vnc-http"},
    {6581,"vnc-http"},
    {6665,"irc"},
    {6666,"irc"},
    {6667,"irc"},
    {6668,"irc"},
    {6669,"irc"},
    {6679,"irc-ssl"},
    {6697,"irc-ssl"},
    {6881,"bittorrent"},
    {6882,"bittorrent"},
    {6883,"bittorrent"},
    {6884,"bittorrent"},
    {6885,"bittorrent"},
    {6886,"bittorrent"},
    {6887,"bittorrent"},
    {6888,"bittorrent"},
    {6889,"bittorrent"},
    {6890,"bittorrent"},
    {6891,"bittorrent"},
    {6892,"bittorrent"},
    {6893,"bittorrent"},
    {6894,"bittorrent"},
    {6895,"bittorrent"},
    {6896,"bittorrent"},
    {6897,"bittorrent"},
    {6898,"bittorrent"},
    {6899,"bittorrent"},
    {6900,"bittorrent"},
    {6901,"bittorrent"},
    {6969,"acmsoda"},
    {6970,"acmsoda"},
    {7000,"afs3-fileserver"},
    {7001,"afs3-callback"},
    {7002,"afs3-prserver"},
    {7003,"afs3-vlserver"},
    {7004,"afs3-kaserver"},
    {7005,"afs3-volser"},
    {7006,"afs3-errors"},
    {7007,"afs3-bos"},
    {7008,"afs3-update"},
    {7009,"afs3-rmtsys"},
    {7010,"afs3-update"},
    {7011,"afs3-afs"},
    {7012,"afs3-crs"},
    {7013,"afs3-crs"},
    {7014,"afs3-crs"},
    {7015,"afs3-crs"},
    {7016,"afs3-crs"},
    {7017,"afs3-crs"},
    {7018,"afs3-crs"},
    {7019,"afs3-crs"},
    {7070,"arcp"},
    {7100,"font-service"},
    {7128,"scencc"},
    {7144,"scencc"},
    {7145,"scencc"},
    {7161,"cabs"},
    {7162,"cabs"},
    {7163,"cabs"},
    {7200,"fodms"},
    {7201,"dlip"},
    {7300,"swx"},
    {7301,"swx"},
    {7302,"swx"},
    {7303,"swx"},
    {7304,"swx"},
    {7305,"swx"},
    {7306,"swx"},
    {7307,"swx"},
    {7308,"swx"},
    {7309,"swx"},
    {7310,"swx"},
    {7311,"swx"},
    {7312,"swx"},
    {7313,"swx"},
    {7314,"swx"},
    {7315,"swx"},
    {7316,"swx"},
    {7317,"swx"},
    {7318,"swx"},
    {7319,"swx"},
    {7320,"swx"},
    {7321,"swx"},
    {7322,"swx"},
    {7323,"swx"},
    {7324,"swx"},
    {7325,"swx"},
    {7326,"swx"},
    {7327,"swx"},
    {7328,"swx"},
    {7329,"swx"},
    {7330,"swx"},
    {7331,"swx"},
    {7332,"swx"},
    {7333,"swx"},
    {7334,"swx"},
    {7335,"swx"},
    {7336,"swx"},
    {7337,"swx"},
    {7338,"swx"},
    {7339,"swx"},
    {7340,"swx"},
    {7341,"swx"},
    {7342,"swx"},
    {7343,"swx"},
    {7344,"swx"},
    {7345,"swx"},
    {7346,"swx"},
    {7347,"swx"},
    {7348,"swx"},
    {7349,"swx"},
    {7350,"swx"},
    {7443,"oracle-apex"},
    {7473,"rise"},
    {7474,"neo4j"},
    {7475,"neo4j"},
    {7476,"neo4j"},
    {7547,"cwmp"},
    {7548,"cwmp"},
    {7674,"iqt"},
    {7675,"iqt"},
    {7676,"iqt"},
    {7741,"ravent"},
    {7742,"ravent"},
    {7777,"cbt"},
    {7778,"cbt"},
    {7779,"cbt"},
    {8000,"http-alt"},
    {8001,"http-alt"},
    {8002,"http-alt"},
    {8008,"http-alt"},
    {8009,"ajp13"},
    {8010,"http-alt"},
    {8020,"http-alt"},
    {8042,"http-alt"},
    {8060,"http-alt"},
    {8074,"http-alt"},
    {8075,"http-alt"},
    {8080,"http-proxy"},
    {8081,"http-alt"},
    {8082,"http-alt"},
    {8086,"http-alt"},
    {8087,"http-alt"},
    {8088,"http-alt"},
    {8089,"http-alt"},
    {8090,"http-alt"},
    {8091,"http-alt"},
    {8092,"http-alt"},
    {8180,"http-alt"},
    {8181,"http-alt"},
    {8200,"trivnet"},
    {8222,"http-alt"},
    {8243,"https-alt"},
    {8280,"http-alt"},
    {8291,"http-alt"},
    {8300,"http-alt"},
    {8332,"bitcoin"},
    {8333,"bitcoin"},
    {8384,"http-alt"},
    {8403,"http-alt"},
    {8404,"http-alt"},
    {8443,"https-alt"},
    {8500,"http-alt"},
    {8530,"http-alt"},
    {8531,"http-alt"},
    {8600,"http-alt"},
    {8649,"ganglia"},
    {8834,"nessus"},
    {8880,"http-alt"},
    {8883,"mqtt-tls"},
    {8888,"http-alt"},
    {8889,"http-alt"},
    {8899,"http-alt"},
    {8983,"solr"},
    {9000,"cslistener"},
    {9001,"tor-orport"},
    {9002,"tor"},
    {9009,"pichat"},
    {9010,"sdr"},
    {9043,"websphere"},
    {9050,"tor-socks"},
    {9060,"websphere"},
    {9080,"websphere"},
    {9090,"websm"},
    {9091,"xmltec-xmlmail"},
    {9092,"xmltec-xmlmail"},
    {9100,"jetdirect"},
    {9101,"jetdirect"},
    {9102,"jetdirect"},
    {9103,"jetdirect"},
    {9110,"ssr"},
    {9150,"tor-control"},
    {9151,"tor-control"},
    {9160,"cassandra"},
    {9191,"http-alt"},
    {9200,"elasticsearch"},
    {9210,"elasticsearch"},
    {9300,"elasticsearch"},
    {9312,"sphinx"},
    {9418,"git"},
    {9443,"https-alt"},
    {9500,"ismserver"},
    {9535,"mngsuite"},
    {9593,"cba"},
    {9594,"cba"},
    {9595,"cba"},
    {9600,"micromuse"},
    {9673,"http-alt"},
    {9700,"http-alt"},
    {9876,"sd"},
    {9877,"sd"},
    {9898,"http-alt"},
    {9900,"http-alt"},
    {9981,"http-alt"},
    {9987,"http-alt"},
    {9993,"http-alt"},
    {9999,"http-alt"},
    {10000,"ndmp"},
    {10001,"sdr"},
    {10002,"sdr"},
    {10009,"http-alt"},
    {10010,"http-alt"},
    {10011,"http-alt"},
    {10050,"zabbix"},
    {10051,"zabbix-trap"},
    {10080,"http-alt"},
    {10082,"http-alt"},
    {10113,"netiq"},
    {10114,"netiq"},
    {10115,"netiq"},
    {10116,"netiq"},
    {10161,"snmp-tls"},
    {10162,"snmp-tls"},
    {10250,"kubelet"},
    {10255,"kubelet"},
    {10443,"https-alt"},
    {10505,"http-alt"},
    {10514,"http-alt"},
    {10800,"http-alt"},
    {10990,"http-alt"},
    {11000,"http-alt"},
    {11111,"http-alt"},
    {11211,"memcached"},
    {11371,"pgpkeyserver"},
    {11720,"http-alt"},
    {11967,"http-alt"},
    {12000,"http-alt"},
    {12001,"http-alt"},
    {12174,"http-alt"},
    {12201,"http-alt"},
    {12222,"http-alt"},
    {12345,"netbus"},
    {12489,"http-alt"},
    {13000,"http-alt"},
    {13008,"http-alt"},
    {13009,"http-alt"},
    {13223,"http-alt"},
    {13224,"http-alt"},
    {13337,"http-alt"},
    {13338,"http-alt"},
    {13579,"http-alt"},
    {13722,"http-alt"},
    {13724,"http-alt"},
    {13782,"http-alt"},
    {13783,"http-alt"},
    {14000,"http-alt"},
    {14141,"http-alt"},
    {14142,"http-alt"},
    {14238,"http-alt"},
    {14441,"http-alt"},
    {14442,"http-alt"},
    {14533,"http-alt"},
    {14534,"http-alt"},
    {14992,"http-alt"},
    {14993,"http-alt"},
    {15118,"http-alt"},
    {15273,"http-alt"},
    {15555,"http-alt"},
    {15556,"http-alt"},
    {15660,"http-alt"},
    {15714,"http-alt"},
    {15740,"http-alt"},
    {15999,"http-alt"},
    {16000,"http-alt"},
    {16001,"http-alt"},
    {16010,"http-alt"},
    {16012,"http-alt"},
    {16016,"http-alt"},
    {16018,"http-alt"},
    {16080,"http-alt"},
    {16113,"http-alt"},
    {16215,"http-alt"},
    {16216,"http-alt"},
    {16225,"http-alt"},
    {16250,"http-alt"},
    {16309,"http-alt"},
    {16310,"http-alt"},
    {16311,"http-alt"},
    {16384,"http-alt"},
    {16385,"http-alt"},
    {16403,"http-alt"},
    {16520,"http-alt"},
    {16621,"http-alt"},
    {16622,"http-alt"},
    {16896,"http-alt"},
    {16993,"http-alt"},
    {16995,"http-alt"},
    {17007,"http-alt"},
    {17180,"http-alt"},
    {17181,"http-alt"},
    {17219,"http-alt"},
    {17220,"http-alt"},
    {17221,"http-alt"},
    {17222,"http-alt"},
    {17300,"http-alt"},
    {17472,"http-alt"},
    {17500,"http-alt"},
    {17777,"http-alt"},
    {18080,"http-alt"},
    {18081,"http-alt"},
    {18091,"http-alt"},
    {18092,"http-alt"},
    {18101,"http-alt"},
    {18102,"http-alt"},
    {18103,"http-alt"},
    {18104,"http-alt"},
    {18180,"http-alt"},
    {18200,"http-alt"},
    {18444,"http-alt"},
    {18455,"http-alt"},
    {18505,"http-alt"},
    {18506,"http-alt"},
    {18634,"http-alt"},
    {18635,"http-alt"},
    {18732,"http-alt"},
    {18733,"http-alt"},
    {18888,"http-alt"},
    {18988,"http-alt"},
    {19000,"http-alt"},
    {19001,"http-alt"},
    {19080,"http-alt"},
    {19105,"http-alt"},
    {19150,"http-alt"},
    {19283,"http-alt"},
    {19302,"http-alt"},
    {19315,"http-alt"},
    {19398,"http-alt"},
    {19410,"http-alt"},
    {19411,"http-alt"},
    {19638,"http-alt"},
    {19790,"http-alt"},
    {19999,"http-alt"},
    {20000,"http-alt"},
    {20001,"http-alt"},
    {20002,"http-alt"},
    {20003,"http-alt"},
    {20005,"http-alt"},
    {20100,"http-alt"},
    {20200,"http-alt"},
    {20201,"http-alt"},
    {20202,"http-alt"},
    {20222,"http-alt"},
    {20389,"http-alt"},
    {20480,"http-alt"},
    {20481,"http-alt"},
    {20670,"http-alt"},
    {20999,"http-alt"},
    {21000,"http-alt"},
    {21010,"http-alt"},
    {21212,"http-alt"},
    {21213,"http-alt"},
    {21544,"http-alt"},
    {21590,"http-alt"},
    {21800,"http-alt"},
    {22000,"http-alt"},
    {22001,"http-alt"},
    {22222,"http-alt"},
    {22223,"http-alt"},
    {23000,"http-alt"},
    {23001,"http-alt"},
    {23002,"http-alt"},
    {23456,"http-alt"},
    {23682,"http-alt"},
    {23772,"http-alt"},
    {23867,"http-alt"},
    {23939,"http-alt"},
    {24000,"http-alt"},
    {24001,"http-alt"},
    {24002,"http-alt"},
    {24242,"http-alt"},
    {24243,"http-alt"},
    {24244,"http-alt"},
    {24386,"http-alt"},
    {24387,"http-alt"},
    {24480,"http-alt"},
    {24554,"http-alt"},
    {24676,"http-alt"},
    {24677,"http-alt"},
    {24678,"http-alt"},
    {25000,"http-alt"},
    {25001,"http-alt"},
    {25200,"http-alt"},
    {25201,"http-alt"},
    {25565,"minecraft"},
    {25575,"minecraft-rcon"},
    {26000,"http-alt"},
    {26001,"http-alt"},
    {26208,"http-alt"},
    {26214,"http-alt"},
    {26260,"http-alt"},
    {26261,"http-alt"},
    {26262,"http-alt"},
    {26263,"http-alt"},
    {26379,"http-alt"},
    {27000,"flexlm"},
    {27001,"flexlm"},
    {27002,"flexlm"},
    {27010,"flexlm"},
    {27015,"steam"},
    {27016,"steam"},
    {27017,"mongod"},
    {27018,"mongod"},
    {27019,"mongod"},
    {27374,"subseven"},
    {27500,"quake"},
    {27666,"http-alt"},
    {28000,"http-alt"},
    {28080,"http-alt"},
    {28100,"http-alt"},
    {28777,"http-alt"},
    {28800,"http-alt"},
    {28888,"http-alt"},
    {29000,"http-alt"},
    {30000,"http-alt"},
    {30001,"http-alt"},
    {30704,"http-alt"},
    {30718,"http-alt"},
    {31000,"http-alt"},
    {31200,"http-alt"},
    {31201,"http-alt"},
    {31337,"backorifice"},
    {31415,"http-alt"},
    {31416,"http-alt"},
    {31457,"http-alt"},
    {31554,"http-alt"},
    {31600,"http-alt"},
    {31765,"http-alt"},
    {31980,"http-alt"},
    {32000,"http-alt"},
    {32137,"http-alt"},
    {32261,"http-alt"},
    {32375,"http-alt"},
    {32400,"plex"},
    {32410,"plex"},
    {32411,"plex"},
    {32412,"plex"},
    {32413,"plex"},
    {32414,"plex"},
    {32415,"plex"},
    {32764,"http-alt"},
    {32768,"filenet"},
    {32769,"filenet"},
    {32770,"filenet"},
    {32771,"filenet"},
    {32772,"filenet"},
    {32773,"filenet"},
    {32774,"filenet"},
    {32775,"filenet"},
    {32776,"filenet"},
    {32777,"filenet"},
    {32778,"filenet"},
    {32779,"filenet"},
    {32780,"filenet"},
    {32781,"filenet"},
    {32782,"filenet"},
    {32783,"filenet"},
    {32784,"filenet"},
    {32785,"filenet"},
    {32786,"filenet"},
    {32787,"filenet"},
    {32788,"filenet"},
    {32789,"filenet"},
    {32790,"filenet"},
    {32791,"filenet"},
    {32792,"filenet"},
    {32793,"filenet"},
    {32794,"filenet"},
    {32795,"filenet"},
    {32796,"filenet"},
    {32797,"filenet"},
    {32798,"filenet"},
    {32799,"filenet"},
    {32800,"filenet"},
    {32801,"filenet"},
    {32802,"filenet"},
    {32803,"filenet"},
    {32804,"filenet"},
    {32805,"filenet"},
    {32806,"filenet"},
    {32807,"filenet"},
    {32808,"filenet"},
    {32809,"filenet"},
    {32810,"filenet"},
    {32811,"filenet"},
    {32812,"filenet"},
    {32813,"filenet"},
    {32814,"filenet"},
    {32815,"filenet"},
    {32816,"filenet"},
    {32817,"filenet"},
    {32818,"filenet"},
    {32819,"filenet"},
    {32820,"filenet"},
    {32821,"filenet"},
    {32822,"filenet"},
    {32823,"filenet"},
    {32824,"filenet"},
    {32825,"filenet"},
    {32826,"filenet"},
    {32827,"filenet"},
    {32828,"filenet"},
    {32829,"filenet"},
    {32830,"filenet"},
    {32831,"filenet"},
    {32832,"filenet"},
    {32833,"filenet"},
    {32834,"filenet"},
    {32835,"filenet"},
    {32836,"filenet"},
    {32837,"filenet"},
    {32838,"filenet"},
    {32839,"filenet"},
    {32840,"filenet"},
    {32841,"filenet"},
    {32842,"filenet"},
    {32843,"filenet"},
    {32844,"filenet"},
    {32845,"filenet"},
    {32846,"filenet"},
    {32847,"filenet"},
    {32848,"filenet"},
    {32849,"filenet"},
    {32850,"filenet"},
    {32851,"filenet"},
    {32852,"filenet"},
    {32853,"filenet"},
    {32854,"filenet"},
    {32855,"filenet"},
    {32856,"filenet"},
    {32857,"filenet"},
    {32858,"filenet"},
    {32859,"filenet"},
    {32860,"filenet"},
    {32861,"filenet"},
    {32862,"filenet"},
    {32863,"filenet"},
    {32864,"filenet"},
    {32865,"filenet"},
    {32866,"filenet"},
    {32867,"filenet"},
    {32868,"filenet"},
    {32869,"filenet"},
    {32870,"filenet"},
    {32871,"filenet"},
    {32872,"filenet"},
    {32873,"filenet"},
    {32874,"filenet"},
    {32875,"filenet"},
    {32876,"filenet"},
    {32877,"filenet"},
    {32878,"filenet"},
    {32879,"filenet"},
    {32880,"filenet"},
    {32881,"filenet"},
    {32882,"filenet"},
    {32883,"filenet"},
    {32884,"filenet"},
    {32885,"filenet"},
    {32886,"filenet"},
    {32887,"filenet"},
    {32888,"filenet"},
    {32889,"filenet"},
    {32890,"filenet"},
    {32891,"filenet"},
    {32892,"filenet"},
    {32893,"filenet"},
    {32894,"filenet"},
    {32895,"filenet"},
    {32896,"filenet"},
    {32897,"filenet"},
    {32898,"filenet"},
    {32899,"filenet"},
    {32900,"filenet"},
    {33000,"http-alt"},
    {33001,"http-alt"},
    {33002,"http-alt"},
    {33003,"http-alt"},
    {33004,"http-alt"},
    {33005,"http-alt"},
    {33006,"http-alt"},
    {33007,"http-alt"},
    {33008,"http-alt"},
    {33009,"http-alt"},
    {33010,"http-alt"},
    {33011,"http-alt"},
    {33012,"http-alt"},
    {33013,"http-alt"},
    {33014,"http-alt"},
    {33015,"http-alt"},
    {33016,"http-alt"},
    {33017,"http-alt"},
    {33018,"http-alt"},
    {33019,"http-alt"},
    {33020,"http-alt"},
    {33021,"http-alt"},
    {33022,"http-alt"},
    {33023,"http-alt"},
    {33024,"http-alt"},
    {33025,"http-alt"},
    {33026,"http-alt"},
    {33027,"http-alt"},
    {33028,"http-alt"},
    {33029,"http-alt"},
    {33030,"http-alt"},
    {33031,"http-alt"},
    {33032,"http-alt"},
    {33033,"http-alt"},
    {33034,"http-alt"},
    {33035,"http-alt"},
    {33036,"http-alt"},
    {33037,"http-alt"},
    {33038,"http-alt"},
    {33039,"http-alt"},
    {33040,"http-alt"},
    {33041,"http-alt"},
    {33042,"http-alt"},
    {33043,"http-alt"},
    {33044,"http-alt"},
    {33045,"http-alt"},
    {33046,"http-alt"},
    {33047,"http-alt"},
    {33048,"http-alt"},
    {33049,"http-alt"},
    {33050,"http-alt"},
    {33051,"http-alt"},
    {33052,"http-alt"},
    {33053,"http-alt"},
    {33054,"http-alt"},
    {33055,"http-alt"},
    {33056,"http-alt"},
    {33057,"http-alt"},
    {33058,"http-alt"},
    {33059,"http-alt"},
    {33060,"http-alt"},
    {33061,"http-alt"},
    {33062,"http-alt"},
    {33063,"http-alt"},
    {33064,"http-alt"},
    {33065,"http-alt"},
    {33066,"http-alt"},
    {33067,"http-alt"},
    {33068,"http-alt"},
    {33069,"http-alt"},
    {33070,"http-alt"},
    {33071,"http-alt"},
    {33072,"http-alt"},
    {33073,"http-alt"},
    {33074,"http-alt"},
    {33075,"http-alt"},
    {33076,"http-alt"},
    {33077,"http-alt"},
    {33078,"http-alt"},
    {33079,"http-alt"},
    {33080,"http-alt"},
    {33081,"http-alt"},
    {33082,"http-alt"},
    {33083,"http-alt"},
    {33084,"http-alt"},
    {33085,"http-alt"},
    {33086,"http-alt"},
    {33087,"http-alt"},
    {33088,"http-alt"},
    {33089,"http-alt"},
    {33090,"http-alt"},
    {33091,"http-alt"},
    {33092,"http-alt"},
    {33093,"http-alt"},
    {33094,"http-alt"},
    {33095,"http-alt"},
    {33096,"http-alt"},
    {33097,"http-alt"},
    {33098,"http-alt"},
    {33099,"http-alt"},
    {33100,"http-alt"},
};
#define PORT_COUNT (sizeof(PORT_NAMES)/sizeof(PORT_NAMES[0]))


typedef struct {
    const char* service;
    const char* pattern;
    const char* product;
    const char* ver_marker;
} scan_sig_t;

static const scan_sig_t SIGNATURES[] = {
    {"http","Server: Apache/","Apache httpd","/"}
    ,{"http","Server: nginx","nginx","nginx"}
    ,{"http","Server: Microsoft-IIS/","Microsoft IIS","/"}
    ,{"http","Server: lighttpd/","Lighttpd","/"}
    ,{"http","Server: Caddy","Caddy","Caddy"}
    ,{"http","Server: TornadoServer/","Tornado","/"}
    ,{"http","Server: gunicorn","Gunicorn","gunicorn"}
    ,{"http","Server: Cherokee","Cherokee","Cherokee"}
    ,{"http","Server: openresty/","OpenResty","/"}
    ,{"http","Server: Jetty(","Jetty","Jetty"}
    ,{"http","Server: GlassFish","GlassFish","GlassFish"}
    ,{"http","Server: WildFly","WildFly","WildFly"}
    ,{"http","Server: Node.js","Node.js","Node.js"}
    ,{"http","Server: Cowboy","Cowboy","Cowboy"}
    ,{"smtp","ESMTP Postfix","Postfix","Postfix"}
    ,{"smtp","ESMTP Exim","Exim","Exim"}
    ,{"smtp","ESMTP Sendmail","Sendmail","Sendmail"}
    ,{"smtp","ESMTP Courier","Courier","Courier"}
    ,{"smtp","Microsoft ESMTP","Microsoft SMTP","ESMTP"}
    ,{"smtp","ESMTP Dovecot","Dovecot","Dovecot"}
    ,{"smtp","ESMTP IceWarp","IceWarp","IceWarp"}
    ,{"ftp","vsFTPd","vsFTPd","vsFTPd"}
    ,{"ftp","ProFTPD","ProFTPD","ProFTPD"}
    ,{"ftp","Pure-FTPd","Pure-FTPd","Pure-FTPd"}
    ,{"ftp","FileZilla Server","FileZilla","FileZilla"}
    ,{"ftp","Microsoft FTP Service","Microsoft FTP","Service"}
    ,{"ftp","wu-FTPD","Wu-FTPD","wu-FTPD"}
    ,{"ftp","Serv-U FTP","Serv-U","Serv-U"}
    ,{"ssh","OpenSSH","OpenSSH","OpenSSH"}
    ,{"ssh","dropbear","Dropbear","dropbear"}
    ,{"ssh","libssh","libssh","libssh"}
    ,{"pop3","Dovecot ready","Dovecot","Dovecot"}
    ,{"pop3","Courier","Courier","Courier"}
    ,{"pop3","+OK POP3","Generic POP3","POP3"}
    ,{"imap","Dovecot ready","Dovecot","Dovecot"}
    ,{"imap","Courier","Courier","Courier"}
    ,{"imap","Cyrus IMAP","Cyrus IMAP","Cyrus"}
    ,{"mysql","mysql_native_password","MySQL/MariaDB","mysql"}
    ,{"mysql","MariaDB","MariaDB","MariaDB"}
    ,{"mysql","MySQL","MySQL","MySQL"}
    ,{"postgresql","PostgreSQL","PostgreSQL","PostgreSQL"}
    ,{"mongod","MongoDB","MongoDB","MongoDB"}
    ,{"redis","+OK","Redis","+OK"}
    ,{"redis","-ERR","Redis","-ERR"}
    ,{"http","OpenSSL","OpenSSL","OpenSSL"}
    ,{"http","php/","PHP","php/"}
    ,{"http","Python/","Python","Python/"}
    ,{"http","IIS","IIS","IIS"}
    ,{"http","Server: LiteSpeed","LiteSpeed","/"}
    ,{"http","X-Powered-By: LiteSpeed","LiteSpeed","LiteSpeed"}
    ,{"http","cpsrvd/","cPanel","cpsrvd/"}
    ,{"http","WHM/","cPanel WHM","/"}
    ,{"http","Apache/","Apache httpd","/"}
    ,{"http","nginx/","nginx","nginx/"}
    ,{"smtp","220 ","Generic SMTP","220"}
    ,{"pop3","+OK","Generic POP3","+OK"}
    ,{"imap"," OK ","Generic IMAP","OK"}
    ,{"ftp","220 ","Generic FTP","220"}
    ,{"ssh","SSH-","Generic SSH","SSH-"}
    ,{NULL,NULL,NULL,NULL}
};

int scan_port(const char* host, int port, int timeout_ms, char* banner, int banner_size) {
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in addr;
    struct hostent* he;
    int result = 0;

    if (banner) banner[0] = 0;

    he = gethostbyname(host);
    if (!he) return 0;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    connect(s, (struct sockaddr*)&addr, sizeof(addr));

    {
        fd_set fdw, fde;
        struct timeval tv;
        FD_ZERO(&fdw); FD_ZERO(&fde);
        FD_SET(s, &fdw); FD_SET(s, &fde);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
        int sel = select(0, NULL, &fdw, &fde, &tv);
#else
        int sel = select(s + 1, NULL, &fdw, &fde, &tv);
#endif
        if (sel > 0 && FD_ISSET(s, &fdw) && !FD_ISSET(s, &fde)) {
            result = 1;
        }
    }

    if (result && banner && banner_size > 0) {
#ifdef _WIN32
        mode = 0;
        ioctlsocket(s, FIONBIO, &mode);
#else
        fcntl(s, F_SETFL, flags);
#endif
        int short_ms = timeout_ms < 500 ? timeout_ms : 500;
        struct timeval rtv;
        rtv.tv_sec = short_ms / 1000;
        rtv.tv_usec = (short_ms % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rtv, sizeof(rtv));

        char tmp[4096];
        int total = 0, n;

        n = (int)recv(s, tmp + total, sizeof(tmp) - 1 - total, 0);
        if (n > 0) total += n;

        if (port == 21)
            send(s, "SYST\r\n", 6, 0);
        else if (port == 22)
            ;
        else if (port == 25 || port == 465 || port == 587 || port == 2525)
            send(s, "EHLO scan\r\n", 12, 0);
        else if (port == 110 || port == 995)
            send(s, "CAPA\r\n", 6, 0);
        else if (port == 143 || port == 993 || port == 220 || port == 585)
            send(s, "A001 CAPABILITY\r\n", 18, 0);
        else if (port == 119)
            send(s, "CAPABILITIES\r\n", 14, 0);
        else if (port == 80 || port == 443 || port == 8080 || port == 8443 ||
                 port == 8000 || port == 8008 || port == 8888 || port == 2082 ||
                 port == 2083 || port == 2086 || port == 2087 || port == 2096)
            send(s, "HEAD / HTTP/1.0\r\n\r\n", 20, 0);
        else if (port == 3306)
            ;
        else if (port == 5432)
            send(s, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8, 0);
        else if (port == 6379)
            send(s, "PING\r\n", 6, 0);
        else if (port == 27017 || port == 27018)
            send(s, "\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
                       "\x00admin.$cmd\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00"
                       "\x10ismaster\x00\x01\x00\x00\x00\x00", 59, 0);
        else
            send(s, "\r\n\r\n", 4, 0);

        SLEEP_MS(200);
        for (int i = 0; i < 3; i++) {
            n = (int)recv(s, tmp + total, sizeof(tmp) - 1 - total, 0);
            if (n > 0) total += n;
            else break;
            if (total >= (int)sizeof(tmp) - 1) break;
        }

        if (total > 0) {
            tmp[total] = 0;
            int si = 0, di = 0;
            while (tmp[si] && di < banner_size - 1) {
                char c = tmp[si++];
                if (c == '\r') continue;
                if (c == '\n') { banner[di++] = ' '; continue; }
                if (c >= 32 && c < 127) banner[di++] = c;
                else if (di > 0 && banner[di-1] != '.') banner[di++] = '.';
            }
            banner[di] = 0;
        }
    }

    CLOSE_SOCKET(s);
    return result;
}

void detect_version(const char* banner, const char* service, char* product_out, int product_size, char* version_out, int version_size) {
    if (!banner || !banner[0]) return;
    if (product_out) product_out[0] = 0;
    if (version_out) version_out[0] = 0;

    for (int i = 0; SIGNATURES[i].pattern; i++) {
        if (SIGNATURES[i].service && service && strcmp(SIGNATURES[i].service, service) != 0) continue;
        const char* m = strstr(banner, SIGNATURES[i].pattern);
        if (!m) continue;
        if (product_out) {
            strncpy(product_out, SIGNATURES[i].product, product_size - 1);
            product_out[product_size - 1] = 0;
        }
        if (version_out && SIGNATURES[i].ver_marker) {
            const char* vp = strstr(banner, SIGNATURES[i].ver_marker);
            if (vp) {
                vp += strlen(SIGNATURES[i].ver_marker);
                while (*vp && *vp != '/' && *vp != ' ' && *vp != '\t' && *vp != '\r' && *vp != '\n' && !isdigit((unsigned char)*vp)) vp++;
                if (isdigit((unsigned char)*vp)) {
                    int vi = 0;
                    while (*vp && vi < version_size - 1 && (isdigit((unsigned char)*vp) || *vp == '.' || *vp == '_' || *vp == '-' || *vp == 'p' || *vp == 'P')) {
                        version_out[vi++] = *vp;
                        vp++;
                    }
                    if (vi > 0) {
                        while (vi > 0 && (version_out[vi-1] == '.' || version_out[vi-1] == '_' || version_out[vi-1] == '-')) vi--;
                        version_out[vi] = 0;
                    }
                }
            }
        }
        return;
    }

    if (version_out && !version_out[0]) {
        const char* markers[] = {"version ", "Version ", "/v", " V", "v", NULL};
        for (int mi = 0; markers[mi]; mi++) {
            const char* p = strstr(banner, markers[mi]);
            if (!p) continue;
            p += strlen(markers[mi]);
            while (*p && !isdigit((unsigned char)*p) && *p != ' ') p++;
            while (*p == ' ') p++;
            if (isdigit((unsigned char)*p)) {
                int vi = 0;
                while (*p && vi < version_size - 1 && (isdigit((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')) {
                    version_out[vi++] = *p;
                    p++;
                }
                if (vi > 0) {
                    while (vi > 0 && (version_out[vi-1] == '.' || version_out[vi-1] == '_' || version_out[vi-1] == '-')) vi--;
                    version_out[vi] = 0;
                }
                break;
            }
        }
    }
}

int parse_ports(const char* port_str, int* ports_out, int max_ports) {
    if (!port_str || !ports_out || max_ports <= 0) return -1;
    char buf[65536];
    strncpy(buf, port_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    int count = 0;
    char* token = strtok(buf, ",");
    while (token && count < max_ports) {
        while (*token == ' ' || *token == '\t') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) end--;
        end[1] = 0;
        if (!*token) { token = strtok(NULL, ","); continue; }
        char* dash = strchr(token, '-');
        if (dash) {
            *dash = 0;
            int start = atoi(token);
            int finish = atoi(dash + 1);
            if (start > 0 && finish > 0 && start <= finish) {
                for (int p = start; p <= finish && count < max_ports; p++)
                    ports_out[count++] = p;
            }
        } else {
            int p = atoi(token);
            if (p > 0) ports_out[count++] = p;
        }
        token = strtok(NULL, ",");
    }
    return count;
}

const char* get_service_name(int port) {
    int lo = 0, hi = PORT_COUNT - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (PORT_NAMES[mid].port == port) return PORT_NAMES[mid].name;
        if (PORT_NAMES[mid].port < port) lo = mid + 1;
        else hi = mid - 1;
    }
    return "unknown";
}

typedef struct {
    char host[256];
    const int* ports;
    int port_count;
    volatile int next_idx;
    int timeout_ms;
    void (*callback)(int port, int state, const char* service, const char* product, const char* version, const char* banner);
    LOCK_T* lock;
} scan_shared_t;

typedef struct {
    scan_shared_t* shared;
    int tid;
} scan_thread_arg_t;

static THREAD_RET thread_worker(void* arg) {
    scan_thread_arg_t* ta = (scan_thread_arg_t*)arg;
    scan_shared_t* sh = ta->shared;
    char banner[2048];
    char service[64], product[64], version[64];
    for (;;) {
        LOCK_ACQUIRE(sh->lock);
        int idx = sh->next_idx;
        if (idx >= sh->port_count) {
            LOCK_RELEASE(sh->lock);
            break;
        }
        sh->next_idx = idx + 1;
        LOCK_RELEASE(sh->lock);
        int port = sh->ports[idx];
        int state = scan_port(sh->host, port, sh->timeout_ms, banner, sizeof(banner));
        const char* svc = get_service_name(port);
        strncpy(service, svc, sizeof(service)-1);
        service[sizeof(service)-1] = 0;
        product[0] = 0; version[0] = 0;
        if (state && banner[0]) {
            detect_version(banner, service, product, sizeof(product), version, sizeof(version));
        }
        if (sh->callback)
            sh->callback(port, state, service, product, version, banner);
    }
    return 0;
}

int scan_ports_full(const char* host, const int* ports, int port_count, int timeout_ms, int threads,
    void (*callback)(int port, int state, const char* service, const char* product, const char* version, const char* banner))
{
    if (!host || !ports || port_count <= 0 || !callback) return -1;
    if (threads <= 0 || threads > MAX_THREADS) threads = MAX_THREADS;
    if (port_count < threads) threads = port_count;

    LOCK_T lock;
    LOCK_INIT(&lock);

    scan_shared_t shared;
    strncpy(shared.host, host, sizeof(shared.host)-1);
    shared.host[sizeof(shared.host)-1] = 0;
    shared.ports = ports;
    shared.port_count = port_count;
    shared.next_idx = 0;
    shared.timeout_ms = timeout_ms;
    shared.callback = callback;
    shared.lock = &lock;

    THREAD_HANDLE handles[MAX_THREADS];
    scan_thread_arg_t args[MAX_THREADS];
    int created = 0;

    for (int i = 0; i < threads; i++) {
        args[i].shared = &shared;
        args[i].tid = i;
        if (THREAD_CREATE(handles[i], thread_worker, &args[i]))
            created++;
        else
            break;
    }

    for (int i = 0; i < created; i++) {
        THREAD_JOIN(handles[i]);
        THREAD_CLOSE(handles[i]);
    }

    LOCK_DESTROY(&lock);
    return port_count;
}

static void print_result(int port, int state, const char* service, const char* product, const char* version, const char* banner) {
    printf("[SCAN] PORT=%d STATE=%s SERVICE=%s", port, state ? "open" : "closed", service);
    if (state && product[0]) printf(" PRODUCT=%s", product);
    if (state && version[0]) printf(" VERSION=%s", version);
    if (state && banner[0]) printf(" BANNER=\"%s\"", banner);
    printf("\n");
    fflush(stdout);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <host> <ports> [timeout_ms] [threads]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s 192.168.1.1 22,80,443\n", argv[0]);
        printf("  %s 192.168.1.1 1-1000\n", argv[0]);
        printf("  %s scanme.nmap.org 22,80,443,8080,1000-2000\n", argv[0]);
        printf("  %s 192.168.1.1 22,80,443 3000 50\n", argv[0]);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    const char* host = argv[1];
    const char* port_str = argv[2];
    int timeout = (argc > 3) ? atoi(argv[3]) : DEFAULT_TIMEOUT;
    if (timeout <= 0) timeout = DEFAULT_TIMEOUT;
    int threads = (argc > 4) ? atoi(argv[4]) : 100;
    if (threads <= 0 || threads > MAX_THREADS) threads = 100;

    int ports[MAX_PORTS];
    int port_count = parse_ports(port_str, ports, MAX_PORTS);
    if (port_count <= 0) {
        fprintf(stderr, "No valid ports specified\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    fprintf(stderr, "[*] Scanning %s with %d ports (%d threads, %dms timeout)\n",
        host, port_count, threads, timeout);
    fflush(stderr);

    scan_ports_full(host, ports, port_count, timeout, threads, print_result);

    fprintf(stderr, "[*] Scan complete: %d ports checked on %s\n", port_count, host);
    fflush(stderr);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

