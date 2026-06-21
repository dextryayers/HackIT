use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_BANNER: usize = 8192;

lazy_static::lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (String, Instant)>> = RwLock::new(HashMap::new());
    static ref PROBE_MAP: HashMap<u16, Vec<Vec<u8>>> = {
        let mut m = HashMap::new();
        m.insert(21, vec![b"SYST\r\n".to_vec(), b"FEAT\r\n".to_vec()]);
        m.insert(22, vec![b"SSH-2.0-HackIT-Probe\r\n".to_vec()]);
        m.insert(25, vec![b"EHLO hackit.discovery\r\n".to_vec()]);
        m.insert(53, vec![b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec()]);
        m.insert(80, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec()]);
        m.insert(110, vec![b"CAPA\r\n".to_vec()]);
        m.insert(143, vec![b"A1 CAPABILITY\r\n".to_vec()]);
        m.insert(161, vec![b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec()]);
        m.insert(389, vec![b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec()]);
        m.insert(443, vec![b"".to_vec()]);
        m.insert(445, vec![b"\x00\x00\x00\xa0\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(465, vec![b"EHLO hackit.discovery\r\n".to_vec()]);
        m.insert(587, vec![b"EHLO hackit.discovery\r\n".to_vec()]);
        m.insert(636, vec![b"".to_vec()]);
        m.insert(873, vec![b"@RSYNCD: 31.0\n".to_vec()]);
        m.insert(990, vec![b"".to_vec()]);
        m.insert(992, vec![b"".to_vec()]);
        m.insert(993, vec![b"".to_vec()]);
        m.insert(995, vec![b"".to_vec()]);
        m.insert(1080, vec![b"\x05\x01\x00".to_vec()]);
        m.insert(1194, vec![b"".to_vec()]);
        m.insert(1433, vec![b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00".to_vec()]);
        m.insert(1521, vec![b"\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x32\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(1723, vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(1883, vec![b"\x10\x0e\x00\x04\x4d\x51\x54\x54\x04\x02\x00\x3c\x00\x0a\x00\x05".to_vec()]);
        m.insert(2082, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(2083, vec![b"".to_vec()]);
        m.insert(2086, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(2087, vec![b"".to_vec()]);
        m.insert(2181, vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(2375, vec![b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(2376, vec![b"".to_vec()]);
        m.insert(2379, vec![b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(3000, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(3128, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(3306, vec![b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(3389, vec![b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec()]);
        m.insert(5432, vec![b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec()]);
        m.insert(5672, vec![b"AMQP\x00\x00\x09\x01".to_vec()]);
        m.insert(5900, vec![b"RFB 003.008\n".to_vec()]);
        m.insert(5984, vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()]);
        m.insert(6379, vec![b"PING\r\n".to_vec(), b"INFO\r\n".to_vec()]);
        m.insert(6443, vec![b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(6667, vec![b"NICK hackit\r\nUSER hackit 0 * :HackIT Scan\r\n".to_vec()]);
        m.insert(8000, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec()]);
        m.insert(8080, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec()]);
        m.insert(8443, vec![b"".to_vec()]);
        m.insert(8500, vec![b"GET /v1/agent/self HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(8888, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(8983, vec![b"GET /solr/ HTTP/1.0\r\n\r\n".to_vec()]);
        m.insert(9000, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(9042, vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(9090, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(9092, vec![b"".to_vec()]);
        m.insert(9100, vec![b"".to_vec()]);
        m.insert(9200, vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()]);
        m.insert(11211, vec![b"stats\r\n".to_vec()]);
        m.insert(15672, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(25565, vec![b"\xfe\x01".to_vec()]);
        m.insert(27017, vec![b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec()]);
        m.insert(32400, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m
    };
}

pub fn resolve_host(host: &str) -> Option<String> {
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ip, expiry)) = cache.get(host) {
            if expiry.elapsed() < DNS_CACHE_TTL {
                return Some(ip.clone());
            }
        }
    }
    let addr = format!("{}:0", host);
    if let Some(ok) = addr.to_socket_addrs().ok()?.find(|a| a.is_ipv4()) {
        let ip = ok.ip().to_string();
        let mut cache = DNS_CACHE.write().unwrap();
        cache.insert(host.to_string(), (ip.clone(), Instant::now()));
        Some(ip)
    } else {
        None
    }
}

pub fn resolve_ip(host: &str) -> Option<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip);
    }
    let addr = format!("{}:0", host);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(a) = addrs.find(|a| a.is_ipv4()) {
            return Some(a.ip());
        }
    }
    None
}

pub fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::with_capacity(1024);
    let input = input.trim();
    if input.eq_ignore_ascii_case("all") {
        return (1..=65535).collect();
    }
    if let Some(top_s) = input.strip_prefix("top:").or_else(|| input.strip_prefix("top")) {
        let n: usize = top_s.parse().unwrap_or(100);
        let top = vec![7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,
            135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
            554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,
            1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,
            4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,
            5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
            9999,10000,32768,49152,49154];
        return top.into_iter().take(n).collect();
    }
    if input.eq_ignore_ascii_case("top100") || input.eq_ignore_ascii_case("fast") {
        return vec![21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,500,514,
            543,544,546,547,548,554,587,631,636,646,873,990,992,993,995,1080,1194,
            1352,1433,1521,1723,1755,1883,1900,2000,2049,2082,2083,2086,2087,2181,
            2375,2376,2379,2483,2484,2628,3000,3128,3260,3306,3389,3478,3632,3690,
            4000,4369,4443,4567,4662,4848,5000,5001,5060,5061,5222,5342,5432,5672,
            5900,5984,5985,5986,6000,6379,6443,6580,6667,6881,6969,7001,7002,7070,
            7100,7443,7474,7547,7741,8000,8008,8009,8080,8081,8082,8088,8090,8181,
            8222,8243,8280,8300,8332,8333,8443,8500,8530,8531,8600,8649,8834,8888,
            8983,9000,9001,9042,9090,9092,9100,9160,9200,9300,9418,9443,9600,9999,
            10000,10001,10009,10010,10050,10051,10250,11211,12000,12345,15672,16080,
            16225,16379,16443,16992,16993,17017,18080,18081,18264,20000,21379,21571,
            22222,23333,24444,24800,25565,26000,26208,27017,27018,27019,27374,28017,
            30718,31337,32400,32764,32768,32822,33848,34012,36865,37444,37651,37777,
            38893,39148,40000,40911,41511,42510,44176,44442,44443,44501,44818,45000,
            45054,45564,45678,45920,47000,47557,47624,47806,47808,48080,49152,49153,
            49154,49155,49156,49157,49158,49159,49160,49161,49162,49163,49164,49165,
            49166,49167,49168,49169,49170,49171,49172,49173,49174,49175,49176,49177,
            49178,49179,49180,49181,49182,49183,49184,49185,49186,49187,49188,49189,
            49190,49191,49192,49301,49400,49999,50000,50001,50002,50003,50006,50300,
            50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,
            55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,60606,
            61613,61616,62078,63331,64623,64680,65000,65129,65389,65535];
    }
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse().unwrap_or(1);
            let e: u16 = end.parse().unwrap_or(65535);
            for p in s..=e { ports.push(p); }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

pub fn service_for_port(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 111 => "RPC", 135 => "MSRPC", 139 => "NetBIOS",
        143 => "IMAP", 161 => "SNMP", 162 => "SNMP-Trap", 179 => "BGP",
        389 => "LDAP", 443 => "HTTPS", 445 => "SMB", 465 => "SMTPS",
        500 => "ISAKMP", 512 => "Exec", 513 => "Login", 514 => "Syslog",
        515 => "Printer", 520 => "RIP", 521 => "RIPng", 540 => "UUCP",
        543 => "Kerberos", 544 => "krcmd", 546 => "DHCPv6-Client",
        547 => "DHCPv6-Server", 548 => "AFP", 554 => "RTSP",
        587 => "SMTP-MSA", 631 => "IPP", 636 => "LDAPS", 646 => "LDP",
        873 => "Rsync", 990 => "FTPS", 992 => "Telnets", 993 => "IMAPS",
        995 => "POP3S", 1080 => "SOCKS", 1194 => "OpenVPN",
        1352 => "Lotus-Notes", 1433 => "MSSQL", 1521 => "Oracle-DB",
        1723 => "PPTP", 1755 => "WMS", 1883 => "MQTT", 1900 => "UPnP",
        2000 => "Cisco-SCCP", 2049 => "NFS", 2082 => "cPanel", 2083 => "cPanel-SSL",
        2086 => "WHM", 2087 => "WHM-SSL", 2181 => "ZooKeeper",
        2375 => "Docker", 2376 => "Docker-TLS", 2379 => "etcd",
        2483 => "Oracle-DB", 2484 => "Oracle-DB-SSL", 2628 => "DICT",
        3000 => "Grafana/Node-App", 3128 => "Squid", 3260 => "iSCSI",
        3306 => "MySQL", 3389 => "RDP", 3478 => "STUN/TURN",
        3632 => "distcc", 3690 => "SVN", 4000 => "ICQ/Direct-Connect",
        4369 => "EPMD", 4443 => "AJP13", 4489 => "ALTS", 4567 => "Sinatra",
        4662 => "eMule", 4848 => "GlassFish", 5000 => "UPnP/Synology",
        5001 => "Synology-DSM", 5002 => "RTP-Media", 5050 => "Yahoo!-Messenger",
        5060 => "SIP", 5061 => "SIP-TLS", 5222 => "XMPP", 5342 => "Kazaa",
        5432 => "PostgreSQL", 5672 => "AMQP", 5900 => "VNC",
        5984 => "CouchDB", 5985 => "WinRM", 5986 => "WinRM-SSL",
        6000 => "X11", 6001 => "X11-1", 6379 => "Redis", 6443 => "K8s-API",
        6580 => "Parsec", 6667 => "IRC", 6881 => "BitTorrent",
        6969 => "BitTorrent-Tracker", 7001 => "WebLogic", 7002 => "WebLogic-SSL",
        7070 => "RealServer", 7100 => "Xfer", 7443 => "OWA-SSL",
        7474 => "Neo4j", 7547 => "CWMP", 7741 => "CUPS-Remote",
        8000 => "HTTP-Alt", 8008 => "HTTP-Alt", 8009 => "AJP13",
        8080 => "HTTP-Proxy", 8081 => "HTTP-Alt", 8082 => "HTTP-Alt",
        8088 => "HTTP-Alt", 8090 => "HTTP-Alt", 8181 => "HTTP-Alt",
        8222 => "VMware", 8243 => "HTTPS-Alt", 8280 => "HTTPS-Alt",
        8300 => "HTTP-Cluster", 8332 => "Bitcoin", 8333 => "Bitcoin-Test",
        8443 => "HTTPS-Alt", 8500 => "Consul", 8530 => "HTTP-Alt",
        8531 => "HTTPS-Alt", 8600 => "HTTP-Alt", 8649 => "Ganglia",
        8834 => "Nessus", 8888 => "HTTP-Alt", 8889 => "HTTP-Alt",
        8983 => "Solr", 9000 => "SonarQube", 9001 => "CCP",
        9042 => "Cassandra", 9090 => "Prometheus", 9092 => "Kafka",
        9100 => "JetDirect", 9160 => "Cassandra-Thrift", 9200 => "Elasticsearch",
        9300 => "Elasticsearch-Cluster", 9418 => "Git", 9443 => "HTTPS-Alt",
        9600 => "OMD", 9999 => "HTTP-Alt", 10000 => "Webmin",
        10001 => "SCP-Config", 10009 => "CrossFire", 10010 => "OpenVPN",
        10050 => "Zabbix-Agent", 10051 => "Zabbix-Trapper",
        10250 => "Kubelet", 11211 => "Memcached", 11214 => "Memcached-SSL",
        12000 => "HSRP", 12345 => "NetBus", 15672 => "RabbitMQ",
        16080 => "HTTP-Alt", 16225 => "PulseSecure", 16379 => "Redis-Alt",
        16443 => "K8s-Dashboard", 16992 => "AMT", 16993 => "AMT-SSL",
        17017 => "HP-SSH", 18080 => "HTTP-Alt", 18081 => "HTTP-Alt",
        18264 => "GPG", 20000 => "DNP", 21379 => "OCS",
        21571 => "AiR", 22222 => "HTTP-Alt", 23333 => "HTTP-Alt",
        24444 => "HTTP-Alt", 24800 => "Synergy", 25565 => "Minecraft",
        26000 => "Quake", 26208 => "HTTP-Alt", 27017 => "MongoDB",
        27018 => "MongoDB-Shard", 27019 => "MongoDB-Config",
        27374 => "Sub7", 28017 => "MongoDB-Web", 30718 => "HTTP-Alt",
        31337 => "BackOrifice", 32400 => "Plex", 32764 => "WRT-Config",
        32768 => "Filenet", 32822 => "HTTP-Alt", 33848 => "Jenkins",
        34012 => "HTTP-Alt", 36865 => "HTTP-Alt", 37444 => "HTTP-Alt",
        37651 => "HTTP-Alt", 37777 => "HTTP-Alt", 38893 => "HTTP-Alt",
        39148 => "HTTP-Alt", 40000 => "HTTP-Alt", 40911 => "HTTP-Alt",
        41511 => "HTTP-Alt", 42510 => "HTTP-Alt", 44176 => "HTTP-Alt",
        44442 => "HTTP-Alt", 44443 => "HTTP-Alt", 44501 => "HTTP-Alt",
        44818 => "EtherNet/IP", 45000 => "HTTP-Alt", 45054 => "HTTP-Alt",
        45564 => "HTTP-Alt", 45678 => "HTTP-Alt", 45920 => "HTTP-Alt",
        47000 => "HTTP-Alt", 47557 => "HTTP-Alt", 47624 => "HTTP-Alt",
        47806 => "HTTP-Alt", 47808 => "BACnet", 48080 => "HTTP-Alt",
        49152..=49192 => "Windows-RPC-Dynamic",
        49301 => "HTTP-Alt", 49400 => "HTTP-Alt", 49999 => "HTTP-Alt",
        50000 => "SAP-Dispatcher", 50001 => "HTTP-Alt", 50002 => "HTTP-Alt",
        50003 => "HTTP-Alt", 50006 => "HTTP-Alt", 50300 => "HTTP-Alt",
        50389 => "HTTP-Alt", 50500 => "HTTP-Alt", 50636 => "HTTP-Alt",
        50800 => "HTTP-Alt", 51103 => "HTTP-Alt", 51493 => "HTTP-Alt",
        52673 => "HTTP-Alt", 52822 => "HTTP-Alt", 52848 => "HTTP-Alt",
        52869 => "HTTP-Alt", 54045 => "HTTP-Alt", 54328 => "HTTP-Alt",
        55055 => "HTTP-Alt", 55056 => "HTTP-Alt", 55555 => "HTTP-Alt",
        55600 => "HTTP-Alt", 56737 => "HTTP-Alt", 56738 => "HTTP-Alt",
        57294 => "HTTP-Alt", 57797 => "HTTP-Alt", 58080 => "HTTP-Alt",
        60020 => "HTTP-Alt", 60443 => "HTTP-Alt", 60606 => "HTTP-Alt",
        61613 => "STOMP", 61616 => "ActiveMQ", 62078 => "iPhone-Sync",
        63331 => "HTTP-Alt", 64623 => "HTTP-Alt", 64680 => "HTTP-Alt",
        65000 => "HTTP-Alt", 65129 => "HTTP-Alt", 65389 => "HTTP-Alt",
        65535 => "HTTP-Alt",
        _ => "unknown",
    }
}

pub fn service_name(port: u16) -> Option<String> {
    let svc = service_for_port(port);
    if svc == "unknown" { None } else { Some(svc.to_string()) }
}

pub fn sanitize_banner(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\r' => {},
            '\n' => { if !out.ends_with(' ') { out.push(' '); } },
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => {}
        }
    }
    if out.len() > 500 { out.truncate(500); out.push_str("..."); }
    out
}

pub fn get_ping_ttl(host: &str) -> i32 {
    if let Ok(out) = Command::new("ping").args(["-c", "1", "-W", "2", host]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(pos) = line.find("ttl=") {
                let rest: String = line[pos + 4..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(ttl) = rest.parse::<i32>() { return ttl; }
            }
        }
    }
    0
}

pub fn grab_banner_sync(host: &str, port: u16, timeout_ms: u64) -> String {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    let probes = PROBE_MAP.get(&port).cloned().unwrap_or_else(|| vec![b"\r\n".to_vec()]);
    let mut best_banner = String::new();
    for probe in probes {
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| format!("{}:{}", host, port).parse().unwrap()),
            Duration::from_millis(timeout_ms)
        ) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
            if !probe.is_empty() {
                let _ = stream.write_all(&probe);
                let _ = stream.flush();
            }
            let mut buffer = [0u8; MAX_BANNER];
            match stream.read(&mut buffer) {
                Ok(bytes_read) if bytes_read > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                    if response.len() > best_banner.len() {
                        best_banner = response.to_string();
                    }
                }
                _ => continue,
            }
        }
    }
    sanitize_banner(&best_banner)
}

pub fn identify_service(banner: &str, port: u16) -> String {
    let b = banner.to_lowercase();
    let patterns: Vec<(&[&str], &str)> = vec![
        (&["openssh", "ssh-"], "SSH"),
        (&["dropbear"], "SSH (Dropbear)"),
        (&["libssh"], "SSH (libssh)"),
        (&["nginx"], "Nginx"),
        (&["apache"], "Apache"),
        (&["microsoft-iis", "iis"], "IIS"),
        (&["litespeed"], "LiteSpeed"),
        (&["lighttpd"], "Lighttpd"),
        (&["openresty"], "OpenResty"),
        (&["caddy"], "Caddy"),
        (&["tomcat"], "Tomcat"),
        (&["gunicorn"], "Gunicorn"),
        (&["node.js", "nodejs"], "Node.js"),
        (&["jetty"], "Jetty"),
        (&["cherokee"], "Cherokee"),
        (&["vsftpd"], "vsftpd"),
        (&["proftpd"], "ProFTPD"),
        (&["pure-ftpd", "pureftpd"], "Pure-FTPd"),
        (&["filezilla"], "FileZilla"),
        (&["postfix"], "Postfix"),
        (&["exim"], "Exim"),
        (&["sendmail"], "Sendmail"),
        (&["mysql", "mariadb"], "MySQL/MariaDB"),
        (&["postgresql", "postgres"], "PostgreSQL"),
        (&["redis_version", "redis_mode", "+ok\r\n"], "Redis"),
        (&["mongodb"], "MongoDB"),
        (&["elasticsearch", "cluster_name"], "Elasticsearch"),
        (&["memcached"], "Memcached"),
        (&["cassandra"], "Cassandra"),
        (&["couchdb"], "CouchDB"),
        (&["rabbitmq", "amqp"], "RabbitMQ"),
        (&["activemq"], "ActiveMQ"),
        (&["kafka"], "Kafka"),
        (&["zookeeper"], "ZooKeeper"),
        (&["consul"], "Consul"),
        (&["etcd"], "etcd"),
        (&["prometheus"], "Prometheus"),
        (&["grafana"], "Grafana"),
        (&["docker"], "Docker"),
        (&["kubernetes"], "Kubernetes"),
        (&["rfb 00", "rfb 003", "rfb 004"], "VNC"),
        (&["ms-terminal", "rdp"], "RDP"),
        (&["sip/2.0", "sip:"], "SIP"),
        (&["smtp", "esmtp"], "SMTP"),
        (&["pop3", "+ok pop"], "POP3"),
        (&["imap", "* ok"], "IMAP"),
        (&["ldap"], "LDAP"),
        (&["snmp"], "SNMP"),
        (&["dns"], "DNS"),
        (&["http/", "<html", "<!doctype", "content-type"], "HTTP"),
    ];
    for (keywords, name) in &patterns {
        for kw in *keywords {
            if b.contains(kw) {
                return name.to_string();
            }
        }
    }
    service_for_port(port).to_string()
}

pub fn extract_service_version(banner: &str) -> String {
    let b = banner.to_lowercase();
    let checks = vec![
        ("openssh_", "OpenSSH"),
        ("nginx/", "nginx"),
        ("apache/", "Apache"),
        ("mysql ", "MySQL"),
        ("postgresql ", "PostgreSQL"),
        ("redis_version:", "Redis"),
    ];
    for (marker, _) in checks {
        if let Some(pos) = b.find(marker) {
            let start = pos + marker.len();
            let rest = &banner[start..];
            let ver: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '_').collect();
            if !ver.is_empty() {
                return ver.trim_matches('.').trim_matches('_').to_string();
            }
        }
    }
    String::new()
}
