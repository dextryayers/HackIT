use regex::Regex;
use rust_port_scanner::*;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

lazy_static::lazy_static! {
    static ref SERVICE_PATTERNS: Vec<(Regex, &'static str, &'static str, &'static str)> = {
        let mut v = Vec::new();
        v.push((Regex::new(r"(?i)ssh-2\.0-openssh[_-]([0-9._p]+)").unwrap(), "SSH", "OpenSSH", "openssh"));
        v.push((Regex::new(r"(?i)ssh-2\.0-dropbear[_-]([0-9._p]+)").unwrap(), "SSH", "Dropbear", "dropbear"));
        v.push((Regex::new(r"(?i)ssh-2\.0-libssh[_-]([0-9._p]+)").unwrap(), "SSH", "libssh", "libssh"));
        v.push((Regex::new(r"(?i)ssh-2\.0-putty[_-]([0-9._p]+)").unwrap(), "SSH", "PuTTY", "putty"));
        v.push((Regex::new(r"(?i)server:\s*nginx/([0-9.]+)").unwrap(), "HTTP", "Nginx", "nginx"));
        v.push((Regex::new(r"(?i)server:\s*apache/([0-9.]+)").unwrap(), "HTTP", "Apache", "apache"));
        v.push((Regex::new(r"(?i)server:\s*apache").unwrap(), "HTTP", "Apache", "apache"));
        v.push((Regex::new(r"(?i)server:\s*microsoft-iis/([0-9.]+)").unwrap(), "HTTP", "IIS", "iis"));
        v.push((Regex::new(r"(?i)server:\s*litespeed/([0-9.]+)").unwrap(), "HTTP", "LiteSpeed", "litespeed"));
        v.push((Regex::new(r"(?i)server:\s*lighttpd/([0-9.]+)").unwrap(), "HTTP", "Lighttpd", "lighttpd"));
        v.push((Regex::new(r"(?i)server:\s*openresty/([0-9.]+)").unwrap(), "HTTP", "OpenResty", "openresty"));
        v.push((Regex::new(r"(?i)server:\s*caddy/([0-9.]+)").unwrap(), "HTTP", "Caddy", "caddy"));
        v.push((Regex::new(r"(?i)server:\s*gunicorn/([0-9.]+)").unwrap(), "HTTP", "Gunicorn", "gunicorn"));
        v.push((Regex::new(r"(?i)server:\s*node\.js/([v]?[0-9.]+)").unwrap(), "HTTP", "Node.js", "nodejs"));
        v.push((Regex::new(r"(?i)server:\s*tomcat/([0-9.]+)").unwrap(), "HTTP", "Tomcat", "tomcat"));
        v.push((Regex::new(r"(?i)server:\s*jboss/([0-9.]+)").unwrap(), "HTTP", "JBoss", "jboss"));
        v.push((Regex::new(r"(?i)server:\s*jetty/([0-9.]+)").unwrap(), "HTTP", "Jetty", "jetty"));
        v.push((Regex::new(r"(?i)server:\s*webrick/([0-9.]+)").unwrap(), "HTTP", "WEBrick", "webrick"));
        v.push((Regex::new(r"(?i)server:\s*cherokee/([0-9.]+)").unwrap(), "HTTP", "Cherokee", "cherokee"));
        v.push((Regex::new(r"(?i)server:\s*hiawatha/([0-9.]+)").unwrap(), "HTTP", "Hiawatha", "hiawatha"));
        v.push((Regex::new(r"(?i)server:\s*cloudflare").unwrap(), "HTTP", "Cloudflare", "cloudflare"));
        v.push((Regex::new(r"(?i)220.*pure-ftpd[^0-9]*([0-9.]+)").unwrap(), "FTP", "Pure-FTPd", "pureftpd"));
        v.push((Regex::new(r"(?i)220.*proftpd[^0-9]*([0-9.]+)").unwrap(), "FTP", "ProFTPD", "proftpd"));
        v.push((Regex::new(r"(?i)220.*vsftpd[^0-9]*([0-9.]+)").unwrap(), "FTP", "vsftpd", "vsftpd"));
        v.push((Regex::new(r"(?i)220.*filezilla[^0-9]*([0-9.]+)").unwrap(), "FTP", "FileZilla", "filezilla"));
        v.push((Regex::new(r"(?i)220.*wu-ftpd[^0-9]*([0-9.]+)").unwrap(), "FTP", "wu-ftpd", "wuftpd"));
        v.push((Regex::new(r"(?i)220.*microsoft.*ftp").unwrap(), "FTP", "Microsoft FTP", "msftp"));
        v.push((Regex::new(r"(?i)220.*postfix[^0-9]*([0-9.]+)").unwrap(), "SMTP", "Postfix", "postfix"));
        v.push((Regex::new(r"(?i)220.*exim[^0-9]*([0-9.]+)").unwrap(), "SMTP", "Exim", "exim"));
        v.push((Regex::new(r"(?i)220.*sendmail[^0-9]*([0-9.]+)").unwrap(), "SMTP", "Sendmail", "sendmail"));
        v.push((Regex::new(r"(?i)220.*dovecot[^0-9]*([0-9.]+)").unwrap(), "IMAP", "Dovecot", "dovecot"));
        v.push((Regex::new(r"(?i)220.*courier[^0-9]*([0-9.]+)").unwrap(), "IMAP", "Courier", "courier"));
        v.push((Regex::new(r"(?i)mysql.*([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MySQL", "MySQL", "mysql"));
        v.push((Regex::new(r"(?i)mariadb.*([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MySQL", "MariaDB", "mariadb"));
        v.push((Regex::new(r"(?i)postgresql[^0-9]*([0-9.]+)").unwrap(), "PostgreSQL", "PostgreSQL", "postgresql"));
        v.push((Regex::new(r"(?i)redis_version:([0-9.]+)").unwrap(), "Redis", "Redis", "redis"));
        v.push((Regex::new(r"(?i)redis_mode:").unwrap(), "Redis", "Redis", "redis"));
        v.push((Regex::new(r"(?i)mongodb[^0-9]*([0-9.]+)").unwrap(), "MongoDB", "MongoDB", "mongodb"));
        v.push((Regex::new(r"(?i)elasticsearch[^0-9]*([0-9.]+)").unwrap(), "Elasticsearch", "Elasticsearch", "elasticsearch"));
        v.push((Regex::new(r"(?i)cluster_name:").unwrap(), "Elasticsearch", "Elasticsearch", "elasticsearch"));
        v.push((Regex::new(r"(?i)memcached[^0-9]*([0-9.]+)").unwrap(), "Memcached", "Memcached", "memcached"));
        v.push((Regex::new(r"(?i)cassandra[^0-9]*([0-9.]+)").unwrap(), "Cassandra", "Cassandra", "cassandra"));
        v.push((Regex::new(r"(?i)couchdb[^0-9]*([0-9.]+)").unwrap(), "CouchDB", "CouchDB", "couchdb"));
        v.push((Regex::new(r"(?i)amqp[^0-9]*([0-9.]+)").unwrap(), "AMQP", "RabbitMQ", "rabbitmq"));
        v.push((Regex::new(r"(?i)prometheus[^0-9]*([0-9.]+)").unwrap(), "Prometheus", "Prometheus", "prometheus"));
        v.push((Regex::new(r"(?i)grafana[^0-9]*([0-9.]+)").unwrap(), "Grafana", "Grafana", "grafana"));
        v.push((Regex::new(r"(?i)rfb[^0-9]*([0-9.]+)").unwrap(), "VNC", "VNC", "vnc"));
        v.push((Regex::new(r"(?i)ms-terminal").unwrap(), "RDP", "MS RDP", "msrdp"));
        v.push((Regex::new(r"(?i)dovecot[\s-]+ready").unwrap(), "IMAP", "Dovecot", "dovecot"));
        v.push((Regex::new(r"(?i)exim[\s-]+([0-9.]+)").unwrap(), "SMTP", "Exim", "exim"));
        v.push((Regex::new(r"(?i)sql.*server.*([0-9.]+)").unwrap(), "MSSQL", "MSSQL", "mssql"));
        v.push((Regex::new(r"(?i)oracle.*[ -]([0-9.]+)").unwrap(), "Oracle-DB", "Oracle", "oracle"));
        v.push((Regex::new(r"(?i)cpanel[\s/]*([0-9.]+)").unwrap(), "Control-Panel", "cPanel", "cpanel"));
        v.push((Regex::new(r"(?i)webmin[\s/]*([0-9.]+)").unwrap(), "Control-Panel", "Webmin", "webmin"));
        v.push((Regex::new(r"(?i)plesk[\s/]*([0-9.]+)").unwrap(), "Control-Panel", "Plesk", "plesk"));
        v.push((Regex::new(r"(?i)cyberpanel[\s/]*([0-9.]+)").unwrap(), "Control-Panel", "CyberPanel", "cyberpanel"));
        v.push((Regex::new(r"(?i)sip/2\.0").unwrap(), "SIP", "SIP", "sip"));
        v.push((Regex::new(r"(?i)squid/([0-9.]+)").unwrap(), "Proxy", "Squid", "squid"));
        v.push((Regex::new(r"(?i)varnish/([0-9.]+)").unwrap(), "Cache", "Varnish", "varnish"));
        v.push((Regex::new(r"(?i)docker").unwrap(), "Docker", "Docker", "docker"));
        v.push((Regex::new(r"(?i)kubernetes").unwrap(), "Kubernetes", "Kubernetes", "kubernetes"));
        v.push((Regex::new(r"(?i)etcd").unwrap(), "etcd", "etcd", "etcd"));
        v.push((Regex::new(r"(?i)consul").unwrap(), "Consul", "Consul", "consul"));
        v.push((Regex::new(r"(?i)zookeeper").unwrap(), "ZooKeeper", "ZooKeeper", "zookeeper"));
        v.push((Regex::new(r"(?i)activemq").unwrap(), "ActiveMQ", "ActiveMQ", "activemq"));
        v.push((Regex::new(r"(?i)rabbitmq").unwrap(), "RabbitMQ", "RabbitMQ", "rabbitmq"));
        v.push((Regex::new(r"(?i)kafka").unwrap(), "Kafka", "Kafka", "kafka"));
        v.push((Regex::new(r"(?i)mongos").unwrap(), "MongoDB", "MongoDB-S", "mongos"));
        v.push((Regex::new(r"(?i)osqueryd").unwrap(), "Osquery", "Osquery", "osquery"));
        v.push((Regex::new(r"(?i)bitcoind").unwrap(), "Bitcoin", "Bitcoin Core", "bitcoin"));
        v.push((Regex::new(r"(?i)lightningd").unwrap(), "Lightning", "Lightning", "lightning"));
        v.push((Regex::new(r"(?i)tincd").unwrap(), "VPN", "tinc", "tinc"));
        v.push((Regex::new(r"(?i)openvpn").unwrap(), "VPN", "OpenVPN", "openvpn"));
        v.push((Regex::new(r"(?i)wireguard").unwrap(), "VPN", "WireGuard", "wireguard"));
        v.push((Regex::new(r"(?i)strongswan").unwrap(), "VPN", "strongSwan", "strongswan"));
        v.push((Regex::new(r"(?i)pptpd").unwrap(), "VPN", "PPTP", "pptp"));
        v.push((Regex::new(r"(?i)dnsmasq").unwrap(), "DNS", "dnsmasq", "dnsmasq"));
        v.push((Regex::new(r"(?i)bind[^0-9]*([0-9.]+)").unwrap(), "DNS", "BIND", "bind"));
        v.push((Regex::new(r"(?i)unbound[^0-9]*([0-9.]+)").unwrap(), "DNS", "Unbound", "unbound"));
        v.push((Regex::new(r"(?i)powerdns").unwrap(), "DNS", "PowerDNS", "powerdns"));
        v.push((Regex::new(r"(?i)apache.*tomcat").unwrap(), "HTTP", "Tomcat", "tomcat"));
        v.push((Regex::new(r"(?i)apache.*coyote").unwrap(), "HTTP", "Tomcat-Coyote", "tomcat"));
        v.push((Regex::new(r"(?i)jetty.*([0-9.]+)").unwrap(), "HTTP", "Jetty", "jetty"));
        v.push((Regex::new(r"(?i)gunicorn.*([0-9.]+)").unwrap(), "HTTP", "Gunicorn", "gunicorn"));
        v.push((Regex::new(r"(?i)wsgiref").unwrap(), "HTTP", "WSGI Ref", "python"));
        v.push((Regex::new(r"(?i)waitress").unwrap(), "HTTP", "Waitress", "waitress"));
        v.push((Regex::new(r"(?i)django").unwrap(), "HTTP", "Django", "django"));
        v.push((Regex::new(r"(?i)flask").unwrap(), "HTTP", "Flask", "flask"));
        v.push((Regex::new(r"(?i)spring").unwrap(), "HTTP", "Spring", "spring"));
        v.push((Regex::new(r"(?i)express").unwrap(), "HTTP", "Express", "express"));
        v.push((Regex::new(r"(?i)kestrel").unwrap(), "HTTP", "Kestrel", "kestrel"));
        v.push((Regex::new(r"(?i)iis").unwrap(), "HTTP", "IIS", "iis"));
        v.push((Regex::new(r"(?i)ASP\.NET").unwrap(), "HTTP", "ASP.NET", "aspnet"));
        v.push((Regex::new(r"(?i)PHP/[0-9]").unwrap(), "HTTP", "PHP", "php"));
        v.push((Regex::new(r"(?i)akia").unwrap(), "CDN", "Akamai", "akamai"));
        v.push((Regex::new(r"(?i)cloudfront").unwrap(), "CDN", "CloudFront", "cloudfront"));
        v.push((Regex::new(r"(?i)fastly").unwrap(), "CDN", "Fastly", "fastly"));
        v.push((Regex::new(r"(?i)cloudflare-nginx").unwrap(), "CDN", "Cloudflare", "cloudflare"));
        v
    };
    static ref HTTP_HEADER_PROBES: Vec<(&'static str, &'static [u8])> = {
        vec![
            ("root", b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-ServiceDetect/3.0\r\nAccept: */*\r\n\r\n"),
            ("headers", b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-ServiceDetect/3.0\r\n\r\n"),
            ("options", b"OPTIONS * HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        ]
    };
}

#[derive(Debug, Serialize)]
struct ServiceResult {
    port: u16,
    protocol: String,
    service: String,
    product: String,
    version: String,
    extra_info: String,
    cpe: String,
    confidence: f64,
    banner: String,
}

#[derive(Debug, Serialize)]
struct FinalOutput {
    target: String,
    total_services: usize,
    elapsed_ms: u64,
    services: Vec<ServiceResult>,
}

#[inline]
fn get_probes_for_port(port: u16) -> Vec<Vec<u8>> {
    match port {
        80 | 443 | 8080 | 8443 | 8000 | 8888 | 9443 | 8008 | 8081 => {
            vec![
                b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-ServiceDetect/3.0\r\nAccept: */*\r\n\r\n".to_vec(),
                b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
                b"OPTIONS * HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            ]
        }
        21 => vec![b"SYST\r\n".to_vec(), b"FEAT\r\n".to_vec(), b"PWD\r\n".to_vec()],
        22 => vec![b"SSH-2.0-HackIT-ServiceDetect\r\n".to_vec()],
        25 | 465 | 587 => vec![
            b"EHLO hackit.service.detect\r\n".to_vec(),
            b"HELO hackit\r\n".to_vec(),
        ],
        110 | 995 => vec![b"CAPA\r\n".to_vec(), b"USER anonymous\r\n".to_vec()],
        143 | 993 => vec![b"A001 CAPABILITY\r\n".to_vec(), b"A001 LOGIN anonymous\r\n".to_vec()],
        3306 => vec![b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        5432 => vec![b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec()],
        6379 => vec![b"INFO\r\n".to_vec(), b"PING\r\n".to_vec(), b"CONFIG GET dir\r\n".to_vec()],
        27017 => vec![b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec()],
        11211 => vec![b"stats\r\n".to_vec(), b"stats items\r\n".to_vec()],
        5900 => vec![b"RFB 003.008\n".to_vec()],
        3389 => vec![b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec()],
        1433 => vec![b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00".to_vec()],
        1521 => vec![b"\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x32\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        389 | 636 => vec![b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec()],
        161 => vec![b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec()],
        5060 | 5061 => vec![b"OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP hackit.local;branch=z9hG4bK\r\nMax-Forwards: 70\r\nTo: <sip:test@localhost>\r\nCSeq: 1 OPTIONS\r\nCall-ID: 123456@hackit\r\nFrom: <sip:test@localhost>;tag=root\r\nContent-Length: 0\r\n\r\n".to_vec()],
        5222 => vec![b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>".to_vec()],
        5672 => vec![b"AMQP\x00\x00\x09\x01".to_vec()],
        2181 => vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        2375 => vec![b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()],
        2376 => vec![b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()],
        2379 => vec![b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()],
        8500 => vec![b"GET /v1/agent/self HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()],
        9090 => vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()],
        9200 => vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()],
        9042 => vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        25565 => vec![b"\xfe\x01".to_vec()],
        873 => vec![b"@RSYNCD: 31.0\n".to_vec()],
        6667 => vec![b"NICK hackit\r\nUSER hackit 0 * :HackIT Scan\r\n".to_vec()],
        1194 => vec![b"\x38\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        1723 => vec![b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        _ => vec![b"\r\n\r\n".to_vec()],
    }
}

fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    let probes = get_probes_for_port(port);
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
    best_banner.chars()
        .filter(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .take(1024)
        .collect::<String>()
        .trim()
        .to_string()
}

#[inline]
fn detect_service_and_product(banner: &str, port: u16) -> (String, String, String, f64) {
    let b = banner.to_lowercase();
    for (re, service, product, _cpe) in SERVICE_PATTERNS.iter() {
        if let Some(caps) = re.captures(banner) {
            let version = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            return (service.to_string(), product.to_string(), version, 95.0);
        }
    }
    let default_svc = match port {
        21 => ("FTP", "FTP Server", ""),
        22 => ("SSH", "SSH Server", ""),
        23 => ("Telnet", "Telnet Server", ""),
        25 => ("SMTP", "SMTP Server", ""),
        53 => ("DNS", "DNS Server", ""),
        80 => ("HTTP", "Web Server", ""),
        110 => ("POP3", "POP3 Server", ""),
        111 => ("RPC", "RPC", ""),
        135 => ("MSRPC", "MSRPC", ""),
        139 => ("NetBIOS", "NetBIOS", ""),
        143 => ("IMAP", "IMAP Server", ""),
        161 => ("SNMP", "SNMP Agent", ""),
        162 => ("SNMP", "SNMP Trap", ""),
        389 => ("LDAP", "LDAP Server", ""),
        443 => ("HTTPS", "Web Server", ""),
        445 => ("SMB", "SMB Server", ""),
        465 => ("SMTPS", "SMTP Server", ""),
        500 => ("ISAKMP", "ISAKMP", ""),
        514 => ("Syslog", "Syslog", ""),
        543 => ("Kerberos", "Kerberos", ""),
        544 => ("krcmd", "krcmd", ""),
        546 => ("DHCPv6", "DHCPv6 Client", ""),
        547 => ("DHCPv6", "DHCPv6 Server", ""),
        548 => ("AFP", "AFP", ""),
        554 => ("RTSP", "RTSP", ""),
        587 => ("SMTP", "SMTP Submission", ""),
        631 => ("IPP", "IPP", ""),
        636 => ("LDAPS", "LDAP Server", ""),
        646 => ("LDP", "LDP", ""),
        873 => ("Rsync", "Rsync", ""),
        990 => ("FTPS", "FTPS Server", ""),
        992 => ("Telnets", "Telnet Server", ""),
        993 => ("IMAPS", "IMAP Server", ""),
        995 => ("POP3S", "POP3 Server", ""),
        1080 => ("SOCKS", "SOCKS Proxy", ""),
        1194 => ("OpenVPN", "OpenVPN", ""),
        1352 => ("Lotus-Notes", "Lotus Notes", ""),
        1433 => ("MSSQL", "MSSQL Server", ""),
        1521 => ("Oracle-DB", "Oracle Database", ""),
        1723 => ("PPTP", "PPTP", ""),
        1883 => ("MQTT", "MQTT Broker", ""),
        2049 => ("NFS", "NFS", ""),
        2082 => ("cPanel", "cPanel", ""),
        2083 => ("cPanel-SSL", "cPanel", ""),
        2086 => ("WHM", "WHM", ""),
        2087 => ("WHM-SSL", "WHM", ""),
        2181 => ("ZooKeeper", "ZooKeeper", ""),
        2375 => ("Docker", "Docker Engine", ""),
        2376 => ("Docker-TLS", "Docker Engine", ""),
        2379 => ("etcd", "etcd", ""),
        3000 => ("HTTP", "Web App", ""),
        3128 => ("Squid", "Squid Proxy", ""),
        3306 => ("MySQL", "MySQL", ""),
        3389 => ("RDP", "MS RDP", ""),
        3690 => ("SVN", "SVN", ""),
        4369 => ("EPMD", "EPMD", ""),
        4443 => ("AJP13", "AJP13", ""),
        4567 => ("Sinatra", "Sinatra", ""),
        5000 => ("UPnP", "UPnP", ""),
        5001 => ("Synology", "Synology DSM", ""),
        5060 => ("SIP", "SIP Proxy", ""),
        5061 => ("SIP-TLS", "SIP Proxy", ""),
        5222 => ("XMPP", "XMPP Server", ""),
        5432 => ("PostgreSQL", "PostgreSQL", ""),
        5672 => ("AMQP", "AMQP Broker", ""),
        5900 => ("VNC", "VNC Server", ""),
        5984 => ("CouchDB", "CouchDB", ""),
        5985 => ("WinRM", "WinRM", ""),
        5986 => ("WinRM-SSL", "WinRM", ""),
        6000 => ("X11", "X11", ""),
        6379 => ("Redis", "Redis", ""),
        6443 => ("K8s-API", "K8s API Server", ""),
        6667 => ("IRC", "IRC Server", ""),
        7001 => ("WebLogic", "WebLogic", ""),
        7474 => ("Neo4j", "Neo4j", ""),
        8000 => ("HTTP", "Web Server", ""),
        8008 => ("HTTP", "Web Server", ""),
        8080 => ("HTTP", "Web Server", ""),
        8081 => ("HTTP", "Web Server", ""),
        8443 => ("HTTPS", "Web Server", ""),
        8500 => ("Consul", "Consul Agent", ""),
        8834 => ("Nessus", "Nessus", ""),
        8888 => ("HTTP", "Web Server", ""),
        8983 => ("Solr", "Solr", ""),
        9000 => ("SonarQube", "SonarQube", ""),
        9042 => ("Cassandra", "Cassandra", ""),
        9090 => ("Prometheus", "Prometheus", ""),
        9092 => ("Kafka", "Kafka", ""),
        9100 => ("JetDirect", "JetDirect", ""),
        9160 => ("Cassandra", "Cassandra Thrift", ""),
        9200 => ("Elasticsearch", "Elasticsearch", ""),
        9300 => ("Elasticsearch", "Elasticsearch Cluster", ""),
        9418 => ("Git", "Git", ""),
        9443 => ("HTTPS", "Web Server", ""),
        9999 => ("HTTP", "Web Server", ""),
        10000 => ("Webmin", "Webmin", ""),
        10250 => ("Kubelet", "Kubelet API", ""),
        11211 => ("Memcached", "Memcached", ""),
        15672 => ("RabbitMQ", "RabbitMQ Management", ""),
        25565 => ("Minecraft", "Minecraft Server", ""),
        27017 => ("MongoDB", "MongoDB", ""),
        27018 => ("MongoDB", "MongoDB Shard", ""),
        27019 => ("MongoDB", "MongoDB Config", ""),
        32400 => ("Plex", "Plex", ""),
        _ => ("unknown", "unknown", ""),
    };
    (default_svc.0.to_string(), default_svc.1.to_string(), default_svc.2.to_string(), 70.0)
}

#[inline]
fn generate_cpe(product: &str, version: &str) -> String {
    let vendor = product.to_lowercase().replace(' ', "_");
    let prod = product.to_lowercase().replace(' ', "_");
    if version.is_empty() {
        format!("cpe:/a:{}:{}", vendor, prod)
    } else {
        format!("cpe:/a:{}:{}:{}", vendor, prod, version)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--ports" | "-p" => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--help" | "-h" => {
                eprintln!("Usage: {} --target <host> --ports <ports> [--timeout <ms>]", args[0]);
                eprintln!("  Deep banner analysis with 100+ service signature patterns");
                eprintln!("  Generates CPE identifiers from version strings");
                eprintln!("  ports: comma-separated (80,443,22), ranges (1-1024)");
                std::process::exit(0);
            }
            _ => {
                if target.is_empty() { target = args[i].clone(); }
                else if port_spec.is_empty() { port_spec = args[i].clone(); }
            }
        }
        i += 1;
    }
    if target.is_empty() || port_spec.is_empty() {
        eprintln!("Usage: {} --target <host> --ports <ports> [--timeout <ms>]", args[0]);
        std::process::exit(1);
    }
    let ports = parse_ports(&port_spec);
    if ports.is_empty() { eprintln!("Error: no valid ports"); std::process::exit(1); }
    eprintln!("SERVICE_DETECT target={} ports={} timeout={}ms", target, ports.len(), timeout_ms);
    let start = Instant::now();
    let total = ports.len();
    let mut services = Vec::with_capacity(total);
    for (idx, &port) in ports.iter().enumerate() {
        eprintln!("STATUS:{{\"progress\":{:.1},\"message\":\"Analyzing port {}/{}\"}}",
            (idx as f64 / total as f64 * 100.0), port, total);
        let banner = grab_banner(&target, port, timeout_ms);
        if banner.is_empty() {
            let svc = match port {
                80|443|8080|8443|8000|8888|9443 => "HTTPS",
                22 => "SSH",
                21 => "FTP",
                _ => "unknown",
            };
            services.push(ServiceResult {
                port,
                protocol: "tcp".to_string(),
                service: svc.to_string(),
                product: String::new(),
                version: String::new(),
                extra_info: String::new(),
                cpe: String::new(),
                confidence: 30.0,
                banner: String::new(),
            });
            continue;
        }
        let (service, product, version, confidence) = detect_service_and_product(&banner, port);
        let cpe = generate_cpe(&product, &version);
        let extra_info = if !version.is_empty() {
            format!("{} version {}", product, version)
        } else {
            String::new()
        };
        let result = ServiceResult {
            port,
            protocol: "tcp".to_string(),
            service,
            product,
            version,
            extra_info,
            cpe,
            confidence,
            banner: banner.chars().take(300).collect(),
        };
        println!("RESULT:{}", serde_json::to_string(&result).unwrap());
        services.push(result);
        eprintln!("STATUS:{{\"progress\":{:.1},\"message\":\"Service detected on port {}: {}\"}}",
            ((idx + 1) as f64 / total as f64 * 100.0), port, services.last().unwrap().service);
    }
    let elapsed = start.elapsed().as_millis() as u64;
    let final_out = FinalOutput {
        target: target.clone(),
        total_services: services.len(),
        elapsed_ms: elapsed,
        services,
    };
    println!("FINAL:{}", serde_json::to_string(&final_out).unwrap());
}
