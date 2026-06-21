package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────────────────────────
// ULTRA SERVICE SIGNATURE DATABASE — 400+ nmap-level patterns
// ─────────────────────────────────────────────────────────────────

type ServiceSignature struct {
	Port     int
	Protocol string
	Pattern  *regexp.Regexp
	Product  string
	Version  string
	OSHint   string
	Confidence float64
}

type OSFingerprint struct {
	Pattern    *regexp.Regexp
	OSName     string
	OSVersion  string
	Confidence float64
	ExpectedTTL int
}

var (
	serviceSignatures  []ServiceSignature
	osFingerprints    []OSFingerprint
	initSigsOnce      sync.Once
	initOSOnce        sync.Once
	portSignatureIndex [65536][]*ServiceSignature
	portIndexOnce     sync.Once
)

func initSignatures() {
	initSigsOnce.Do(func() {

	// ─── SSH ───
	addSig(22, "SSH", `SSH-2\.0-OpenSSH_([\d.]+p?\d*)`, "OpenSSH", "Unix/Linux", 0.95)
	addSig(22, "SSH", `SSH-2\.0-dropbear_([\d.]+)`, "Dropbear", "Unix/Linux", 0.90)
	addSig(22, "SSH", `SSH-2\.0-Cisco-([\d.]+)`, "Cisco SSH", "Cisco IOS", 0.85)
	addSig(22, "SSH", `SSH-1\.99-`, "SSH Legacy", "Generic", 0.70)
	addSig(22, "SSH", `SSH-1\.5-`, "SSH v1 (Insecure)", "Generic", 0.70)
	addSig(22, "SSH", `SSH-2\.0-libssh_([\d.]+)`, "libssh", "Unix/Linux", 0.90)
	addSig(22, "SSH", `SSH-2\.0-([\w.-]+)`, "Custom SSH", "Generic", 0.60)

	// ─── HTTP — Apache ───
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)`, "Apache httpd", "Generic", 0.90)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(Ubuntu\)`, "Apache httpd", "Ubuntu Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(Debian\)`, "Apache httpd", "Debian Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(CentOS\)`, "Apache httpd", "CentOS Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(FreeBSD\)`, "Apache httpd", "FreeBSD", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(Win32\)`, "Apache httpd", "Windows", 0.90)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(Red Hat\)`, "Apache httpd", "Red Hat Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache/([\d.]+)\s+\(Fedora\)`, "Apache httpd", "Fedora Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*Apache-Coyote/1\.1`, "Apache Tomcat/Coyote", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*Apache.*Tomcat.*([\d.]+)`, "Apache Tomcat", "Generic", 0.90)

	// ─── HTTP — nginx ───
	addSig(80, "HTTP", `Server:\s*nginx/([\d.]+)`, "nginx", "Generic", 0.90)
	addSig(80, "HTTP", `Server:\s*nginx/([\d.]+)\s+\(Ubuntu\)`, "nginx", "Ubuntu Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*nginx/([\d.]+)\s+\(Debian\)`, "nginx", "Debian Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*nginx/([\d.]+)\s+\(CentOS\)`, "nginx", "CentOS Linux", 0.95)
	addSig(80, "HTTP", `Server:\s*openresty/([\d.]+)`, "OpenResty", "Generic", 0.90)
	addSig(80, "HTTP", `Server:\s*Tengine/?([\d.]*)`, "Tengine", "Generic", 0.85)

	// ─── HTTP — IIS ───
	addSig(80, "HTTP", `Server:\s*Microsoft-IIS/([\d.]+)`, "Microsoft IIS", "Windows Server", 0.90)
	addSig(80, "HTTP", `Server:\s*Microsoft-HTTPAPI/([\d.]+)`, "Microsoft HTTPAPI", "Windows Server", 0.85)
	addSig(80, "HTTP", `X-Powered-By:\s*ASP\.NET`, "ASP.NET", "Windows Server", 0.80)
	addSig(80, "HTTP", `X-AspNet-Version:\s*([\d.]+)`, "ASP.NET", "Windows Server", 0.85)
	addSig(80, "HTTP", `Server:\s*Kestrel`, "ASP.NET Kestrel", "Windows/Linux", 0.80)

	// ─── HTTP — Others ───
	addSig(80, "HTTP", `Server:\s*LiteSpeed`, "LiteSpeed", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*lighttpd/([\d.]+)`, "Lighttpd", "Generic", 0.90)
	addSig(80, "HTTP", `Server:\s*Caddy`, "Caddy", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*Cowboy`, "Cowboy (Erlang)", "Generic", 0.80)
	addSig(80, "HTTP", `Server:\s*GWS`, "Google Web Server", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*Cloudflare`, "Cloudflare", "Generic", 0.90)
	addSig(80, "HTTP", `Server:\s*Jetty\(([\d.]+)\)`, "Jetty", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*gunicorn/([\d.]+)`, "Gunicorn", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*uvicorn`, "Uvicorn (ASGI)", "Generic", 0.80)
	addSig(80, "HTTP", `Server:\s*Werkzeug/?([\d.]*)`, "Werkzeug (Flask)", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*Cherokee/?([\d.]*)`, "Cherokee", "Generic", 0.85)
	addSig(80, "HTTP", `Server:\s*Node\.js`, "Node.js", "Generic", 0.80)
	addSig(80, "HTTP", `Server:\s*GlassFish`, "GlassFish", "Generic", 0.80)
	addSig(80, "HTTP", `Server:\s*WildFly`, "WildFly", "Generic", 0.80)
	addSig(80, "HTTP", `Server:\s*Pumpkin`, "Pumpkin", "Generic", 0.70)

	// ─── X-Powered-By / Generator ───
	addSig(80, "HTTP", `X-Powered-By:\s*PHP/([\d.]+)`, "PHP", "Generic", 0.90)
	addSig(80, "HTTP", `X-Powered-By:\s*Express`, "Express (Node.js)", "Generic", 0.85)
	addSig(80, "HTTP", `X-Powered-By:\s*Railo|Lucee`, "Railo/Lucee (CFML)", "Generic", 0.80)
	addSig(80, "HTTP", `X-Powered-By:\s*Servlet/([\d.]+)`, "Java Servlet", "Generic", 0.85)
	addSig(80, "HTTP", `X-Generator:\s*Drupal ([\d.]+)`, "Drupal", "Generic", 0.90)
	addSig(80, "HTTP", `X-Generator:\s*WordPress ([\d.]+)`, "WordPress", "Generic", 0.90)
	addSig(80, "HTTP", `X-Generator:\s*Joomla! ([\d.]+)`, "Joomla", "Generic", 0.90)
	addSig(80, "HTTP", `X-Drupal-Cache`, "Drupal", "Generic", 0.70)

	// ─── FTP ───
	addSig(21, "FTP", `220.*vsftpd\s*([\d.]+)`, "vsftpd", "Unix/Linux", 0.95)
	addSig(21, "FTP", `220.*ProFTPD\s*([\d.]+)`, "ProFTPD", "Unix/Linux", 0.95)
	addSig(21, "FTP", `220.*FileZilla Server\s*([\d.]+)`, "FileZilla Server", "Windows", 0.90)
	addSig(21, "FTP", `220.*Pure-FTPd\s*([\d.]+)`, "Pure-FTPd", "Unix/Linux", 0.90)
	addSig(21, "FTP", `220.*Microsoft FTP`, "Microsoft FTP", "Windows Server", 0.85)
	addSig(21, "FTP", `220.*Wu-FTPd`, "Wu-FTPd", "Unix/Linux", 0.85)
	addSig(21, "FTP", `220.*glFTPd`, "glFTPd", "Unix/Linux", 0.80)
	addSig(21, "FTP", `220.*Serv-U FTP`, "Serv-U", "Windows", 0.85)
	addSig(21, "FTP", `220.*Cerberus FTP`, "Cerberus FTP", "Windows", 0.80)
	addSig(21, "FTP", `220.*BulletProof`, "BulletProof FTP", "Windows", 0.80)
	addSig(21, "FTP", `220.*Apache FtpServer`, "Apache FtpServer", "Generic", 0.75)

	// ─── SMTP ───
	addSig(25, "SMTP", `220.*Postfix\s*([\d.]+)`, "Postfix", "Unix/Linux", 0.95)
	addSig(25, "SMTP", `220.*Postfix ESMTP`, "Postfix", "Unix/Linux", 0.85)
	addSig(25, "SMTP", `220.*Exim\s*([\d.]+)`, "Exim", "Unix/Linux", 0.95)
	addSig(25, "SMTP", `220.*Sendmail\s*([\d.]+)`, "Sendmail", "Unix/Linux", 0.90)
	addSig(25, "SMTP", `220.*Microsoft ESMTP`, "Microsoft Exchange", "Windows Server", 0.85)
	addSig(25, "SMTP", `220.*MailEnable`, "MailEnable", "Windows", 0.80)
	addSig(25, "SMTP", `220.*qmail`, "Qmail", "Unix/Linux", 0.80)
	addSig(25, "SMTP", `220.*Courier`, "Courier Mail", "Unix/Linux", 0.80)
	addSig(25, "SMTP", `220.*OpenSMTPD`, "OpenSMTPD", "OpenBSD", 0.85)
	addSig(25, "SMTP", `220.*IceWarp`, "IceWarp", "Windows/Unix", 0.80)
	addSig(25, "SMTP", `220.*Zimbra`, "Zimbra", "Unix/Linux", 0.85)

	// ─── POP3 ───
	addSig(110, "POP3", `\+OK.*Dovecot.*ready`, "Dovecot POP3", "Unix/Linux", 0.90)
	addSig(110, "POP3", `\+OK.*Courier POP3`, "Courier POP3", "Unix/Linux", 0.85)
	addSig(110, "POP3", `\+OK.*Qpopper`, "Qpopper", "Unix/Linux", 0.80)
	addSig(110, "POP3", `\+OK.*Microsoft.*POP3`, "Microsoft POP3", "Windows Server", 0.85)
	addSig(110, "POP3", `\+OK.*MailEnable POP3`, "MailEnable POP3", "Windows", 0.80)
	addSig(110, "POP3", `\+OK.*Cyrus`, "Cyrus POP3", "Unix/Linux", 0.80)

	// ─── IMAP ───
	addSig(143, "IMAP", `\* OK.*Dovecot`, "Dovecot IMAP", "Unix/Linux", 0.90)
	addSig(143, "IMAP", `\* OK.*Courier`, "Courier IMAP", "Unix/Linux", 0.85)
	addSig(143, "IMAP", `\* OK.*Cyrus IMAP`, "Cyrus IMAP", "Unix/Linux", 0.85)
	addSig(143, "IMAP", `\* OK.*Microsoft.*IMAP`, "Microsoft Exchange IMAP", "Windows Server", 0.85)
	addSig(143, "IMAP", `\* OK.*Zimbra`, "Zimbra IMAP", "Unix/Linux", 0.85)

	// ─── MySQL / MariaDB ───
	addSig(3306, "MySQL", `mysql_native_password`, "MySQL", "Generic", 0.85)
	addSig(3306, "MySQL", `MariaDB`, "MariaDB", "Generic", 0.90)
	addSig(3306, "MySQL", `5\.5\.\d+-MySQL`, "MySQL 5.5", "Generic", 0.90)
	addSig(3306, "MySQL", `5\.6\.\d+-MySQL`, "MySQL 5.6", "Generic", 0.90)
	addSig(3306, "MySQL", `5\.7\.\d+-MySQL`, "MySQL 5.7", "Generic", 0.90)
	addSig(3306, "MySQL", `8\.\d+\.\d+-MySQL`, "MySQL 8.x", "Generic", 0.90)
	addSig(3306, "MySQL", `10\.\d+\.\d+-MariaDB`, "MariaDB 10.x", "Generic", 0.90)

	// ─── PostgreSQL ───
	addSig(5432, "PostgreSQL", `PostgreSQL\s+([\d.]+)`, "PostgreSQL", "Generic", 0.95)
	addSig(5432, "PostgreSQL", `psql.*PostgreSQL`, "PostgreSQL", "Generic", 0.80)

	// ─── Redis ───
	addSig(6379, "Redis", `redis_version:([\d.]+)`, "Redis", "Unix/Linux", 0.95)
	addSig(6379, "Redis", `redis_mode:`, "Redis", "Unix/Linux", 0.80)
	addSig(6379, "Redis", `role:master`, "Redis Master", "Unix/Linux", 0.85)
	addSig(6379, "Redis", `role:slave`, "Redis Slave", "Unix/Linux", 0.85)

	// ─── MongoDB ───
	addSig(27017, "MongoDB", `MongoDB`, "MongoDB", "Generic", 0.85)
	addSig(27017, "MongoDB", `"ok"\s*:\s*1`, "MongoDB", "Generic", 0.80)
	addSig(27017, "MongoDB", `MongoDB\s+([\d.]+)`, "MongoDB", "Generic", 0.90)

	// ─── Other Databases ───
	addSig(5984, "CouchDB", `CouchDB/([\d.]+)`, "CouchDB", "Generic", 0.90)
	addSig(9200, "Elasticsearch", `"cluster_name"`, "Elasticsearch", "Generic", 0.85)
	addSig(9200, "Elasticsearch", `"version":\s*\{`, "Elasticsearch", "Generic", 0.85)
	addSig(9200, "Elasticsearch", `"tagline"\s*:\s*"You Know, for Search"`, "Elasticsearch", "Generic", 0.90)
	addSig(11211, "Memcached", `STAT pid`, "Memcached", "Generic", 0.85)
	addSig(11211, "Memcached", `STAT uptime`, "Memcached", "Generic", 0.85)
	addSig(9042, "Cassandra", `Cassandra`, "Apache Cassandra", "Generic", 0.85)
	addSig(9160, "Cassandra", `Cassandra`, "Apache Cassandra Thrift", "Generic", 0.80)

	// ─── Docker / Containers ───
	addSig(2375, "Docker", `Docker/([\d.]+)`, "Docker Engine", "Linux", 0.90)
	addSig(2375, "Docker", `"Version":"([\d.]+)`, "Docker Engine", "Linux", 0.90)
	addSig(2375, "Docker", `"Platform":"docker"`, "Docker Engine", "Linux", 0.85)
	addSig(2376, "Docker", `Docker/([\d.]+)`, "Docker Engine SSL", "Linux", 0.85)
	addSig(6443, "Kubernetes", `kubernetes|k8s`, "Kubernetes API", "Generic", 0.85)
	addSig(8001, "Kubernetes", `kubernetes|k8s`, "Kubernetes Proxy", "Generic", 0.80)
	addSig(2379, "etcd", `etcd\s+([\d.]+)`, "etcd", "Linux", 0.90)
	addSig(2379, "etcd", `"etcd"`, "etcd", "Linux", 0.80)

	// ─── CI/CD ───
	addSig(8080, "CI/CD", `Jenkins`, "Jenkins CI", "Generic", 0.90)
	addSig(8081, "CI/CD", `Artifactory`, "JFrog Artifactory", "Generic", 0.85)
	addSig(8081, "CI/CD", `Nexus`, "Sonatype Nexus", "Generic", 0.85)
	addSig(80, "CI/CD", `GitLab`, "GitLab", "Generic", 0.85)
	addSig(3000, "CI/CD", `Gitea`, "Gitea", "Generic", 0.85)
	addSig(3000, "CI/CD", `Gogs`, "Gogs", "Generic", 0.80)

	// ─── Message Queues ───
	addSig(5672, "MQ", `AMQP`, "RabbitMQ / AMQP", "Generic", 0.85)
	addSig(5672, "MQ", `RabbitMQ`, "RabbitMQ", "Generic", 0.85)
	addSig(61613, "MQ", `ActiveMQ`, "Apache ActiveMQ", "Generic", 0.80)
	addSig(9092, "MQ", `Kafka`, "Apache Kafka", "Generic", 0.85)
	addSig(4222, "MQ", `NATS`, "NATS", "Generic", 0.80)

	// ─── Monitoring ───
	addSig(9090, "Monitoring", `Prometheus`, "Prometheus", "Generic", 0.90)
	addSig(3000, "Monitoring", `Grafana`, "Grafana", "Generic", 0.85)
	addSig(5666, "Monitoring", `Nagios`, "Nagios", "Generic", 0.85)
	addSig(10050, "Monitoring", `Zabbix`, "Zabbix", "Generic", 0.85)
	addSig(6555, "Monitoring", `Check_MK|checkmk`, "CheckMK", "Generic", 0.80)

	// ─── Load Balancers / Proxies ───
	addSig(80, "Proxy", `HAProxy\s*([\d.]+)`, "HAProxy", "Generic", 0.85)
	addSig(3128, "Proxy", `Squid/([\d.]+)`, "Squid Proxy", "Generic", 0.90)
	addSig(80, "Proxy", `Varnish`, "Varnish Cache", "Generic", 0.85)
	addSig(80, "Proxy", `Traefik`, "Traefik Proxy", "Generic", 0.85)
	addSig(80, "Proxy", `Envoy`, "Envoy Proxy", "Generic", 0.85)
	addSig(80, "Proxy", `Apache Traffic Server`, "Apache Traffic Server", "Generic", 0.80)
	addSig(80, "Proxy", `Pound`, "Pound LB", "Generic", 0.70)

	// ─── VPN ───
	addSig(1194, "VPN", `OpenVPN`, "OpenVPN", "Generic", 0.85)
	addSig(51820, "VPN", `WireGuard`, "WireGuard", "Generic", 0.80)
	addSig(500, "VPN", `StrongSwan`, "StrongSwan", "Linux", 0.80)
	addSig(500, "VPN", `SoftEther`, "SoftEther", "Generic", 0.80)

	// ─── Embedded / Network Devices ───
	addSig(80, "Embedded", `OpenWrt`, "OpenWrt", "OpenWrt/LEDE", 0.90)
	addSig(80, "Embedded", `DD-WRT`, "DD-WRT", "DD-WRT", 0.90)
	addSig(80, "Embedded", `pfSense`, "pfSense", "FreeBSD", 0.90)
	addSig(80, "Embedded", `OPNsense`, "OPNsense", "FreeBSD", 0.85)
	addSig(80, "Embedded", `Cisco`, "Cisco IOS", "Cisco", 0.85)
	addSig(80, "Embedded", `Juniper`, "Juniper JunOS", "Juniper", 0.85)

	// ─── CMS ───
	addSig(80, "CMS", `WordPress`, "WordPress", "Generic", 0.85)
	addSig(80, "CMS", `Drupal`, "Drupal", "Generic", 0.85)
	addSig(80, "CMS", `Joomla`, "Joomla", "Generic", 0.85)
	addSig(80, "CMS", `Magento`, "Magento", "Generic", 0.85)
	addSig(80, "CMS", `phpMyAdmin`, "phpMyAdmin", "Generic", 0.80)

	// ─── Control Panels ───
	addSig(10000, "Panel", `Webmin`, "Webmin", "Generic", 0.85)
	addSig(2082, "Panel", `cPanel`, "cPanel/WHM", "CentOS/CloudLinux", 0.85)
	addSig(2083, "Panel", `cPanel`, "cPanel/WHM SSL", "CentOS/CloudLinux", 0.85)
	addSig(80, "Panel", `Plesk`, "Plesk", "Windows/CentOS", 0.85)
	addSig(80, "Panel", `Cockpit`, "Cockpit", "Linux", 0.80)

	// ─── Misc Services ───
	addSig(873, "Rsync", `@RSYNCD:`, "Rsync", "Unix/Linux", 0.90)
	addSig(873, "Rsync", `rsync`, "Rsync", "Unix/Linux", 0.75)
	addSig(2181, "ZooKeeper", `ZooKeeper`, "Apache ZooKeeper", "Generic", 0.85)
	addSig(2181, "ZooKeeper", `ruok`, "Apache ZooKeeper", "Generic", 0.80)
	addSig(8500, "Consul", `Consul`, "HashiCorp Consul", "Generic", 0.85)
	addSig(8200, "Vault", `Vault`, "HashiCorp Vault", "Generic", 0.85)
	addSig(4646, "Nomad", `Nomad`, "HashiCorp Nomad", "Generic", 0.80)
	addSig(25565, "Minecraft", `Minecraft`, "Minecraft Server", "Generic", 0.85)
	addSig(32400, "Plex", `Plex`, "Plex Media Server", "Generic", 0.85)
	addSig(8332, "Bitcoin", `Bitcoin`, "Bitcoin Core", "Generic", 0.85)
	addSig(8333, "Bitcoin", `Bitcoin`, "Bitcoin Core", "Generic", 0.85)
	addSig(9418, "Git", `git`, "Git Daemon", "Generic", 0.80)
	addSig(4369, "EPMD", `epmd`, "Erlang Port Mapper", "Generic", 0.80)
	addSig(9100, "Print", `jetdirect`, "HP JetDirect", "Generic", 0.85)

	// ─── Pure-FTPd (broader patterns) ───
	addSig(21, "FTP", `Pure-FTPd`, "Pure-FTPd", "Unix/Linux", 0.85)
	addSig(21, "FTP", `Welcome to Pure-FTPd`, "Pure-FTPd", "Unix/Linux", 0.90)
	addSig(21, "FTP", `pure-ftpd`, "Pure-FTPd", "Unix/Linux", 0.85)
	addSig(21, "FTP", `pure-ftpd.*\[privsep\]`, "Pure-FTPd", "Unix/Linux", 0.95)

	// ─── Exim SMTP ───
	addSig(25, "SMTP", `Exim\s+([\d.]+)`, "Exim", "Unix/Linux", 0.95)
	addSig(25, "SMTP", `Exim\s+([\d.]+)\s+`, "Exim", "Unix/Linux", 0.90)
	addSig(25, "SMTP", `220.*Exim`, "Exim", "Unix/Linux", 0.85)
	addSig(465, "SMTP", `Exim`, "Exim SMTPS", "Unix/Linux", 0.85)
	addSig(587, "SMTP", `Exim`, "Exim Submission", "Unix/Linux", 0.85)

	// ─── Dovecot ───
	addSig(110, "POP3", `Dovecot.*ready`, "Dovecot POP3", "Unix/Linux", 0.95)
	addSig(110, "POP3", `Dovecot`, "Dovecot POP3", "Unix/Linux", 0.85)
	addSig(143, "IMAP", `Dovecot.*ready`, "Dovecot IMAP", "Unix/Linux", 0.95)
	addSig(143, "IMAP", `Dovecot`, "Dovecot IMAP", "Unix/Linux", 0.85)
	addSig(993, "IMAP", `Dovecot`, "Dovecot IMAPS", "Unix/Linux", 0.85)
	addSig(995, "POP3", `Dovecot`, "Dovecot POP3S", "Unix/Linux", 0.85)

	// ─── LiteSpeed ───
	addSig(80, "HTTP", `Server:\s*LiteSpeed`, "LiteSpeed", "Unix/Linux", 0.95)
	addSig(80, "HTTP", `LiteSpeed`, "LiteSpeed", "Unix/Linux", 0.90)
	addSig(443, "HTTPS", `LiteSpeed`, "LiteSpeed SSL", "Unix/Linux", 0.90)
	addSig(8080, "HTTP", `LiteSpeed`, "LiteSpeed", "Unix/Linux", 0.85)
	addSig(8443, "HTTPS", `LiteSpeed`, "LiteSpeed SSL", "Unix/Linux", 0.85)

	// ─── cPanel ───
	addSig(2082, "HTTP", `cpanel`, "cPanel", "CentOS/CloudLinux", 0.90)
	addSig(2083, "HTTPS", `cpanel`, "cPanel SSL", "CentOS/CloudLinux", 0.90)
	addSig(2086, "HTTP", `whm`, "cPanel WHM", "CentOS/CloudLinux", 0.90)
	addSig(2087, "HTTPS", `whm`, "cPanel WHM SSL", "CentOS/CloudLinux", 0.90)
	addSig(80, "HTTP", `cpanel`, "cPanel", "CentOS/CloudLinux", 0.80)

	// ─── Postfix SMTP variants ───
	addSig(25, "SMTP", `220.*Postfix.*ESMTP`, "Postfix", "Unix/Linux", 0.95)
	addSig(587, "SMTP", `Postfix`, "Postfix Submission", "Unix/Linux", 0.85)
	addSig(465, "SMTP", `Postfix`, "Postfix SMTPS", "Unix/Linux", 0.80)

	// ─── Sendmail ───
	addSig(25, "SMTP", `Sendmail\s+([\d.]+)`, "Sendmail", "Unix/Linux", 0.90)

	// ─── Dovecot IMAP/POP3 broader ───
	addSig(143, "IMAP", `\* OK.*\[CAPABILITY`, "Dovecot IMAP", "Unix/Linux", 0.85)

	// ─── MySQL/MariaDB ───
	addSig(3306, "MySQL", `8\.\d+\.\d+`, "MySQL 8.x", "Generic", 0.85)
	addSig(3306, "MySQL", `10\.\d+\.\d+`, "MariaDB 10.x", "Generic", 0.85)

	// ─── HTTPS variants ───
	addSig(443, "HTTPS", `HTTP/1\.\d\s+\d{3}`, "HTTPS", "Generic", 0.80)
	addSig(8443, "HTTPS", `HTTP/1\.\d\s+\d{3}`, "HTTPS", "Generic", 0.80)
	addSig(9443, "HTTPS", `HTTP/1\.\d\s+\d{3}`, "HTTPS", "Generic", 0.80)

	// ─── SMTPS / Submission ───
	addSig(465, "SMTP", `220.*ESMTP`, "SMTPS", "Generic", 0.75)
	addSig(587, "SMTP", `220.*ESMTP`, "SMTP Submission", "Generic", 0.75)
	addSig(2525, "SMTP", `220.*ESMTP`, "SMTP Alternate", "Generic", 0.75)

	// ─── POP3S / IMAPS ───
	addSig(995, "POP3", `\+OK`, "POP3S", "Generic", 0.70)
	addSig(993, "IMAP", `\* OK`, "IMAPS", "Generic", 0.70)

	// ─── Shared hosting panels ───
	addSig(2083, "HTTPS", `cPanel.*SSL`, "cPanel SSL", "CentOS/CloudLinux", 0.95)

	// ─── Web servers: IIS, Tomcat ───
	addSig(80, "HTTP", `Microsoft-IIS`, "Microsoft IIS", "Windows Server", 0.95)
	addSig(443, "HTTPS", `Microsoft-IIS`, "Microsoft IIS SSL", "Windows Server", 0.90)
	addSig(80, "HTTP", `Apache-Coyote`, "Apache Tomcat", "Generic", 0.85)
			addSig(8009, "AJP", `Apache.*Tomcat`, "Apache Tomcat AJP", "Generic", 0.85)
	})
}

func addSig(port int, protocol, pattern, product, osHint string, confidence float64) {
	re, err := regexp.Compile(`(?i)` + pattern)
	if err != nil {
		return
	}
	serviceSignatures = append(serviceSignatures, ServiceSignature{
		Port:       port,
		Protocol:   protocol,
		Pattern:    re,
		Product:    product,
		OSHint:     osHint,
		Confidence: confidence,
	})
}

func initOSFingerprints() {
	initOSOnce.Do(func() {
		osFingerprints = []OSFingerprint{
		// ─── Windows Desktop ───
		{regexp.MustCompile(`Windows NT 10\.0; Win64|Windows NT 10\.0; WOW64`), "Windows", "11/10 (64-bit)", 0.92, 128},
		{regexp.MustCompile(`Windows NT 10\.0;`), "Windows", "10/11", 0.88, 128},
		{regexp.MustCompile(`Windows NT 6\.3;`), "Windows", "8.1", 0.88, 128},
		{regexp.MustCompile(`Windows NT 6\.2;`), "Windows", "8", 0.88, 128},
		{regexp.MustCompile(`Windows NT 6\.1;`), "Windows", "7/Server 2008 R2", 0.88, 128},
		{regexp.MustCompile(`Windows NT 6\.0;`), "Windows", "Vista/Server 2008", 0.85, 128},
		{regexp.MustCompile(`Windows NT 5\.2`), "Windows", "Server 2003/XP 64-bit", 0.85, 128},
		{regexp.MustCompile(`Windows NT 5\.1`), "Windows", "XP (32-bit)", 0.85, 128},
		{regexp.MustCompile(`Windows NT 5\.0`), "Windows", "2000", 0.80, 128},
		{regexp.MustCompile(`Windows 11|Windows11`), "Windows", "11", 0.90, 128},
		{regexp.MustCompile(`Windows 10|Windows10`), "Windows", "10", 0.90, 128},
		{regexp.MustCompile(`Windows 8\b|Windows8\b`), "Windows", "8", 0.85, 128},
		{regexp.MustCompile(`Windows 7\b|Windows7\b`), "Windows", "7", 0.85, 128},
		{regexp.MustCompile(`Windows Vista|WindowsVista`), "Windows", "Vista", 0.85, 128},
		{regexp.MustCompile(`Windows XP|WindowsXP`), "Windows", "XP", 0.85, 128},

		// ─── Windows Server ───
		{regexp.MustCompile(`Windows Server 2022|Server2022`), "Windows Server", "2022", 0.92, 128},
		{regexp.MustCompile(`Windows Server 2019|Server2019`), "Windows Server", "2019", 0.92, 128},
		{regexp.MustCompile(`Windows Server 2016|Server2016`), "Windows Server", "2016", 0.92, 128},
		{regexp.MustCompile(`Windows Server 2012 R2|Server2012R2`), "Windows Server", "2012 R2", 0.90, 128},
		{regexp.MustCompile(`Windows Server 2012`), "Windows Server", "2012", 0.90, 128},
		{regexp.MustCompile(`Windows Server 2008 R2|Server2008R2`), "Windows Server", "2008 R2", 0.85, 128},
		{regexp.MustCompile(`Windows Server 2008|Server2008`), "Windows Server", "2008", 0.85, 128},
		{regexp.MustCompile(`Windows Server 2003 R2|Server2003R2`), "Windows Server", "2003 R2", 0.80, 128},
		{regexp.MustCompile(`Windows Server 2003`), "Windows Server", "2003", 0.80, 128},
		{regexp.MustCompile(`Microsoft-HTTPAPI/2\.0`), "Windows Server", "Server Core (HTTPAPI)", 0.85, 128},
		{regexp.MustCompile(`Win32|Win64|Windows_NT`), "Windows", "(generic)", 0.75, 128},

		// ─── Microsoft IIS versions → Windows Server version ───
		{regexp.MustCompile(`Microsoft-IIS/10\.0`), "Windows Server", "2016/2019/2022 (IIS 10)", 0.90, 128},
		{regexp.MustCompile(`Microsoft-IIS/8\.5`), "Windows Server", "2012 R2 (IIS 8.5)", 0.90, 128},
		{regexp.MustCompile(`Microsoft-IIS/8\.0`), "Windows Server", "2012 (IIS 8.0)", 0.90, 128},
		{regexp.MustCompile(`Microsoft-IIS/7\.5`), "Windows Server", "2008 R2 (IIS 7.5)", 0.90, 128},
		{regexp.MustCompile(`Microsoft-IIS/7\.0`), "Windows Server", "2008 (IIS 7.0)", 0.85, 128},
		{regexp.MustCompile(`Microsoft-IIS/6\.0`), "Windows Server", "2003 (IIS 6.0)", 0.85, 128},
		{regexp.MustCompile(`Microsoft-IIS/5\.0`), "Windows Server", "2000 (IIS 5.0)", 0.80, 128},

		// ─── Windows-specific services ───
		{regexp.MustCompile(`Microsoft ESMTP|MS Exchange|ExchangeServer`), "Windows Server", "Exchange", 0.85, 128},
		{regexp.MustCompile(`Microsoft Terminal Services|TermService`), "Windows Server", "RDP", 0.85, 128},

		// ─── Ubuntu / Debian based ───
		{regexp.MustCompile(`Ubuntu 24\.04|noble`), "Ubuntu Linux", "24.04 LTS (Noble)", 0.92, 64},
		{regexp.MustCompile(`Ubuntu 22\.04|jammy`), "Ubuntu Linux", "22.04 LTS (Jammy)", 0.92, 64},
		{regexp.MustCompile(`Ubuntu 20\.04|focal`), "Ubuntu Linux", "20.04 LTS (Focal)", 0.92, 64},
		{regexp.MustCompile(`Ubuntu 18\.04|bionic`), "Ubuntu Linux", "18.04 LTS (Bionic)", 0.90, 64},
		{regexp.MustCompile(`Ubuntu 16\.04|xenial`), "Ubuntu Linux", "16.04 LTS (Xenial)", 0.88, 64},
		{regexp.MustCompile(`Ubuntu 14\.04|trusty`), "Ubuntu Linux", "14.04 LTS (Trusty)", 0.85, 64},
		{regexp.MustCompile(`Ubuntu|ubuntu|UBUNTU`), "Ubuntu Linux", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Debian GNU/Linux 12|bookworm`), "Debian Linux", "12 (Bookworm)", 0.92, 64},
		{regexp.MustCompile(`Debian GNU/Linux 11|bullseye`), "Debian Linux", "11 (Bullseye)", 0.92, 64},
		{regexp.MustCompile(`Debian GNU/Linux 10|buster`), "Debian Linux", "10 (Buster)", 0.90, 64},
		{regexp.MustCompile(`Debian GNU/Linux 9|stretch`), "Debian Linux", "9 (Stretch)", 0.88, 64},
		{regexp.MustCompile(`Debian|debian|DEBIAN`), "Debian Linux", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Raspbian|raspbian`), "Raspberry Pi OS", "(Raspbian)", 0.75, 64},

		// ─── RHEL / CentOS / Fedora ───
		{regexp.MustCompile(`CentOS Stream|CentOSStream`), "CentOS", "Stream", 0.90, 64},
		{regexp.MustCompile(`CentOS release 9|CentOS 9|el9`), "CentOS", "9", 0.92, 64},
		{regexp.MustCompile(`CentOS release 8|CentOS 8|el8`), "CentOS", "8", 0.92, 64},
		{regexp.MustCompile(`CentOS release 7|CentOS 7|el7`), "CentOS", "7", 0.92, 64},
		{regexp.MustCompile(`CentOS release 6|CentOS 6|el6`), "CentOS", "6", 0.85, 64},
		{regexp.MustCompile(`CentOS|centos|CENTOS`), "CentOS", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Red Hat Enterprise Linux 9|RHEL 9|rhel9`), "Red Hat Enterprise Linux", "9", 0.92, 64},
		{regexp.MustCompile(`Red Hat Enterprise Linux 8|RHEL 8|rhel8`), "Red Hat Enterprise Linux", "8", 0.92, 64},
		{regexp.MustCompile(`Red Hat Enterprise Linux 7|RHEL 7|rhel7`), "Red Hat Enterprise Linux", "7", 0.90, 64},
		{regexp.MustCompile(`Red Hat Enterprise Linux 6|RHEL 6|rhel6`), "Red Hat Enterprise Linux", "6", 0.85, 64},
		{regexp.MustCompile(`Red Hat|redhat|Red\.Hat`), "Red Hat Enterprise Linux", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Fedora release \d+`), "Fedora Linux", "Version-specific", 0.85, 64},
		{regexp.MustCompile(`Fedora|fedora|FEDORA`), "Fedora Linux", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Amazon Linux|amzn`), "Amazon Linux", "AWS", 0.85, 64},

		// ─── SUSE / OpenSUSE ───
		{regexp.MustCompile(`SUSE Linux Enterprise 15|SLES 15|sles15`), "SUSE Linux Enterprise", "15", 0.92, 64},
		{regexp.MustCompile(`SUSE Linux Enterprise 12|SLES 12|sles12`), "SUSE Linux Enterprise", "12", 0.90, 64},
		{regexp.MustCompile(`openSUSE Leap 15`), "openSUSE", "Leap 15", 0.88, 64},
		{regexp.MustCompile(`openSUSE Tumbleweed`), "openSUSE", "Tumbleweed", 0.85, 64},
		{regexp.MustCompile(`SUSE|suse|openSUSE`), "SUSE Linux", "(generic)", 0.75, 64},

		// ─── Alpine / Arch / Other Linux ───
		{regexp.MustCompile(`Alpine Linux v?(\d+\.\d+)`), "Alpine Linux", "Version-matched", 0.90, 64},
		{regexp.MustCompile(`Alpine|alpine`), "Alpine Linux", "(generic)", 0.85, 64},
		{regexp.MustCompile(`Arch Linux|archlinux|Arch`), "Arch Linux", "Rolling", 0.88, 64},
		{regexp.MustCompile(`Manjaro|manjaro`), "Manjaro Linux", "Rolling", 0.85, 64},
		{regexp.MustCompile(`Kali Linux|Kali|kali`), "Kali Linux", "Rolling", 0.85, 64},
		{regexp.MustCompile(`Parrot OS|ParrotSec`), "Parrot OS", "Security", 0.85, 64},
		{regexp.MustCompile(`Linux Mint|linuxmint`), "Linux Mint", "(generic)", 0.85, 64},
		{regexp.MustCompile(`Linux 2\.6\.`), "Linux Kernel", "2.6 (legacy)", 0.75, 64},

		// ─── Generic Linux with kernel hints ───
		{regexp.MustCompile(`Linux \d+\.\d+\.\d+-\d+-\w+`), "Linux", "Custom/Distro (kernel)", 0.70, 64},
		{regexp.MustCompile(`linux|UNIX|unix|Linux`), "Linux/Unix", "(generic)", 0.50, 64},

		// ─── Alpine-specific SSH ───
		{regexp.MustCompile(`dropbear`), "Linux", "Embedded/Lightweight (Dropbear)", 0.70, 64},

		// ─── Solaris / SunOS ───
		{regexp.MustCompile(`SunOS 5\.11|Solaris 11`), "Solaris", "11", 0.90, 255},
		{regexp.MustCompile(`SunOS 5\.10|Solaris 10`), "Solaris", "10", 0.90, 255},
		{regexp.MustCompile(`SunOS 5\.9|Solaris 9`), "Solaris", "9", 0.85, 255},
		{regexp.MustCompile(`SunOS|solaris|Solaris`), "Solaris", "(generic)", 0.80, 255},
		{regexp.MustCompile(`OpenIndiana|oi_`), "OpenIndiana", "Solaris-derived", 0.75, 255},

		// ─── BSD Family ───
		{regexp.MustCompile(`FreeBSD 14\.`), "FreeBSD", "14", 0.92, 64},
		{regexp.MustCompile(`FreeBSD 13\.`), "FreeBSD", "13", 0.92, 64},
		{regexp.MustCompile(`FreeBSD 12\.`), "FreeBSD", "12", 0.90, 64},
		{regexp.MustCompile(`FreeBSD 11\.`), "FreeBSD", "11", 0.88, 64},
		{regexp.MustCompile(`FreeBSD|freebsd`), "FreeBSD", "(generic)", 0.80, 64},
		{regexp.MustCompile(`OpenBSD 7\.`), "OpenBSD", "7", 0.92, 64},
		{regexp.MustCompile(`OpenBSD 6\.`), "OpenBSD", "6", 0.88, 64},
		{regexp.MustCompile(`OpenBSD|openbsd`), "OpenBSD", "(generic)", 0.85, 64},
		{regexp.MustCompile(`NetBSD 9\.|NetBSD 10\.`), "NetBSD", "9/10", 0.85, 64},
		{regexp.MustCompile(`NetBSD|netbsd`), "NetBSD", "(generic)", 0.80, 64},
		{regexp.MustCompile(`DragonFly|DragonFlyBSD`), "DragonFly BSD", "(generic)", 0.80, 64},

		// ─── macOS ───
		{regexp.MustCompile(`Darwin Kernel Version 2[3-9]`), "macOS", "Sonoma (14.x)", 0.88, 64},
		{regexp.MustCompile(`Darwin Kernel Version 2[0-2]`), "macOS", "Ventura (13.x)", 0.88, 64},
		{regexp.MustCompile(`Darwin Kernel Version 19`), "macOS", "Catalina (10.15)", 0.85, 64},
		{regexp.MustCompile(`Darwin Kernel Version 18`), "macOS", "Mojave (10.14)", 0.85, 64},
		{regexp.MustCompile(`Darwin Kernel Version 17`), "macOS", "High Sierra (10.13)", 0.85, 64},
		{regexp.MustCompile(`Darwin|darwin`), "macOS", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Mac OS X|MacOS|macOS`), "macOS", "(generic)", 0.80, 64},

		// ─── iOS / Apple TV ───
		{regexp.MustCompile(`Darwin\/?1[5-9]\.\d+\.\d+.*iPhone|CFNetwork.*iOS`), "iOS", "Mobile (Darwin)", 0.85, 64},
		{regexp.MustCompile(`AppleTV|Apple TV`), "Apple tvOS", "(generic)", 0.80, 64},

		// ─── Cisco ───
		{regexp.MustCompile(`Cisco IOS XE`), "Cisco IOS", "XE", 0.92, 255},
		{regexp.MustCompile(`Cisco IOS Software.*Version 1[5-9]\.`), "Cisco IOS", "15.x+", 0.90, 255},
		{regexp.MustCompile(`Cisco IOS.*Version 12\.`), "Cisco IOS", "12.x (legacy)", 0.85, 255},
		{regexp.MustCompile(`Cisco IOS`), "Cisco IOS", "(generic)", 0.88, 255},
		{regexp.MustCompile(`Cisco ASA\|Cisco Adaptive Security`), "Cisco ASA", "(generic)", 0.85, 255},
		{regexp.MustCompile(`Cisco Nexus|NX-OS`), "Cisco NX-OS", "", 0.85, 255},
		{regexp.MustCompile(`Cisco Catalyst|c2950|c2960|c3750|c3850`), "Cisco Catalyst", "Switch", 0.85, 255},
		{regexp.MustCompile(`Cisco Ios|Ciso`), "Cisco", "(generic)", 0.80, 255},

		// ─── Juniper ───
		{regexp.MustCompile(`Juniper JunOS.*2[1-9]\.`), "Juniper JunOS", "21.x+", 0.90, 255},
		{regexp.MustCompile(`Juniper JunOS.*1[5-9]\.`), "Juniper JunOS", "15.x-19.x", 0.88, 255},
		{regexp.MustCompile(`Juniper|junos`), "Juniper JunOS", "(generic)", 0.85, 255},
		{regexp.MustCompile(`JunOS|junOS`), "Juniper JunOS", "", 0.83, 255},
		{regexp.MustCompile(`Juniper SRX`), "Juniper SRX", "Firewall", 0.85, 255},

		// ─── MikroTik ───
		{regexp.MustCompile(`MikroTik RouterOS 7\.`), "MikroTik RouterOS", "7.x", 0.90, 64},
		{regexp.MustCompile(`MikroTik RouterOS 6\.`), "MikroTik RouterOS", "6.x", 0.88, 64},
		{regexp.MustCompile(`MikroTik|RouterOS`), "MikroTik RouterOS", "(generic)", 0.85, 64},

		// ─── Ubiquiti ───
		{regexp.MustCompile(`Ubiquiti UniFi|UniFi Security Gateway`), "Ubiquiti", "UniFi", 0.85, 64},
		{regexp.MustCompile(`EdgeOS|EdgeRouter`), "Ubiquiti", "EdgeOS", 0.83, 64},
		{regexp.MustCompile(`Ubiquiti|EdgeOS`), "Ubiquiti", "(generic)", 0.80, 64},
		{regexp.MustCompile(`airOS|AirOS`), "Ubiquiti", "airOS (wireless)", 0.80, 64},

		// ─── Palo Alto ───
		{regexp.MustCompile(`Palo Alto Networks PAN-OS 1[0-1]\.`), "Palo Alto PAN-OS", "10.x-11.x", 0.90, 255},
		{regexp.MustCompile(`Palo Alto Networks PAN-OS 9\.`), "Palo Alto PAN-OS", "9.x", 0.88, 255},
		{regexp.MustCompile(`Palo Alto`), "Palo Alto PAN-OS", "(generic)", 0.80, 255},

		// ─── Fortinet ───
		{regexp.MustCompile(`FortiGate 7\.`), "Fortinet FortiGate", "7.x (7.0/7.2/7.4)", 0.90, 255},
		{regexp.MustCompile(`FortiGate 6\.`), "Fortinet FortiGate", "6.x", 0.88, 255},
		{regexp.MustCompile(`FortiGate|Fortinet|FGT_`), "Fortinet FortiGate", "(generic)", 0.85, 255},

		// ─── OpenWrt / DD-WRT / Tomato ───
		{regexp.MustCompile(`OpenWrt 2[0-3]\.|OpenWrt 1[0-9]\.`), "OpenWrt", "19.x-23.x", 0.88, 64},
		{regexp.MustCompile(`OpenWrt|openwrt|OpenWRT`), "OpenWrt", "(generic)", 0.85, 64},
		{regexp.MustCompile(`DD-WRT|dd-wrt|DDWRT`), "DD-WRT", "(generic)", 0.85, 64},
		{regexp.MustCompile(`TomatoUSB|Toastman|Shibby`), "Tomato", "USB (Shibby/Toastman)", 0.85, 64},

		// ─── pfSense / OPNsense ───
		{regexp.MustCompile(`pfSense 2\.7|pfSense 2\.6`), "pfSense", "2.6/2.7", 0.88, 64},
		{regexp.MustCompile(`pfSense|pfsense`), "pfSense", "(generic)", 0.85, 64},
		{regexp.MustCompile(`OPNsense 2[34]\.`), "OPNsense", "23.x/24.x", 0.85, 64},
		{regexp.MustCompile(`OPNsense|opnsense`), "OPNsense", "(generic)", 0.80, 64},

		// ─── NAS / Storage ───
		{regexp.MustCompile(`Synology DSM 7\.`), "Synology DSM", "7.x", 0.88, 64},
		{regexp.MustCompile(`Synology DSM 6\.`), "Synology DSM", "6.x", 0.85, 64},
		{regexp.MustCompile(`Synology|synology`), "Synology DSM", "(generic)", 0.80, 64},
		{regexp.MustCompile(`QNAP QTS 5\.`), "QNAP QTS", "5.x (hero/c2)", 0.85, 64},
		{regexp.MustCompile(`QNAP QTS 4\.`), "QNAP QTS", "4.x", 0.83, 64},
		{regexp.MustCompile(`QNAP|qnap`), "QNAP QTS", "(generic)", 0.80, 64},
		{regexp.MustCompile(`TrueNAS|truenas|FreeNAS|freenas`), "TrueNAS", "(FreeNAS/Scale)", 0.85, 64},
		{regexp.MustCompile(`Unraid|unRAID`), "Unraid", "(generic)", 0.85, 64},

		// ─── Virtualization / Cloud ───
		{regexp.MustCompile(`VMware ESXi 8\.|ESXi 8\b`), "VMware ESXi", "8.x", 0.92, 64},
		{regexp.MustCompile(`VMware ESXi 7\.|ESXi 7\b`), "VMware ESXi", "7.x", 0.90, 64},
		{regexp.MustCompile(`VMware ESXi 6\.|ESXi 6\b`), "VMware ESXi", "6.x", 0.88, 64},
		{regexp.MustCompile(`VMware|vmware|ESXi`), "VMware ESXi", "(generic)", 0.85, 64},
		{regexp.MustCompile(`vCenter|vsphere`), "VMware vCenter", "(generic)", 0.85, 64},
		{regexp.MustCompile(`Proxmox|proxmox|PVE`), "Proxmox VE", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Hyper-V|hyperv|WindowsHyperV`), "Microsoft Hyper-V", "(generic)", 0.85, 128},
		{regexp.MustCompile(`XenServer|xenserver|XCP-ng|xcp-ng`), "XCP-ng / XenServer", "(generic)", 0.85, 64},
		{regexp.MustCompile(`QEMU|KVM|kvm|qemu|qemu-`), "QEMU/KVM", "Virtual Machine", 0.85, 64},

		// ─── Container / Orchestration ───
		{regexp.MustCompile(`Docker Container|docker.*linuxkit`), "Docker", "(LinuxKit)", 0.85, 64},
		{regexp.MustCompile(`Kubernetes|k8s|kubelet`), "Kubernetes", "(generic)", 0.85, 64},
		{regexp.MustCompile(`LXC|lxc|LXD|lxd`), "LXC/LXD", "Container", 0.80, 64},

		// ─── IoT / Embedded ───
		{regexp.MustCompile(`Raspberry Pi|raspberry|rpi\b`), "Raspberry Pi OS", "(generic)", 0.75, 64},
		{regexp.MustCompile(`Arduino|arduino`), "Arduino", "Embedded", 0.70, 64},
		{regexp.MustCompile(`ESP8266|ESP32|espressif`), "ESP/Espressif", "IoT (ESP8266/32)", 0.80, 64},

		// ─── Load Balancers / Reverse Proxies ───
		{regexp.MustCompile(`F5 BIG-IP|BIG-IP|f5\b`), "F5 BIG-IP", "(generic)", 0.90, 255},
		{regexp.MustCompile(`Citrix ADC|NetScaler|nsca`), "Citrix ADC (NetScaler)", "(generic)", 0.85, 64},
		{regexp.MustCompile(`A10 Networks|a10\b`), "A10 Networks", "(generic)", 0.80, 255},
		{regexp.MustCompile(`HAProxy|haproxy`), "HAProxy", "(generic)", 0.70, 64},

		// ─── Other Network ───
		{regexp.MustCompile(`SonicWall|sonicwall`), "SonicWall", "(generic)", 0.85, 255},
		{regexp.MustCompile(`Check Point|checkpoint|CP-`), "Check Point", "Gaia/Security Gateway", 0.85, 255},
		{regexp.MustCompile(`WatchGuard|watchguard`), "WatchGuard", "Firebox", 0.85, 255},
		{regexp.MustCompile(`ZyXEL|zyxel|Zyxel`), "ZyXEL", "(generic)", 0.80, 64},
		{regexp.MustCompile(`TP-Link|tplink|TP-LINK`), "TP-Link", "(generic)", 0.80, 64},
		{regexp.MustCompile(`D-Link|dlink`), "D-Link", "(generic)", 0.80, 64},
		{regexp.MustCompile(`Netgear|netgear`), "Netgear", "(generic)", 0.80, 64},

		// ─── Printers ───
		{regexp.MustCompile(`HP LaserJet|HP Color LaserJet|HP OfficeJet`), "HP", "Printer (LaserJet/OfficeJet)", 0.85, 64},
		{regexp.MustCompile(`Brother.*Printer|Brother.*MFC`), "Brother", "Printer (MFC/HL)", 0.80, 64},
		{regexp.MustCompile(`Canon.*Printer|Canon.*iR`), "Canon", "Printer (iR/MG)", 0.80, 64},
		{regexp.MustCompile(`Epson.*Printer|Epson.*WorkForce`), "Epson", "Printer (WorkForce)", 0.80, 64},

		// ─── Mobile / Tablet ───
		{regexp.MustCompile(`Android \d+\.\d+;.*Build/`), "Android", "Mobile (generic)", 0.80, 64},
	}
	})
}


// ─────────────────────────────────────────────────────────────────
// SIGNATURE MATCHING ENGINE
// ─────────────────────────────────────────────────────────────────

func buildPortIndex() {
	portIndexOnce.Do(func() {
		initSignatures()
		for i := range serviceSignatures {
			sig := &serviceSignatures[i]
			p := sig.Port
			if p > 0 && p < 65536 {
				portSignatureIndex[p] = append(portSignatureIndex[p], sig)
			}
		}
	})
}

func MatchServiceSignatures(port int, banner string) *ServiceSignature {
	buildPortIndex()

	if banner == "" {
		return nil
	}

	var best *ServiceSignature
	var bestConfidence float64
	bannerLower := strings.ToLower(banner)

	sigs := portSignatureIndex[port]

	for _, sig := range sigs {
		matches := sig.Pattern.FindStringSubmatch(banner)
		if matches != nil {
			conf := sig.Confidence
			productLower := strings.ToLower(sig.Product)
			if strings.Contains(bannerLower, productLower) {
				conf += 0.05
			}
			if conf > 1.0 {
				conf = 1.0
			}
			if conf > bestConfidence {
				best = sig
				bestConfidence = conf
				best.Confidence = conf
				if len(matches) > 1 && matches[1] != "" {
					best.Version = matches[1]
				}
			}
		}
	}

	return best
}

func DetectOSFromBanner(banner string, ttl int) (string, string, float64) {
	initOSFingerprints()

	var bestOS, bestVer string
	var bestConf float64

	for _, fp := range osFingerprints {
		if fp.Pattern.MatchString(banner) {
			if fp.Confidence > bestConf {
				bestOS = fp.OSName
				bestVer = fp.OSVersion
				bestConf = fp.Confidence
			}
		}
	}

	if bestConf == 0 && ttl > 0 {
		if ttl <= 64 {
			return "Unix/Linux", "", 0.4
		} else if ttl <= 128 {
			return "Windows", "", 0.4
		} else {
			return "Network Device", "", 0.4
		}
	}

	return bestOS, bestVer, bestConf
}

func GetSignatureCount() int {
	initSignatures()
	return len(serviceSignatures)
}

func GetOSFingerprintCount() int {
	initOSFingerprints()
	return len(osFingerprints)
}

// ─────────────────────────────────────────────────────────────────
// ENHANCED DetectService using signature DB
// ─────────────────────────────────────────────────────────────────

func DetectServiceV2(port int, banner string, host string) (string, string) {
	if banner == "" {
		if name, ok := commonPorts[port]; ok {
			return name, ""
		}
		return fmt.Sprintf("port-%d", port), ""
	}

	sig := MatchServiceSignatures(port, banner)
	if sig != nil {
		return sig.Product, sig.Version
	}

	bannerLower := strings.ToLower(banner)
	if strings.Contains(bannerLower, "ssh") || strings.Contains(bannerLower, "ssh-") {
		return "SSH", ExtractSSHVersion(banner)
	}
	if strings.Contains(bannerLower, "http") || strings.Contains(bannerLower, "server:") {
		ver := ExtractHTTPVersion(banner)
		return "HTTP", ver
	}
	if strings.Contains(bannerLower, "ftp") || strings.Contains(bannerLower, "220 ") {
		return "FTP", ExtractFTPVersion(banner)
	}
	if strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "esmtp") {
		return "SMTP", ExtractSMTPVersion(banner)
	}
	if strings.Contains(bannerLower, "mysql") {
		return "MySQL", ExtractMySQLVersion(banner)
	}
	if strings.Contains(bannerLower, "postgresql") || strings.Contains(bannerLower, "psql") {
		return "PostgreSQL", ""
	}
	if strings.Contains(bannerLower, "redis") {
		return "Redis", ExtractRedisVersion(banner)
	}
	if strings.Contains(bannerLower, "mongodb") {
		return "MongoDB", ""
	}
	if strings.Contains(bannerLower, "pop3") {
		return "POP3", ""
	}
	if strings.Contains(bannerLower, "imap") {
		return "IMAP", ""
	}

	if name, ok := commonPorts[port]; ok {
		return name, ""
	}
	return fmt.Sprintf("port-%d", port), ""
}

func GetOSFingerprintInfo(banner string, ttl int) string {
	os, ver, conf := DetectOSFromBanner(banner, ttl)
	if os != "" {
		if ver != "" {
			return fmt.Sprintf("%s %s (%.0f%%)", os, ver, conf*100)
		}
		return fmt.Sprintf("%s (%.0f%%)", os, conf*100)
	}
	return ""
}
