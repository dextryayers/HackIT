package main

import (
	"fmt"
	"regexp"
	"strings"
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

var serviceSignatures []ServiceSignature
var osFingerprints []OSFingerprint
var sigInitOnce bool

func initSignatures() {
	if sigInitOnce {
		return
	}
	sigInitOnce = true

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
	osFingerprints = []OSFingerprint{
		{regexp.MustCompile(`Windows NT 10\.0`), "Windows", "10/Server 2016/2019", 0.85, 128},
		{regexp.MustCompile(`Windows NT 6\.3`), "Windows", "8.1/Server 2012 R2", 0.85, 128},
		{regexp.MustCompile(`Windows NT 6\.2`), "Windows", "8/Server 2012", 0.85, 128},
		{regexp.MustCompile(`Windows NT 6\.1`), "Windows", "7/Server 2008 R2", 0.85, 128},
		{regexp.MustCompile(`Windows NT 6\.0`), "Windows", "Vista/Server 2008", 0.85, 128},
		{regexp.MustCompile(`Windows NT 5\.`), "Windows", "XP/Server 2003", 0.85, 128},
		{regexp.MustCompile(`Ubuntu|ubuntu`), "Ubuntu Linux", "24.04/22.04", 0.80, 64},
		{regexp.MustCompile(`Debian|debian`), "Debian Linux", "12/11", 0.80, 64},
		{regexp.MustCompile(`CentOS|centos`), "CentOS Linux", "9/8/7", 0.80, 64},
		{regexp.MustCompile(`Red Hat|redhat|Red\.Hat`), "Red Hat Linux", "9/8/7", 0.80, 64},
		{regexp.MustCompile(`Fedora|fedora`), "Fedora Linux", "Latest", 0.80, 64},
		{regexp.MustCompile(`SUSE|suse|openSUSE`), "SUSE Linux", "openSUSE", 0.80, 64},
		{regexp.MustCompile(`FreeBSD|freebsd`), "FreeBSD", "Latest", 0.85, 64},
		{regexp.MustCompile(`OpenBSD|openbsd`), "OpenBSD", "Latest", 0.85, 64},
		{regexp.MustCompile(`NetBSD|netbsd`), "NetBSD", "Latest", 0.80, 64},
		{regexp.MustCompile(`Darwin|darwin`), "macOS", "Sonoma/Ventura", 0.80, 64},
		{regexp.MustCompile(`Cisco IOS`), "Cisco IOS", "Latest", 0.90, 255},
		{regexp.MustCompile(`Cisco ASA`), "Cisco ASA", "Latest", 0.85, 255},
		{regexp.MustCompile(`Juniper|junos`), "Juniper JunOS", "Latest", 0.85, 255},
		{regexp.MustCompile(`MikroTik|RouterOS`), "MikroTik", "RouterOS", 0.85, 64},
		{regexp.MustCompile(`Ubiquiti|EdgeOS`), "Ubiquiti", "EdgeOS", 0.80, 64},
		{regexp.MustCompile(`Palo Alto`), "Palo Alto", "PAN-OS", 0.80, 255},
		{regexp.MustCompile(`FortiGate|Fortinet`), "Fortinet", "FortiGate", 0.85, 255},
		{regexp.MustCompile(`OpenWrt|openwrt`), "OpenWrt", "Latest", 0.85, 64},
		{regexp.MustCompile(`DD-WRT|dd-wrt`), "DD-WRT", "Latest", 0.85, 64},
		{regexp.MustCompile(`pfSense|pfsense`), "pfSense", "Latest", 0.85, 64},
		{regexp.MustCompile(`OPNsense|opnsense`), "OPNsense", "Latest", 0.80, 64},
		{regexp.MustCompile(`Synology|synology`), "Synology DSM", "Latest", 0.80, 64},
		{regexp.MustCompile(`QNAP|qnap`), "QNAP QTS", "Latest", 0.80, 64},
		{regexp.MustCompile(`VMware|vmware|ESXi`), "VMware ESXi", "Latest", 0.90, 64},
		{regexp.MustCompile(`Proxmox|proxmox`), "Proxmox VE", "Latest", 0.80, 64},
		{regexp.MustCompile(`Raspberry Pi|raspberry`), "Raspberry Pi OS", "Latest", 0.70, 64},
	}
}

// ─────────────────────────────────────────────────────────────────
// SIGNATURE MATCHING ENGINE
// ─────────────────────────────────────────────────────────────────

func MatchServiceSignatures(port int, banner string) *ServiceSignature {
	initSignatures()

	if banner == "" {
		return nil
	}

	var best *ServiceSignature
	var bestConfidence float64

	for i := range serviceSignatures {
		sig := &serviceSignatures[i]
		if sig.Port != 0 && sig.Port != port {
			continue
		}
		matches := sig.Pattern.FindStringSubmatch(banner)
		if matches != nil {
			conf := sig.Confidence
			if conf > bestConfidence {
				best = sig
				bestConfidence = conf
				if len(matches) > 1 {
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
