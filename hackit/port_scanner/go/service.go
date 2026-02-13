package main

import "strings"

var commonPorts = map[int]string{
	11: "systat", 13: "daytime", 17: "qotd", 19: "chargen", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	37: "time", 42: "nameserver", 43: "whois", 53: "dns", 67: "dhcps", 68: "dhcpc", 69: "tftp", 70: "gopher",
	79: "finger", 80: "http", 81: "hosts2-ns", 88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
	119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
	445: "microsoft-ds", 464: "kpasswd", 465: "smtps", 513: "rlogin", 514: "syslog", 515: "printer",
	543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
	873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1025: "msrpc", 1080: "socks", 1194: "openvpn",
	1433: "mssql", 1434: "ms-sql-m", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
	2121: "ftp-alt", 2375: "docker", 2376: "docker-ssl", 3306: "mysql", 3389: "ms-wbt-server",
	3690: "svn", 4444: "metasploit", 5000: "upnp", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
	5984: "couchdb", 6379: "redis", 6443: "kubernetes-api", 6667: "irc", 7000: "cassandra",
	7001: "cassandra", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
	8888: "http-alt", 9000: "php-fpm", 9042: "cassandra-native", 9090: "zeus-admin",
	9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch", 9418: "git", 9999: "adb",
	10000: "webmin", 11211: "memcached", 22222: "ssh-alt", 26257: "cockroachdb",
	27017: "mongodb", 27018: "mongodb", 28017: "mongodb-web", 50000: "db2", 54321: "database-alt",
}

// IdentifyService guesses the service and version based on port and banner
func IdentifyService(port int, banner string, host string) (string, string) {
	// 0. Try Rust fingerprinting (High Power)
	rustService := RustFingerprintService(banner)
	version := RustExtractVersion(banner, rustService)

	if strings.ToUpper(rustService) != "UNKNOWN" {
		return rustService, version
	}

	// 1. Check Banner Content (High Confidence)
	bannerLower := strings.ToLower(banner)
	if strings.Contains(bannerLower, "ssh") || strings.Contains(bannerLower, "ssh-") {
		return "ssh", version
	}
	if strings.Contains(bannerLower, "ftp") || strings.Contains(bannerLower, "220 ") {
		return "ftp", version
	}
	if strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "esmtp") {
		return "smtp", version
	}
	if strings.Contains(bannerLower, "http") || strings.Contains(bannerLower, "html") {
		return "http", version
	}

	// 2. Fallback to Common Ports (Medium Confidence)
	if name, ok := commonPorts[port]; ok {
		return name, version
	}

	return "unknown", version
}
