package main

import (
	"sort"
	"strconv"
	"strings"
)

var commonPorts = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 43: "whois",
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 81: "http-alt", 
	88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc", 
	137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 
	179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "smb", 
	465: "SMTPS (SMTP over SSL / submissions)", 
	514: "syslog", 515: "lpd", 543: "klogin", 544: "kshell", 548: "afp", 
	587: "smtp", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps", 
	993: "IMAPS (IMAP over SSL)", 
	995: "POP3S (POP3 over SSL)", 
	1080: "socks", 1194: "openvpn", 1433: "mssql", 
	1521: "oracle", 2049: "nfs", 
	2082: "cPanel (HTTP)", 
	2083: "cPanel (SSL)", 
	2086: "cPanel WHM (HTTP)", 
	2087: "cPanel WHM (SSL)", 
	2375: "Docker API (HTTP)", 
	2376: "Docker API (SSL)", 
	2379: "etcd Server",
	2380: "etcd Peer",
	3000: "Gogs / Grafana", 
	3306: "MySQL / MariaDB", 
	3389: "Remote Desktop (RDP)", 
	3690: "SVN (Subversion)", 
	4000: "Quake / Stun Server", 
	5000: "UPnP / Docker Registry", 
	5432: "PostgreSQL Database", 
	5672: "RabbitMQ (AMQP)", 
	5900: "VNC Remote Access", 
	5984: "CouchDB", 
	6379: "Redis Database", 
	6443: "Kubernetes API Server", 
	7000: "AFS / Filesystem", 
	7001: "WebLogic Server", 
	8000: "HTTP-ALT (Dev)", 
	8008: "HTTP-ALT (Alt)", 
	8080: "HTTP Proxy / Alternate", 
	8081: "HTTP Alternate / Proxy", 
	8443: "HTTPS-ALT / Plesk", 
	8888: "cPanel / Litespeed Alt", 
	9000: "PHP-FPM / SonarQube", 
	9090: "Prometheus / Zeus", 
	9200: "Elasticsearch", 
	9443: "HTTPS-ALT (Managed)",
	10000: "Webmin / Control Panel", 
	11211: "Memcached", 
	27017: "MongoDB Database", 
	28017: "MongoDB Web Panel",
}

func IsCommonPort(port int) bool {
	_, ok := commonPorts[port]
	return ok
}

func parsePorts(pStr string) []int {
	var ports []int
	if pStr == "" || pStr == "default" {
		for k := range commonPorts {
			ports = append(ports, k)
		}
		return unique(ports)
	}
	if pStr == "all" || pStr == "full" {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports
	}
	if strings.HasPrefix(pStr, "top100") {
		count := 0
		for k := range commonPorts {
			ports = append(ports, k)
			count++
			if count >= 100 { break }
		}
		return unique(ports)
	}
	if strings.HasPrefix(pStr, "top") {
		n := 100
		if idx := strings.Index(pStr, ":"); idx > 0 {
			if v, err := strconv.Atoi(pStr[idx+1:]); err == nil && v > 0 {
				n = v
			}
		}
		count := 0
		for k := range commonPorts {
			ports = append(ports, k)
			count++
			if count >= n { break }
		}
		return unique(ports)
	}
	parts := strings.Split(pStr, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			ranges := strings.Split(part, "-")
			if len(ranges) == 2 {
				start, err1 := strconv.Atoi(ranges[0])
				end, err2 := strconv.Atoi(ranges[1])
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						if i > 0 && i <= 65535 {
							ports = append(ports, i)
						}
					}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return unique(ports)
}

func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	sort.Ints(list)
	return list
}
