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
	993:  "IMAPS (IMAP over SSL)",
	995:  "POP3S (POP3 over SSL)",
	1080: "socks", 1194: "openvpn", 1433: "mssql",
	1521: "oracle", 2049: "nfs",
	2082:  "cPanel (HTTP)",
	2083:  "cPanel (SSL)",
	2086:  "cPanel WHM (HTTP)",
	2087:  "cPanel WHM (SSL)",
	2375:  "Docker API (HTTP)",
	2376:  "Docker API (SSL)",
	2379:  "etcd Server",
	2380:  "etcd Peer",
	3000:  "Gogs / Grafana",
	3306:  "MySQL / MariaDB",
	3389:  "Remote Desktop (RDP)",
	3690:  "SVN (Subversion)",
	4000:  "Quake / Stun Server",
	5000:  "UPnP / Docker Registry",
	5432:  "PostgreSQL Database",
	5672:  "RabbitMQ (AMQP)",
	5900:  "VNC Remote Access",
	5984:  "CouchDB",
	6379:  "Redis Database",
	6443:  "Kubernetes API Server",
	7000:  "AFS / Filesystem",
	7001:  "WebLogic Server",
	8000:  "HTTP-ALT (Dev)",
	8008:  "HTTP-ALT (Alt)",
	8080:  "HTTP Proxy / Alternate",
	8081:  "HTTP Alternate / Proxy",
	8443:  "HTTPS-ALT / Plesk",
	8888:  "cPanel / Litespeed Alt",
	9000:  "PHP-FPM / SonarQube",
	9090:  "Prometheus / Zeus",
	9200:  "Elasticsearch",
	9443:  "HTTPS-ALT (Managed)",
	10000: "Webmin / Control Panel",
	11211: "Memcached",
	27017: "MongoDB Database",
	28017: "MongoDB Web Panel",
}

func IsCommonPort(port int) bool {
	_, ok := commonPorts[port]
	return ok
}

// universalPorts is the default scan surface: the ports that actually carry
// services on real networks, ordered by how often they are found open. A bare
// `scan -t host` scans exactly this list — never 1-65535.
var universalPorts = []int{
	80, 443, 22, 21, 25, 53, 110, 143, 993, 995,
	3306, 3389, 445, 139, 135, 8080, 8443, 8000, 8888, 9000,
	6379, 27017, 5432, 1433, 1521, 11211, 5672, 9200, 9300, 2375,
	2376, 6443, 10250, 5000, 5001, 3000, 9090, 9100, 9091, 7001,
	7002, 8009, 8081, 8082, 8090, 8161, 8500, 8880, 8983, 9418,
	5900, 5901, 5902, 5903, 5800, 6080, 873, 111, 2049, 3260,
	631, 515, 548, 139, 445, 3389, 5985, 5986, 47001, 49152,
	587, 465, 2525, 4190, 5060, 5061, 1720, 1723, 1883, 8883,
	1935, 554, 8554, 1936, 10000, 10001, 50000, 61616, 15672, 15692,
	4369, 25672, 8500, 8600, 3000, 5601, 9092, 2181, 2888, 3888,
	9042, 9160, 7199, 2379, 2380, 10255, 10256, 443, 80, 8080,
}

func parsePorts(pStr string) []int {
	var ports []int
	if pStr == "" || pStr == "default" {
		return append([]int(nil), universalPorts...)
	}
	if pStr == "all" || pStr == "full" {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports
	}
	if strings.HasPrefix(pStr, "top") {
		n := 100
		tail := strings.TrimPrefix(pStr, "top")
		if idx := strings.Index(tail, ":"); idx >= 0 {
			tail = tail[idx+1:]
		}
		if tail != "" {
			if v, err := strconv.Atoi(tail); err == nil && v > 0 {
				n = v
			}
		}
		if n <= len(universalPorts) {
			return append([]int(nil), universalPorts[:n]...)
		}
		// Beyond the curated list, extend deterministically with the remaining
		// common ports, then the rest of the range — never a random map walk.
		seen := make(map[int]bool, len(universalPorts))
		for _, p := range universalPorts {
			seen[p] = true
		}
		ports = append(ports, universalPorts...)
		rest := make([]int, 0, len(commonPorts))
		for p := range commonPorts {
			if !seen[p] {
				rest = append(rest, p)
			}
		}
		sort.Ints(rest)
		for _, p := range rest {
			if len(ports) >= n {
				break
			}
			ports = append(ports, p)
		}
		for p := 1; p <= 65535 && len(ports) < n; p++ {
			if !seen[p] && !IsCommonPort(p) {
				ports = append(ports, p)
			}
		}
		return ports
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
