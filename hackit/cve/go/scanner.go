package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// CommonPorts maps massive ports to standard software services
var CommonPorts = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "openssh", 23: "telnet", 25: "smtp",
	53: "dns", 67: "dhcp", 68: "dhcp-client", 69: "tftp",
	80: "httpd", 81: "http-alt", 88: "kerberos",
	110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
	135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp",
	389: "ldap", 443: "httpd", 445: "smb", 465: "smtps",
	514: "syslog", 515: "lpd", 543: "kerberos-login", 548: "afp",
	554: "rtsp", 587: "smtp-submission", 631: "ipp", 636: "ldaps",
	873: "rsync", 902: "vmware-esxi", 989: "ftps-data", 990: "ftps-control",
	993: "imaps", 995: "pop3s", 1025: "msrpc", 1080: "socks",
	1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor", 1521: "oracle",
	1701: "l2tp", 1723: "pptp", 1812: "radius", 1813: "radius-acct",
	1900: "ssdp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2086: "whm", 2087: "whm-ssl", 2181: "zookeeper", 2375: "docker",
	2376: "docker-tls", 3306: "mysql", 3389: "rdp", 3690: "svn",
	4444: "metasploit", 5000: "flask", 5060: "sip", 5061: "sip-tls",
	5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "rabbitmq",
	5900: "vnc", 5985: "winrm", 5986: "winrm-https", 6379: "redis",
	6443: "kubernetes", 6667: "irc", 7001: "weblogic", 7002: "weblogic-ssl",
	8000: "http-alt", 8008: "http-proxy", 8080: "http-proxy", 8081: "http-alt",
	8088: "http-service", 8443: "https-alt", 8888: "jupyter", 9000: "sonarqube",
	9001: "supervisord", 9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
	9418: "git", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
	27018: "mongodb-shard", 27019: "mongodb-config", 50000: "sap",
}

// DeepScanPorts performs a safe, fast port scan and basic banner grab
func DeepScanPorts(target string) []DetectedTech {
	var techs []DetectedTech
	
	// Strip http/https
	host := strings.Replace(target, "http://", "", 1)
	host = strings.Replace(host, "https://", "", 1)
	if strings.Contains(host, "/") {
		host = strings.Split(host, "/")[0]
	}

	fmt.Printf("[*] Mode 2 (Main URL) Active: Initiating Deep Port Scanning on %s...\n", host)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for port, serviceGuess := range CommonPorts {
		wg.Add(1)
		go func(p int, guess string) {
			defer wg.Done()
			address := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return
			}
			
			// If connected, it's open
			fmt.Printf("    [+] Port %d/TCP is OPEN\n", p)
			
			// Quick banner grab
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			banner := string(buf[:n])
			conn.Close()

			software := guess
			version := "unknown"

			if banner != "" {
				// Simple heuristic for SSH
				if strings.Contains(banner, "SSH-2.0-OpenSSH") {
					software = "openssh"
					parts := strings.Split(banner, "_")
					if len(parts) > 1 {
						version = strings.Split(parts[1], " ")[0]
					}
				} else if strings.Contains(strings.ToLower(banner), "mysql") {
					software = "mysql"
				}
			}

			mu.Lock()
			techs = append(techs, DetectedTech{Software: software, Version: version})
			mu.Unlock()

		}(port, serviceGuess)
	}

	wg.Wait()
	return techs
}
