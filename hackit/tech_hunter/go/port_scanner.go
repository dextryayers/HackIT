package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	State   string `json:"state"`
}

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143,
	161, 162, 389, 443, 445, 465, 500, 514, 587, 593, 636,
	993, 995, 1080, 1194, 1352, 1433, 1434, 1521, 2049, 2082,
	2083, 2086, 2087, 2095, 2096, 2222, 2375, 2376, 3128, 3306,
	3389, 3690, 4333, 4444, 4500, 4848, 5000, 5001, 5060, 5061,
	5222, 5223, 5349, 5432, 5672, 5800, 5900, 5901, 5984, 6000,
	6001, 6379, 6443, 7070, 7777, 8000, 8001, 8008, 8009, 8080,
	8081, 8090, 8443, 8888, 9000, 9001, 9042, 9090, 9092, 9100,
	9200, 9300, 9418, 10000, 11211, 27017, 27018, 50070, 61613,
}

var portServiceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC",
	139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
	443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
	587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
	2049: "NFS", 2375: "Docker", 2376: "Docker TLS", 3128: "Squid",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5672: "RabbitMQ",
	5900: "VNC", 5901: "VNC-1", 5984: "CouchDB", 6379: "Redis",
	6443: "Kubernetes", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
	9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached",
	27017: "MongoDB", 50070: "HDFS",
}

func ScanPorts(target string, ports []int, timeout time.Duration) []PortResult {
	if len(ports) == 0 {
		ports = commonPorts
	}

	var results []PortResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := net.JoinHostPort(target, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(3 * time.Second))

			banner := ""
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = string(buf[:n])
				for _, b := range []byte{0, 10, 13, 32} {
					banner = strings.TrimRight(banner, string(b))
				}
				if len(banner) > 200 {
					banner = banner[:200]
				}
			}

			service := "Unknown"
			if s, ok := portServiceMap[p]; ok {
				service = s
			}
			if strings.Contains(strings.ToLower(banner), "ssh") {
				service = "SSH"
			} else if strings.Contains(strings.ToLower(banner), "http") {
				service = "HTTP"
			} else if strings.Contains(strings.ToLower(banner), "ftp") {
				service = "FTP"
			}

			mu.Lock()
			results = append(results, PortResult{
				Port:    p,
				Proto:   "tcp",
				Service: service,
				Banner:  banner,
				State:   "open",
			})
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return results
}
