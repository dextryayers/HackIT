package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type PortResult struct {
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	Service   string `json:"service"`
	TLS       bool   `json:"tls"`
	Banner    string `json:"banner,omitempty"`
	CertCN    string `json:"cert_cn,omitempty"`
}

type PortScanReport struct {
	Target     string       `json:"target"`
	OpenPorts  []PortResult `json:"open_ports"`
	TotalOpen  int          `json:"total_open"`
	TotalScanned int        `json:"total_scanned"`
	Issues     []string     `json:"issues"`
}

var commonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	587:  "SMTP Submission",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	1521: "Oracle",
	2049: "NFS",
	2082: "cPanel",
	2083: "cPanel SSL",
	2086: "WHM",
	2087: "WHM SSL",
	2096: "CPanel Webmail SSL",
	2222: "DirectAdmin",
	2375: "Docker",
	2376: "Docker SSL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	5901: "VNC-1",
	5985: "WinRM HTTP",
	5986: "WinRM HTTPS",
	6379: "Redis",
	8080: "HTTP-Proxy",
	8443: "HTTPS-Alt",
	9000: "PHP-FPM",
	9090: "HTTP-Alt",
	9200: "Elasticsearch",
	9418: "Git",
	11211: "Memcached",
	27017: "MongoDB",
}

func scanPorts(hostname, addr string, timeout time.Duration) PortScanReport {
	r := PortScanReport{
		Target:    addr,
		OpenPorts: make([]PortResult, 0),
		Issues:    make([]string, 0),
	}
	serverName := hostname
	if serverName == "" {
		serverName = addr
	}

	portList := []int{443, 80, 993, 995, 8443, 22, 21, 25, 3306, 3389, 5432, 5900, 6379, 8080}
	r.TotalScanned = len(portList)
	perPortTimeout := timeout
	if perPortTimeout > 500*time.Millisecond {
		perPortTimeout = 500 * time.Millisecond
	}
	totalDeadline := time.Now().Add(timeout)

	for _, p := range portList {
		if time.Now().After(totalDeadline) {
			break
		}
		targetAddr := fmt.Sprintf("%s:%d", addr, p)
		conn, err := net.DialTimeout("tcp", targetAddr, perPortTimeout)
		if err != nil {
			continue
		}

		pr := PortResult{
			Port:    p,
			Open:    true,
			Service: commonPorts[p],
			TLS:     false,
		}

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			pr.Banner = strings.TrimSpace(string(buf[:min(n, 128)]))
		}
		conn.Close()

		if p == 443 || p == 8443 || p == 993 || p == 995 || p == 465 || p == 2083 || p == 2087 || p == 5986 {
			tlsConn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: perPortTimeout},
				"tcp", targetAddr,
				&tls.Config{InsecureSkipVerify: true, ServerName: serverName},
			)
			if err == nil {
				pr.TLS = true
				if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
					pr.CertCN = tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
				}
				tlsConn.Close()
			}
		}

		r.OpenPorts = append(r.OpenPorts, pr)
		r.TotalOpen++
	}

	r.Issues = buildPortIssues(&r, serverName)
	return r
}

func buildPortIssues(r *PortScanReport, host string) []string {
	issues := make([]string, 0)
	if r.TotalOpen == 0 {
		issues = append(issues, "No open ports detected on common ports")
		return issues
	}
	for _, p := range r.OpenPorts {
		if p.Port == 21 {
			issues = append(issues, "FTP (21) is open - use SFTP/SCP instead")
		}
		if p.Port == 23 {
			issues = append(issues, "Telnet (23) is open - use SSH instead")
		}
		if p.Port == 80 {
			if !hasTLSPort(r, 443) {
				issues = append(issues, "HTTP (80) open but HTTPS (443) not detected")
			}
		}
		if p.Port == 3306 {
			issues = append(issues, "MySQL (3306) exposed - database should not be public")
		}
		if p.Port == 3389 {
			issues = append(issues, "RDP (3389) exposed - potential brute-force target")
		}
		if p.Port == 6379 {
			issues = append(issues, "Redis (6379) exposed - ensure authentication is configured")
		}
		if p.Port == 27017 {
			issues = append(issues, "MongoDB (27017) exposed - ensure authentication is configured")
		}
	}
	return issues
}

func hasTLSPort(r *PortScanReport, port int) bool {
	for _, p := range r.OpenPorts {
		if p.Port == port && p.TLS {
			return true
		}
	}
	for _, p := range r.OpenPorts {
		if p.Port == port {
			return true
		}
	}
	return false
}

func printPortReport(r PortScanReport) {
	fmt.Printf("\n  [+] Port Scan Results (%d open / %d scanned):", r.TotalOpen, r.TotalScanned)
	if r.TotalOpen == 0 {
		fmt.Printf("\n    No open ports detected")
	} else {
		for _, p := range r.OpenPorts {
			tlsMark := ""
			if p.TLS {
				tlsMark = " \033[32m[TLS]\033[0m"
			}
			bannerInfo := ""
			if p.Banner != "" {
				bannerInfo = fmt.Sprintf(" - %s", p.Banner)
			}
			certInfo := ""
			if p.CertCN != "" {
				certInfo = fmt.Sprintf(" (CN: %s)", p.CertCN)
			}
			fmt.Printf("\n    %s%5d/%-4s%s%s%s\033[0m",
				"\033[32m", p.Port, p.Service, tlsMark, bannerInfo, certInfo)
		}
	}
	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] Port Issues (%d):", len(r.Issues))
		for _, iss := range r.Issues {
			fmt.Printf("\n      - %s", iss)
		}
	}
	fmt.Println()
}
