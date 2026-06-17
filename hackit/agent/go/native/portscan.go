package native

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// PortResult holds the results of a port scan
type PortResult struct {
	Port    int
	State   string
	Service string
	Banner  string
}

// Common ports to scan if top 100 is requested
var TopPorts = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
	8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465,
	548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
	32768, 1027, 1028, 1029, 1030, 8081, 2001, 8082, 6000, 9000, 6443,
	6379, 27017, 3000, 5432, 5672, 11211, 4369, 1521, 1433, 7001, 50000,
}

var portServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	443: "https", 445: "microsoft-ds", 587: "submission", 993: "imaps",
	995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server",
	5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
	8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}

// ScanPorts runs a highly concurrent TCP connect scan against the target
func ScanPorts(target string, ports []int, concurrency int, timeout time.Duration) []PortResult {
	// If target is a hostname, resolve to IP to avoid resolving per port
	ip := resolveToIPv4(target)
	if ip == "" {
		fmt.Printf("[!] Could not resolve IPv4 for %s\n", target)
		return nil
	}

	portsChan := make(chan int, len(ports))
	resultsChan := make(chan PortResult, len(ports))
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go portWorker(ip, portsChan, resultsChan, &wg, timeout)
	}

	// Send jobs
	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	// Wait in background and close results when done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var openPorts []PortResult
	for res := range resultsChan {
		if res.State == "open" {
			openPorts = append(openPorts, res)
		}
	}

	return openPorts
}

func portWorker(ip string, ports <-chan int, results chan<- PortResult, wg *sync.WaitGroup, timeout time.Duration) {
	defer wg.Done()

	for port := range ports {
		targetAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", targetAddr, timeout)

		if err != nil {
			// Closed or filtered
			continue
		}

		// Port is OPEN, let's try to grab a banner
		svcName := portServices[port]
		if svcName == "" {
			svcName = "unknown"
		}

		banner := grabBanner(conn, port, timeout)
		conn.Close()

		results <- PortResult{
			Port:    port,
			State:   "open",
			Service: svcName,
			Banner:  banner,
		}
	}
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))

	// Send basic probe for HTTP-like services
	if port == 80 || port == 8080 || port == 8000 || port == 443 || port == 8443 {
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: scanner\r\nConnection: close\r\n\r\n"))
	} else if port == 21 || port == 22 || port == 25 || port == 110 {
		// Just wait for server greeting
	} else {
		// Generic ping
		conn.Write([]byte("\r\n"))
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	banner := string(buffer[:n])
	banner = strings.Split(banner, "\n")[0] // Just get first line
	banner = strings.TrimSpace(banner)
	banner = cleanUTF8(banner)

	if len(banner) > 80 {
		return banner[:77] + "..."
	}
	return banner
}

// cleanUTF8 removes non-printable characters
func cleanUTF8(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}

func resolveToIPv4(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return ""
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return ""
}
