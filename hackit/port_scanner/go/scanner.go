package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func classifyDialError(err error) string {
	if err == nil {
		return "open"
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "filtered"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") || strings.Contains(msg, "actively refused") {
		return "closed"
	}
	if strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable") || strings.Contains(msg, "host is down") {
		return "filtered"
	}
	// For UDP, ICMP port unreachable is common
	if strings.Contains(msg, "icmp") {
		return "closed"
	}
	return "closed"
}

func QuickCheckPort(host string, port int, timeoutMs int, network string) string {
	if network == "" {
		network = "tcp"
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout(network, address, time.Duration(timeoutMs)*time.Millisecond)
	if err == nil {
		conn.Close()
		return "open"
	}
	
	state := classifyDialError(err)
	if state == "filtered" {
		// Re-check with slightly longer timeout to reduce false filtered
		conn2, err2 := net.DialTimeout(network, address, time.Duration(timeoutMs+800)*time.Millisecond)
		if err2 == nil {
			conn2.Close()
			return "open"
		}
		state = classifyDialError(err2)
	}
	return state
}

// ScanPort performs a TCP Connect Scan on a single port
func ScanPort(host string, port int, timeoutMs int) (PortResult, bool) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return PortResult{}, false
	}
	defer conn.Close()

	// Connection successful, port is open
	// Extract TTL (Limited in standard net package, but we can try via Syscall or Raw if needed)
	// For Connect scan, getting TTL is harder without raw sockets, but we'll try a basic probe
	ttl := 0
	// Try to get TTL if we can (Simplified for now)

	// Try to grab banner with retry logic for "Real Open" validation
	var banner string
	var service string
	var version string

	banner = GrabBanner(conn, timeoutMs, port, host)
	service, version = IdentifyService(port, banner, host)

	// If IdentifyService didn't find a version, try ExtractVersion (local Go logic)
	if version == "" && banner != "" {
		version = ExtractVersion(service, banner)
	}

	return PortResult{
		Port:    port,
		State:   "open",
		Service: service,
		Banner:  banner,
		Version: version,
		TTL:     ttl,
	}, true
}

// GrabBanner attempts to read the first few bytes from the connection
func GrabBanner(conn net.Conn, timeoutMs int, port int, host string) string {
	// Keep banner grabbing fast; do not block the whole port scan on slow banners.
	readMs := timeoutMs / 3
	if readMs < 200 {
		readMs = 200
	}
	if readMs > 600 {
		readMs = 600
	}
	deadline := time.Now().Add(time.Duration(readMs) * time.Millisecond)
	conn.SetReadDeadline(deadline)

	buffer := make([]byte, 2048)

	// --- PHASE 1: Pro-active Probes (Before reading anything) ---
	// Some services need a "kick" to send anything
	if port == 80 || port == 8080 || port == 8000 || port == 8081 || port == 8888 {
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, getRandomUA())
		_, _ = conn.Write([]byte(req))
	} else if port == 6379 {
		_, _ = conn.Write([]byte("INFO\r\n"))
	} else if port == 3306 {
		// MySQL server sends handshake greeting immediately upon connection
		// DO NOT send anything - just read the server's initial handshake packet
		// The first byte will be protocol version (0x0a for MySQL 4.1+)
	} else if port == 5432 {
		// PostgreSQL SSLRequest
		_, _ = conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
	} else if port == 1433 {
		// MSSQL Pre-Login
		_, _ = conn.Write([]byte{0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	} else if port == 27017 {
		// MongoDB isMaster
		_, _ = conn.Write([]byte{0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	} else if port == 21 {
		// FTP
		_, _ = conn.Write([]byte("SYST\r\n"))
	} else if port == 25 || port == 587 {
		// SMTP
		_, _ = conn.Write([]byte("HELO ikipesat.test\r\n"))
	} else if port == 110 {
		// POP3
		_, _ = conn.Write([]byte("CAPA\r\n"))
	} else if port == 143 {
		// IMAP
		_, _ = conn.Write([]byte("A1 CAPABILITY\r\n"))
	}

	// --- PHASE 2: Wait for Response/Greeting ---
	// No sleep: rely on deadline-based reads.
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return cleanBanner(string(buffer[:n]))
	}

	// --- PHASE 3: TLS/SSL Handshake (If Phase 2 failed and it's an SSL port) ---
	if isSSLPort(port) {
		// We need a fresh connection or we can try to wrap the existing one if it's still alive
		// But since we already tried to read/write, it's safer to just return if it's not a clear banner
		// Actually, let's try a TLS handshake if the initial read failed
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		tlsConn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
		if err := tlsConn.Handshake(); err == nil {
			if port == 443 || port == 8443 || port == 9443 {
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, getRandomUA())
				_, _ = tlsConn.Write([]byte(req))
			} else if port == 993 {
				_, _ = tlsConn.Write([]byte("A1 CAPABILITY\r\n"))
			} else if port == 995 {
				_, _ = tlsConn.Write([]byte("CAPA\r\n"))
			}
			n, err = tlsConn.Read(buffer)
			if err == nil && n > 0 {
				return cleanBanner(string(buffer[:n]))
			}
		}
	}

	// --- PHASE 4: Specific Protocol Probes (If still no banner) ---
	if port == 25 || port == 587 || port == 465 || port == 2525 {
		_, _ = conn.Write([]byte("EHLO hackit.local\r\n"))
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			return cleanBanner(string(buffer[:n]))
		}
	} else if port == 21 {
		_, _ = conn.Write([]byte("HELP\r\n"))
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			return cleanBanner(string(buffer[:n]))
		}
	}

	return ""
}

func isHTTPPort(port int) bool {
	httpPorts := []int{80, 8080, 8000, 8081, 8888, 443, 8443, 9443}
	for _, p := range httpPorts {
		if p == port {
			return true
		}
	}
	return false
}

func isSSLPort(port int) bool {
	sslPorts := []int{443, 8443, 993, 995, 465, 548, 2376, 6443}
	for _, p := range sslPorts {
		if p == port {
			return true
		}
	}
	return false
}

func cleanBanner(banner string) string {
	banner = strings.TrimSpace(banner)
	// Remove non-printable characters but keep common ones
	var cleaned strings.Builder
	for _, r := range banner {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\r' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}

	bannerStr := cleaned.String()

	// If it's an HTTP response, try to extract Server and X-Powered-By headers
	if strings.Contains(strings.ToUpper(bannerStr), "HTTP/") {
		var relevantHeaders []string
		lines := strings.Split(bannerStr, "\r\n")
		if len(lines) == 1 {
			lines = strings.Split(bannerStr, "\n")
		}

		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.HasPrefix(lineLower, "server:") ||
				strings.HasPrefix(lineLower, "x-powered-by:") ||
				strings.HasPrefix(lineLower, "x-aspnet-version:") {
				relevantHeaders = append(relevantHeaders, strings.TrimSpace(line))
			}
		}

		if len(relevantHeaders) > 0 {
			return strings.Join(relevantHeaders, " | ")
		}

		// Fallback to first line if no interesting headers found
		if len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
	}

	// For other services, return first line if multi-line
	lines := strings.Split(bannerStr, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return strings.TrimSpace(bannerStr)
}

func getRandomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
	}
	return uas[time.Now().UnixNano()%int64(len(uas))]
}
// GrabBannerByHost opens a connection and grabs the banner
func GrabBannerByHost(host string, port int, timeoutMs int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return GrabBanner(conn, timeoutMs, port, host)
}
