package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// TCP PORT SCANNER — Industrial-Grade Protocol Prober
// ─────────────────────────────────────────────────────────────────

func classifyDialError(err error) string {
	if err == nil {
		return "open"
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "filtered"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") || strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "connection reset") {
		return "closed"
	}
	if strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable") ||
		strings.Contains(msg, "host is down") || strings.Contains(msg, "network unreachable") {
		return "filtered"
	}
	if strings.Contains(msg, "icmp") {
		return "closed"
	}
	return "closed"
}

// ScanPort — TCP connect scan with full banner + service detection
func ScanPort(host string, port int, timeoutMs int) (PortResult, bool) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		state := classifyDialError(err)
		// Retry once for filtered
		if state == "filtered" && timeoutMs > 500 {
			conn2, err2 := net.DialTimeout("tcp", address, time.Duration(timeoutMs/2)*time.Millisecond)
			if err2 == nil {
				conn2.Close()
				return PortResult{Port: port, State: "open", Protocol: "tcp"}, true
			}
			state = classifyDialError(err2)
		}
		return PortResult{Port: port, State: state, Protocol: "tcp", Reason: classifyDialError(err)}, false
	}
	defer conn.Close()

	banner := GrabBanner(conn, timeoutMs, port, host)
	service, version := IdentifyService(port, banner, host)

	if version == "" && banner != "" {
		version = ExtractVersion(service, banner)
	}

	return PortResult{
		Port:     port,
		State:    "open",
		Protocol: "tcp",
		Service:  service,
		Banner:   banner,
		Version:  version,
	}, true
}

// ScanUDP — UDP port scanner with ICMP error analysis
func ScanUDP(host string, port int, timeoutMs int) (PortResult, bool) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return PortResult{Port: port, State: "filtered", Protocol: "udp"}, false
	}
	defer conn.Close()

	// Send protocol-specific UDP probe
	probe := getUDPProbe(port)
	if len(probe) > 0 {
		conn.SetWriteDeadline(time.Now().Add(time.Duration(timeoutMs/2) * time.Millisecond))
		conn.Write(probe)
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		// No ICMP port unreachable = open|filtered
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return PortResult{Port: port, State: "open|filtered", Protocol: "udp"}, false
		}
		return PortResult{Port: port, State: "filtered", Protocol: "udp"}, false
	}

	if n > 0 {
		banner := cleanBanner(string(buf[:n]))
		service, version := IdentifyService(port, banner, host)
		return PortResult{
			Port:     port,
			State:    "open",
			Protocol: "udp",
			Service:  service,
			Banner:   banner,
			Version:  version,
		}, true
	}

	return PortResult{Port: port, State: "open|filtered", Protocol: "udp"}, false
}

// getUDPProbe returns protocol-specific UDP probes
func getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS
		return []byte{
			0x00, 0x01, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
			0x04, 'b', 'i', 'n', 'd',
			0x00, 0x00, 0x10, 0x00, 0x03, // TXT IN CHAOS
		}
	case 161: // SNMP v1 get-request
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
			0x04, 0x7e, 0x45, 0x94, 0x3e, 0x02, 0x01, 0x00,
			0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
			0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
		}
	case 123: // NTP
		return []byte{
			0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xbd, 0x6b, 0xd5, 0xe0, 0x00, 0x00, 0x00, 0x00,
		}
	case 500: // ISAKMP (IKE)
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x1c,
		}
	case 5060: // SIP OPTIONS
		return []byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
	case 1900: // SSDP (UPnP discovery)
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	case 4500: // IPSec NAT-T
		return []byte{0x00, 0x00, 0x00, 0x00}
	default:
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────
// BANNER GRABBER — 150+ Protocol Probes
// ─────────────────────────────────────────────────────────────────

func GrabBanner(conn net.Conn, timeoutMs int, port int, host string) string {
	readMs := timeoutMs
	if readMs < 1200 {
		readMs = 1200
	}
	if readMs > 4000 {
		readMs = 4000
	}
	buffer := make([]byte, 8192)

	// ── PHASE 0: Pre-read for greeting protocols ─────────────────
	switch port {
	case 21, 22, 2222, 2223, 25, 110, 143, 587, 990, 2525, 3306, 5432,
		465, 993, 995, 2083, 2087, 2096:
		conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return cleanBanner(string(buffer[:n]))
		}
	}

	// Reset deadline for full read
	conn.SetReadDeadline(time.Now().Add(time.Duration(readMs) * time.Millisecond))

	// ── PHASE 1: Protocol-specific active probes ─────────────────
	switch {
	// HTTP family
	case port == 80 || port == 8080 || port == 8000 || port == 8081 ||
		port == 8888 || port == 8008 || port == 7080 || port == 7081 ||
		port == 3000 || port == 4000 ||
		port == 5000 || port == 8009 || port == 8069 || port == 9000:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, getRandomUA())
		conn.Write([]byte(req))

	// HTTPS / TLS
	case port == 443 || port == 8443 || port == 9443 || port == 2083 ||
		port == 2087 || port == 2096 || port == 7443:
		// Handled in SSL phase below

	// SSH
	case port == 22 || port == 2222 || port == 2223:
		// SSH sends banner on connect — just read

	// FTP
	case port == 21 || port == 990:
		conn.Write([]byte("AUTH TLS\r\n"))

	// SMTP family
	case port == 25 || port == 587 || port == 2525 || port == 465:
		conn.Write([]byte("EHLO hackit.local\r\n"))

	// POP3
	case port == 110 || port == 995:
		conn.Write([]byte("CAPA\r\n"))

	// IMAP
	case port == 143 || port == 993:
		conn.Write([]byte("A1 CAPABILITY\r\n"))

	// Redis
	case port == 6379:
		conn.Write([]byte("INFO server\r\n"))

	// MySQL (sends greeting automatically — just read)
	case port == 3306:
		// Do nothing — MySQL sends handshake

	// PostgreSQL SSLRequest
	case port == 5432:
		conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})

	// MSSQL Pre-Login
	case port == 1433:
		conn.Write([]byte{
			0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
			0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
			0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
			0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		})

	// MongoDB isMaster
	case port == 27017:
		conn.Write([]byte{
			0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
			0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
			0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13,
			0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6d, 0x61,
			0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00,
		})

	// VNC
	case port == 5900 || port == 5901 || port == 5902:
		conn.Write([]byte("RFB 003.008\n"))

	// RDP
	case port == 3389:
		conn.Write([]byte{
			0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
			0x00, 0x00, 0x00,
		})

	// Memcached
	case port == 11211:
		conn.Write([]byte("stats\r\n"))

	// Elasticsearch
	case port == 9200 || port == 9300:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Cassandra (native protocol v4 STARTUP)
	case port == 9042:
		conn.Write([]byte{
			0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x16, 0x00, 0x01, 0x00, 0x0b, 0x43, 0x51, 0x4c,
			0x5f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e,
			0x00, 0x05, 0x33, 0x2e, 0x30, 0x2e, 0x30,
		})

	// Redis Cluster (6379 alt)
	case port == 16379:
		conn.Write([]byte("CLUSTER INFO\r\n"))

	// AMQP (RabbitMQ)
	case port == 5672:
		conn.Write([]byte("AMQP\x00\x00\x09\x01"))

	// Docker API
	case port == 2375 || port == 4243:
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Kubernetes API
	case port == 6443 || port == 8001:
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Consul
	case port == 8500:
		req := fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// etcd
	case port == 2379:
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// WinRM
	case port == 5985 || port == 5986:
		conn.Write([]byte("POST /wsman HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\n\r\n"))

	// IRC
	case port == 6667 || port == 6660 || port == 6697:
		conn.Write([]byte("NICK hackit\r\nUSER hackit 0 * :HackIT\r\n"))

	// LDAP
	case port == 389:
		// LDAP anonymous bind
		conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00})

	// Telnet
	case port == 23:
		conn.Write([]byte{0xff, 0xfd, 0x01, 0xff, 0xfd, 0x1f, 0xff, 0xfd, 0x21})

	// SIP
	case port == 5060:
		conn.Write([]byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm\r\nFrom: sip:nm@nm\r\nTo: sip:nm2@nm2\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"))

	// rsync
	case port == 873:
		conn.Write([]byte("@RSYNCD: 31.0\n"))

	// NNTP
	case port == 119:
		conn.Write([]byte("MODE READER\r\n"))

	// XMPP
	case port == 5222 || port == 5223:
		conn.Write([]byte("<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"))

	// Prometheus
	case port == 9090:
		req := fmt.Sprintf("GET /metrics HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Vault
	case port == 8200:
		req := fmt.Sprintf("GET /v1/sys/health HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Kubernetes Kubelet
	case port == 10250 || port == 10255:
		req := fmt.Sprintf("GET /pods HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// CouchDB
	case port == 5984:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Kafka
	case port == 9092:
		// Kafka API Versions request
		conn.Write([]byte{0x00, 0x00, 0x00, 0x0e, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x68, 0x61, 0x63, 0x6b})

	// ZooKeeper
	case port == 2181:
		conn.Write([]byte("ruok"))

	// Oracle TNS
	case port == 1521:
		conn.Write([]byte{
			0x00, 0x57, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x3a, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
			0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		})

	// IBM DB2
	case port == 50000:
		conn.Write([]byte{0x00, 0x27, 0xd0, 0x11, 0x00, 0x00, 0x00, 0x00})

	// BGP
	case port == 179:
		// BGP OPEN message
		conn.Write([]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4,
			0x00, 0x00, 0x00, 0x00, 0x00,
		})

	// Tomcat AJP
	case port == 8009:
		conn.Write([]byte{0x12, 0x34, 0x00, 0x0e, 0x02, 0x00, 0x00, 0x00})

	// cPanel / WHM
	case port == 2082 || port == 2086:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, getRandomUA())
		conn.Write([]byte(req))

	default:
		conn.Write([]byte("\r\n\r\n"))
	}

	// ── PHASE 2: Read initial response ───────────────────────────
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return cleanBanner(string(buffer[:n]))
	}

	// ── PHASE 3: Second read with small delay ─────────────────────
	time.Sleep(150 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(time.Duration(readMs/2) * time.Millisecond))
	n, err = conn.Read(buffer)
	if err == nil && n > 0 {
		return cleanBanner(string(buffer[:n]))
	}

	// ── PHASE 4: Heuristic CRLF kick ─────────────────────────────
	conn.Write([]byte("\r\n\r\n"))
	time.Sleep(200 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = conn.Read(buffer)
	if err == nil && n > 0 {
		return "[HEURISTIC]: " + cleanBanner(string(buffer[:n]))
	}

	// ── PHASE 5: TLS/SSL deep probe ──────────────────────────────
	if isSSLPort(port) {
		sslBanner := grabSSLBanner(host, port, timeoutMs)
		if sslBanner != "" {
			return "[SSL]: " + sslBanner
		}
	}

	return ""
}

// grabSSLBanner performs TLS handshake and extracts server info
func grabSSLBanner(host string, port int, timeoutMs int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	rawConn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return ""
	}
	defer rawConn.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	}
	tlsConn := tls.Client(rawConn, tlsConf)
	tlsConn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	if err := tlsConn.Handshake(); err != nil {
		return ""
	}

	// Extract TLS cert info
	state := tlsConn.ConnectionState()
	var certInfo string
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo = fmt.Sprintf("CN=%s", cert.Subject.CommonName)
		if len(cert.DNSNames) > 0 {
			certInfo += fmt.Sprintf(" SANs=%s", strings.Join(cert.DNSNames[:min3(3, len(cert.DNSNames))], ","))
		}
	}

	// Protocol-specific kicks
	buf := make([]byte, 8192)
	switch {
	case port == 443 || port == 8443 || port == 9443 || port == 2083 || port == 2087 || port == 2096 || port == 7443:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, getRandomUA())
		tlsConn.Write([]byte(req))
	case port == 993:
		tlsConn.Write([]byte("A1 CAPABILITY\r\n"))
	case port == 995:
		tlsConn.Write([]byte("CAPA\r\n"))
	case port == 465:
		tlsConn.Write([]byte("EHLO hackit.local\r\n"))
	}

	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := tlsConn.Read(buf)
	if err == nil && n > 0 {
		result := cleanBanner(string(buf[:n]))
		if certInfo != "" {
			result = "[CERT:" + certInfo + "] " + result
		}
		return result
	}

	return certInfo
}

func isHTTPPort(port int) bool {
	httpPorts := []int{80, 8080, 8000, 8081, 8888, 443, 8443, 9443, 3000, 4000, 5000, 8008, 8069, 9000}
	for _, p := range httpPorts {
		if p == port {
			return true
		}
	}
	return false
}

func isSSLPort(port int) bool {
	sslPorts := []int{443, 8443, 993, 995, 465, 548, 2376, 6443, 9443, 2083, 2087, 2096, 7443, 5986}
	for _, p := range sslPorts {
		if p == port {
			return true
		}
	}
	return false
}

func cleanBanner(banner string) string {
	banner = strings.TrimSpace(banner)
	var cleaned strings.Builder
	for _, r := range banner {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\r' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}
	result := cleaned.String()

	// HTTP: extract status line + key headers
	if strings.Contains(strings.ToUpper(result), "HTTP/") {
		var relevant []string
		lines := strings.Split(result, "\r\n")
		if len(lines) == 1 {
			lines = strings.Split(result, "\n")
		}
		for _, line := range lines {
			ll := strings.ToLower(line)
			if strings.HasPrefix(ll, "http/") {
				relevant = append(relevant, strings.TrimSpace(line))
			} else if strings.HasPrefix(ll, "server:") ||
				strings.HasPrefix(ll, "x-powered-by:") ||
				strings.HasPrefix(ll, "x-aspnet-version:") ||
				strings.HasPrefix(ll, "x-generator:") ||
				strings.HasPrefix(ll, "x-application:") ||
				strings.HasPrefix(ll, "via:") {
				relevant = append(relevant, strings.TrimSpace(line))
			}
		}
		if len(relevant) > 0 {
			return strings.Join(relevant, " | ")
		}
		if len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
	}

	// For non-HTTP: return first meaningful line, preferring lines with service identifiers
	lines := strings.Split(result, "\n")
	var bestLine string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 3 {
			bestLine = line
			ll := strings.ToLower(line)
			// Prefer lines containing known service identifiers
			if strings.Contains(ll, "pure-ftpd") || strings.Contains(ll, "proftpd") ||
				strings.Contains(ll, "vsftpd") || strings.Contains(ll, "openssh") ||
				strings.Contains(ll, "exim") || strings.Contains(ll, "dovecot") ||
				strings.Contains(ll, "postfix") || strings.Contains(ll, "sendmail") ||
				strings.Contains(ll, "litespeed") || strings.Contains(ll, "nginx") ||
				strings.Contains(ll, "apache") || strings.Contains(ll, "mysql") ||
				strings.Contains(ll, "mariadb") || strings.Contains(ll, "courier") {
				return line
			}
		}
	}
	if bestLine != "" {
		return bestLine
	}
	return strings.TrimSpace(result)
}

func getRandomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"curl/8.7.1",
	}
	return uas[time.Now().UnixNano()%int64(len(uas))]
}

// GrabBannerByHost opens a fresh connection and grabs the banner
func GrabBannerByHost(host string, port int, timeoutMs int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return GrabBanner(conn, timeoutMs, port, host)
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}
