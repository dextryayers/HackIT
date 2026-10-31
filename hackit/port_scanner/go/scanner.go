package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────────────────────────
// DNS CACHE + BUFFER POOLS
// ─────────────────────────────────────────────────────────────────

type dnsCacheEntry struct {
	ips    []net.IP
	expiry time.Time
}

var (
	dnsCache       sync.Map
	bufferPool8192 = sync.Pool{
		New: func() interface{} { b := make([]byte, 8192); return &b },
	}
	bufferPool4096 = sync.Pool{
		New: func() interface{} { b := make([]byte, 4096); return &b },
	}
)

func preferIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

func resolveHostCached(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if val, ok := dnsCache.Load(host); ok {
		entry := val.(*dnsCacheEntry)
		if time.Now().Before(entry.expiry) {
			ip := preferIPv4(entry.ips)
			if ip != nil {
				return ip.String(), nil
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := &net.Resolver{PreferGo: false}
	ipas, err := r.LookupIPAddr(ctx, host)
	if err != nil || len(ipas) == 0 {
		dnsCache.Store(host, &dnsCacheEntry{expiry: time.Now().Add(30 * time.Second)})
		return host, err
	}
	ipList := make([]net.IP, len(ipas))
	for i, ipa := range ipas {
		ipList[i] = ipa.IP
	}
	dnsCache.Store(host, &dnsCacheEntry{
		ips:    ipList,
		expiry: time.Now().Add(5 * time.Minute),
	})
	ip := preferIPv4(ipList)
	if ip != nil {
		return ip.String(), nil
	}
	return ipList[0].String(), nil
}

// ─────────────────────────────────────────────────────────────────
// TCP DIALER — TCP_QUICKACK + TCP_NODELAY for max throughput
// ─────────────────────────────────────────────────────────────────

var (
	dialerPool8192 = sync.Pool{
		New: func() interface{} {
			return newTCPDialer(10 * time.Second)
		},
	}
	tcpDialerInit  sync.Once
	quickAckDialer *net.Dialer
)

func newTCPDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1, // no keepalive for scanning
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			c.Control(func(fd uintptr) {
				operr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
				if operr == nil {
					operr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
				}
			})
			return operr
		},
	}
	return d
}

func getDialer(timeout time.Duration) *net.Dialer {
	tcpDialerInit.Do(func() {
		quickAckDialer = newTCPDialer(timeout)
	})
	quickAckDialer.Timeout = timeout
	return quickAckDialer
}

// ─────────────────────────────────────────────────────────────────
// TCP PORT SCANNER — Industrial-Grade Protocol Prober
// ─────────────────────────────────────────────────────────────────

func classifyDialError(err error) string {
	if err == nil {
		return "open"
	}
	msg := strings.ToLower(err.Error())

	// ── CLOSED: Port actively refuses connection ──
	if strings.Contains(msg, "refused") || strings.Contains(msg, "actively refused") {
		return "closed"
	}

	// ── CLOSED: Connection reset by peer (port is up but service crashed/closed) ──
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "broken pipe") {
		// Double-check with a quick timeout: if it resets fast, it's closed
		return "closed"
	}

	// ── FILTERED: Firewall dropped/discarded packet (timeout) ──
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// Timeout strongly suggests firewall silently dropping
		return "filtered"
	}

	// ── FILTERED: No route to host / network unreachable ──
	if strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable") ||
		strings.Contains(msg, "host is down") || strings.Contains(msg, "network unreachable") {
		return "filtered"
	}

	// ── FILTERED: ICMP admin-prohibited ──
	if strings.Contains(msg, "icmp") && (strings.Contains(msg, "prohibited") ||
		strings.Contains(msg, "admin") || strings.Contains(msg, "filter")) {
		return "filtered"
	}

	// ── FILTERED: i/o timeout (general network issue) ──
	if strings.Contains(msg, "i/o timeout") {
		return "filtered"
	}

	// Default: closed (conservative — assume closed unless clear filtering evidence)
	return "closed"
}

// QuickScanPort — Ultra-fast single-pass TCP scan (no retry)
// Used for mass scan remaining ports. Distinguishes:
//   - OPEN: connect succeeds
//   - CLOSED: RST received fast (< 50ms elapsed)
//   - FILTERED: timeout or ICMP unreachable
func QuickScanPort(host string, port int, timeoutMs int) PortResult {
	if timeoutMs < 200 {
		timeoutMs = 200
	}
	if timeoutMs > 5000 {
		timeoutMs = 3000
	}
	ip, err := resolveHostCached(host)
	if err != nil {
		return PortResult{Port: port, State: "filtered", Protocol: "tcp"}
	}
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	dialer := getDialer(time.Duration(timeoutMs) * time.Millisecond)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		banner := GrabBannerByHost(host, port, timeoutMs/2)
		service, version := IdentifyService(port, banner, host)
		return PortResult{
			Port: port, State: "open", Protocol: "tcp",
			Service: service, Banner: banner, Version: version,
		}
	}
	state := classifyDialError(err)
	// Correction: if connection reset very fast (< 5ms), it's definitely closed
	// If the error was a timeout but elapsed is very short, still filtered
	if state == "filtered" && elapsed < 50*time.Millisecond {
		// Fast failure with timeout error could be kernel-level rejection
		// Check if it's specifically a refused error
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "refused") || strings.Contains(msg, "connection reset") {
			return PortResult{Port: port, State: "closed", Protocol: "tcp", Reason: "fast-refused"}
		}
	}
	return PortResult{Port: port, State: state, Protocol: "tcp", Reason: fmt.Sprintf("%s-in-%v", state, elapsed.Round(time.Millisecond))}
}

// ScanPort — TCP connect scan with full banner + service detection
func ScanPort(host string, port int, timeoutMs int) (PortResult, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	return scanPortWithContext(ctx, host, port, timeoutMs)
}

func scanPortWithContext(ctx context.Context, host string, port int, timeoutMs int) (PortResult, bool) {
	ip, err := resolveHostCached(host)
	if err != nil {
		return PortResult{Port: port, State: "filtered", Protocol: "tcp"}, false
	}
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// ── Try 1: Standard dial ──
	dialer := getDialer(time.Duration(timeoutMs) * time.Millisecond)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		// Connected → OPEN
		defer conn.Close()
		pr := ProbeConn(conn, timeoutMs, port, host)
		banner := pr.Banner
		service, version := IdentifyService(port, banner, host)
		if pr.Product != "" {
			service = pr.Product
		} else if pr.Protocol == "unknown" {
			service = "unknown"
		}
		if pr.Version != "" {
			version = pr.Version
		} else if version == "" && banner != "" && pr.Protocol != "" && pr.Protocol != "unknown" {
			version = ExtractVersion(service, banner)
		}
		if pr.Protocol == "unknown" || !looksLikeServerVersion(version) {
			version = ""
		}
		return PortResult{
			Port: port, State: "open", Protocol: "tcp",
			Service: service, Banner: banner, Version: version,
			BannerProtocol: pr.Protocol, BannerConfidence: pr.Confidence,
			BannerEvidence: pr.Evidence, BannerMismatch: pr.Mismatch,
		}, true
	}

	firstState := classifyDialError(err)

	// ── Try 2: Quick retry with shorter timeout to confirm ──
	// If first attempt timed out (filtered), a quick retry helps distinguish
	// actual firewall drop from transient network delay
	if firstState == "filtered" {
		quickTimeout := timeoutMs / 3
		if quickTimeout < 200 {
			quickTimeout = 200
		}
		quickCtx, quickCancel := context.WithTimeout(context.Background(), time.Duration(quickTimeout)*time.Millisecond)
		defer quickCancel()
		dialer2 := getDialer(time.Duration(quickTimeout) * time.Millisecond)
		conn2, err2 := dialer2.DialContext(quickCtx, "tcp", address)
		if err2 == nil {
			conn2.Close()
			// Connected on retry → OPEN
			banner := GrabBannerByHost(host, port, quickTimeout)
			service, version := IdentifyService(port, banner, host)
			return PortResult{
				Port: port, State: "open", Protocol: "tcp",
				Service: service, Banner: banner, Version: version,
			}, true
		}
		retryState := classifyDialError(err2)
		if retryState == "closed" {
			// Second attempt got refused — first was just slow, port is closed
			return PortResult{Port: port, State: "closed", Protocol: "tcp", Reason: "refused-on-retry"}, false
		}
		// Both attempts timed out → confirmed filtered
		return PortResult{Port: port, State: "filtered", Protocol: "tcp", Reason: "timeout-x2"}, false
	}

	// ── Try 3: If first said closed, do one more quick check ──
	if firstState == "closed" {
		quickTimeout := timeoutMs / 2
		if quickTimeout < 150 {
			quickTimeout = 150
		}
		quickCtx, quickCancel := context.WithTimeout(context.Background(), time.Duration(quickTimeout)*time.Millisecond)
		defer quickCancel()
		dialer3 := getDialer(time.Duration(quickTimeout) * time.Millisecond)
		conn3, err3 := dialer3.DialContext(quickCtx, "tcp", address)
		if err3 == nil {
			conn3.Close()
			banner := GrabBannerByHost(host, port, quickTimeout)
			service, version := IdentifyService(port, banner, host)
			return PortResult{
				Port: port, State: "open", Protocol: "tcp",
				Service: service, Banner: banner, Version: version,
			}, true
		}
		// Confirmed closed
		return PortResult{Port: port, State: "closed", Protocol: "tcp", Reason: classifyDialError(err3)}, false
	}

	return PortResult{Port: port, State: firstState, Protocol: "tcp", Reason: firstState}, false
}

// ScanUDP — UDP port scanner with ICMP error analysis
func ScanUDP(host string, port int, timeoutMs int) (PortResult, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	return scanUDPWithContext(ctx, host, port, timeoutMs)
}

func scanUDPWithContext(ctx context.Context, host string, port int, timeoutMs int) (PortResult, bool) {
	ip, _ := resolveHostCached(host)
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return PortResult{Port: port, State: "filtered", Protocol: "udp"}, false
	}
	defer conn.Close()

	probe := getUDPProbe(port)
	if len(probe) > 0 {
		conn.SetWriteDeadline(time.Now().Add(time.Duration(timeoutMs/2) * time.Millisecond))
		conn.Write(probe)
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	bufPtr := bufferPool4096.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool4096.Put(bufPtr)
	n, err := conn.Read(buf)
	if err != nil {
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
	case 67: // DHCP discover
		return []byte{0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 69: // TFTP RRQ
		return []byte{0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00}
	case 137: // NetBIOS name service
		return []byte{0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01}
	case 514: // syslog
		return []byte("<14>1 2024-01-01T00:00:00Z testhost hackit - - - probe\n")
	case 520: // RIP v2
		return []byte{0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 1434: // MSSQL browser
		return []byte{0x02}
	case 1719: // H323
		return []byte{0x00, 0x00, 0x00, 0x00}
	case 3456: // VAT
		return []byte{0x00, 0x00, 0x00, 0x00}
	case 5351: // NAT-PMP
		return []byte{0x00, 0x00}
	case 5353: // mDNS
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x2e, 0x75, 0x64, 0x70, 0x00, 0x00, 0x10, 0x00, 0x01}
	case 5683: // CoAP
		return []byte{0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 10000: // Network Data Management Protocol
		return []byte{0x00, 0x00, 0x00, 0x00}
	case 65535:
		return []byte{0x00, 0x00}
	case 162: // SNMP v2c trap
		return []byte{
			0x30, 0x30, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa4, 0x23, 0x06,
			0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03,
			0x00, 0x43, 0x02, 0x00, 0x00, 0x06, 0x0a, 0x2b,
			0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01,
			0x00, 0x30, 0x02, 0x04, 0x00,
		}
	case 124, 125: // NTP alt
		return []byte{
			0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xbd, 0x6b, 0xd5, 0xe0, 0x00, 0x00, 0x00, 0x00,
		}
	case 501: // ISAKMP alt
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x1c,
		}
	case 4501: // IPSec NAT-T alt
		return []byte{0x00, 0x00, 0x00, 0x00}
	case 521: // RIPng
		return []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 517: // Talk
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 518: // ntalk
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 5354: // mDNS alt
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x2e, 0x75, 0x64, 0x70, 0x00, 0x00, 0x10, 0x00, 0x01}
	case 5355: // LLMNR
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x68, 0x61, 0x63, 0x6b, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01}
	case 1901, 1902: // SSDP alt
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	case 68: // DHCP client (send from client port)
		return []byte{0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 70, 71, 72: // TFTP alt / generic
		return []byte{0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00}
	case 138: // NetBIOS datagram
		return []byte{0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01}
	case 139: // NetBIOS session
		return []byte{0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01}
	case 389: // LDAP UDP
		return []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	case 636: // LDAPS UDP
		return []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	case 1812: // RADIUS authentication
		return []byte{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x68, 0x61, 0x63, 0x6b,
			0x69, 0x74,
		}
	case 1813: // RADIUS accounting
		return []byte{
			0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x68, 0x61, 0x63, 0x6b,
			0x69, 0x74,
		}
	case 1645, 1646: // RADIUS old auth/acct
		return []byte{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
		}
	case 3702: // WS-Discovery
		return []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>uuid:00000000-0000-0000-0000-000000000001</wsa:MessageID><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header><soap:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><Types>wsdp:Device</Types></Probe></soap:Body></soap:Envelope>")
	case 5684: // CoAPS (DTLS)
		return []byte{0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	default:
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────
// BANNER GRABBER — 150+ Protocol Probes
// ─────────────────────────────────────────────────────────────────

func GrabBanner(conn net.Conn, timeoutMs int, port int, host string) string {
	res := ProbeConn(conn, timeoutMs, port, host)
	if res.Banner == "" {
		return ""
	}
	return res.Banner
}

// grabSSLBanner performs TLS handshake and extracts server info
func grabSSLBanner(host string, port int, timeoutMs int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := getDialer(time.Duration(timeoutMs) * time.Millisecond)
	rawConn, err := dialer.Dial("tcp", address)
	if err != nil {
		return ""
	}
	defer rawConn.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1", "grpc-exp"},
	}
	tlsConn := tls.Client(rawConn, tlsConf)
	tlsConn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	if err := tlsConn.Handshake(); err != nil {
		return ""
	}

	// Extract TLS cert info + ALPN
	state := tlsConn.ConnectionState()
	var certInfo string
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo = fmt.Sprintf("CN=%s", cert.Subject.CommonName)
		if len(cert.DNSNames) > 0 {
			certInfo += fmt.Sprintf(" SANs=%s", strings.Join(cert.DNSNames[:min3(3, len(cert.DNSNames))], ","))
		}
	}

	// ALPN analysis
	alpnInfo := ""
	if state.NegotiatedProtocol != "" {
		alpnInfo = fmt.Sprintf("ALPN=%s", state.NegotiatedProtocol)
		if state.NegotiatedProtocol == "h2" {
			alpnInfo += " (HTTP/2)"
		} else if state.NegotiatedProtocol == "grpc-exp" {
			alpnInfo += " (gRPC)"
		}
	}
	if alpnInfo != "" {
		if certInfo != "" {
			certInfo += " " + alpnInfo
		} else {
			certInfo = alpnInfo
		}
	}

	// TLS version info
	tlsVerStr := fmt.Sprintf("TLSv")
	switch state.Version {
	case tls.VersionTLS10:
		tlsVerStr += "1.0"
	case tls.VersionTLS11:
		tlsVerStr += "1.1"
	case tls.VersionTLS12:
		tlsVerStr += "1.2"
	case tls.VersionTLS13:
		tlsVerStr += "1.3"
	default:
		tlsVerStr += "?"
	}
	certInfo += " [" + tlsVerStr + "]"

	// Protocol-specific kicks
	bufSSLPtr := bufferPool8192.Get().(*[]byte)
	buf := *bufSSLPtr
	defer bufferPool8192.Put(bufSSLPtr)
	switch {
	case port == 443 || port == 8443 || port == 9443 || port == 2083 || port == 2087 || port == 2096 || port == 7443:
		// Try HTTP/2 upgrade first
		tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
		tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n2, err2 := tlsConn.Read(buf)
		if err2 == nil && n2 > 0 {
			// HTTP/2 detected
			result := cleanBanner(string(buf[:n2]))
			result = "[H2] " + result
			if certInfo != "" {
				result = "[CERT:" + certInfo + "] " + result
			}
			return result
		}
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

var httpPortSet map[int]struct{}

func init() {
	httpPortSet = make(map[int]struct{}, 150)
	ports := []int{80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 443, 4433, 4443,
		3000, 3001, 3002, 3003, 3004, 4000, 5000, 554, 631,
		7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007,
		7080, 7081, 7443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
		8010, 8011, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
		8090, 8091, 8092, 8123, 8200, 8201, 8222, 8300, 8301, 8302, 8400,
		8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450,
		8500, 8501, 8502, 8503, 8504, 8554, 8600,
		8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887, 8888, 8889, 8890, 8891, 8892,
		9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
		9090, 9091, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207, 9208, 9209, 9210,
		9443, 9444, 9445, 9446, 9447, 9448, 9449, 9450,
		10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
		15672, 18080, 18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088, 18089, 18090,
		28080, 28081, 28082, 28083, 28084, 28085, 28086, 28087, 28088, 28089, 28090,
		3100, 3101, 3102, 4646, 50001, 50002, 50003, 50004, 50005,
		5800, 5801, 5802, 5803, 5804, 5805, 5984, 61616, 61620, 6443, 6444,
		9093, 9094, 9095, 9096, 9097, 10250, 10251, 10252, 10253, 10254, 10255, 10256,
		2375, 2377, 4243}
	for _, p := range ports {
		httpPortSet[p] = struct{}{}
	}
}

var sslPortSet map[int]struct{}

func init() {
	sslPortSet = make(map[int]struct{}, 40)
	ports := []int{443, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450,
		993, 995, 465, 548, 2376, 6443, 6444, 9443, 9444, 9445, 9446, 9447, 9448, 9449, 9450,
		2083, 2087, 2096, 7443, 5986, 4433, 4443, 5671, 61614, 636, 5684, 8554}
	for _, p := range ports {
		sslPortSet[p] = struct{}{}
	}
}

func isHTTPPort(port int) bool {
	_, ok := httpPortSet[port]
	return ok
}

func isSSLPort(port int) bool {
	_, ok := sslPortSet[port]
	return ok
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
	return uas[rand.Intn(len(uas))]
}

// GrabBannerByHost opens a fresh connection and grabs the banner
func GrabBannerByHost(host string, port int, timeoutMs int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := getDialer(time.Duration(timeoutMs) * time.Millisecond)
	conn, err := dialer.Dial("tcp", address)
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
