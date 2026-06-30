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
	tcpDialerInit sync.Once
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
		banner := GrabBanner(conn, timeoutMs, port, host)
		service, version := IdentifyService(port, banner, host)
		if version == "" && banner != "" {
			version = ExtractVersion(service, banner)
		}
		return PortResult{
			Port: port, State: "open", Protocol: "tcp",
			Service: service, Banner: banner, Version: version,
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
	readMs := timeoutMs
	if readMs < 1200 {
		readMs = 1200
	}
	if readMs > 4000 {
		readMs = 4000
	}
	bufPtr := bufferPool8192.Get().(*[]byte)
	buffer := *bufPtr
	defer bufferPool8192.Put(bufPtr)

	// ── PHASE 0: Pre-read for greeting protocols ─────────────────
	switch port {
	case 21, 22, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230,
		25, 110, 143, 587, 990, 2525,
		3306, 3307, 3308, 3309, 3310, 3311, 3312,
		5432, 5433, 5434, 5435, 5436, 5437, 5438, 5439, 5440,
		465, 993, 995, 2083, 2087, 2096,
		6379, 6380, 6381, 6382, 6383, 6384, 6385,
		27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025,
		1521, 1522, 1523, 1524, 1525, 1526, 1527,
		5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910,
		3389, 3390, 3391, 3392:
		conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return cleanBanner(string(buffer[:n]))
		}
	}

	// SSL ports: skip TCP probe, go direct to TLS handshake
	if isSSLPort(port) {
		if sslBanner := grabSSLBanner(host, port, timeoutMs); sslBanner != "" {
			return "[SSL]: " + sslBanner
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

	// HTTP/2 prior knowledge (h2c upgrade)
	case port == 80 || port == 8080 || port == 8000 || port == 3000 || port == 5000:
		conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

	// gRPC health probe
	case port == 50051 || port == 50052 || port == 50053 || port == 50054 || port == 50055:
		conn.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// WebSocket upgrade detection
	case port == 80 || port == 443 || port == 8080 || port == 8443:
		req := fmt.Sprintf("GET /chat HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", host, port)
		conn.Write([]byte(req))

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

	// Cassandra native transport v5
	case port == 9042:
		conn.Write([]byte{0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x01, 0x00, 0x0b, 0x43, 0x51, 0x4c, 0x5f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, 0x00, 0x05, 0x33, 0x2e, 0x30, 0x2e, 0x30})

	// ZooKeeper stat (four-letter word)
	case port == 2181:
		conn.Write([]byte("stat"))

	// CouchDB
	case port == 5984:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Oracle XML DB
	case port == 1521:
		conn.Write([]byte{0x00, 0x5a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x3a, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 0x7f, 0xff, 0x87, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// IBM DB2
	case port == 50000:
		conn.Write([]byte{0x00, 0x27, 0xd0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// BGP OPEN
	case port == 179:
		conn.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// NetFlow / IPFIX
	case port == 2055 || port == 4739:
		conn.Write([]byte{0x00, 0x0a, 0x00, 0x01})

	// syslog
	case port == 514:
		conn.Write([]byte("<14>1 2024-01-01T00:00:00Z testhost hackit - - - probe\r\n"))

	// RPC portmapper
	case port == 111:
		conn.Write([]byte{0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Minecraft
	case port == 25565:
		conn.Write([]byte{0xfe, 0x01})

	// MQTT
	case port == 1883 || port == 8883:
		conn.Write([]byte{0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// MemSQL / SingleStore
	case port == 3307:
		conn.Write([]byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// ClickHouse
	case port == 8123 || port == 9000:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// NATS
	case port == 4222:
		conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n"))

	// STOMP (ActiveMQ)
	case port == 61613:
		conn.Write([]byte("CONNECT\naccept-version:1.2\nhost:test\n\n\x00\n"))

	// Syslog over TLS
	case port == 6514:
		conn.Write([]byte("<14>1 2024-06-21T12:00:00Z testhost hackit - - - probe\r\n"))

	// Windows SMB
	case port == 445:
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42})

	// SIP over TLS
	case port == 5061:
		conn.Write([]byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TLS nm\r\nFrom: sip:nm@nm\r\nTo: sip:nm2@nm2\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"))

	// HBase Thrift
	case port == 9090 || port == 9095:
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Spark Master Web UI
	case port == 8080 || port == 8081:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Cassandra OpsCenter
	case port == 61620:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// cPanel / WHM
	case port == 2082 || port == 2086:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, getRandomUA())
		conn.Write([]byte(req))

	// HTTP alt ports — common admin panels, dev dashboards, etc.
	case port == 81 || port == 82 || port == 83 || port == 84 || port == 85 || port == 86 ||
		port == 88 || port == 89 || port == 90 ||
		port == 4433 || port == 4443 ||
		port == 7000 || port == 7001 || port == 7002 || port == 7003 || port == 7004 || port == 7005 || port == 7006 || port == 7007 ||
		port == 8001 || port == 8002 || port == 8003 || port == 8004 || port == 8005 || port == 8006 || port == 8007 ||
		port == 8010 || port == 8011 ||
		port == 8082 || port == 8083 || port == 8084 || port == 8085 || port == 8086 || port == 8087 || port == 8088 || port == 8089 ||
		port == 8090 || port == 8091 || port == 8092 ||
		port == 8444 || port == 8445 || port == 8446 || port == 8447 || port == 8448 || port == 8449 || port == 8450 ||
		port == 8880 || port == 8881 || port == 8882 || port == 8883 || port == 8884 || port == 8885 || port == 8886 || port == 8887 ||
		port == 8889 || port == 8890 || port == 8891 || port == 8892 ||
		port == 9001 || port == 9002 || port == 9003 || port == 9004 || port == 9005 || port == 9006 || port == 9007 || port == 9008 || port == 9009 || port == 9010 ||
		port == 9444 || port == 9445 || port == 9446 || port == 9447 || port == 9448 || port == 9449 || port == 9450 ||
		port == 10000 || port == 10001 || port == 10002 || port == 10003 || port == 10004 || port == 10005 || port == 10006 || port == 10007 || port == 10008 || port == 10009 || port == 10010 ||
		port == 18080 || port == 18081 || port == 18082 || port == 18083 || port == 18084 || port == 18085 || port == 18086 || port == 18087 || port == 18088 || port == 18089 || port == 18090 ||
		port == 28080 || port == 28081 || port == 28082 || port == 28083 || port == 28084 || port == 28085 || port == 28086 || port == 28087 || port == 28088 || port == 28089 || port == 28090 ||
		port == 50001 || port == 50002 || port == 50003 || port == 50004 || port == 50005:
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, getRandomUA())
		conn.Write([]byte(req))

	// Database alt ports
	case port == 1434: // MSSQL browser monitor
		conn.Write([]byte{0x02})
	case port == 1522 || port == 1523 || port == 1524 || port == 1525 || port == 1526 || port == 1527: // Oracle TNS alt
		conn.Write([]byte{
			0x00, 0x57, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x01, 0x3a, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
			0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		})
	case port == 3308 || port == 3309 || port == 3310 || port == 3311 || port == 3312: // MySQL alt (greeting auto-sent)
	case port == 5433 || port == 5434 || port == 5435 || port == 5436 || port == 5437 || port == 5438 || port == 5439 || port == 5440: // PostgreSQL alt
		conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
	case port == 6380 || port == 6381 || port == 6382 || port == 6383 || port == 6384 || port == 6385: // Redis alt
		conn.Write([]byte("INFO server\r\n"))
	case port == 27018 || port == 27019 || port == 27020 || port == 27021 || port == 27022 || port == 27023 || port == 27024 || port == 27025: // MongoDB alt
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
	case port == 9043 || port == 9044: // Cassandra alt
		conn.Write([]byte{
			0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x16, 0x00, 0x01, 0x00, 0x0b, 0x43, 0x51, 0x4c,
			0x5f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e,
			0x00, 0x05, 0x33, 0x2e, 0x30, 0x2e, 0x30,
		})
	case port == 9160: // Cassandra Thrift
		conn.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	case port == 9201 || port == 9202 || port == 9203 || port == 9204 || port == 9205 || port == 9206 || port == 9207 || port == 9208 || port == 9209 || port == 9210: // ES alt
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 11212 || port == 11213 || port == 11214 || port == 11215: // Memcached alt
		conn.Write([]byte("stats\r\n"))
	case port == 4369: // Erlang port mapper
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 15672: // RabbitMQ mgmt
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 15674: // RabbitMQ STOMP
		conn.Write([]byte("CONNECT\naccept-version:1.2\nhost:test\n\n\x00\n"))
	case port == 15675: // RabbitMQ MQTT
		conn.Write([]byte{0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Message Queues
	case port == 5671: // AMQPS
		conn.Write([]byte("AMQP\x00\x00\x09\x01"))
	case port == 61614: // STOMPS
		conn.Write([]byte("CONNECT\naccept-version:1.2\nhost:test\n\n\x00\n"))
	case port == 61616: // ActiveMQ
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 9093 || port == 9094 || port == 9095 || port == 9096 || port == 9097: // Kafka alt
		conn.Write([]byte{0x00, 0x00, 0x00, 0x0e, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x68, 0x61, 0x63, 0x6b})
	case port == 6222: // NATS routing
		conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n"))
	case port == 8222: // NATS HTTP
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 2381 || port == 2382: // etcd alt
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 8501 || port == 8502 || port == 8503 || port == 8504: // Consul alt
		req := fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 8201: // Vault alt
		req := fmt.Sprintf("GET /v1/sys/health HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Monitoring
	case port == 9091: // Prometheus alt
		req := fmt.Sprintf("GET /metrics HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 3001 || port == 3002 || port == 3003 || port == 3004: // Grafana alt
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 3100 || port == 3101 || port == 3102: // Loki
		req := fmt.Sprintf("GET /ready HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))

	// Infrastructure
	case port == 2377: // Docker Swarm
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 6444: // K8s API alt
		req := fmt.Sprintf("GET /version HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 10251 || port == 10252 || port == 10253 || port == 10254 || port == 10256: // Kubelet alt
		req := fmt.Sprintf("GET /pods HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 8300 || port == 8301 || port == 8302 || port == 8400 || port == 8600: // Consul infra
		req := fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 4646: // Nomad HTTP
		req := fmt.Sprintf("GET /v1/status/leader HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 4647: // Nomad RPC
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 4648: // Nomad Serf
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// Remote Desktop
	case port == 3390 || port == 3391 || port == 3392: // RDP alt
		conn.Write([]byte{
			0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
			0x00, 0x00, 0x00,
		})
	case port == 5903 || port == 5904 || port == 5905 || port == 5906 || port == 5907 || port == 5908 || port == 5909 || port == 5910: // VNC alt
		conn.Write([]byte("RFB 003.008\n"))
	case port == 5800 || port == 5801 || port == 5802 || port == 5803 || port == 5804 || port == 5805: // VNC HTTP
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 2224 || port == 2225 || port == 2226 || port == 2227 || port == 2228 || port == 2229 || port == 2230: // SSH alt
		// SSH sends banner on connect — just read

	// VPN
	case port == 1194 || port == 1195 || port == 1196 || port == 1197 || port == 1198: // OpenVPN
		conn.Write([]byte{0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 51820 || port == 51821 || port == 51822 || port == 51823: // WireGuard
		conn.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Game Servers
	case port == 25566 || port == 25567 || port == 25568 || port == 25569 || port == 25570 || port == 25571 || port == 25572 || port == 25573 || port == 25574 || port == 25575: // Minecraft alt
		conn.Write([]byte{0xfe, 0x01})
	case port == 27015 || port == 27016 || port == 27017 || port == 27018 || port == 27019 || port == 27020: // Source/HLDS
		conn.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00})
	case port == 7777 || port == 7778 || port == 7779 || port == 7780: // Terraria
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 2302 || port == 2303 || port == 2304 || port == 2305: // Arma
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 28960 || port == 28961 || port == 28962 || port == 28963 || port == 28964: // CoD
		conn.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x67, 0x65, 0x74, 0x69, 0x6e, 0x66, 0x6f, 0x00})
	case port == 3074 || port == 3075 || port == 3076: // Xbox Live
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 3478 || port == 3479 || port == 3480 || port == 3481: // PlayStation
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// Industrial
	case port == 502: // Modbus
		conn.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x0a})
	case port == 102: // Siemens S7
		conn.Write([]byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc2, 0x02, 0x03, 0x02, 0xc0, 0x01, 0x0a, 0x00})
	case port == 20000: // DNP3
		conn.Write([]byte{0x05, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 44818: // EtherNet/IP
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 47808: // BACnet
		conn.Write([]byte{0x81, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 623: // IPMI RMCP
		conn.Write([]byte{0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 664: // ASF
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 427: // SLP
		conn.Write([]byte{0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 161 || port == 162 || port == 163 || port == 164: // SNMP TCP
		conn.Write([]byte{0x30, 0x00})
	case port == 515: // LPD
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 631: // IPP
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
		conn.Write([]byte(req))
	case port == 9100: // JetDirect
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// Audio/Video
	case port == 554 || port == 8554: // RTSP
		conn.Write([]byte("OPTIONS rtsp:// RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
	case port == 1935 || port == 1936 || port == 1937: // RTMP
		conn.Write([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case port == 1755: // MMS
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	case port == 7070 || port == 7071: // RealAudio
		conn.Write([]byte{0x00, 0x00, 0x00, 0x00})

	default:
		conn.Write([]byte("\r\n\r\n"))
	}

	// ── PHASE 2: Read initial response ───────────────────────────
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return cleanBanner(string(buffer[:n]))
	}

	// ── PHASE 3: Extended read (no fixed sleep) ──────────────────
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, err = conn.Read(buffer)
	if err == nil && n > 0 {
		return cleanBanner(string(buffer[:n]))
	}

	// ── PHASE 4: Heuristic CRLF kick + quick read ────────────────
	conn.Write([]byte("\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = conn.Read(buffer)
	if err == nil && n > 0 {
		return "[HEURISTIC]: " + cleanBanner(string(buffer[:n]))
	}

	return ""
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
