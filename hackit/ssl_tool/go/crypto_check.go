package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type CryptoReport struct {
	DHGroups        bool     `json:"dh_groups_detected"`
	DHSizes         []int    `json:"dh_sizes"`
	ECCurves        []string `json:"ec_curves"`
	WeakCurves      []string `json:"weak_curves"`
	KeyExchange     string   `json:"key_exchange"`
	ForwardSecrecy   bool    `json:"forward_secrecy"`
	PerfectForward  bool     `json:"perfect_forward_secrecy"`
	TicketKeyRotate bool     `json:"ticket_key_rotation"`
	Issues          []string `json:"issues"`
	Score           int      `json:"score"`
}

func scanCrypto(host string, port int, timeout time.Duration) CryptoReport {
	r := CryptoReport{
		ECCurves:   make([]string, 0),
		WeakCurves: make([]string, 0),
		Issues:     make([]string, 0),
	}
	cryptoT := timeout
	if cryptoT > 8*time.Second {
		cryptoT = 8 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: cryptoT}

	curvesToTest := []struct {
		id   tls.CurveID
		name string
	}{
		{tls.CurveP256, "secp256r1 (P-256)"},
		{tls.CurveP384, "secp384r1 (P-384)"},
		{tls.CurveP521, "secp521r1 (P-521)"},
		{tls.X25519, "X25519"},
	}

	for _, curve := range curvesToTest {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []tls.CurveID{curve.id},
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err == nil {
			conn.Close()
			r.ECCurves = append(r.ECCurves, curve.name)

			if strings.Contains(curve.name, "secp256r1") {
				r.KeyExchange = fmt.Sprintf("ECDHE on secp256r1 (P-256)")
			} else if strings.Contains(curve.name, "X25519") {
				r.KeyExchange = fmt.Sprintf("ECDHE on X25519")
			}

			if !strings.Contains(strings.ToLower(curve.name), "weak") {
				if !r.ForwardSecrecy {
					csName := tls.CipherSuiteName(config.CipherSuites[0])
					r.ForwardSecrecy = strings.HasPrefix(csName, "TLS_ECDHE") ||
						strings.HasPrefix(csName, "TLS_DHE")
				}
			}

			if strings.Contains(strings.ToLower(curve.name), "secp192") ||
				strings.Contains(strings.ToLower(curve.name), "secp160") {
				r.WeakCurves = append(r.WeakCurves, curve.name)
			}
		}
	}

	r.DHGroups = false
	dhConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, dhConfig)
	if err == nil {
		conn.Close()
	}

	if len(r.ECCurves) > 0 {
		r.PerfectForward = true
	}

	tls13Config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	conn13, err := tls.DialWithDialer(dialer, "tcp", addr, tls13Config)
	if err == nil {
		conn13.Close()
		r.ForwardSecrecy = true
		r.PerfectForward = true
	}

	ticketConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(2),
	}
	connA, _ := tls.DialWithDialer(dialer, "tcp", addr, ticketConfig)
	if connA != nil {
		connA.Close()
		connB, _ := tls.DialWithDialer(dialer, "tcp", addr, ticketConfig)
		if connB != nil {
			r.TicketKeyRotate = !connB.ConnectionState().DidResume
			connB.Close()
		}
	}

	r.Issues = buildCryptoIssues(&r)
	r.Score = calcCryptoScore(&r)
	return r
}

func buildCryptoIssues(r *CryptoReport) []string {
	var issues []string
	if len(r.ECCurves) == 0 {
		issues = append(issues, "No ECC curves negotiated")
	}
	if len(r.WeakCurves) > 0 {
		issues = append(issues, fmt.Sprintf("Weak EC curves supported: %s", strings.Join(r.WeakCurves, ", ")))
	}
	if !r.ForwardSecrecy {
		issues = append(issues, "Forward secrecy not available")
	}
	if !r.PerfectForward {
		issues = append(issues, "Perfect forward secrecy (PFS) not achieved")
	}
	if !r.TicketKeyRotate {
		issues = append(issues, "Session ticket keys may not rotate between connections")
	}
	return issues
}

func calcCryptoScore(r *CryptoReport) int {
	s := 100
	if len(r.ECCurves) == 0 {
		s -= 25
	}
	if len(r.WeakCurves) > 0 {
		s -= 20
	}
	if !r.ForwardSecrecy {
		s -= 20
	}
	if !r.PerfectForward {
		s -= 15
	}
	if s < 0 {
		s = 0
	}
	return s
}

func printCryptoReport(r CryptoReport) {
	fmt.Printf("\n  [+] Cryptographic Analysis:")
	fmt.Printf("\n    %-24s : %v", "ECC Curves", len(r.ECCurves))
	if len(r.ECCurves) > 0 {
		fmt.Printf("\n    %-24s : %s", "  Curves", strings.Join(r.ECCurves, ", "))
	}
	fmt.Printf("\n    %-24s : %v", "Forward Secrecy", r.ForwardSecrecy)
	fmt.Printf("\n    %-24s : %v", "PFS Achieved", r.PerfectForward)
	fmt.Printf("\n    %-24s : %v", "Key Exchange", r.KeyExchange)
	fmt.Printf("\n    %-24s : %v", "Ticket Key Rotates", r.TicketKeyRotate)
	fmt.Printf("\n    %-24s : %d/100", "Crypto Score", r.Score)
	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] Crypto Issues (%d):", len(r.Issues))
		for _, iss := range r.Issues {
			fmt.Printf("\n      - %s", iss)
		}
	}
	fmt.Println()
}
