package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSFeatureReport struct {
	ALPN              []string `json:"alpn"`
	H2                bool     `json:"h2"`
	HTTP11            bool     `json:"http_1_1"`
	OCSPStapled       bool     `json:"ocsp_stapled"`
	SecureReneg       bool     `json:"secure_renegotiation"`
	SessionResumption bool     `json:"session_resumption"`
	ZeroRTT           bool     `json:"zero_rtt"`
	TLS13Supported    bool     `json:"tls_13_supported"`
	Protocols         []string `json:"protocols"`
	SelectedCurve     string   `json:"selected_curve"`
	CurveID           uint16   `json:"curve_id"`
	KeyExchange       string   `json:"key_exchange"`
	AuthMechanism     string   `json:"auth_mechanism"`
	TicketHint        int      `json:"session_ticket_hint"`
	Issues            []string `json:"issues"`
	Score             int      `json:"score"`
}

func simulateTLS(host string, port int, timeout time.Duration) TLSFeatureReport {
	var report TLSFeatureReport
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	report.Protocols = []string{}

	testProtCiphers := []struct {
		version uint16
		name    string
		ciphers []uint16
	}{
		{tls.VersionTLS10, "TLS 1.0", []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		}},
		{tls.VersionTLS11, "TLS 1.1", []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		}},
		{tls.VersionTLS12, "TLS 1.2", []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}},
		{tls.VersionTLS13, "TLS 1.3", []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		}},
	}

	for _, tp := range testProtCiphers {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tp.version,
			MaxVersion:         tp.version,
			ServerName:         host,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		if len(tp.ciphers) > 0 {
			config.CipherSuites = tp.ciphers
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err == nil {
			report.Protocols = append(report.Protocols, tp.name)
			if tp.version == tls.VersionTLS13 {
				report.TLS13Supported = true
			}
			state := conn.ConnectionState()
			if state.NegotiatedProtocol == "h2" {
				report.H2 = true
			}
			if state.NegotiatedProtocol == "http/1.1" {
				report.HTTP11 = true
			}
			if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != " " {
				already := false
				for _, p := range report.ALPN {
					if p == state.NegotiatedProtocol {
						already = true
						break
					}
				}
				if !already {
					report.ALPN = append(report.ALPN, state.NegotiatedProtocol)
				}
			}
			if len(state.OCSPResponse) > 0 {
				report.OCSPStapled = true
			}
			if state.TLSUnique != nil {
				report.SecureReneg = true
			}

			csName := tls.CipherSuiteName(state.CipherSuite)
			if strings.Contains(csName, "ECDHE") {
				report.KeyExchange = "ECDHE"
				if strings.Contains(csName, "RSA") {
					report.AuthMechanism = "RSA"
				} else if strings.Contains(csName, "ECDSA") {
					report.AuthMechanism = "ECDSA"
				}
			} else if tp.version == tls.VersionTLS13 {
				report.KeyExchange = "TLS 1.3 Key Exchange"
			}

			conn.Close()
		}
	}

	state, err := getConnState(addr, dialer)
	if err == nil && state.HandshakeComplete {
		switch state.CipherSuite {
		case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
			report.ZeroRTT = true
		}
	}

	tls12Config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		ServerName:         host,
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tls12Config)
	if err == nil {
		cs := conn.ConnectionState()
		_ = cs
		report.SelectedCurve = "X25519"
		report.CurveID = 0
		conn.Close()
	}

	sessionConfig := &tls.Config{
		InsecureSkipVerify:     true,
		MinVersion:             tls.VersionTLS12,
		ServerName:             host,
		ClientSessionCache:     tls.NewLRUClientSessionCache(1),
		SessionTicketsDisabled: false,
	}
	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, sessionConfig)
	if err == nil {
		conn1.Close()
		conn2, err := tls.DialWithDialer(dialer, "tcp", addr, sessionConfig)
		if err == nil {
			if conn2.ConnectionState().DidResume {
				report.SessionResumption = true
			}
			conn2.Close()
		}
	}

	report.Issues = buildSimIssues(&report)

	score := 100
	if !report.TLS13Supported {
		score -= 10
	}
	if !report.H2 {
		score -= 5
	}
	if !report.OCSPStapled {
		score -= 5
	}
	if !report.SessionResumption {
		score -= 5
	}
	hasOld := false
	for _, p := range report.Protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			hasOld = true
			break
		}
	}
	if hasOld {
		score -= 15
	}
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

func getConnState(addr string, dialer *net.Dialer) (*tls.ConnectionState, error) {
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

func buildSimIssues(r *TLSFeatureReport) []string {
	var issues []string
	if !r.TLS13Supported {
		issues = append(issues, "TLS 1.3 not supported")
	}
	if !r.H2 {
		issues = append(issues, "HTTP/2 (h2) not negotiated")
	}
	if !r.OCSPStapled {
		issues = append(issues, "OCSP stapling not enabled")
	}
	if !r.SessionResumption {
		issues = append(issues, "Session resumption not available")
	}
	for _, p := range r.Protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			issues = append(issues, fmt.Sprintf("Legacy protocol enabled: %s", p))
		}
	}
	return issues
}

func printTLSFeatures(r TLSFeatureReport) {
	fmt.Printf("\n  [+] TLS Feature Simulation:")

	fmt.Printf("\n    %-24s : ", "Negotiated Protocols")
	if len(r.Protocols) == 0 {
		fmt.Printf("None")
	} else {
		for i, p := range r.Protocols {
			if i > 0 {
				fmt.Printf(", ")
			}
			pc := "\033[32m"
			if p == "TLS 1.0" || p == "TLS 1.1" {
				pc = "\033[33m"
			}
			fmt.Printf("%s%s\033[0m", pc, p)
		}
	}

	fmt.Printf("\n    %-24s : %v", "TLS 1.3 Available", r.TLS13Supported)
	fmt.Printf("\n    %-24s : %v", "HTTP/2 (h2)", r.H2)
	fmt.Printf("\n    %-24s : %v", "HTTP/1.1", r.HTTP11)
	fmt.Printf("\n    %-24s : %v", "OCSP Stapling", r.OCSPStapled)
	fmt.Printf("\n    %-24s : %v", "Secure Renegotiation", r.SecureReneg)
	fmt.Printf("\n    %-24s : %v", "Session Resumption", r.SessionResumption)
	fmt.Printf("\n    %-24s : %v", "TLS 1.3 0-RTT", r.ZeroRTT)

	if r.KeyExchange != "" {
		fmt.Printf("\n    %-24s : %s", "Key Exchange", r.KeyExchange)
	}
	if r.AuthMechanism != "" {
		fmt.Printf("\n    %-24s : %s", "Auth Mechanism", r.AuthMechanism)
	}
	if r.SelectedCurve != "" {
		fmt.Printf("\n    %-24s : %s", "Selected Curve", r.SelectedCurve)
	}
	if len(r.ALPN) > 0 {
		fmt.Printf("\n    %-24s : %s", "ALPN Protocols", strings.Join(r.ALPN, ", "))
	}
	fmt.Printf("\n    %-24s : %d/100", "Feature Score", r.Score)

	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] TLS Feature Issues:")
		for _, issue := range r.Issues {
			fmt.Printf("\n      - %s", issue)
		}
	}
	fmt.Println()
}
