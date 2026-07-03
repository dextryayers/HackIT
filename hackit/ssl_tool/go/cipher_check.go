package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type CipherSuite struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Bits   int    `json:"bits"`
	Secure bool   `json:"secure"`
	PFS    bool   `json:"pfs"`
	Reason string `json:"reason,omitempty"`
}

type CipherReport struct {
	Supported    []CipherSuite `json:"supported"`
	Secure       []CipherSuite `json:"secure"`
	Weak         []CipherSuite `json:"weak"`
	Insecure     []CipherSuite `json:"insecure"`
	TLS13Only    []CipherSuite `json:"tls_13_only"`
	PFSEnabled   bool          `json:"pfs_enabled"`
	PFSOnly      bool          `json:"pfs_only"`
	BestCipher   string        `json:"best_cipher"`
	WorstCipher  string        `json:"worst_cipher"`
	TotalCiphers int           `json:"total_ciphers"`
	Score        int           `json:"score"`
}

var cipherPriority = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	0xc008,  // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	0xc012,  // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
}

func classifyCipher(id uint16, name string) (secure bool, reason string) {
	if strings.Contains(name, "CHACHA20") || (strings.Contains(name, "GCM") && !strings.Contains(name, "RC4")) {
		return true, ""
	}
	if strings.Contains(name, "RC4") {
		return false, "RC4 is broken (deprecated by IETF)"
	}
	if strings.Contains(name, "3DES") || strings.Contains(name, "3DES_EDE") {
		return false, "3DES is vulnerable to Sweet32 attack (64-bit block)"
	}
	if strings.Contains(name, "CBC") {
		return true, "CBC mode - consider GCM/CHACHA20 for better security"
	}
	if strings.Contains(name, "NULL") {
		return false, "NULL encryption provides no confidentiality"
	}
	if strings.Contains(name, "EXPORT") || strings.Contains(name, "EXP") {
		return false, "Export-grade cipher (FREAK/Logjam vulnerability)"
	}
	if strings.Contains(name, "anon") || strings.Contains(name, "ADH") || strings.Contains(name, "AECDH") {
		return false, "Anonymous cipher provides no authentication"
	}
	if strings.Contains(name, "MD5") {
		return false, "MD5 is broken"
	}
	if strings.Contains(name, "IDEA") {
		return false, "IDEA cipher is obsolete (64-bit block)"
	}
	if strings.Contains(name, "SEED") {
		return true, ""
	}
	if strings.Contains(name, "CAMELLIA") {
		return true, ""
	}
	if strings.Contains(name, "AES") {
		return true, ""
	}
	return true, ""
}

func isPFS(id uint16) bool {
	return id != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 &&
		id != tls.TLS_RSA_WITH_AES_256_GCM_SHA384 &&
		id != tls.TLS_RSA_WITH_AES_128_CBC_SHA &&
		id != tls.TLS_RSA_WITH_AES_256_CBC_SHA &&
		id != tls.TLS_RSA_WITH_AES_128_CBC_SHA256 &&
		id != tls.TLS_RSA_WITH_RC4_128_SHA &&
		id != tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

func cipherBits(id uint16) int {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return 128
	case tls.TLS_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return 256
	case tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return 256
	default:
		return 0
	}
}

func scanCiphers(host string, port int, timeout time.Duration) CipherReport {
	var report CipherReport
	addr := fmt.Sprintf("%s:%d", host, port)
	seen := make(map[uint16]bool)

	shortTimeout := timeout
	if shortTimeout > 5*time.Second {
		shortTimeout = 5 * time.Second
	}

	for _, cipherID := range cipherPriority {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{cipherID},
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			ServerName:         host,
		}

		dialer := &net.Dialer{Timeout: shortTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err != nil {
			continue
		}
		state := conn.ConnectionState()
		negID := state.CipherSuite
		conn.Close()

		if seen[negID] {
			continue
		}
		seen[negID] = true

		name := tls.CipherSuiteName(negID)
		secure, reason := classifyCipher(negID, name)
		pfs := isPFS(negID)
		bits := cipherBits(negID)
		if bits == 0 {
			bits = 128
		}

		cs := CipherSuite{
			ID:     negID,
			Name:   name,
			Bits:   bits,
			Secure: secure,
			PFS:    pfs,
			Reason: reason,
		}
		report.Supported = append(report.Supported, cs)

		if secure {
			report.Secure = append(report.Secure, cs)
		} else if strings.Contains(reason, "broken") || strings.Contains(reason, "FREAK") || strings.Contains(reason, "confidentiality") || strings.Contains(reason, "NULL") || strings.Contains(reason, "authentication") {
			report.Insecure = append(report.Insecure, cs)
		} else {
			report.Weak = append(report.Weak, cs)
		}

		if pfs {
			report.PFSEnabled = true
		}
	}

	if !seen[tls.TLS_AES_128_GCM_SHA256] && !seen[tls.TLS_AES_256_GCM_SHA384] && !seen[tls.TLS_CHACHA20_POLY1305_SHA256] {
		for _, _ = range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
			config := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				ServerName:         host,
			}
			dialer := &net.Dialer{Timeout: shortTimeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
			if err != nil {
				continue
			}
			state := conn.ConnectionState()
			negID := state.CipherSuite
			conn.Close()

			if seen[negID] {
				continue
			}
			seen[negID] = true

			name := tls.CipherSuiteName(negID)
			bits := cipherBits(negID)
			if bits == 0 {
				bits = 256
			}

			cs := CipherSuite{
				ID:     negID,
				Name:   name,
				Bits:   bits,
				Secure: true,
				PFS:    true,
			}
			report.Supported = append(report.Supported, cs)
			report.Secure = append(report.Secure, cs)
			report.TLS13Only = append(report.TLS13Only, cs)
			report.PFSEnabled = true
		}
	}

	if len(report.Supported) > 0 {
		report.BestCipher = report.Supported[0].Name
		report.WorstCipher = report.Supported[len(report.Supported)-1].Name
	}
	report.TotalCiphers = len(report.Supported)

	pfsOnly := true
	for _, c := range report.Supported {
		if c.Name != "" && !c.PFS {
			pfsOnly = false
			break
		}
	}
	report.PFSOnly = pfsOnly

	score := 100
	for range report.Weak {
		score -= 10
	}
	for range report.Insecure {
		score -= 25
	}
	if !report.PFSEnabled {
		score -= 20
	}
	if report.PFSOnly {
		score += 10
	}
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

func scanWeakCiphersLegacy(host string, port int, timeout time.Duration) CipherReport {
	var report CipherReport
	addr := fmt.Sprintf("%s:%d", host, port)
	seen := make(map[uint16]bool)

	legacyTestSuites := []struct {
		id     uint16
		name   string
		minV   uint16
		maxV   uint16
		secure bool
		reason string
	}{
		{tls.TLS_RSA_WITH_RC4_128_SHA, "RC4-128-SHA (TLS 1.0)", tls.VersionTLS10, tls.VersionTLS12, false, "RC4 is broken"},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "3DES-EDE-CBC-SHA", tls.VersionTLS10, tls.VersionTLS12, false, "Sweet32 vulnerable"},
	}

	for _, suite := range legacyTestSuites {
		if seen[suite.id] {
			continue
		}
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{suite.id},
			MinVersion:         suite.minV,
			MaxVersion:         suite.maxV,
			ServerName:         host,
		}
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err != nil {
			continue
		}
		state := conn.ConnectionState()
		negID := state.CipherSuite
		conn.Close()
		if seen[negID] {
			continue
		}
		seen[negID] = true
		cs := CipherSuite{ID: negID, Name: suite.name, Secure: false, Reason: suite.reason}
		report.Supported = append(report.Supported, cs)
		report.Insecure = append(report.Insecure, cs)
	}

	return report
}

func printCipherReport(r CipherReport) {
	fmt.Printf("\n  [+] Cipher Suite Analysis:")
	fmt.Printf("\n    %-24s : %d suites", "Total Ciphers", r.TotalCiphers)
	fmt.Printf("\n    %-24s : %v", "PFS Enabled", r.PFSEnabled)
	fmt.Printf("\n    %-24s : %v", "PFS Only", r.PFSOnly)
	fmt.Printf("\n    %-24s : %d/100", "Cipher Score", r.Score)
	if r.BestCipher != "" {
		fmt.Printf("\n    %-24s : %s", "Best Cipher", r.BestCipher)
	}
	if r.WorstCipher != "" {
		fmt.Printf("\n    %-24s : %s", "Worst Cipher", r.WorstCipher)
	}

	if len(r.Secure) > 0 {
		fmt.Printf("\n\n    [+] Secure Ciphers (%d):", len(r.Secure))
		for _, c := range r.Secure {
			pfsMark := ""
			if c.PFS {
				pfsMark = " [PFS]"
			}
			fmt.Printf("\n       \033[32m[+] %s (%d-bit)%s\033[0m", c.Name, c.Bits, pfsMark)
		}
	}
	if len(r.Weak) > 0 {
		fmt.Printf("\n\n    [!] Weak Ciphers (%d):", len(r.Weak))
		for _, c := range r.Weak {
			fmt.Printf("\n       \033[33m[-] %s (%d-bit)\033[0m", c.Name, c.Bits)
		}
	}
	if len(r.Insecure) > 0 {
		fmt.Printf("\n\n    [!!] Insecure Ciphers (%d):", len(r.Insecure))
		for _, c := range r.Insecure {
			fmt.Printf("\n       \033[31m[!] %s (%d-bit)", c.Name, c.Bits)
			if c.Reason != "" {
				fmt.Printf(" - %s", c.Reason)
			}
			fmt.Printf("\033[0m")
		}
	}
	fmt.Println()
}
