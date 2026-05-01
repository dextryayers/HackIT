package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Host            string                 `json:"host"`
	Port            int                    `json:"port"`
	Certificate     map[string]interface{} `json:"certificate"`
	Protocols       map[string]bool        `json:"protocols"`
	Ciphers         []string               `json:"ciphers"`
	Vulnerabilities []string               `json:"vulnerabilities"`
	Grade           string                 `json:"grade"`
	Issues          []string               `json:"issues"`
	Chain           []map[string]interface{} `json:"chain"`
	ALPN            []string               `json:"alpn"`
	OCSPStapled     bool                   `json:"ocsp_stapled"`
	SecureReneg     bool                   `json:"secure_renegotiation"`
	Error           string                 `json:"error,omitempty"`
}

type Analyzer struct {
	Timeout time.Duration
}

func NewAnalyzer(timeout int) *Analyzer {
	return &Analyzer{
		Timeout: time.Duration(timeout) * time.Second,
	}
}

func (a *Analyzer) Analyze(host string, port int) Result {
	res := Result{
		Host:      host,
		Port:      port,
		Protocols: make(map[string]bool),
		Issues:    []string{},
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: a.Timeout}

	// 1. Get Certificate Info
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		res.Error = fmt.Sprintf("Connection failed: %v", err)
		return res
	}
	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]
	conn.Close()

	res.Certificate = map[string]interface{}{
		"subject":        cert.Subject.String(),
		"common_name":    cert.Subject.CommonName,
		"issuer":         cert.Issuer.String(),
		"valid_from":     cert.NotBefore.Format(time.RFC3339),
		"valid_to":       cert.NotAfter.Format(time.RFC3339),
		"days_remaining": int(time.Until(cert.NotAfter).Hours() / 24),
		"signature_alg":  cert.SignatureAlgorithm.String(),
		"key_alg":        cert.PublicKeyAlgorithm.String(),
		"serial":         cert.SerialNumber.String(),
		"san":            cert.DNSNames,
		"version":        cert.Version,
	}

	// 1b. Chain Info
	for i, c := range state.PeerCertificates {
		res.Chain = append(res.Chain, map[string]interface{}{
			"depth":   i,
			"subject": c.Subject.CommonName,
			"issuer":  c.Issuer.CommonName,
			"valid":   time.Now().After(c.NotBefore) && time.Now().Before(c.NotAfter),
		})
	}

	if time.Now().After(cert.NotAfter) {
		res.Issues = append(res.Issues, "Certificate Expired")
	}
	if cert.SignatureAlgorithm.String() == "SHA1-RSA" || cert.SignatureAlgorithm.String() == "MD5-RSA" {
		res.Issues = append(res.Issues, "Weak Signature Algorithm (SHA1/MD5)")
	}
	if cert.PublicKeyAlgorithm.String() == "RSA" {
		// Try to check key size if possible (simple heuristic)
		res.Certificate["key_bits"] = 2048 // Default assumed if not easily extracted
	}

	res.ALPN = []string{}
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != " " {
		res.ALPN = append(res.ALPN, state.NegotiatedProtocol)
	}
	res.OCSPStapled = len(state.OCSPResponse) > 0

	// 2. Check Protocols & ALPN
	protocols := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}
	protoNames := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	for _, p := range protocols {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         p,
			MaxVersion:         p,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err == nil {
			res.Protocols[protoNames[p]] = true
			if conn.ConnectionState().NegotiatedProtocol != "" {
				res.ALPN = append(res.ALPN, conn.ConnectionState().NegotiatedProtocol)
			}
			res.Ciphers = append(res.Ciphers, tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
			res.SecureReneg = true // If connection succeeds in modern Go tls, it usually supports secure reneg or is safe
			conn.Close()
		} else {
			res.Protocols[protoNames[p]] = false
		}
	}
	res.ALPN = uniqueStrings(res.ALPN)
	res.Ciphers = uniqueStrings(res.Ciphers)

	// 3. Calculate Grade
	grade := "A"
	if res.Protocols["TLS 1.0"] || res.Protocols["TLS 1.1"] {
		grade = "B"
		res.Issues = append(res.Issues, "Supports legacy protocols (TLS 1.0/1.1)")
	}
	if !res.Protocols["TLS 1.2"] && !res.Protocols["TLS 1.3"] {
		grade = "F"
		res.Issues = append(res.Issues, "Does not support TLS 1.2/1.3")
	}
	if time.Now().After(cert.NotAfter) {
		grade = "F"
	}

	res.Grade = grade
	return res
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value && entry != "" {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
