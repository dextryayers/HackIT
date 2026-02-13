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
	Ciphers         []string               `json:"ciphers"` // Simplified
	Vulnerabilities []string               `json:"vulnerabilities"`
	Grade           string                 `json:"grade"`
	Issues          []string               `json:"issues"`
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
		"subject":        cert.Subject.CommonName,
		"issuer":         cert.Issuer.CommonName,
		"valid_from":     cert.NotBefore.Format(time.RFC3339),
		"valid_to":       cert.NotAfter.Format(time.RFC3339),
		"days_remaining": int(time.Until(cert.NotAfter).Hours() / 24),
		"signature_alg":  cert.SignatureAlgorithm.String(),
	}

	if time.Now().After(cert.NotAfter) {
		res.Issues = append(res.Issues, "Certificate Expired")
	}
	if cert.SignatureAlgorithm.String() == "SHA1-RSA" || cert.SignatureAlgorithm.String() == "MD5-RSA" {
		res.Issues = append(res.Issues, "Weak Signature Algorithm")
	}

	// 2. Check Protocols
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
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err == nil {
			res.Protocols[protoNames[p]] = true
			conn.Close()
		} else {
			res.Protocols[protoNames[p]] = false
		}
	}

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
