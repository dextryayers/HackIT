package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSRealInfo struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Expiry      string   `json:"expiry"`
	ValidFrom   string   `json:"valid_from"`
	DNSNames    []string `json:"dns_names"`
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
}

func GetRealTLSInfo(domain string) *TLSRealInfo {
	host := domain
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second, Resolver: dnsResolver}, "tcp", host, conf)
	if err != nil {
		return &TLSRealInfo{Issuer: "Unknown (No HTTPS)", Expiry: "N/A"}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &TLSRealInfo{Issuer: "Unknown (No cert)", Expiry: "N/A"}
	}

	cert := state.PeerCertificates[0]

	versionStr := fmt.Sprintf("TLS %d.%d", state.Version/256, state.Version%256)
	switch state.Version {
	case tls.VersionTLS10:
		versionStr = "TLS 1.0"
	case tls.VersionTLS11:
		versionStr = "TLS 1.1"
	case tls.VersionTLS12:
		versionStr = "TLS 1.2"
	case tls.VersionTLS13:
		versionStr = "TLS 1.3"
	}

	cipherName := tls.CipherSuiteName(state.CipherSuite)

	return &TLSRealInfo{
		Issuer:      cert.Issuer.CommonName,
		Subject:     cert.Subject.CommonName,
		Expiry:      cert.NotAfter.Format("2006-01-02"),
		ValidFrom:   cert.NotBefore.Format("2006-01-02"),
		DNSNames:    cert.DNSNames,
		Version:     versionStr,
		CipherSuite: cipherName,
	}
}
