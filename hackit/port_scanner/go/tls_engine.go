package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type TlsInfo struct {
	TLSVersion         string   `json:"tls_version"`
	CipherSuite        string   `json:"cipher_suite"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	SHA256Fingerprint  string   `json:"sha256_fingerprint"`
	ValidFrom          string   `json:"valid_from"`
	ValidTo            string   `json:"valid_to"`
	SANs               []string `json:"sans"`
	IsSelfSigned       bool     `json:"is_self_signed"`
	KeySize            int      `json:"key_size"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

var tlsVersionMap = map[uint16]string{
	tls.VersionTLS10: "TLSv1.0",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

func ScanTLS(host string, port int, timeout time.Duration) (*TlsInfo, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(rawConn, tlsConf)
	tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.Handshake(); err != nil {
		// Fallback: try with TLS 1.0-1.1 allowed
		rawConn.Close()
		rawConn2, err2 := dialer.DialContext(ctx, "tcp", addr)
		if err2 != nil {
			return nil, fmt.Errorf("tcp dial failed: %w", err2)
		}
		defer rawConn2.Close()

		tlsConf2 := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
		tlsConn2 := tls.Client(rawConn2, tlsConf2)
		tlsConn2.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn2.Handshake(); err != nil {
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		tlsConn = tlsConn2
	}

	state := tlsConn.ConnectionState()
	tlsConn.Close()

	info := &TlsInfo{}

	if v, ok := tlsVersionMap[state.Version]; ok {
		info.TLSVersion = v
	} else {
		info.TLSVersion = fmt.Sprintf("0x%04x", state.Version)
	}

	if suite := tls.CipherSuiteName(state.CipherSuite); suite != "" {
		info.CipherSuite = suite
	} else {
		info.CipherSuite = fmt.Sprintf("0x%04x", state.CipherSuite)
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.SerialNumber = cert.SerialNumber.String()
		info.ValidFrom = cert.NotBefore.Format(time.RFC3339)
		info.ValidTo = cert.NotAfter.Format(time.RFC3339)
		info.SANs = append(info.SANs, cert.DNSNames...)
		info.SANs = append(info.SANs, cert.EmailAddresses...)
		for _, ip := range cert.IPAddresses {
			info.SANs = append(info.SANs, ip.String())
		}
		info.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()

		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			info.SignatureAlgorithm = "RSA"
		case x509.ECDSA:
			info.SignatureAlgorithm = "ECDSA"
		case x509.Ed25519:
			info.SignatureAlgorithm = "Ed25519"
		case x509.DSA:
			info.SignatureAlgorithm = "DSA"
		}

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			info.KeySize = pub.N.BitLen()
		case *ecdsa.PublicKey:
			info.KeySize = pub.Curve.Params().BitSize
		case ed25519.PublicKey:
			info.KeySize = 256
		}

		derBytes := cert.Raw
		if len(derBytes) > 0 {
			h := sha256.Sum256(derBytes)
			info.SHA256Fingerprint = hex.EncodeToString(h[:])
		}
	}

	return info, nil
}

func GetSupportedCiphers(host string, port int) []string {
	var supported []string

	commonCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	for _, cipher := range commonCiphers {
		conf := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{cipher},
		}

		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			continue
		}

		tlsConn := tls.Client(conn, conf)
		tlsConn.SetDeadline(time.Now().Add(3 * time.Second))

		if err := tlsConn.Handshake(); err == nil {
			supported = append(supported, tls.CipherSuiteName(cipher))
		}
		tlsConn.Close()
		conn.Close()
	}

	return supported
}

func CheckSSLvulnerabilities(info *TlsInfo) []string {
	var vulns []string
	low := strings.ToLower(info.TLSVersion)

	if low == "tlsv1.0" {
		vulns = append(vulns, "POODLE (CVE-2014-3566) — TLS 1.0 CBC padding oracle attack")
		vulns = append(vulns, "BEAST (CVE-2011-3389) — TLS 1.0 CBC chosen-plaintext attack")
	}
	if low == "tlsv1.1" {
		vulns = append(vulns, "BEAST (CVE-2011-3389) — TLS 1.1 CBC chosen-plaintext attack")
	}

	if strings.Contains(low, "tlsv1.0") || strings.Contains(low, "tlsv1.1") {
		vulns = append(vulns, "Deprecated TLS version — should use TLS 1.2 or higher")
	}

	csLow := strings.ToLower(info.CipherSuite)
	if strings.Contains(csLow, "cbc") && (strings.Contains(low, "tlsv1.0") || strings.Contains(low, "tlsv1.1")) {
		vulns = append(vulns, "Lucky13 (CVE-2013-0169) — CBC padding oracle timing attack")
	}

	if strings.Contains(csLow, "rc4") {
		vulns = append(vulns, "RC4 cipher — weak, allows plaintext recovery (CVE-2013-2566)")
	}

	if strings.Contains(csLow, "des") || strings.Contains(csLow, "3des") {
		vulns = append(vulns, "Sweet32 (CVE-2016-2183) — 64-bit block cipher collision attack")
	}

	if strings.Contains(csLow, "export") || strings.Contains(csLow, "exp") {
		vulns = append(vulns, "Export-grade cipher — FREAK attack (CVE-2015-0204)")
	}

	if strings.Contains(csLow, "anon") || strings.Contains(csLow, "dh_anon") {
		vulns = append(vulns, "Anonymous Diffie-Hellman — no authentication, MITM possible")
	}

	if strings.Contains(csLow, "null") {
		vulns = append(vulns, "NULL cipher — no encryption, plaintext exposed")
	}

	if info.IsSelfSigned {
		vulns = append(vulns, "Self-signed certificate — no trust chain verification")
	}

	if info.KeySize < 2048 && info.KeySize > 0 {
		vulns = append(vulns, fmt.Sprintf("Weak key size (%d bits) — should be ≥2048 bits", info.KeySize))
	}

	return vulns
}

var _ = md5.Sum // quiet linter; available for fingerprinting if needed

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
