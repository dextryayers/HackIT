package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type SSLResult struct {
	CN                string   `json:"cn"`
	SANs              []string `json:"sans"`
	Issuer            string   `json:"issuer"`
	ValidityFrom      string   `json:"validity_from"`
	ValidityTo        string   `json:"validity_to"`
	Serial            string   `json:"serial"`
	PublicKey         string   `json:"public_key"`
	SigAlgorithm      string   `json:"sig_algorithm"`
	FingerprintSHA1   string   `json:"fingerprint_sha1"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
}

func AnalyzeSSL(target string) (*SSLResult, error) {
	host := target
	if strings.Contains(host, "://") {
		host = strings.Split(host, "://")[1]
	}
	host = strings.Split(host, "/")[0]

	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	
	sha1Fingerprint := sha1.Sum(cert.Raw)
	sha256Fingerprint := sha256.Sum256(cert.Raw)

	res := &SSLResult{
		CN:           cert.Subject.CommonName,
		SANs:         cert.DNSNames,
		Issuer:       cert.Issuer.CommonName,
		ValidityFrom: cert.NotBefore.Format("2006-01-02"),
		ValidityTo:   cert.NotAfter.Format("2006-01-02"),
		Serial:       cert.SerialNumber.String(),
		PublicKey:    fmt.Sprintf("%T (%d bits)", cert.PublicKey, getPublicKeySize(cert.PublicKey)),
		SigAlgorithm: cert.SignatureAlgorithm.String(),
		FingerprintSHA1:   fmt.Sprintf("%X", sha1Fingerprint),
		FingerprintSHA256: fmt.Sprintf("%X", sha256Fingerprint),
	}

	return res, nil
}

func getPublicKeySize(pub interface{}) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}
