package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type SSLResult struct {
	CN                string   `json:"cn"`
	SANs              []string `json:"sans"`
	Issuer            string   `json:"issuer"`
	IssuerOrg         string   `json:"issuer_org"`
	ValidityFrom      string   `json:"validity_from"`
	ValidityTo        string   `json:"validity_to"`
	DaysRemaining     int      `json:"days_remaining"`
	Serial            string   `json:"serial"`
	Version           int      `json:"version"`
	TLSVersion        string   `json:"tls_version"`
	CipherSuite       string   `json:"cipher_suite"`
	PublicKey         string   `json:"public_key"`
	PublicKeySize     int      `json:"public_key_size"`
	SigAlgorithm      string   `json:"sig_algorithm"`
	FingerprintSHA1   string   `json:"fingerprint_sha1"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	SelfSigned        bool     `json:"self_signed"`
	Expired           bool     `json:"expired"`
	ChainLength       int      `json:"chain_length"`
	ChainIssuers      []string `json:"chain_issuers"`
	OCSPServer        []string `json:"ocsp_server"`
	IssuerURL         []string `json:"issuer_url"`
	KeyUsage          []string `json:"key_usage,omitempty"`
	ExtKeyUsage       []string `json:"ext_key_usage,omitempty"`
	CRLDistribution   []string `json:"crl_distribution,omitempty"`
	IsCA              bool     `json:"is_ca"`
	MaxPathLen        int      `json:"max_path_len,omitempty"`
	PolicyIdentifiers []string `json:"policy_ids,omitempty"`
	PermittedDomains  []string `json:"permitted_domains,omitempty"`
	ExcludedDomains   []string `json:"excluded_domains,omitempty"`
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

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second, Resolver: dnsResolver},
		"tcp", host,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}

	cert := state.PeerCertificates[0]

	sha1Fingerprint := sha1.Sum(cert.Raw)
	sha256Fingerprint := sha256.Sum256(cert.Raw)

	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	expired := time.Now().After(cert.NotAfter)
	selfSigned := cert.Subject.CommonName == cert.Issuer.CommonName

	keyType := "Unknown"
	keySize := 0
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = "RSA"
		keySize = k.N.BitLen()
	case *ecdsa.PublicKey:
		keyType = "ECDSA"
		keySize = k.Curve.Params().BitSize
	case *ed25519.PublicKey:
		keyType = "Ed25519"
		keySize = 256
	}

	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	// TLS version string
	tlsVer := fmt.Sprintf("TLS 1.%d", state.Version-tls.VersionTLS10)
	if state.Version == tls.VersionTLS13 {
		tlsVer = "TLS 1.3"
	}

	// Cipher suite name
	cipherName := tls.CipherSuiteName(state.CipherSuite)

	// Chain issuers
	chainIssuers := []string{}
	for _, c := range state.PeerCertificates {
		chainIssuers = append(chainIssuers, c.Issuer.CommonName)
	}

	// Key usage strings
	keyUsageStrs := []string{}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 { keyUsageStrs = append(keyUsageStrs, "Digital Signature") }
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 { keyUsageStrs = append(keyUsageStrs, "Non-Repudiation") }
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 { keyUsageStrs = append(keyUsageStrs, "Key Encipherment") }
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 { keyUsageStrs = append(keyUsageStrs, "Data Encipherment") }
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 { keyUsageStrs = append(keyUsageStrs, "Key Agreement") }
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 { keyUsageStrs = append(keyUsageStrs, "Certificate Sign") }
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 { keyUsageStrs = append(keyUsageStrs, "CRL Sign") }
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 { keyUsageStrs = append(keyUsageStrs, "Encipher Only") }
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 { keyUsageStrs = append(keyUsageStrs, "Decipher Only") }

	// Extended key usage strings
	extKeyUsageStrs := []string{}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth: extKeyUsageStrs = append(extKeyUsageStrs, "Server Auth")
		case x509.ExtKeyUsageClientAuth: extKeyUsageStrs = append(extKeyUsageStrs, "Client Auth")
		case x509.ExtKeyUsageCodeSigning: extKeyUsageStrs = append(extKeyUsageStrs, "Code Signing")
		case x509.ExtKeyUsageEmailProtection: extKeyUsageStrs = append(extKeyUsageStrs, "Email Protection")
		case x509.ExtKeyUsageTimeStamping: extKeyUsageStrs = append(extKeyUsageStrs, "Timestamping")
		case x509.ExtKeyUsageOCSPSigning: extKeyUsageStrs = append(extKeyUsageStrs, "OCSP Signing")
		case x509.ExtKeyUsageAny: extKeyUsageStrs = append(extKeyUsageStrs, "Any Purpose")
		}
	}

	// Name constraints
	var permittedDomains, excludedDomains []string
	if cert.PermittedDNSDomainsCritical || len(cert.PermittedDNSDomains) > 0 {
		permittedDomains = cert.PermittedDNSDomains
	}
	if len(cert.ExcludedDNSDomains) > 0 {
		excludedDomains = cert.ExcludedDNSDomains
	}

	// Policy identifiers
	policyIDs := []string{}
	for _, policy := range cert.PolicyIdentifiers {
		policyIDs = append(policyIDs, policy.String())
	}

	res := &SSLResult{
		CN:                cert.Subject.CommonName,
		SANs:              cert.DNSNames,
		Issuer:            cert.Issuer.CommonName,
		IssuerOrg:         issuerOrg,
		ValidityFrom:      cert.NotBefore.Format("2006-01-02"),
		ValidityTo:        cert.NotAfter.Format("2006-01-02"),
		DaysRemaining:     daysRemaining,
		Serial:            cert.SerialNumber.String(),
		Version:           cert.Version,
		TLSVersion:        tlsVer,
		CipherSuite:       cipherName,
		PublicKey:         keyType,
		PublicKeySize:     keySize,
		SigAlgorithm:      cert.SignatureAlgorithm.String(),
		FingerprintSHA1:   fmt.Sprintf("%X", sha1Fingerprint),
		FingerprintSHA256: fmt.Sprintf("%X", sha256Fingerprint),
		SelfSigned:        selfSigned,
		Expired:           expired,
		ChainLength:       len(state.PeerCertificates),
		ChainIssuers:      chainIssuers,
		OCSPServer:        cert.OCSPServer,
		IssuerURL:         cert.IssuingCertificateURL,
		KeyUsage:          keyUsageStrs,
		ExtKeyUsage:       extKeyUsageStrs,
		CRLDistribution:   cert.CRLDistributionPoints,
		IsCA:              cert.IsCA,
		MaxPathLen:        cert.MaxPathLen,
		PolicyIdentifiers: policyIDs,
		PermittedDomains:  permittedDomains,
		ExcludedDomains:   excludedDomains,
	}

	return res, nil
}
