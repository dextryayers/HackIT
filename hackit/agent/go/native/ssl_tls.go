package native

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type SSLResult struct {
	Issuer          string
	Subject         string
	ExpiryDate      time.Time
	DaysUntilExpy   int
	TLSVersion      string
	IsExpired       bool
	Vulnerabilities []string
}

// AuditSSL audits the SSL/TLS configuration of an HTTPS port
func AuditSSL(ip string, port int) *SSLResult {
	target := fmt.Sprintf("%s:%d", ip, port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // We still want to see the cert even if it's invalid
	})

	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]

	result := &SSLResult{
		Issuer:        cert.Issuer.Organization[0] + " " + cert.Issuer.CommonName,
		Subject:       cert.Subject.CommonName,
		ExpiryDate:    cert.NotAfter,
		DaysUntilExpy: int(time.Until(cert.NotAfter).Hours() / 24),
		IsExpired:     time.Now().After(cert.NotAfter),
	}

	// Map TLS Version
	switch state.Version {
	case tls.VersionTLS10:
		result.TLSVersion = "TLS 1.0"
		result.Vulnerabilities = append(result.Vulnerabilities, "Obsolete TLS 1.0 used (Vulnerable to BEAST, POODLE)")
	case tls.VersionTLS11:
		result.TLSVersion = "TLS 1.1"
		result.Vulnerabilities = append(result.Vulnerabilities, "Obsolete TLS 1.1 used")
	case tls.VersionTLS12:
		result.TLSVersion = "TLS 1.2"
	case tls.VersionTLS13:
		result.TLSVersion = "TLS 1.3"
	default:
		result.TLSVersion = "Unknown/Legacy SSL"
		result.Vulnerabilities = append(result.Vulnerabilities, "Legacy SSL version used")
	}

	if result.IsExpired {
		result.Vulnerabilities = append(result.Vulnerabilities, "SSL Certificate is Expired")
	} else if result.DaysUntilExpy < 30 {
		result.Vulnerabilities = append(result.Vulnerabilities, fmt.Sprintf("SSL Certificate expires soon (%d days)", result.DaysUntilExpy))
	}

	// Check if it's a self-signed certificate
	if cert.Issuer.CommonName == cert.Subject.CommonName {
		result.Vulnerabilities = append(result.Vulnerabilities, "Self-signed certificate in use")
	}

	return result
}
