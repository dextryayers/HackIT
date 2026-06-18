package main

import (
	"crypto/tls"
	"strings"
	"time"
)

func AuditTLS(targetURL string) *TLSInfo {
	state := GetTLSConnectionState(targetURL)
	if state == nil {
		return nil
	}

	info := &TLSInfo{
		Version:     tlsVersionString(state.Version),
		CipherSuite: tlsCipherSuiteString(state.CipherSuite),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CertificateSubject = cert.Subject.CommonName
		info.CertificateIssuer = cert.Issuer.CommonName
		info.CertificateExpiry = cert.NotAfter.Format(time.RFC3339)
		info.CertificateDaysLeft = int(cert.NotAfter.Sub(time.Now()).Hours() / 24)

		info.SelfSigned = cert.IsCA && strings.EqualFold(cert.Subject.CommonName, cert.Issuer.CommonName)

		if strings.HasPrefix(cert.Subject.CommonName, "*.") {
			info.WildcardCert = true
		}

		for _, name := range cert.DNSNames {
			if strings.HasPrefix(name, "*.") {
				info.WildcardCert = true
				break
			}
		}
	}

	return info
}

func AuditTLSSecurity(info *TLSInfo) []Finding {
	var findings []Finding

	if info == nil {
		return findings
	}

	if info.Version == "TLS 1.0" || info.Version == "TLS 1.1" {
		findings = append(findings, Finding{
			Header:         "TLS Version",
			Value:          info.Version,
			Description:    "Outdated TLS version - vulnerable to protocol downgrade attacks",
			Recommendation: "Disable TLS 1.0/1.1, enable TLS 1.2 and 1.3",
			Severity:       SeverityHigh,
			Category:       "TLS",
		})
	}

	if info.CertificateDaysLeft < 0 {
		findings = append(findings, Finding{
			Header:         "Certificate Expiry",
			Value:          info.CertificateExpiry,
			Description:    "SSL/TLS certificate has expired",
			Recommendation: "Renew the certificate immediately",
			Severity:       SeverityCritical,
			Category:       "TLS",
		})
	} else if info.CertificateDaysLeft < 14 {
		findings = append(findings, Finding{
			Header:         "Certificate Expiry",
			Value:          info.CertificateExpiry,
			Description:    "SSL/TLS certificate expires in less than 14 days",
			Recommendation: "Renew the certificate soon",
			Severity:       SeverityHigh,
			Category:       "TLS",
		})
	} else if info.CertificateDaysLeft < 30 {
		findings = append(findings, Finding{
			Header:         "Certificate Expiry",
			Value:          info.CertificateExpiry,
			Description:    "SSL/TLS certificate expires in less than 30 days",
			Recommendation: "Plan certificate renewal",
			Severity:       SeverityLow,
			Category:       "TLS",
		})
	}

	if info.SelfSigned {
		findings = append(findings, Finding{
			Header:         "Certificate Type",
			Value:          "Self-signed",
			Description:    "Self-signed certificate - not trusted by browsers",
			Recommendation: "Use a certificate from a trusted CA (Let's Encrypt, etc.)",
			Severity:       SeverityMedium,
			Category:       "TLS",
		})
	}

	if info.WildcardCert {
		findings = append(findings, Finding{
			Header:         "Certificate Type",
			Value:          "Wildcard",
			Description:    "Wildcard certificate (*.domain.com) - less secure than specific hostnames",
			Recommendation: "Use specific hostname certificates when possible",
			Severity:       SeverityLow,
			Category:       "TLS",
		})
	}

	return findings
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func tlsCipherSuiteString(id uint16) string {
	s := tls.CipherSuiteName(id)
	if s == "" {
		return "Unknown (0x" + strings.ToUpper(string(rune(id))) + ")"
	}
	return s
}

func isTLSModern(info *TLSInfo) bool {
	if info == nil {
		return false
	}
	return info.Version == "TLS 1.3" || info.Version == "TLS 1.2"
}
