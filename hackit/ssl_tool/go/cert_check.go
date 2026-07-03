package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type CertReport struct {
	IssuerOrg         string   `json:"issuer_org"`
	IssuerCN          string   `json:"issuer_cn"`
	SubjectCN         string   `json:"subject_cn"`
	SubjectOrg        string   `json:"subject_org"`
	SubjectCountry    string   `json:"subject_country"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	DaysRemaining     int      `json:"days_remaining"`
	Expired           bool     `json:"expired"`
	ExpiresSoon       bool     `json:"expires_soon"`
	KeyType           string   `json:"key_type"`
	KeyBits           int      `json:"key_bits"`
	SigAlg            string   `json:"sig_alg"`
	Serial            string   `json:"serial"`
	SerialBits        int      `json:"serial_bits"`
	Version           int      `json:"version"`
	SANs              []string `json:"sans"`
	SanCount          int      `json:"san_count"`
	Wildcard          bool     `json:"wildcard"`
	IsCA              bool     `json:"is_ca"`
	MaxPathLen        int      `json:"max_path_len"`
	ChainDepth        int      `json:"chain_depth"`
	ChainValid        bool     `json:"chain_valid"`
	SelfSigned        bool     `json:"self_signed"`
	SCTCount          int      `json:"sct_count"`
	SCTPresent        bool     `json:"sct_present"`
	KeyStrength       string   `json:"key_strength"`
	Issues            []string `json:"issues"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	FingerprintSHA1   string   `json:"fingerprint_sha1"`
	SubjectKeyID      string   `json:"subject_key_id"`
	AuthorityKeyID    string   `json:"authority_key_id"`
	IsEV              bool     `json:"is_ev"`
	OCSPMustStaple    bool     `json:"ocsp_must_staple"`
	CRLDPs            []string `json:"crl_dps"`
	OCSPURLs          []string `json:"ocsp_urls"`
	CAIssuerURLs      []string `json:"ca_issuer_urls"`
	KeyUsage          []string `json:"key_usage"`
	ExtKeyUsage       []string `json:"ext_key_usage"`
	CertPolicy        []string `json:"certificate_policies"`
	Revoked           bool     `json:"revoked"`
}

func analyzeCertificate(cert *x509.Certificate, chain []*x509.Certificate) CertReport {
	r := CertReport{
		SubjectCN:  cert.Subject.CommonName,
		SubjectOrg: strings.Join(cert.Subject.Organization, ", "),
		SubjectCountry: strings.Join(cert.Subject.Country, ", "),
		IssuerCN:   cert.Issuer.CommonName,
		IssuerOrg:  strings.Join(cert.Issuer.Organization, ", "),
		NotBefore:  cert.NotBefore.Format(time.RFC3339),
		NotAfter:   cert.NotAfter.Format(time.RFC3339),
		Version:    cert.Version,
		Serial:     cert.SerialNumber.String(),
	}

	r.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	r.Expired = time.Now().After(cert.NotAfter)
	r.ExpiresSoon = !r.Expired && r.DaysRemaining < 30

	r.SANs = append([]string{}, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		found := false
		for _, s := range cert.DNSNames {
			if s == cert.Subject.CommonName {
				found = true
				break
			}
		}
		if !found && !strings.HasPrefix(cert.Subject.CommonName, "*") {
			r.SANs = append(r.SANs, cert.Subject.CommonName)
		}
	}
	r.SanCount = len(r.SANs)

	for _, san := range r.SANs {
		if strings.HasPrefix(san, "*") {
			r.Wildcard = true
			break
		}
	}

	r.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName &&
		strings.Join(cert.Subject.Organization, "") == strings.Join(cert.Issuer.Organization, "")

	r.ChainDepth = len(chain)
	if len(chain) > 0 {
		allValid := true
		for _, c := range chain {
			if time.Now().After(c.NotAfter) || time.Now().Before(c.NotBefore) {
				allValid = false
				break
			}
		}
		r.ChainValid = allValid
	}

	r.IsCA = cert.IsCA
	if cert.MaxPathLen > 0 {
		r.MaxPathLen = cert.MaxPathLen
	} else if cert.IsCA {
		r.MaxPathLen = -1
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyType = "RSA"
		r.KeyBits = pub.N.BitLen()
		switch {
		case r.KeyBits >= 4096:
			r.KeyStrength = "Very Strong"
		case r.KeyBits >= 2048:
			r.KeyStrength = "Strong"
		case r.KeyBits >= 1024:
			r.KeyStrength = "Weak"
		default:
			r.KeyStrength = "Insecure"
		}
	case *ecdsa.PublicKey:
		r.KeyType = "ECDSA"
		r.KeyBits = pub.Curve.Params().BitSize
		switch {
		case r.KeyBits >= 384:
			r.KeyStrength = "Very Strong"
		case r.KeyBits >= 256:
			r.KeyStrength = "Strong"
		default:
			r.KeyStrength = "Weak"
		}
	case ed25519.PublicKey:
		r.KeyType = "Ed25519"
		r.KeyBits = 256
		r.KeyStrength = "Strong"
	default:
		r.KeyType = "Unknown"
		r.KeyStrength = "Unknown"
	}

	r.SigAlg = cert.SignatureAlgorithm.String()

	h := sha256.Sum256(cert.Raw)
	r.FingerprintSHA256 = strings.ToUpper(hex.EncodeToString(h[:]))

	h2 := sha256.Sum256(cert.Raw)
	r.FingerprintSHA1 = base64.StdEncoding.EncodeToString(h2[:16])

	if len(cert.SubjectKeyId) > 0 {
		r.SubjectKeyID = strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId))
	}
	if len(cert.AuthorityKeyId) > 0 {
		r.AuthorityKeyID = strings.ToUpper(hex.EncodeToString(cert.AuthorityKeyId))
	}

	r.SerialBits = cert.SerialNumber.BitLen()

	r.KeyUsage = parseKeyUsage(cert.KeyUsage)
	r.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	r.SCTCount = countSCTs(cert)
	r.SCTPresent = r.SCTCount > 0

	r.IsEV = checkEV(cert)
	r.OCSPMustStaple = checkOCSPMustStaple(cert)

	r.CRLDPs = cert.CRLDistributionPoints
	r.OCSPURLs = cert.OCSPServer
	r.CAIssuerURLs = cert.IssuingCertificateURL

	r.CertPolicy = parseCertPolicies(cert.PolicyIdentifiers)

	r.Issues = buildCertIssues(cert, &r)

	return r
}

func countSCTs(cert *x509.Certificate) int {
	count := 0
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.11129.2.4.2" {
			count++
		}
	}
	return count
}

func checkEV(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.32" {
			return strings.Contains(string(ext.Value), "\x67\x81\x0c\x16\x04")
		}
	}
	return false
}

func checkOCSPMustStaple(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.5.5.7.1.24" {
			return true
		}
	}
	return false
}

func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Non Repudiation")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

func parseExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:        "Server Auth",
		x509.ExtKeyUsageClientAuth:        "Client Auth",
		x509.ExtKeyUsageCodeSigning:       "Code Signing",
		x509.ExtKeyUsageEmailProtection:   "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:    "IPSec End System",
		x509.ExtKeyUsageIPSECTunnel:       "IPSec Tunnel",
		x509.ExtKeyUsageIPSECUser:         "IPSec User",
		x509.ExtKeyUsageTimeStamping:      "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:       "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MS SGC",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape SGC",
	}
	var out []string
	for _, u := range eku {
		if n, ok := m[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("Unknown(%d)", u))
		}
	}
	return out
}

func parseCertPolicies(policies []asn1.ObjectIdentifier) []string {
	if len(policies) == 0 {
		return nil
	}
	out := make([]string, len(policies))
	for i, p := range policies {
		out[i] = p.String()
	}
	return out
}

func buildCertIssues(cert *x509.Certificate, r *CertReport) []string {
	var issues []string
	if r.Expired {
		issues = append(issues, fmt.Sprintf("Certificate expired %d days ago", -r.DaysRemaining))
	}
	if r.ExpiresSoon && !r.Expired {
		issues = append(issues, fmt.Sprintf("Certificate expires in %d days", r.DaysRemaining))
	}
	sigLower := strings.ToLower(r.SigAlg)
	if strings.Contains(sigLower, "sha1") || strings.Contains(sigLower, "sha-1") {
		issues = append(issues, fmt.Sprintf("Weak signature algorithm: %s (deprecated SHA-1)", r.SigAlg))
	}
	if strings.Contains(sigLower, "md5") {
		issues = append(issues, fmt.Sprintf("Broken signature algorithm: %s (MD5 is compromised)", r.SigAlg))
	}
	if r.KeyStrength == "Weak" || r.KeyStrength == "Insecure" {
		issues = append(issues, fmt.Sprintf("Weak public key: %d-bit %s (%s)", r.KeyBits, r.KeyType, r.KeyStrength))
	}
	if r.SelfSigned {
		issues = append(issues, "Self-signed certificate (not trusted by browsers)")
	}
	if r.Wildcard {
		issues = append(issues, "Wildcard certificate (*.domain.com) - broader attack surface")
	}
	if cert.SerialNumber.BitLen() < 64 {
		issues = append(issues, fmt.Sprintf("Short serial number (%d bits, should be >= 64)", cert.SerialNumber.BitLen()))
	}
	if r.SanCount == 0 {
		issues = append(issues, "No Subject Alternative Names (SANs)")
	}
	if !r.SCTPresent {
		issues = append(issues, "No Signed Certificate Timestamps (SCT) - may not be recognized by some browsers")
	}
	if !r.ChainValid && r.ChainDepth > 1 {
		issues = append(issues, "Certificate chain validation failed (one or more intermediates expired)")
	}
	if r.IsCA {
		issues = append(issues, "Certificate is a CA certificate (should not be used for server auth)")
	}
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth && len(cert.ExtKeyUsage) > 0 {
		issues = append(issues, "Extended Key Usage does not include Server Authentication")
	}
	if r.OCSPMustStaple {
		issues = append(issues, "OCSP Must-Staple extension present (requires OCSP stapling)")
	}
	if r.IsEV {
		issues = append(issues, "Extended Validation (EV) certificate - high assurance")
	}
	return issues
}

func printCertReport(r CertReport) {
	statusColor := "\033[32mValid"
	if r.Expired {
		statusColor = "\033[31mEXPIRED"
	} else if r.ExpiresSoon {
		statusColor = "\033[33mExpires Soon"
	}
	fmt.Printf("\n  [+] Certificate Deep Analysis:")
	fmt.Printf("\n    %-24s : \033[1m%s\033[0m", "Status", statusColor)
	fmt.Printf("\n    %-24s : %s", "Subject CN", r.SubjectCN)
	if r.SubjectOrg != "" {
		fmt.Printf("\n    %-24s : %s", "Organization", r.SubjectOrg)
	}
	if r.SubjectCountry != "" {
		fmt.Printf("\n    %-24s : %s", "Country", r.SubjectCountry)
	}
	fmt.Printf("\n    %-24s : %s", "Issuer", r.IssuerCN)
	fmt.Printf("\n    %-24s : %s", "Issuer Org", r.IssuerOrg)
	fmt.Printf("\n    %-24s : %s", "Valid From", r.NotBefore[:10])
	fmt.Printf("\n    %-24s : %s", "Valid Until", r.NotAfter[:10])
	fmt.Printf("\n    %-24s : %d days", "Days Remaining", r.DaysRemaining)
	fmt.Printf("\n    %-24s : %d-bit %s (%s)", "Public Key", r.KeyBits, r.KeyType, r.KeyStrength)
	fmt.Printf("\n    %-24s : %s", "Signature Algorithm", r.SigAlg)
	fmt.Printf("\n    %-24s : %d entries", "SAN Count", r.SanCount)
	fmt.Printf("\n    %-24s : %v", "Wildcard", r.Wildcard)
	fmt.Printf("\n    %-24s : %v", "Self-Signed", r.SelfSigned)

	if len(r.KeyUsage) > 0 {
		fmt.Printf("\n    %-24s : %s", "Key Usage", strings.Join(r.KeyUsage, ", "))
	}
	if len(r.ExtKeyUsage) > 0 {
		fmt.Printf("\n    %-24s : %s", "Extended Key Usage", strings.Join(r.ExtKeyUsage, ", "))
	}

	fmt.Printf("\n    %-24s : %v", "CA Certificate", r.IsCA)
	if r.IsCA {
		fmt.Printf("\n    %-24s : %v", "Max Path Len", r.MaxPathLen)
	}
	fmt.Printf("\n    %-24s : %v", "Chain Valid", r.ChainValid)
	fmt.Printf("\n    %-24s : %d", "Chain Depth", r.ChainDepth)
	fmt.Printf("\n    %-24s : %d", "SCT Count", r.SCTCount)
	fmt.Printf("\n    %-24s : %v", "Is EV", r.IsEV)
	fmt.Printf("\n    %-24s : %v", "OCSP Must-Staple", r.OCSPMustStaple)

	if r.SubjectKeyID != "" {
		fmt.Printf("\n    %-24s : %s", "Subject Key ID", r.SubjectKeyID[:min(len(r.SubjectKeyID), 32)])
	}
	if r.AuthorityKeyID != "" {
		fmt.Printf("\n    %-24s : %s", "Authority Key ID", r.AuthorityKeyID[:min(len(r.AuthorityKeyID), 32)])
	}

	if len(r.OCSPURLs) > 0 {
		fmt.Printf("\n    %-24s : %s", "OCSP Responders", strings.Join(r.OCSPURLs, "; "))
	}
	if len(r.CRLDPs) > 0 {
		fmt.Printf("\n    %-24s : %d URLs", "CRL Distribution", len(r.CRLDPs))
	}

	fmt.Printf("\n    %-24s : %s...", "SHA-256 FP", r.FingerprintSHA256[:32])

	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] Certificate Issues:")
		for _, issue := range r.Issues {
			ic := "\033[33m"
			low := strings.ToLower(issue)
			if strings.Contains(low, "expired") || strings.Contains(low, "insecure") || strings.Contains(low, "md5") || strings.Contains(low, "broken") {
				ic = "\033[31m"
			}
			fmt.Printf("\n      %s- %s\033[0m", ic, issue)
		}
	}
	fmt.Println()
}
