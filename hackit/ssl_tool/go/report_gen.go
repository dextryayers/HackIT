package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type GenReport struct {
	Target       string      `json:"target"`
	ScanTime     string      `json:"scan_time"`
	Duration     string      `json:"duration"`
	Grade        string      `json:"grade"`
	Score        int         `json:"score"`
	Cert         CertReport  `json:"certificate"`
	Ciphers      CipherReport `json:"ciphers"`
	Vulns        VulnReport  `json:"vulnerabilities"`
	TLS          TLSFeatureReport `json:"tls_features"`
	DNS          DNSReport   `json:"dns"`
	HTTP         HTTPReport  `json:"http"`
	Chain        ChainReport `json:"chain"`
	Crypto       CryptoReport `json:"crypto"`
	Ports        PortScanReport `json:"ports"`
	AllIssues    []string    `json:"all_issues"`
	Recommendations []string `json:"recommendations"`
}

func generateReport(target string, grade string, score int, duration time.Duration,
	cert CertReport, ciphers CipherReport, vulns VulnReport, tls TLSFeatureReport,
	dns DNSReport, http HTTPReport, chain ChainReport, crypto CryptoReport, ports PortScanReport) GenReport {

	r := GenReport{
		Target:       target,
		ScanTime:     time.Now().Format(time.RFC3339),
		Duration:     fmt.Sprintf("%dms", duration.Milliseconds()),
		Grade:        grade,
		Score:        score,
		Cert:         cert,
		Ciphers:      ciphers,
		Vulns:        vulns,
		TLS:          tls,
		DNS:          dns,
		HTTP:         http,
		Chain:        chain,
		Crypto:       crypto,
		Ports:        ports,
	}

	r.AllIssues = collectReportIssues(cert, ciphers, vulns, tls, dns, http, chain, crypto, ports)
	r.Recommendations = generateRecs(&r)
	return r
}

func collectReportIssues(cert CertReport, ciphers CipherReport, vulns VulnReport,
	tls TLSFeatureReport, dns DNSReport, http HTTPReport, chain ChainReport,
	crypto CryptoReport, ports PortScanReport) []string {

	issues := make([]string, 0)
	issues = append(issues, cert.Issues...)
	for _, c := range ciphers.Weak {
		issues = append(issues, fmt.Sprintf("Weak cipher: %s", c.Name))
	}
	for _, c := range ciphers.Insecure {
		issues = append(issues, fmt.Sprintf("Insecure cipher: %s (%s)", c.Name, c.Reason))
	}
	for _, f := range vulns.Findings {
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			issues = append(issues, fmt.Sprintf("[%s] %s: %s", f.Severity, f.Name, f.Detail))
		}
	}
	issues = append(issues, tls.Issues...)
	issues = append(issues, dns.Issues...)
	issues = append(issues, http.Issues...)
	issues = append(issues, chain.Issues...)
	issues = append(issues, crypto.Issues...)
	issues = append(issues, ports.Issues...)
	return issues
}

func generateRecs(r *GenReport) []string {
	var recs []string

	if r.Cert.Expired {
		recs = append(recs, "RENEW: Certificate has expired - renew immediately")
	}
	if r.Cert.ExpiresSoon {
		recs = append(recs, "RENEW: Certificate expires soon - schedule renewal")
	}
	if r.Cert.SelfSigned {
		recs = append(recs, "REPLACE: Self-signed cert - use trusted CA certificate")
	}
	if !r.Cert.SCTPresent {
		recs = append(recs, "ENHANCE: Add Certificate Transparency (SCT) logs")
	}
	if r.Cert.KeyStrength == "Weak" || r.Cert.KeyStrength == "Insecure" {
		recs = append(recs, "UPGRADE: Weak key - generate stronger key (2048+ RSA or 256+ ECDSA)")
	}
	if strings.Contains(strings.ToLower(r.Cert.SigAlg), "sha1") {
		recs = append(recs, "UPDATE: Weak signature algorithm (SHA-1) - use SHA-256+")
	}

	if len(r.Ciphers.Weak) > 0 || len(r.Ciphers.Insecure) > 0 {
		recs = append(recs, "DISABLE: Remove weak/insecure ciphers from server config")
	}
	if !r.Ciphers.PFSEnabled {
		recs = append(recs, "ENABLE: Configure PFS ciphers (ECDHE) for forward secrecy")
	}

	for _, f := range r.Vulns.Findings {
		if f.Status == "VULNERABLE" {
			recs = append(recs, fmt.Sprintf("PATCH: Fix %s (CVE: %s)", f.Name, f.CVE))
		}
	}

	if !r.TLS.TLS13Supported {
		recs = append(recs, "ENABLE: Enable TLS 1.3 for best security")
	}
	if !r.TLS.H2 {
		recs = append(recs, "ENABLE: Enable HTTP/2 (h2) for performance")
	}
	if !r.TLS.OCSPStapled {
		recs = append(recs, "ENABLE: Configure OCSP stapling")
	}
	for _, p := range r.TLS.Protocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			recs = append(recs, fmt.Sprintf("DISABLE: Deprecated protocol %s", p))
		}
	}

	if r.DNS.SPFRecord == "" {
		recs = append(recs, "CONFIGURE: Add SPF record to prevent email spoofing")
	}
	if r.DNS.DMARC == "" {
		recs = append(recs, "CONFIGURE: Add DMARC record for email auth policy")
	}
	if !r.DNS.DNSSEC {
		recs = append(recs, "ENABLE: Configure DNSSEC for DNS security")
	}

	if r.HTTP.HSTS == "" {
		recs = append(recs, "ADD: HTTP Strict-Transport-Security (HSTS) header")
	}
	if r.HTTP.CSP == "" {
		recs = append(recs, "ADD: Content-Security-Policy (CSP) header")
	}
	if r.HTTP.XFrameOptions == "" {
		recs = append(recs, "ADD: X-Frame-Options header to prevent clickjacking")
	}
	if !r.HTTP.CookiesSecure {
		recs = append(recs, "SECURE: Add Secure flag to cookies")
	}
	if !r.HTTP.CookiesHttpOnly {
		recs = append(recs, "SECURE: Add HttpOnly flag to cookies")
	}

	for _, p := range r.Ports.OpenPorts {
		if p.Port == 21 {
			recs = append(recs, "REPLACE: FTP (21) with SFTP/SCP")
		}
		if p.Port == 23 {
			recs = append(recs, "REPLACE: Telnet (23) with SSH")
		}
		if p.Port == 3306 || p.Port == 5432 {
			recs = append(recs, fmt.Sprintf("RESTRICT: Database port %d from public access", p.Port))
		}
	}

	return recs
}

func (r GenReport) toMarkdown() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# SSL/TLS Security Report: %s\n\n", r.Target))
	b.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", r.ScanTime[:10]))
	b.WriteString(fmt.Sprintf("**Duration:** %s  \n", r.Duration))
	b.WriteString(fmt.Sprintf("**Overall Grade:** %s (%d/100)  \n\n", r.Grade, r.Score))

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Total Issues:** %d\n", len(r.AllIssues)))
	b.WriteString(fmt.Sprintf("- **Active Vulnerabilities:** %d\n", r.Vulns.Count))
	b.WriteString(fmt.Sprintf("- **Certificate Issues:** %d\n", len(r.Cert.Issues)))
	b.WriteString(fmt.Sprintf("- **Cipher Issues:** %d weak + %d broken\n", len(r.Ciphers.Weak), len(r.Ciphers.Insecure)))
	b.WriteString(fmt.Sprintf("- **TLS Feature Issues:** %d\n", len(r.TLS.Issues)))
	b.WriteString(fmt.Sprintf("- **DNS Issues:** %d\n", len(r.DNS.Issues)))
	b.WriteString(fmt.Sprintf("- **HTTP Issues:** %d\n\n", len(r.HTTP.Issues)))

	if len(r.AllIssues) > 0 {
		b.WriteString("## All Issues\n\n")
		for _, iss := range r.AllIssues {
			b.WriteString(fmt.Sprintf("- %s\n", iss))
		}
		b.WriteString("\n")
	}

	if len(r.Recommendations) > 0 {
		b.WriteString("## Recommendations\n\n")
		for i, rec := range r.Recommendations {
			prefix := string(rune('A' + i%26))
			b.WriteString(fmt.Sprintf("- **[%s]** %s\n", prefix, rec))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n")
	b.WriteString("*Generated by HackIT SSL Security Suite v3.0*\n")
	return b.String()
}

func (r GenReport) saveMarkdown(path string) error {
	data := r.toMarkdown()
	return os.WriteFile(path, []byte(data), 0644)
}

func printFullReport(r GenReport) {
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  FINAL SECURITY REPORT: %s", r.Target)
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\n  Duration  : %s", r.Duration)
	fmt.Printf("\n  Final Grade : %s (%d/100)", r.Grade, r.Score)
	fmt.Printf("\n  Total Issues: %d", len(r.AllIssues))
	fmt.Printf("\n%s", strings.Repeat("-", 60))

	if len(r.Recommendations) > 0 {
		fmt.Printf("\n\n  RECOMMENDATIONS:")
		for i, rec := range r.Recommendations {
			if i >= 10 {
				fmt.Printf("\n    ... and %d more", len(r.Recommendations)-10)
				break
			}
			fmt.Printf("\n    %s%s%s", "\033[33m", rec, "\033[0m")
		}
	}
	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Println()
}
