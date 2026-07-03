package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type FinalReport struct {
	Host           string          `json:"host"`
	Port           int             `json:"port"`
	Grade          string          `json:"grade"`
	Score          int             `json:"score"`
	Speed          string          `json:"speed_ms"`
	Cert           CertReport      `json:"certificate"`
	Ciphers        CipherReport    `json:"ciphers"`
	Vulns          VulnReport      `json:"vulnerabilities"`
	TLSFeatures    TLSFeatureReport `json:"tls_features"`
	Protocols      []string        `json:"protocols"`
	Issues         []string        `json:"issues"`
	Summary        SummarySection  `json:"summary"`
}

type SummarySection struct {
	TotalIssues    int `json:"total_issues"`
	CriticalIssues int `json:"critical"`
	HighIssues     int `json:"high"`
	MediumIssues   int `json:"medium"`
	LowIssues      int `json:"low"`
	CiphersWeak    int `json:"weak_ciphers"`
	CiphersBroken  int `json:"broken_ciphers"`
	CertIssues     int `json:"cert_issues"`
	TLSIssues      int `json:"tls_issues"`
}

func buildReport(host string, port int, certReport CertReport, cipherReport CipherReport,
	vulnReport VulnReport, tlsReport TLSFeatureReport, protocols []string) FinalReport {

	report := FinalReport{
		Host:        host,
		Port:        port,
		Cert:        certReport,
		Ciphers:     cipherReport,
		Vulns:       vulnReport,
		TLSFeatures: tlsReport,
		Protocols:   protocols,
	}

	report.Issues = collectAllIssues(certReport, cipherReport, vulnReport, tlsReport)

	totalScore := 0
	count := 0
	if !certReport.Expired && !certReport.SelfSigned {
		cs := 100
		if certReport.KeyStrength == "Weak" || certReport.KeyStrength == "Insecure" {
			cs -= 20
		}
		if strings.Contains(strings.ToLower(certReport.SigAlg), "sha1") {
			cs -= 15
		}
		if certReport.ExpiresSoon {
			cs -= 10
		}
		if certReport.Wildcard {
			cs -= 5
		}
		if cs < 0 {
			cs = 0
		}
		totalScore += cs
		count++
	}

	totalScore += cipherReport.Score
	count++

	totalScore += vulnReport.Score
	count++

	totalScore += tlsReport.Score
	count++

	if count > 0 {
		report.Score = totalScore / count
	}

	report.Grade = calculateGrade(report.Score)

	report.Summary = SummarySection{
		TotalIssues:    len(report.Issues),
		CriticalIssues: vulnReport.Critical,
		HighIssues:     vulnReport.High,
		MediumIssues:   vulnReport.Medium,
		LowIssues:      vulnReport.Low,
		CiphersWeak:    len(cipherReport.Weak),
		CiphersBroken:  len(cipherReport.Insecure),
		CertIssues:     len(certReport.Issues),
		TLSIssues:      len(tlsReport.Issues),
	}

	return report
}

func calculateFinalGrade(cert CertReport, cipher CipherReport, vuln VulnReport, tls TLSFeatureReport) int {
	score := 100

	if cert.Expired {
		score = 0
		return score
	}
	if cert.SelfSigned {
		score -= 30
	}
	if cert.KeyStrength == "Insecure" {
		score -= 25
	} else if cert.KeyStrength == "Weak" {
		score -= 15
	}
	if strings.Contains(strings.ToLower(cert.SigAlg), "sha1") {
		score -= 15
	}
	if cert.ExpiresSoon {
		score -= 10
	}
	if cert.Wildcard {
		score -= 5
	}
	if !cert.SCTPresent {
		score -= 5
	}

	for range cipher.Insecure {
		score -= 20
	}
	for range cipher.Weak {
		score -= 10
	}
	if !cipher.PFSEnabled {
		score -= 15
	}

	for _, f := range vuln.Findings {
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			switch f.Severity {
			case "CRITICAL":
				score -= 35
			case "HIGH":
				score -= 25
			case "MEDIUM":
				score -= 15
			case "LOW":
				score -= 5
			}
		}
	}

	if !tls.TLS13Supported {
		score -= 10
	}
	if !tls.OCSPStapled {
		score -= 5
	}
	if !tls.SessionResumption {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	return score
}

func calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "A-"
	case score >= 70:
		return "B+"
	case score >= 60:
		return "B"
	case score >= 50:
		return "C+"
	case score >= 40:
		return "C"
	case score >= 30:
		return "D+"
	case score >= 20:
		return "D"
	default:
		return "F"
	}
}

func collectAllIssues(cert CertReport, cipher CipherReport, vuln VulnReport, tls TLSFeatureReport) []string {
	issues := make([]string, 0)
	issues = append(issues, cert.Issues...)
	for _, c := range cipher.Weak {
		issues = append(issues, fmt.Sprintf("Weak cipher: %s", c.Name))
	}
	for _, c := range cipher.Insecure {
		issues = append(issues, fmt.Sprintf("Insecure cipher: %s (%s)", c.Name, c.Reason))
	}
	for _, f := range vuln.Findings {
		if f.Status == "VULNERABLE" || f.Status == "WEAK" {
			issues = append(issues, fmt.Sprintf("[%s] %s: %s", f.Severity, f.Name, f.Detail))
		}
	}
	issues = append(issues, tls.Issues...)
	return issues
}

func printFinalReport(r FinalReport) {
	gradeColor := "\033[32m"
	switch r.Grade {
	case "A", "A-":
		gradeColor = "\033[32m"
	case "B+", "B", "C+", "C":
		gradeColor = "\033[33m"
	case "D+", "D":
		gradeColor = "\033[31m"
	case "F":
		gradeColor = "\033[31;1m"
	}

	fmt.Printf("\n%s", strings.Repeat("=", 55))
	fmt.Printf("\n  FINAL SSL/TLS REPORT")
	fmt.Printf("\n%s", strings.Repeat("=", 55))
	fmt.Printf("\n  Target     : %s:%d", r.Host, r.Port)
	fmt.Printf("\n  Grade      : %s%s\033[0m  (%d/100)", gradeColor, r.Grade, r.Score)
	fmt.Printf("\n  Speed      : %s", r.Speed)
	fmt.Printf("\n%s", strings.Repeat("-", 55))

	fmt.Printf("\n  SUMMARY:")
	fmt.Printf("\n    %-22s : %d", "Total Issues", r.Summary.TotalIssues)
	if r.Summary.CriticalIssues > 0 {
		fmt.Printf("\n    %-22s : \033[31m%d\033[0m", "Critical", r.Summary.CriticalIssues)
	}
	if r.Summary.HighIssues > 0 {
		fmt.Printf("\n    %-22s : \033[31m%d\033[0m", "High", r.Summary.HighIssues)
	}
	if r.Summary.MediumIssues > 0 {
		fmt.Printf("\n    %-22s : \033[33m%d\033[0m", "Medium", r.Summary.MediumIssues)
	}
	if r.Summary.LowIssues > 0 {
		fmt.Printf("\n    %-22s : %d", "Low", r.Summary.LowIssues)
	}
	fmt.Printf("\n    %-22s : %d weak + %d broken", "Ciphers", r.Summary.CiphersWeak, r.Summary.CiphersBroken)
	fmt.Printf("\n    %-22s : %d", "Certificate Issues", r.Summary.CertIssues)
	fmt.Printf("\n    %-22s : %d", "TLS Feature Issues", r.Summary.TLSIssues)

	if len(r.Issues) > 0 {
		fmt.Printf("\n\n  [!] All Issues:")
		for _, issue := range r.Issues {
			ic := "\033[33m"
			low := strings.ToLower(issue)
			if strings.Contains(low, "critical") || strings.Contains(low, "insecure") || strings.Contains(low, "broken") {
				ic = "\033[31m"
			} else if strings.Contains(low, "low") || strings.Contains(low, "info") {
				ic = "\033[2m"
			}
			fmt.Printf("\n    %s- %s\033[0m", ic, issue)
		}
	}
	fmt.Printf("\n%s", strings.Repeat("=", 55))
	fmt.Println()
}

func toJSON(r FinalReport) string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\":%q}", err.Error())
	}
	return string(data)
}
