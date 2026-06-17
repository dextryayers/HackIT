package native

import (
	"fmt"
	"strings"
	"time"
)

type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	CVSS        string `json:"cvss"`
}

type Report struct {
	Target       string    `json:"target"`
	Date         string    `json:"date"`
	Duration     string    `json:"duration"`
	Findings     []Finding `json:"findings"`
	Summary      string    `json:"summary"`
	RiskScore    int       `json:"risk_score"`
}

func GenerateReport(target string, findings []Finding, startTime time.Time) Report {
	duration := time.Since(startTime)
	riskScore := 0
	severityWeights := map[string]int{
		"CRITICAL": 40,
		"HIGH":     25,
		"MEDIUM":   15,
		"LOW":      5,
		"INFO":     1,
	}

	for _, f := range findings {
		if w, ok := severityWeights[f.Severity]; ok {
			riskScore += w
		}
	}
	if riskScore > 100 {
		riskScore = 100
	}

	summary := fmt.Sprintf("Pentest completed on %s. Found %d findings with risk score %d/100.",
		target, len(findings), riskScore)
	if riskScore >= 70 {
		summary += " Target is CRITICALLY vulnerable. Immediate remediation required."
	} else if riskScore >= 40 {
		summary += " Target has significant security gaps. Prioritize high-severity fixes."
	} else if riskScore >= 20 {
		summary += " Target is moderately secure. Address medium findings."
	} else {
		summary += " Target is well-secured. Maintain current posture."
	}

	return Report{
		Target:    target,
		Date:      startTime.Format("2006-01-02 15:04:05"),
		Duration:  duration.Round(time.Second).String(),
		Findings:  findings,
		Summary:   summary,
		RiskScore: riskScore,
	}
}

func (r Report) Markdown() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Pentest Report: %s\n\n", r.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", r.Date))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n", r.Duration))
	sb.WriteString(fmt.Sprintf("**Risk Score:** %d/100  \n\n", r.RiskScore))

	sb.WriteString("## Executive Summary\n")
	sb.WriteString(r.Summary + "\n\n")

	sb.WriteString("## Risk Classification\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if c, ok := counts[s]; ok {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", s, c))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## Detailed Findings\n")
	for i, f := range r.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s (%s)\n", i+1, f.Title, f.Severity))
		if f.CVSS != "" {
			sb.WriteString(fmt.Sprintf("**CVSS:** %s  \n", f.CVSS))
		}
		sb.WriteString(fmt.Sprintf("**Description:** %s  \n", f.Description))
		sb.WriteString(fmt.Sprintf("**Impact:** %s  \n", f.Impact))
		sb.WriteString(fmt.Sprintf("**Remediation:** %s  \n\n", f.Remediation))
	}

	return sb.String()
}
