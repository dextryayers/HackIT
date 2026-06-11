package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// BugReport represents the final output of the AI Hunter.
type BugReport struct {
	Target       string
	ScanTime     string
	ExecutiveSum string
	Vectors      []AttackVector
	Conclusion   string
	Remediation  string
}

// GenerateReport writes the bug report to a markdown file and returns it as a string.
func GenerateReport(target string, vectors []AttackVector, flowchart string) string {
	report := BugReport{
		Target:   target,
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
		Vectors:  vectors,
	}

	// AI logic for generating summaries
	if len(vectors) > 0 {
		report.ExecutiveSum = fmt.Sprintf("The AI Hunter has successfully completed an autonomous attack simulation on %s. The target is VULNERABLE. %d active attack vectors were identified and successfully simulated.", target, len(vectors))
		report.Conclusion = "The target exhibits significant security flaws that allow for active exploitation. Immediate patching and network isolation are required."
		report.Remediation = "1. Update all identified vulnerable services.\n2. Restrict public access to administrative ports.\n3. Implement WAF to filter malicious payloads."
	} else {
		report.ExecutiveSum = fmt.Sprintf("The AI Hunter has completed an autonomous attack simulation on %s. The target appears SECURE. No critical attack vectors were successfully simulated.", target)
		report.Conclusion = "The target demonstrates a strong security posture against the simulated attacks."
		report.Remediation = "1. Maintain current patch levels.\n2. Continue regular monitoring and autonomous testing."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# 🛡️ HackIT Autonomous AI Hunter Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", report.Target))
	sb.WriteString(fmt.Sprintf("**Scan Time:** `%s`\n\n", report.ScanTime))

	sb.WriteString("## 1. Executive Summary\n")
	sb.WriteString(report.ExecutiveSum + "\n\n")

	sb.WriteString("## 2. Attack Vectors & Flowchart\n")
	sb.WriteString(flowchart + "\n\n")

	sb.WriteString("## 3. Detailed Findings\n")
	if len(vectors) == 0 {
		sb.WriteString("*No vulnerabilities exploited.*\n\n")
	} else {
		for i, v := range vectors {
			sb.WriteString(fmt.Sprintf("### 3.%d. %s on Port %d\n", i+1, v.Vulnerability, v.Port))
			sb.WriteString(fmt.Sprintf("- **Service:** %s\n", v.Service))
			sb.WriteString(fmt.Sprintf("- **Impact:** %s\n", v.Impact))
			sb.WriteString("- **Status:** `Verified by AI`\n\n")
		}
	}

	sb.WriteString("## 4. Conclusion & Remediation\n")
	sb.WriteString("**Conclusion:**\n" + report.Conclusion + "\n\n")
	sb.WriteString("**Remediation:**\n" + report.Remediation + "\n")

	// Save to file
	filename := fmt.Sprintf("AI_Report_%s.md", strings.ReplaceAll(target, ".", "_"))
	_ = os.WriteFile(filename, []byte(sb.String()), 0644)

	return sb.String()
}
