package main

import (
	"fmt"
	"strings"
)

// VulnerabilityAnalyzer specialized in finding gaps in scan artifacts
type VulnerabilityAnalyzer struct {
	SystemPrompt string
}

func NewVulnerabilityAnalyzer() *VulnerabilityAnalyzer {
	return &VulnerabilityAnalyzer{
		SystemPrompt: `
You are the HackIt AI Vuln-Scanner Core. 
Your mission is to analyze the provided scan results and identify security vulnerabilities, misconfigurations, and potential attack vectors.
Categorize your findings as:
[CRITICAL] - Immediate RCE, Data Breach, or Full Compromise.
[HIGH] - Serious gaps like SQLi, SSRF, or clear authentication bypass.
[MEDIUM] - Significant misconfigurations or sensitive information disclosure.
[LOW] - Best practices and minor info leaks.

Provide a brief "Attack Vector" and "Mitigation" for each high/critical finding.
Be surgical, technical, and objective.
`,
	}
}

func (a *VulnerabilityAnalyzer) GenerateAnalysisPrompt(toolName string, scanData string) string {
	return fmt.Sprintf(`
Analyze the following scan results from the tool: %s

SCAN DATA:
---
%s
---

Identify any vulnerabilities and provide a tactical report.
`, toolName, scanData)
}

// CleanScanData removes excessive noise from raw logs to save tokens
func (a *VulnerabilityAnalyzer) CleanScanData(raw string) string {
	lines := strings.Split(raw, "\n")
	var cleaned []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "DEBUG") {
			continue
		}
		// Limit line length for long JS/HTML blobs
		if len(trimmed) > 500 {
			trimmed = trimmed[:500] + "... [TRUNCATED]"
		}
		cleaned = append(cleaned, trimmed)
	}
	return strings.Join(cleaned, "\n")
}
