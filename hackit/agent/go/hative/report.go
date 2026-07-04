package main

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ReportData struct {
	Target      string         `json:"target"`
	GeneratedAt string         `json:"generated_at"`
	Duration    float64        `json:"duration_seconds"`
	Results     []ModuleResult `json:"results"`
	RiskScore   float64        `json:"risk_score"`
}

func generateReport(target string, results []ModuleResult, duration float64) {
	riskScore := calculateRiskScore(results)
	data := ReportData{
		Target:      target,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Duration:    duration,
		Results:     results,
		RiskScore:   riskScore,
	}

	reportsDir := filepath.Join("go", "reports", "pentest")
	if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
		// Try from agent/go/
		reportsDir = filepath.Join("..", "..", "go", "reports", "pentest")
		if _, err2 := os.Stat(reportsDir); os.IsNotExist(err2) {
			reportsDir = filepath.Join(os.Getenv("HOME"), ".hackit", "reports", "pentest")
		}
	}
	os.MkdirAll(reportsDir, 0755)

	safeTarget := strings.ReplaceAll(target, ".", "_")
	timestamp := time.Now().Format("20060102_150405")

	mdPath := filepath.Join(reportsDir, fmt.Sprintf("%s_%s.md", safeTarget, timestamp))
	htmlPath := filepath.Join(reportsDir, fmt.Sprintf("%s_%s.html", safeTarget, timestamp))
	mermaidPath := filepath.Join(reportsDir, fmt.Sprintf("%s_%s.mmd", safeTarget, timestamp))

	writeMarkdownReport(mdPath, data)
	writeHTMLReport(htmlPath, data)
	writeMermaidGraph(mermaidPath, data)

	fmt.Printf("\n  Reports generated:\n")
	fmt.Printf("    Markdown : %s\n", mdPath)
	fmt.Printf("    HTML     : %s\n", htmlPath)
	fmt.Printf("    Mermaid  : %s\n", mermaidPath)
}

func calculateRiskScore(results []ModuleResult) float64 {
	score := 0.0
	for _, r := range results {
		data := r.Data
		switch d := data.(type) {
		case []interface{}:
			score += float64(len(d)) * 0.5
		}
	}
	if score > 10 {
		score = 10
	}
	return score
}

func collectVulnerabilities(results []ModuleResult) []map[string]interface{} {
	vulns := make([]map[string]interface{}, 0)
	for _, r := range results {
		mod := r.Module
		data := r.Data
		switch d := data.(type) {
		case []interface{}:
			for _, item := range d {
				if m, ok := item.(map[string]interface{}); ok {
					vuln := map[string]interface{}{
						"module": mod,
						"target": r.Target,
					}
					for k, v := range m {
						vuln[k] = v
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}
	return vulns
}

func writeMarkdownReport(path string, data ReportData) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	vulns := collectVulnerabilities(data.Results)

	fmt.Fprintf(f, "# Pentest Report: %s\n\n", data.Target)
	fmt.Fprintf(f, "**Generated:** %s\n", data.GeneratedAt)
	fmt.Fprintf(f, "**Duration:** %.1fs\n", data.Duration)
	fmt.Fprintf(f, "**Risk Score:** %.1f/10\n\n", data.RiskScore)

	fmt.Fprintf(f, "## Summary\n\n")
	fmt.Fprintf(f, "| Module | Status | Findings |\n")
	fmt.Fprintf(f, "|--------|--------|----------|\n")
	for _, r := range data.Results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
		}
		findings := 0
		if list, ok := r.Data.([]interface{}); ok {
			findings = len(list)
		}
		fmt.Fprintf(f, "| %s | %s | %d |\n", r.Module, status, findings)
	}

	if len(vulns) > 0 {
		fmt.Fprintf(f, "\n## Findings\n\n")
		for i, v := range vulns {
			fmt.Fprintf(f, "### Finding %d: %s\n\n", i+1, v["module"])
			fmt.Fprintf(f, "- **Type:** %v\n", v["type"])
			fmt.Fprintf(f, "- **Target:** %v\n", v["target"])
			fmt.Fprintf(f, "- **Evidence:** %v\n", v["evidence"])
			fmt.Fprintf(f, "- **Payload:** %v\n", v["payload"])
			fmt.Fprintf(f, "\n")
		}
	}

	fmt.Fprintf(f, "\n## Attack Graph\n\n")
	fmt.Fprintf(f, "See the Mermaid diagram file for the attack flow visualization.\n")
}

func writeHTMLReport(path string, data ReportData) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	vulns := collectVulnerabilities(data.Results)

	severityColors := map[string]string{
		"critical": "#dc3545",
		"high":     "#fd7e14",
		"medium":   "#ffc107",
		"low":      "#28a745",
		"info":     "#17a2b8",
	}

	moduleRows := ""
	for _, r := range data.Results {
		findings := 0
		if list, ok := r.Data.([]interface{}); ok {
			findings = len(list)
		}
		color := "#28a745"
		if !r.Success {
			color = "#dc3545"
		}
		moduleRows += fmt.Sprintf("<tr><td>%s</td><td><span style='color:%s'>●</span> %s</td><td>%d</td></tr>\n",
			html.EscapeString(r.Module), color, map[bool]string{true: "OK", false: "FAIL"}[r.Success], findings)
	}

	findingRows := ""
	for _, v := range vulns {
		sev := "info"
		if s, ok := v["severity"]; ok {
			sev = fmt.Sprintf("%v", s)
		}
		sc := severityColors[sev]
		if sc == "" {
			sc = "#6c757d"
		}
		mod := ""
		if m, ok := v["module"]; ok {
			mod = fmt.Sprintf("%v", m)
		}
		vtype := ""
		if t, ok := v["type"]; ok {
			vtype = fmt.Sprintf("%v", t)
		}
		evidence := ""
		if e, ok := v["evidence"]; ok {
			evidence = fmt.Sprintf("%v", e)
		}
		findingRows += fmt.Sprintf("<tr><td><span style='color:%s'>●</span> %s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n",
			sc, html.EscapeString(sev), html.EscapeString(mod), html.EscapeString(vtype), html.EscapeString(evidence))
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report - %s</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:0;padding:20px;background:#f8f9fa;color:#333}
  .container{max-width:1000px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
  h1{border-bottom:3px solid #dc3545;padding-bottom:10px}
  .score{font-size:48px;font-weight:bold;text-align:center;padding:20px;border-radius:8px;margin:20px 0}
  .score.critical{background:#dc3545;color:#fff}
  .score.high{background:#fd7e14;color:#fff}
  .score.medium{background:#ffc107;color:#333}
  .score.low{background:#28a745;color:#fff}
  table{width:100%%;border-collapse:collapse;margin:15px 0}
  th,td{padding:10px;text-align:left;border-bottom:1px solid #dee2e6}
  th{background:#f8f9fa;font-weight:600}
  tr:hover{background:#f1f3f5}
  code{background:#e9ecef;padding:2px 6px;border-radius:3px;font-size:13px}
  .footer{margin-top:30px;color:#6c757d;font-size:14px;text-align:center}
  .chart-bar{height:20px;border-radius:4px;margin:2px 0;min-width:2px;transition:width 0.3s}
</style>
</head>
<body>
<div class="container">
<h1>Pentest Report: %s</h1>
<p><strong>Generated:</strong> %s | <strong>Duration:</strong> %.1fs</p>

<div class="score %s">Risk Score: %.1f / 10</div>

<h2>Module Results</h2>
<table>
<thead><tr><th>Module</th><th>Status</th><th>Findings</th></tr></thead>
<tbody>%s</tbody>
</table>

<h2>Vulnerability Findings (%d)</h2>
<table>
<thead><tr><th>Severity</th><th>Module</th><th>Type</th><th>Evidence</th></tr></thead>
<tbody>%s</tbody>
</table>

<h2>Risk Distribution</h2>
<div style="margin:20px 0">`,
		html.EscapeString(data.Target),
		html.EscapeString(data.Target),
		html.EscapeString(data.GeneratedAt),
		data.Duration,
		riskLevel(data.RiskScore),
		data.RiskScore,
		moduleRows,
		len(vulns),
		findingRows)

	// Add chart bars for severity distribution
	sevCount := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, v := range vulns {
		sev := "info"
		if s, ok := v["severity"]; ok {
			sev = fmt.Sprintf("%v", s)
		}
		sevCount[sev]++
	}
	maxCount := 1
	for _, c := range sevCount {
		if c > maxCount {
			maxCount = c
		}
	}
	for sev, count := range sevCount {
		pct := float64(count) / float64(maxCount) * 100
		color := severityColors[sev]
		htmlContent += fmt.Sprintf("<div style='margin:5px 0'><span style='width:80px;display:inline-block'>%s</span><div class='chart-bar' style='width:%.0f%%%%;background:%s'></div><span style='margin-left:10px'>%d</span></div>\n",
			sev, pct, color, count)
	}

	htmlContent += fmt.Sprintf(`
<div class="footer">Generated by HackIT Hative Engine | %s</div>
</div>
</body>
</html>`, data.GeneratedAt)

	f.WriteString(htmlContent)
}

func writeMermaidGraph(path string, data ReportData) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	vulns := collectVulnerabilities(data.Results)

	fmt.Fprintf(f, "graph TD\n")
	fmt.Fprintf(f, "    T[\"Target: %s\"]\n", data.Target)

	reconNode := "    subgraph Reconnaissance\n"
	reconDone := false
	vulnNode := "    subgraph Vulnerabilities\n"
	vulnDone := false
	webNode := "    subgraph Web Security\n"
	webDone := false
	advNode := "    subgraph Advanced\n"
	advDone := false

	for _, r := range data.Results {
		mod := r.Module
		switch mod {
		case "portscan", "subdomain", "tech":
			if !reconDone {
				reconDone = true
			}
			reconNode += fmt.Sprintf("        %s[\"%s: OK\"]\n", mod, mod)
		case "waf", "ssl", "headers", "fuzz", "cors", "csrf":
			if !webDone {
				webDone = true
			}
			webNode += fmt.Sprintf("        %s[\"%s: OK\"]\n", mod, mod)
		case "sqli", "xss", "ssrf", "redirect", "bypass403", "lfi", "ssti", "xxe", "cmd", "nosqli", "ldap", "jwt":
			if !vulnDone {
				vulnDone = true
			}
			vulnNode += fmt.Sprintf("        %s[\"%s: OK\"]\n", mod, mod)
		case "js", "param", "takeover":
			if !advDone {
				advDone = true
			}
			advNode += fmt.Sprintf("        %s[\"%s: OK\"]\n", mod, mod)
		}
	}

	if reconDone {
		fmt.Fprintf(f, "%s    end\n", reconNode)
	}
	if webDone {
		fmt.Fprintf(f, "%s    end\n", webNode)
	}
	if vulnDone {
		fmt.Fprintf(f, "%s    end\n", vulnNode)
	}
	if advDone {
		fmt.Fprintf(f, "%s    end\n", advNode)
	}

	fmt.Fprintf(f, "\n    T --> recon\n")
	fmt.Fprintf(f, "    recon --> vulns\n")
	fmt.Fprintf(f, "    vulns --> web\n")
	fmt.Fprintf(f, "    web --> advanced\n")

	if len(vulns) > 0 {
		fmt.Fprintf(f, "\n    classDef critical fill:#dc3545,color:#fff\n")
		fmt.Fprintf(f, "    classDef high fill:#fd7e14,color:#fff\n")
		fmt.Fprintf(f, "    classDef medium fill:#ffc107\n")
		fmt.Fprintf(f, "    classDef low fill:#28a745,color:#fff\n")

		for i, v := range vulns {
			sev := "info"
			if s, ok := v["severity"]; ok {
				sev = fmt.Sprintf("%v", s)
			}
			vtype := v["type"]
			nid := fmt.Sprintf("V%d", i+1)
			fmt.Fprintf(f, "    %s[\"%s\"]:::%s\n", nid, vtype, sev)
		}
	}
}

func riskLevel(score float64) string {
	switch {
	case score >= 8:
		return "critical"
	case score >= 5:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}
