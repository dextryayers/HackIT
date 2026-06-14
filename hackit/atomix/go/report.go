package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func GenerateMarkdownReport(results []Result, stats *ScanStats) string {
	var b strings.Builder
	b.WriteString("# Atomix Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("**Total Templates:** %d\n", stats.TemplatesTotal))
	b.WriteString(fmt.Sprintf("**Requests Sent:** %d\n", stats.RequestsSent))
	b.WriteString(fmt.Sprintf("**Findings:** %d\n", stats.Findings))
	b.WriteString(fmt.Sprintf("**Errors:** %d\n", stats.Errors))
	b.WriteString(fmt.Sprintf("**Duration:** %s\n\n", stats.Duration))

	if len(results) == 0 {
		b.WriteString("## ✅ No vulnerabilities found.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	b.WriteString("| Severity | Template | URL | Matcher | Tags |\n")
	b.WriteString("|----------|----------|-----|---------|------|\n")
	for _, r := range results {
		sev := r.Severity
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			sev, r.TemplateName, r.URL, r.MatcherName, r.Tags))
	}

	b.WriteString("\n### Details\n\n")
	for _, r := range results {
		b.WriteString(fmt.Sprintf("#### %s - %s\n", strings.ToUpper(r.Severity), r.TemplateName))
		b.WriteString(fmt.Sprintf("- **Template ID:** %s\n", r.TemplateID))
		b.WriteString(fmt.Sprintf("- **URL:** %s\n", r.URL))
		b.WriteString(fmt.Sprintf("- **Matcher:** %s\n", r.MatcherName))
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", r.Severity))
		b.WriteString(fmt.Sprintf("- **Tags:** %s\n", r.Tags))
		if r.Extracted != "" {
			b.WriteString(fmt.Sprintf("- **Extracted:** `%s`\n", r.Extracted))
		}
		b.WriteString(fmt.Sprintf("- **Response Time:** %s\n", r.ResponseTime))
		b.WriteString("\n")
	}
	return b.String()
}

func GenerateHTMLReport(results []Result, stats *ScanStats) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><title>Atomix Scan Report</title>")
	b.WriteString("<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}")
	b.WriteString("h1{color:#00d4ff}table{border-collapse:collapse;width:100%}")
	b.WriteString("th{background:#16213e;color:#00d4ff;padding:8px;text-align:left}")
	b.WriteString("td{padding:8px;border-bottom:1px solid #333}")
	b.WriteString(".critical{color:#ff4444}.high{color:#ff8800}.medium{color:#ffcc00}")
	b.WriteString(".low{color:#4488ff}.info{color:#44ff44}")
	b.WriteString(".stat{display:inline-block;padding:10px;margin:5px;background:#16213e;border-radius:5px}")
	b.WriteString("</style></head><body>")
	b.WriteString(fmt.Sprintf("<h1>⚛ Atomix Scan Report</h1>"))
	b.WriteString(fmt.Sprintf("<p><strong>Date:</strong> %s</p>", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("<div class='stat'>Templates: %d</div>", stats.TemplatesTotal))
	b.WriteString(fmt.Sprintf("<div class='stat'>Requests: %d</div>", stats.RequestsSent))
	b.WriteString(fmt.Sprintf("<div class='stat'>Findings: %d</div>", stats.Findings))
	b.WriteString(fmt.Sprintf("<div class='stat'>Errors: %d</div>", stats.Errors))
	b.WriteString(fmt.Sprintf("<div class='stat'>Duration: %s</div>", stats.Duration))

	if len(results) > 0 {
		b.WriteString("<h2>Findings</h2><table><tr><th>Severity</th><th>Template</th><th>URL</th><th>Matcher</th><th>Tags</th></tr>")
		for _, r := range results {
			b.WriteString(fmt.Sprintf("<tr><td class='%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				r.Severity, strings.ToUpper(r.Severity), r.TemplateName, r.URL, r.MatcherName, r.Tags))
		}
		b.WriteString("</table>")
	} else {
		b.WriteString("<h2>No vulnerabilities found.</h2>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func WriteReport(results []Result, stats *ScanStats, format, path string) error {
	var content string
	switch format {
	case "json":
		content = FormatResultsJSON(results)
	case "markdown", "md":
		content = GenerateMarkdownReport(results, stats)
	case "html":
		content = GenerateHTMLReport(results, stats)
	default:
		content = FormatResultsJSON(results)
	}

	if path == "" || path == "-" {
		fmt.Println(content)
		return nil
	}

	return os.WriteFile(path, []byte(content), 0644)
}
