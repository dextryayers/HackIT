package formatter

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type ScannerResult struct {
	Target     string  `json:"target"`
	Port       int     `json:"port"`
	Status     string  `json:"status"`
	Service    string  `json:"service"`
	Version    string  `json:"version"`
	OS         string  `json:"os"`
	RiskScore  float64 `json:"risk_score"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Banner     string  `json:"banner"`
	Pattern    string  `json:"pattern"`
	MatchCount int     `json:"match_count"`
}

type Report struct {
	XMLName     xml.Name        `xml:"report"`
	Generated   string          `xml:"generated,attr"`
	Engine      string          `xml:"engine"`
	TotalPorts  int             `xml:"totalPorts"`
	Results     []ScannerResult `xml:"results>result"`
}

type XMLResult struct {
	XMLName xml.Name `xml:"result"`
	Target  string   `xml:"target"`
	Port    int      `xml:"port"`
	Status  string   `xml:"status"`
	Service string   `xml:"service"`
	Version string   `xml:"version"`
	OS      string   `xml:"os"`
	Risk    float64  `xml:"riskScore"`
	Sev     string   `xml:"severity"`
	Conf    float64  `xml:"confidence"`
	Banner  string   `xml:"banner"`
}

func parseResultLine(line string) ScannerResult {
	var r ScannerResult
	re := regexp.MustCompile(`"([^"]+)":"([^"]*)"|"([^"]+)":([^,}]+)`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, m := range matches {
		key := m[1]
		if key == "" {
			key = m[3]
		}
		val := m[2]
		if val == "" {
			val = strings.TrimSpace(m[4])
		}
		switch key {
		case "target":
			r.Target = val
		case "status":
			r.Status = val
		case "service":
			r.Service = val
		case "version":
			r.Version = val
		case "os":
			r.OS = val
		case "severity":
			r.Severity = val
		case "banner":
			r.Banner = val
		case "pattern":
			r.Pattern = val
		case "port":
			fmt.Sscanf(val, "%d", &r.Port)
		case "risk_score":
			fmt.Sscanf(val, "%f", &r.RiskScore)
		case "confidence":
			fmt.Sscanf(val, "%f", &r.Confidence)
		case "matches":
			fmt.Sscanf(val, "%d", &r.MatchCount)
		}
	}
	return r
}

func formatText(results []ScannerResult) string {
	var b strings.Builder
	b.WriteString("========================================\n")
	b.WriteString("  PORT SCANNER RESULTS\n")
	b.WriteString("========================================\n\n")

	for _, r := range results {
		b.WriteString(fmt.Sprintf("  %s:%d\n", r.Target, r.Port))
		b.WriteString(fmt.Sprintf("  Status:    %s\n", colorStatus(r.Status)))
		if r.Service != "" {
			b.WriteString(fmt.Sprintf("  Service:   %s\n", r.Service))
		}
		if r.Version != "" {
			b.WriteString(fmt.Sprintf("  Version:   %s\n", r.Version))
		}
		if r.OS != "" {
			b.WriteString(fmt.Sprintf("  OS:        %s\n", r.OS))
		}
		if r.RiskScore > 0 {
			b.WriteString(fmt.Sprintf("  Risk:      %.1f/10 (%s)\n", r.RiskScore, colorSeverity(r.Severity)))
		}
		if r.Confidence > 0 {
			b.WriteString(fmt.Sprintf("  Confidence: %.0f%%\n", r.Confidence*100))
		}
		if r.Banner != "" {
			banner := r.Banner
			if len(banner) > 80 {
				banner = banner[:80] + "..."
			}
			b.WriteString(fmt.Sprintf("  Banner:    %s\n", banner))
		}
		b.WriteString("  ----------------------------------------\n")
	}
	return b.String()
}

func colorStatus(s string) string {
	switch s {
	case "open":
		return "\033[32mopen\033[0m"
	case "filtered":
		return "\033[33mfiltered\033[0m"
	case "closed":
		return "\033[31mclosed\033[0m"
	default:
		return s
	}
}

func colorSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "\033[31mCritical\033[0m"
	case "high":
		return "\033[38;5;202mHigh\033[0m"
	case "medium":
		return "\033[33mMedium\033[0m"
	case "low":
		return "\033[32mLow\033[0m"
	default:
		return s
	}
}

func formatCSV(results []ScannerResult) string {
	var b strings.Builder
	writer := csv.NewWriter(&b)
	writer.Write([]string{"Target", "Port", "Status", "Service", "Version", "OS", "RiskScore", "Severity", "Confidence", "Banner"})

	for _, r := range results {
		writer.Write([]string{
			r.Target,
			fmt.Sprintf("%d", r.Port),
			r.Status,
			r.Service,
			r.Version,
			r.OS,
			fmt.Sprintf("%.1f", r.RiskScore),
			r.Severity,
			fmt.Sprintf("%.2f", r.Confidence),
			r.Banner,
		})
	}
	writer.Flush()
	return b.String()
}

func formatHTML(results []ScannerResult) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>Port Scanner Results</title>`)
	b.WriteString(`<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#1a1a2e;color:#e0e0e0;margin:20px;padding:0;}
h1{color:#00d4ff;border-bottom:2px solid #0f3460;padding-bottom:10px;}
table{width:100%;border-collapse:collapse;margin:15px 0;background:#16213e;
border-radius:8px;overflow:hidden;}
th{background:#0f3460;color:#00d4ff;padding:12px 15px;text-align:left;font-size:13px;}
td{padding:10px 15px;border-bottom:1px solid #1a1a3e;font-size:13px;}
tr:hover{background:#1a1a3e;}
.status-open{color:#44ff44;font-weight:bold;}
.status-filtered{color:#ffcc00;}
.status-closed{color:#ff4444;}
.sev-critical{color:#ff4444;font-weight:bold;}
.sev-high{color:#ff8800;font-weight:bold;}
.sev-medium{color:#ffcc00;}
.sev-low{color:#88ccff;}
.summary{background:#16213e;border-radius:8px;padding:15px;margin:15px 0;}
.footer{text-align:center;color:#666;margin-top:30px;font-size:12px;}
</style></head><body>`)

	b.WriteString(fmt.Sprintf(`<h1>Port Scanner Results</h1>`))
	b.WriteString(fmt.Sprintf(`<div class="summary">Total ports: %d</div>`, len(results)))
	b.WriteString(`<table><tr><th>Port</th><th>Status</th><th>Service</th><th>Version</th><th>OS</th><th>Risk</th><th>Severity</th><th>Banner</th></tr>`)

	for _, r := range results {
		statusClass := "status-" + r.Status
		sevClass := "sev-" + strings.ToLower(r.Severity)
		banner := r.Banner
		if len(banner) > 60 {
			banner = banner[:60] + "..."
		}
		b.WriteString(fmt.Sprintf(`<tr><td>%d</td><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td class="%s">%s</td><td>%s</td></tr>`,
			r.Port, statusClass, r.Status, r.Service, r.Version, r.OS, r.RiskScore, sevClass, r.Severity, banner))
	}
	b.WriteString(`</table>`)
	b.WriteString(`<div class="footer">Generated by HackIT Port Scanner</div>`)
	b.WriteString(`</body></html>`)
	return b.String()
}

func formatXML(results []ScannerResult) string {
	report := Report{
		Generated:  "now",
		Engine:     "HackIT Port Scanner",
		TotalPorts: len(results),
	}
	for _, r := range results {
		report.Results = append(report.Results, r)
	}
	data, _ := xml.MarshalIndent(report, "", "  ")
	return string(data)
}

func main() {
	format := flag.String("format", "text", "Output format: text, json, html, csv, xml")
	flag.Parse()

	validFormats := map[string]bool{"text": true, "json": true, "html": true, "csv": true, "xml": true}
	if !validFormats[*format] {
		fmt.Fprintf(os.Stderr, "Invalid format: %s. Use text, json, html, csv, or xml\n", *format)
		os.Exit(1)
	}

	var results []ScannerResult
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "RESULT:") || strings.HasPrefix(line, "FINAL:") {
			jsonStart := strings.Index(line, "{")
			if jsonStart >= 0 {
				r := parseResultLine(line[jsonStart:])
				results = append(results, r)
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "No valid results found on stdin\n")
	}

	var output string
	switch *format {
	case "text":
		output = formatText(results)
	case "json":
		data, _ := json.MarshalIndent(map[string]interface{}{
			"engine":  "HackIT Port Scanner",
			"total":   len(results),
			"results": results,
		}, "", "  ")
		output = string(data)
	case "html":
		output = formatHTML(results)
	case "csv":
		output = formatCSV(results)
	case "xml":
		output = formatXML(results)
	}

	fmt.Println(output)
}
