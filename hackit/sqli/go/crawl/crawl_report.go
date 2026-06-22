package crawl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"hackit/sqli/go/utils"
)

// CrawlReport generates comprehensive reports of crawl results
type CrawlReport struct {
	results *CrawlResults
	log     *utils.Logger
	config  *ReportConfig
}

// ReportConfig configures report output
type ReportConfig struct {
	Format          string // "json", "html", "text", "csv"
	OutputDir       string
	IncludeSamples  bool
	MaxSampleLen    int
	GroupByDB       bool
	GroupByCategory bool
	SortByRisk      bool
	IncludeRaw      bool
	PrettyPrint     bool
}

var DefaultReportConfig = &ReportConfig{
	Format:          "json",
	OutputDir:       "crawl_reports",
	IncludeSamples:  true,
	MaxSampleLen:    100,
	GroupByDB:       true,
	GroupByCategory: true,
	SortByRisk:      true,
	IncludeRaw:      false,
	PrettyPrint:     true,
}

func NewCrawlReport(results *CrawlResults, log *utils.Logger, config *ReportConfig) *CrawlReport {
	if config == nil {
		config = DefaultReportConfig
	}
	return &CrawlReport{results: results, log: log, config: config}
}

// GenerateAll generates all report formats
func (cr *CrawlReport) GenerateAll() []string {
	var files []string

	formats := []string{"json", "html", "text", "csv"}
	for _, format := range formats {
		cr.config.Format = format
		if file, err := cr.Generate(); err == nil {
			files = append(files, file)
		}
	}

	cr.log.Success(fmt.Sprintf("Generated %d report files", len(files)))
	return files
}

// Generate generates a report in the configured format
func (cr *CrawlReport) Generate() (string, error) {
	if err := os.MkdirAll(cr.config.OutputDir, 0755); err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102_150405")
	var filename string

	switch cr.config.Format {
	case "json":
		filename = filepath.Join(cr.config.OutputDir, fmt.Sprintf("crawl_report_%s.json", timestamp))
		if err := cr.generateJSON(filename); err != nil {
			return "", err
		}
	case "html":
		filename = filepath.Join(cr.config.OutputDir, fmt.Sprintf("crawl_report_%s.html", timestamp))
		if err := cr.generateHTML(filename); err != nil {
			return "", err
		}
	case "text":
		filename = filepath.Join(cr.config.OutputDir, fmt.Sprintf("crawl_report_%s.txt", timestamp))
		if err := cr.generateText(filename); err != nil {
			return "", err
		}
	case "csv":
		filename = filepath.Join(cr.config.OutputDir, fmt.Sprintf("crawl_report_%s.csv", timestamp))
		if err := cr.generateCSV(filename); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported format: %s", cr.config.Format)
	}

	cr.log.Success(fmt.Sprintf("Report saved: %s", filename))
	return filename, nil
}

func (cr *CrawlReport) generateJSON(filename string) error {
	report := cr.buildJSONReport()

	var data []byte
	var err error
	if cr.config.PrettyPrint {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func (cr *CrawlReport) generateHTML(filename string) error {
	html := cr.buildHTMLReport()
	return os.WriteFile(filename, []byte(html), 0644)
}

func (cr *CrawlReport) generateText(filename string) error {
	text := cr.buildTextReport()
	return os.WriteFile(filename, []byte(text), 0644)
}

func (cr *CrawlReport) generateCSV(filename string) error {
	var sb strings.Builder
	// Header
	sb.WriteString("Database,Table,Column,Type,Sensitive,Category,Risk,Sample,Confidence\n")

	for dbName, dbInfo := range cr.results.Databases {
		for _, tblInfo := range dbInfo.Tables {
			for _, col := range tblInfo.Columns {
				isSensitive := "No"
				category := ""
				risk := ""
				sample := ""
				confidence := ""

				if col.IsSensitive {
					isSensitive = "Yes"
					for _, f := range cr.results.Sensitive {
						if f.Database == dbName && f.Table == tblInfo.Name && f.Column == col.Name {
							category = f.Category
							risk = f.Risk
							sample = f.Sample
							confidence = fmt.Sprintf("%.0f%%", f.Confidence*100)
							break
						}
					}
				}

				sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,\"%s\",%s\n",
					csvEscape(dbName), csvEscape(tblInfo.Name), csvEscape(col.Name),
					csvEscape(col.Type), isSensitive, category, risk,
					sample, confidence))
			}
		}
		// Tables data
		for _, tblInfo := range dbInfo.Tables {
			if len(tblInfo.Data) > 0 {
				sb.WriteString(fmt.Sprintf("\n--- %s.%s Data ---\n", dbName, tblInfo.Name))
				// Header
				var colNames []string
				for _, c := range tblInfo.Columns {
					colNames = append(colNames, c.Name)
				}
				sb.WriteString(strings.Join(colNames, ",") + "\n")
				// Rows
				for _, row := range tblInfo.Data {
					sb.WriteString(strings.Join(row, ",") + "\n")
				}
			}
		}
	}

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

func (cr *CrawlReport) buildJSONReport() map[string]interface{} {
	summary := cr.results.Summary
	if summary == nil {
		summary = &CrawlSummary{}
	}

	report := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"summary": map[string]interface{}{
			"databases": summary.TotalDatabases,
			"tables":    summary.TotalTables,
			"columns":   summary.TotalColumns,
			"rows":      summary.TotalRows,
			"sensitive": summary.TotalSensitive,
			"errors":    summary.TotalErrors,
			"duration":  summary.Duration,
		},
		"sensitive_findings": cr.results.Sensitive,
		"system_info":        cr.results.SystemInfo,
		"relations":          cr.results.Relations,
	}

	if cr.config.IncludeRaw {
		databases := make(map[string]interface{})
		for dbName, dbInfo := range cr.results.Databases {
			dbData := map[string]interface{}{
				"size":     dbInfo.Size,
				"collation": dbInfo.Collation,
				"charset":  dbInfo.Charset,
			}
			tables := make(map[string]interface{})
			for tblName, tblInfo := range dbInfo.Tables {
				tblData := map[string]interface{}{
					"engine":    tblInfo.Engine,
					"collation": tblInfo.Collation,
					"row_count": tblInfo.RowCount,
				}
				cols := make([]map[string]interface{}, len(tblInfo.Columns))
				for i, col := range tblInfo.Columns {
					cols[i] = map[string]interface{}{
						"name":     col.Name,
						"type":     col.Type,
						"nullable": col.Nullable,
						"default":  col.Default,
						"pk":       col.IsPK,
						"fk":       col.IsFK,
						"sensitive": col.IsSensitive,
					}
				}
				tblData["columns"] = cols
				tables[tblName] = tblData
			}
			dbData["tables"] = tables
			databases[dbName] = dbData
		}
		report["databases"] = databases
	}

	return report
}

func (cr *CrawlReport) buildHTMLReport() string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Database Crawl Report</title>
<style>
body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; margin: 20px; background: #0a0a0a; color: #e0e0e0; }
h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
h2 { color: #00ccff; margin-top: 30px; }
h3 { color: #ffcc00; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th, td { border: 1px solid #333; padding: 8px 12px; text-align: left; }
th { background: #1a1a2e; color: #00ff88; }
tr:nth-child(even) { background: #111122; }
tr:nth-child(odd) { background: #0d0d1a; }
.critical { color: #ff4444; font-weight: bold; }
.high { color: #ff8800; font-weight: bold; }
.medium { color: #ffcc00; }
.low { color: #88ff88; }
.summary-box { background: #111133; border: 1px solid #333; border-radius: 8px; padding: 20px; margin: 20px 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
.stat { text-align: center; }
.stat-value { font-size: 2em; font-weight: bold; color: #00ff88; }
.stat-label { color: #888; font-size: 0.85em; }
.sensitive-table td:first-child { font-family: monospace; }
.system-info { background: #111133; border: 1px solid #333; padding: 15px; border-radius: 8px; }
.system-info dt { color: #00ccff; font-weight: bold; margin-top: 8px; }
.system-info dd { margin-left: 20px; color: #ccc; }
</style>
</head>
<body>
<h1> Database Crawl Report</h1>
<p>Generated: ` + time.Now().Format(time.RFC3339) + `</p>
`)

	// Summary stats
	summary := cr.results.Summary
	sb.WriteString(fmt.Sprintf(`<div class="summary-box">
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Databases</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Tables</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Columns</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Rows</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Sensitive</div></div>
<div class="stat"><div class="stat-value">%s</div><div class="stat-label">Duration</div></div>
</div>`,
		summary.TotalDatabases, summary.TotalTables, summary.TotalColumns,
		summary.TotalRows, summary.TotalSensitive, summary.Duration))

	// System Info
	if len(cr.results.SystemInfo) > 0 {
		sb.WriteString("<h2>System Information</h2><div class=\"system-info\"><dl>")
		keys := sortedKeys(cr.results.SystemInfo)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("<dt>%s</dt><dd>%s</dd>", htmlEscape(k), htmlEscape(cr.results.SystemInfo[k])))
		}
		sb.WriteString("</dl></div>")
	}

	// Sensitive Findings
	if len(cr.results.Sensitive) > 0 {
		sb.WriteString("<h2>Sensitive Data Findings</h2><table><tr><th>Risk</th><th>Database</th><th>Table</th><th>Column</th><th>Category</th><th>Sample</th><th>Confidence</th></tr>")

		// Sort by risk
		findings := cr.results.Sensitive
		sort.Slice(findings, func(i, j int) bool {
			return riskWeight(findings[i].Risk) > riskWeight(findings[j].Risk)
		})

		for _, f := range findings {
			riskClass := strings.ToLower(f.Risk)
			sample := f.Sample
			if !cr.config.IncludeSamples {
				sample = "***"
			}
			if len(sample) > cr.config.MaxSampleLen {
				sample = sample[:cr.config.MaxSampleLen] + "..."
			}
			sb.WriteString(fmt.Sprintf(`<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.0f%%</td></tr>`,
				riskClass, htmlEscape(f.Risk), htmlEscape(f.Database), htmlEscape(f.Table),
				htmlEscape(f.Column), htmlEscape(f.Category), htmlEscape(sample), f.Confidence*100))
		}
		sb.WriteString("</table>")
	}

	// Database Structure
	sb.WriteString("<h2>Database Structure</h2>")
	for dbName, dbInfo := range cr.results.Databases {
		sb.WriteString(fmt.Sprintf("<h3>%s</h3>", htmlEscape(dbName)))
		for tblName, tblInfo := range dbInfo.Tables {
			sb.WriteString(fmt.Sprintf("<h4>%s <span style='color:#888;font-size:0.8em'>(%d rows)</span></h4>", htmlEscape(tblName), tblInfo.RowCount))
			if len(tblInfo.Columns) > 0 {
				sb.WriteString("<table><tr><th>Column</th><th>Type</th><th>Nullable</th><th>PK</th><th>Sensitive</th></tr>")
				for _, col := range tblInfo.Columns {
					sensitive := ""
					if col.IsSensitive {
						sensitive = "&#9888;"
					}
					sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%v</td><td>%v</td><td>%s</td></tr>",
						htmlEscape(col.Name), htmlEscape(col.Type), col.Nullable, col.IsPK, sensitive))
				}
				sb.WriteString("</table>")
			}
		}
	}

	// Relations
	if len(cr.results.Relations) > 0 {
		sb.WriteString("<h2>Cross-Database Relations</h2><ul>")
		for _, r := range cr.results.Relations {
			sb.WriteString(fmt.Sprintf("<li>%s</li>", htmlEscape(r)))
		}
		sb.WriteString("</ul>")
	}

	sb.WriteString("</body></html>")
	return sb.String()
}

func (cr *CrawlReport) buildTextReport() string {
	var sb strings.Builder
	summary := cr.results.Summary

	sb.WriteString("╔══════════════════════════════════════╗\n")
	sb.WriteString("║     DATABASE CRAWL REPORT            ║\n")
	sb.WriteString("╚══════════════════════════════════════╝\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	sb.WriteString("── Summary ──\n")
	sb.WriteString(fmt.Sprintf("  Databases : %d\n", summary.TotalDatabases))
	sb.WriteString(fmt.Sprintf("  Tables    : %d\n", summary.TotalTables))
	sb.WriteString(fmt.Sprintf("  Columns   : %d\n", summary.TotalColumns))
	sb.WriteString(fmt.Sprintf("  Rows      : %d\n", summary.TotalRows))
	sb.WriteString(fmt.Sprintf("  Sensitive : %d\n", summary.TotalSensitive))
	sb.WriteString(fmt.Sprintf("  Duration  : %s\n\n", summary.Duration))

	if len(cr.results.SystemInfo) > 0 {
		sb.WriteString("── System Info ──\n")
		keys := sortedKeys(cr.results.SystemInfo)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("  %-15s: %s\n", k, cr.results.SystemInfo[k]))
		}
		sb.WriteString("\n")
	}

	if len(cr.results.Sensitive) > 0 {
		sb.WriteString("── Sensitive Findings ──\n")
		for _, f := range cr.results.Sensitive {
			sb.WriteString(fmt.Sprintf("  [%s] %s.%s.%s (%s) %.0f%%\n",
				f.Risk, f.Database, f.Table, f.Column, f.Category, f.Confidence*100))
		}
		sb.WriteString("\n")
	}

	for dbName, dbInfo := range cr.results.Databases {
		sb.WriteString(fmt.Sprintf("── %s ──\n", dbName))
		for tblName, tblInfo := range dbInfo.Tables {
			sb.WriteString(fmt.Sprintf("  %s (%d rows)\n", tblName, tblInfo.RowCount))
			for _, col := range tblInfo.Columns {
				sensitive := ""
				if col.IsSensitive {
					sensitive = " [SENSITIVE]"
				}
				sb.WriteString(fmt.Sprintf("    %-25s %-20s PK:%-5v%s\n", col.Name, col.Type, col.IsPK, sensitive))
			}
		}
		sb.WriteString("\n")
	}

	if len(cr.results.Relations) > 0 {
		sb.WriteString("── Relations ──\n")
		for _, r := range cr.results.Relations {
			sb.WriteString(fmt.Sprintf("  %s\n", r))
		}
	}

	return sb.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func riskWeight(risk string) int {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

// PrintToConsole prints a formatted summary to console
func (cr *CrawlReport) PrintToConsole() {
	summary := cr.results.Summary
	if summary == nil {
		return
	}

	fmt.Println("\n═══════════════════════════════════════")
	fmt.Println("  DATABASE CRAWL RESULTS")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  %-12s → %d\n", "Databases", summary.TotalDatabases)
	fmt.Printf("  %-12s → %d\n", "Tables", summary.TotalTables)
	fmt.Printf("  %-12s → %d\n", "Columns", summary.TotalColumns)
	fmt.Printf("  %-12s → %d\n", "Rows Extracted", summary.TotalRows)
	fmt.Printf("  %-12s → %d\n", "Sensitive", summary.TotalSensitive)
	fmt.Printf("  %-12s → %d\n", "Errors", summary.TotalErrors)
	fmt.Printf("  %-12s → %s\n", "Duration", summary.Duration)
	fmt.Println("───────────────────────────────────────")

	if len(cr.results.Sensitive) > 0 {
		// Count by risk
		critical, high, medium, low := 0, 0, 0, 0
		for _, f := range cr.results.Sensitive {
			switch f.Risk {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			}
		}
		fmt.Println("\n  ⚠ SENSITIVE DATA BREAKDOWN:")
		if critical > 0 {
			fmt.Printf("    ■ CRITICAL: %d findings\n", critical)
		}
		if high > 0 {
			fmt.Printf("    ■ HIGH:     %d findings\n", high)
		}
		if medium > 0 {
			fmt.Printf("    ■ MEDIUM:   %d findings\n", medium)
		}
		if low > 0 {
			fmt.Printf("    ■ LOW:      %d findings\n", low)
		}
	}

	fmt.Println("═══════════════════════════════════════\n")
}
