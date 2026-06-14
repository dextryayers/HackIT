package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

func FormatResultsJSON(results []Result) string {
	j, _ := json.MarshalIndent(results, "", "  ")
	return string(j)
}

func FormatResultsJSONL(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		j, _ := json.Marshal(r)
		b.WriteString(string(j) + "\n")
	}
	return b.String()
}

func FormatResultsCSV(results []Result) string {
	var b strings.Builder
	writer := csv.NewWriter(&b)
	writer.Write([]string{"TemplateID", "TemplateName", "Severity", "URL", "MatcherName", "Extracted", "Tags", "Timestamp"})
	for _, r := range results {
		writer.Write([]string{
			r.TemplateID, r.TemplateName, r.Severity, r.URL,
			r.MatcherName, r.Extracted, r.Tags, r.Timestamp,
		})
	}
	writer.Flush()
	return b.String()
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifResult struct {
	RuleID    string         `json:"ruleId"`
	Message   SarifMessage   `json:"message"`
	Locations []SarifLocation `json:"locations"`
	Level     string         `json:"level"`
}

type SarifRule struct {
	ID               string       `json:"id"`
	ShortDescription SarifMessage `json:"shortDescription"`
	FullDescription  SarifMessage `json:"fullDescription"`
	Severity         string       `json:"defaultConfiguration"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifLog struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

func FormatResultsSarif(results []Result) string {
	rules := make([]SarifRule, 0)
	sarifResults := make([]SarifResult, 0)
	for _, r := range results {
		level := "note"
		switch strings.ToLower(r.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low":
			level = "note"
		}
		rules = append(rules, SarifRule{
			ID: r.TemplateID,
			ShortDescription: SarifMessage{Text: r.TemplateName},
			FullDescription:  SarifMessage{Text: r.Description},
		})
		sarifResults = append(sarifResults, SarifResult{
			RuleID:  r.TemplateID,
			Message: SarifMessage{Text: r.MatcherName},
			Locations: []SarifLocation{{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{URI: r.URL},
					Region: SarifRegion{StartLine: 1},
				},
			}},
			Level: level,
		})
	}
	log := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SarifRun{{
			Tool: SarifTool{
				Driver: SarifDriver{
					Name: "Atomix", Version: "2.1.0",
					InformationURI: "https://github.com/aniipid/hackit",
					Rules: rules,
				},
			},
			Results: sarifResults,
		}},
	}
	j, _ := json.MarshalIndent(log, "", "  ")
	return string(j)
}

func PrintResults(results []Result) {
	if len(results) == 0 { return }
	PrintFindingsTable(results)
}

func PrintTemplateList(templates []*Template) {
	if noColor {
		fmt.Printf("[+] Loaded %d templates:\n", len(templates))
		for _, t := range templates {
			fmt.Printf("  %-30s | %-8s | %s\n", t.ID, t.Info.Severity, t.Info.Name)
		}
		return
	}
	fmt.Printf("\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, fmt.Sprintf("TEMPLATES (%d)", len(templates))))
	for _, t := range templates {
		id := SColor(ColorCyan, t.ID)
		sev := SColor(SeverityColor(t.Info.Severity), fmt.Sprintf("%-8s", t.Info.Severity))
		name := SColor(ColorBWhite, t.Info.Name)
		fmt.Printf("  %s | %s | %s\n", id, sev, name)
	}
	fmt.Println()
}

func PrintLoadingInfo(count int, filters FilterOptions) {
	if noColor {
		fmt.Fprintf(os.Stderr, "[*] Loaded %d templates\n", count)
		if filters.Severity != "" { fmt.Fprintf(os.Stderr, "    Filter: severity=%s\n", filters.Severity) }
		if len(filters.Tags) > 0 { fmt.Fprintf(os.Stderr, "    Filter: tags=%s\n", strings.Join(filters.Tags, ",")) }
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", SColor(ColorGreen, "[+]"), SColor(ColorBWhite, fmt.Sprintf("Loaded %d templates", count)))
	if filters.Severity != "" || len(filters.Tags) > 0 || len(filters.ExcludeTags) > 0 {
		parts := []string{}
		if filters.Severity != "" { parts = append(parts, fmt.Sprintf("severity=%s", filters.Severity)) }
		if len(filters.Tags) > 0 { parts = append(parts, fmt.Sprintf("tags=%s", strings.Join(filters.Tags, ","))) }
		if len(filters.ExcludeTags) > 0 { parts = append(parts, fmt.Sprintf("exclude-tags=%s", strings.Join(filters.ExcludeTags, ","))) }
		fmt.Fprintf(os.Stderr, "%s %s\n", SColor(ColorDim, "   Filter:"), SColor(ColorYellow, strings.Join(parts, ", ")))
	}
}

func PrintScanStart(url string, threads, timeout int, count int) {
	if noColor {
		fmt.Fprintf(os.Stderr, "[*] Scanning target: %s\n", url)
		fmt.Fprintf(os.Stderr, "[*] %d templates | %d threads | %ds timeout\n", count, threads, timeout)
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", SColor(ColorBCyan, "►"), SColor(ColorBWhite, fmt.Sprintf("Scanning target: %s", url)))
	fmt.Fprintf(os.Stderr, "  %s %d templates | %d threads | %ds timeout | %s\n",
		SColor(ColorCyan, "⚡"), count, threads, timeout, SColor(ColorDim, "Press Ctrl+C to stop"))
}

func PrintResultRealTime(r Result) {
	if noColor {
		fmt.Fprintf(os.Stderr, "\r  [%s] %s | %s\n", strings.ToUpper(r.Severity), r.URL, r.TemplateID)
		return
	}
	sev := strings.ToUpper(r.Severity)
	sevColor := SeverityColor(r.Severity)
	sevBg := SeverityBgColor(r.Severity)
	fmt.Fprintf(os.Stderr, "\r  %s%s %s%s %s %s %s\n",
		sevBg, SColor(sevColor, fmt.Sprintf(" [%s] ", sev)),
		SColor(ColorReset, ""),
		SColor(ColorBWhite, r.URL),
		SColor(ColorCyan, fmt.Sprintf("(%s)", r.TemplateID)),
		SColor(ColorDim, fmt.Sprintf("[%s]", r.MatcherName)),
		SColor(ColorGreen, r.Tags))
}

func PrintError(url string, err error) {
	if noColor {
		fmt.Fprintf(os.Stderr, "  [!] %s: %v\n", url, err)
		return
	}
	fmt.Fprintf(os.Stderr, "\r  %s %s: %v\n", SColor(ColorRed, "[!]"), SColor(ColorDim, url), err)
}

func PrintFindingsTable(results []Result) {
	if len(results) == 0 { return }
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tTEMPLATE\tURL\tMATCHER\tTAGS")
	fmt.Fprintln(w, "--------\t--------\t---\t-------\t----")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(r.Severity), r.TemplateID, r.URL, r.MatcherName, r.Tags)
	}
	w.Flush()
	fmt.Println()
}

func PrintStats(stats *ScanStats) {
	if noColor {
		fmt.Fprintf(os.Stderr, "\n[STATS] Templates: %d/%d | Requests: %d | Findings: %d | Errors: %d | Duration: %s\n",
			stats.TemplatesTested, stats.TemplatesTotal, stats.RequestsSent,
			stats.Findings, stats.Errors, stats.Duration)
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", SColor(ColorBCyan, "═══"), SColor(ColorBWhite, "SCAN STATISTICS"))
	fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Templates tested:"), SColor(ColorGreen, fmt.Sprintf("%d/%d", stats.TemplatesTested, stats.TemplatesTotal)))
	fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Requests sent:"), SColor(ColorCyan, fmt.Sprintf("%d", stats.RequestsSent)))
	fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Findings:"), SColor(ColorBRed, fmt.Sprintf("%d", stats.Findings)))
	fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Errors:"), SColor(ColorRed, fmt.Sprintf("%d", stats.Errors)))
	fmt.Fprintf(os.Stderr, "  %s %s\n", SColor(ColorBWhite, "Duration:"), SColor(ColorYellow, stats.Duration))
}

func WriteOutput(results []Result, config *ScanConfig, stats *ScanStats) error {
	var content string
	switch {
	case config.JSON:
		content = FormatResultsJSON(results)
	case config.JSONL:
		content = FormatResultsJSONL(results)
	case config.CSV:
		content = FormatResultsCSV(results)
	case config.SARIF:
		content = FormatResultsSarif(results)
	case config.Markdown != "":
		content = GenerateMarkdownReport(results, stats)
	case config.HTML:
		content = GenerateHTMLReport(results, stats)
	default:
		content = FormatResultsJSON(results)
	}
	if config.OutputFile == "" {
		fmt.Println(content)
		return nil
	}
	return os.WriteFile(config.OutputFile, []byte(content), 0644)
}
