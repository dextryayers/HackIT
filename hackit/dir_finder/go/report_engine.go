package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type ScanReport struct {
	Target        string       `json:"target"`
	Timestamp     string       `json:"timestamp"`
	Duration      string       `json:"duration"`
	TotalRequests int          `json:"total_requests"`
	Found         int          `json:"found"`
	Filtered      int          `json:"filtered"`
	Errors        int          `json:"errors"`
	Results       []DirResult  `json:"results"`
	Config        ReportConfig `json:"config"`
	WAFDetected   string       `json:"waf_detected,omitempty"`
	TechDetected  []string     `json:"tech_detected,omitempty"`
}

type ReportConfig struct {
	Threads    int      `json:"threads"`
	Extensions []string `json:"extensions,omitempty"`
	Method     string   `json:"method"`
	Wordlist   string   `json:"wordlist,omitempty"`
	Proxy      string   `json:"proxy,omitempty"`
	Recursive  bool     `json:"recursive"`
	Timeout    int      `json:"timeout"`
}

func GenerateReport(config *ScanConfig, results []DirResult, stats *ScanStats, startTime time.Time) *ScanReport {
	elapsed := time.Since(startTime)

	report := &ScanReport{
		Target:        config.Target,
		Timestamp:     startTime.Format(time.RFC3339),
		Duration:      elapsed.Round(time.Second).String(),
		TotalRequests: stats.TotalRequests,
		Found:         stats.Found,
		Filtered:      stats.Filtered,
		Errors:        stats.Errors,
		Results:       results,
		WAFDetected:   config.DetectedWAF,
		TechDetected:  config.DetectedTech,
		Config: ReportConfig{
			Threads:    config.Threads,
			Extensions: config.Extensions,
			Method:     config.Method,
			Wordlist:   formatWordlistInfo(config),
			Proxy:      config.Proxy,
			Recursive:  config.Recursive,
			Timeout:    config.Timeout,
		},
	}

	return report
}

func SaveJSONReport(report *ScanReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func PrintResultsSummary(config *ScanConfig, results []DirResult, stats *ScanStats, startTime time.Time) {
	elapsed := time.Since(startTime).Round(time.Second)

	fmt.Fprintf(color.Output, "\n%s Scan completed in %s\n", color.GreenString("[+]"), elapsed)
	fmt.Fprintf(color.Output, "%s Requests: %d | Found: %d | Filtered: %d | Errors: %d\n",
		color.CyanString("[*]"), stats.TotalRequests, stats.Found, stats.Filtered, stats.Errors)

	if len(results) > 0 {
		fmt.Fprintf(color.Output, "\n%s Results (%d found):\n", color.GreenString("[+]"), len(results))
		for _, res := range results {
			displayPath := "/" + strings.TrimPrefix(res.Path, "/")
			if config.FullURL {
				displayPath = buildFullURL(config.Target, displayPath)
			}
			fmt.Fprintf(color.Output, "  [%s] %s %s%s\n",
				color.YellowString("%d", res.Status),
				color.BlueString(displayPath),
				color.CyanString(FormatSize(res.Size)),
				formatResultTags(&res))
		}
	}
}

func formatResultTags(res *DirResult) string {
	var tags []string
	if res.IsLogin {
		tags = append(tags, "login")
	}
	if res.IsAPI {
		tags = append(tags, "api")
	}
	if res.Title != "" {
		tags = append(tags, res.Title)
	}
	if res.Redirect != "" {
		tags = append(tags, "->"+res.Redirect)
	}
	if len(tags) > 0 {
		return " /* " + strings.Join(tags, ", ") + " */"
	}
	return ""
}

func SaveLogFile(config *ScanConfig, logPath string, results []DirResult, stats *ScanStats) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Dir Finder Scan Log\n"))
	sb.WriteString(fmt.Sprintf("Target: %s\n", config.Target))
	sb.WriteString(fmt.Sprintf("Time: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Requests: %d\n", stats.TotalRequests))
	sb.WriteString(fmt.Sprintf("Found: %d\n", stats.Found))
	sb.WriteString(fmt.Sprintf("Errors: %d\n\n", stats.Errors))

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("%d %s %s\n", r.Status, r.Path, FormatSize(r.Size)))
	}

	return os.WriteFile(logPath, []byte(sb.String()), 0644)
}
