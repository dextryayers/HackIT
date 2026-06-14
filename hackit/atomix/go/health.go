package main

import (
	"fmt"
	"os"
	"strings"
)

type HealthReport struct {
	Status           string   `json:"status"`
	Version          string   `json:"version"`
	TemplatesLoaded  int      `json:"templates_loaded"`
	TemplatesValid   int      `json:"templates_valid"`
	TemplatesInvalid int      `json:"templates_invalid"`
	Issues           []string `json:"issues"`
	GoVersion        string   `json:"go_version"`
	ConfigFile       string   `json:"config_file"`
}

func RunHealthCheck(cfg *ScanConfig) *HealthReport {
	report := &HealthReport{
		Status:  "ok",
		Version: "2.1.0",
		Issues:  []string{},
	}

	// Check template directory
	if _, err := os.Stat(cfg.TemplateDir); os.IsNotExist(err) {
		report.Issues = append(report.Issues, fmt.Sprintf("Template directory not found: %s", cfg.TemplateDir))
		report.Status = "degraded"
	} else {
		templates, err := LoadTemplates(cfg.TemplateDir)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("Error loading templates: %v", err))
			report.Status = "degraded"
		} else {
			report.TemplatesLoaded = len(templates)
			valid, invalid := ValidateTemplates(templates)
			report.TemplatesValid = valid
			report.TemplatesInvalid = invalid
			if invalid > 0 {
				report.Issues = append(report.Issues, fmt.Sprintf("%d invalid templates found", invalid))
				report.Status = "degraded"
			}
		}
	}

	// Check config file
	if cfg.ConfigFile != "" {
		if _, err := os.Stat(cfg.ConfigFile); os.IsNotExist(err) {
			report.Issues = append(report.Issues, fmt.Sprintf("Config file not found: %s", cfg.ConfigFile))
		} else {
			report.ConfigFile = cfg.ConfigFile
		}
	}

	// Network check
	if cfg.URL != "" {
		client := NewHTTPClient(5)
		resp, err := SendRequest(client, cfg.URL, "GET", "", nil)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("Target unreachable: %s (%v)", cfg.URL, err))
		} else {
			_ = resp
		}
	}

	return report
}

func PrintHealthReport(report *HealthReport) {
	if noColor {
		fmt.Printf("\n=== HEALTH CHECK ===\n")
		fmt.Printf("Status: %s\n", report.Status)
		fmt.Printf("Version: %s\n", report.Version)
		fmt.Printf("Templates: %d loaded (%d valid, %d invalid)\n", report.TemplatesLoaded, report.TemplatesValid, report.TemplatesInvalid)
		if report.ConfigFile != "" { fmt.Printf("Config: %s\n", report.ConfigFile) }
		if len(report.Issues) > 0 {
			fmt.Printf("Issues:\n")
			for _, issue := range report.Issues {
				fmt.Printf("  • %s\n", issue)
			}
		}
		return
	}
	statusColor := ColorGreen
	if report.Status == "degraded" { statusColor = ColorYellow }
	fmt.Printf("\n%s %s\n", SColor(ColorBCyan, "═══"), SColor(ColorBWhite, "HEALTH CHECK"))
	fmt.Printf("  %s %s\n", SColor(ColorBWhite, "Status:"), SColor(statusColor, strings.ToUpper(report.Status)))
	fmt.Printf("  %s %s\n", SColor(ColorBWhite, "Version:"), SColor(ColorCyan, report.Version))
	fmt.Printf("  %s %s\n", SColor(ColorBWhite, "Templates:"), SColor(ColorGreen, fmt.Sprintf("%d loaded (%d valid, %d invalid)", report.TemplatesLoaded, report.TemplatesValid, report.TemplatesInvalid)))
	if report.ConfigFile != "" {
		fmt.Printf("  %s %s\n", SColor(ColorBWhite, "Config:"), SColor(ColorYellow, report.ConfigFile))
	}
	if len(report.Issues) > 0 {
		fmt.Printf("  %s\n", SColor(ColorBRed, "Issues:"))
		for _, issue := range report.Issues {
			fmt.Printf("    %s %s\n", SColor(ColorRed, "•"), issue)
		}
	}
	fmt.Println()
}
