package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

var (
	software   string
	version    string
	outputFile string
)

func main() {
	flag.StringVar(&software, "software", "", "Software name")
	flag.StringVar(&version, "version", "", "Version")
	flag.StringVar(&outputFile, "output", "", "Save results to JSON file")
	flag.Parse()

	if software == "" || version == "" {
		fmt.Println("Error: --software and --version are required")
		os.Exit(1)
	}

	fmt.Printf("[*] Checking %s %s...\n", software, version)

	fetcher := NewFetcher()
	cves := fetcher.Fetch(software, version)

	result := Result{
		Software:   software,
		Version:    version,
		Vulnerable: len(cves) > 0,
		Count:      len(cves),
		CVEs:       cves,
	}

	if result.Vulnerable {
		fmt.Printf("\n[!] FOUND %d VULNERABILITIES:\n", result.Count)
		for _, cve := range result.CVEs {
			severity := "Medium"
			if cve.CVSS >= 9.0 {
				severity = "Critical"
			} else if cve.CVSS >= 7.0 {
				severity = "High"
			} else if cve.CVSS < 4.0 {
				severity = "Low"
			}
			cve.Severity = severity

			// Color output (ANSI)
			color := "\033[33m" // Yellow
			if severity == "Critical" || severity == "High" {
				color = "\033[31m" // Red
			}
			reset := "\033[0m"

			fmt.Printf("    %s[%s] %s%s\n", color, severity, cve.ID, reset)
			fmt.Printf("    %s\n\n", cve.Description)
		}
	} else {
		fmt.Println("\n[✓] No vulnerabilities found (via public API).")
	}

	if outputFile != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		} else {
			err = os.WriteFile(outputFile, data, 0644)
			if err != nil {
				fmt.Printf("Error writing file: %v\n", err)
			} else {
				fmt.Printf("[+] Results saved to %s\n", outputFile)
			}
		}
	}
}
