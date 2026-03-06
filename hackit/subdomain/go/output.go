package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

// cleanUTF8 removes non-printable or invalid UTF-8 characters to prevent terminal encoding errors
func cleanUTF8(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}

// getStatusColor returns ANSI color for a given status code
func getStatusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorYellow
	case code >= 400 && code < 500:
		return colorRed
	case code >= 500:
		return colorPurple
	default:
		return colorWhite
	}
}

// printResults prints the results based on configuration
func printResults(results []*Result, config Config) {
	// If Output file is specified, save JSON
	if config.Output != "" {
		saveJSON(results, config.Output)
	}

	cGreen := colorGreen
	cYellow := colorYellow
	cCyan := colorCyan
	cBlue := colorBlue
	cWhite := colorWhite
	cRed := colorRed
	cReset := colorReset

	// Console Output
	for _, r := range results {
		// Default mode (Silent): Just Subdomain
		if !config.ShowIP && !config.ShowSC && !config.ShowTitle && !config.ShowServer && !config.ShowASN && !config.TechDetect && !config.Probe {
			fmt.Printf("%s%s%s\n", cCyan, r.Subdomain, cReset)
			continue
		}

		// Expert UI Style: [+] subdomain.com [1.1.1.1] [200]
		fmt.Printf("%s[+]%s %s%-30s%s", cGreen, cReset, cWhite, r.Subdomain, cReset)

		if config.ShowIP && len(r.IPs) > 0 {
			fmt.Printf(" %s[%s]%s", cBlue, strings.Join(r.IPs, ", "), cReset)
		}

		if config.ShowSC && r.Status > 0 {
			color := getStatusColor(r.Status)
			fmt.Printf(" %s[%d]%s", color, r.Status, cReset)
		}

		if config.ShowASN && r.ASN != "" {
			fmt.Printf(" %s(%s)%s", cYellow, r.ASN, cReset)
		}

		if r.TakeoverVuln != "" {
			fmt.Printf(" %s[VULN: %s]%s", cRed, r.TakeoverVuln, cReset)
		}

		// New line for details if title/tech/server exists
		details := []string{}
		if config.ShowTitle && r.Title != "" {
			details = append(details, fmt.Sprintf("Title: %s", cleanUTF8(r.Title)))
		}
		if config.ShowServer && r.Server != "" {
			details = append(details, fmt.Sprintf("Server: %s", cleanUTF8(r.Server)))
		}
		if config.TechDetect && len(r.Tech) > 0 {
			details = append(details, fmt.Sprintf("Tech: %s", strings.Join(r.Tech, ", ")))
		}

		if len(details) > 0 {
			fmt.Printf("\n   %s|--%s %s", cCyan, cReset, strings.Join(details, " | "))
		}

		fmt.Println()
	}
}

func saveJSON(results []*Result, filename string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("[!] Error marshaling JSON: %v\n", err)
		return
	}
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("[!] Error saving output file: %v\n", err)
	}
}
