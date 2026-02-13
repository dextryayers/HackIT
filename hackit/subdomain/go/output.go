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

	// Console Output
	for _, r := range results {
		// Default mode (Silent): Just Subdomain
		if !config.ShowIP && !config.ShowSC && !config.ShowTitle && !config.ShowServer && !config.ShowASN && !config.TechDetect && !config.Probe {
			fmt.Println(r.Subdomain)
			continue
		}

		// Detailed Mode
		parts := []string{r.Subdomain}

		if config.ShowIP && len(r.IPs) > 0 {
			parts = append(parts, fmt.Sprintf("[%s]", strings.Join(r.IPs, ", ")))
		}

		if config.ShowSC && r.Status > 0 {
			color := getStatusColor(r.Status)
			parts = append(parts, fmt.Sprintf("[%sStatus: %d%s]", color, r.Status, colorReset))
		}

		if config.ShowTitle && r.Title != "" {
			parts = append(parts, fmt.Sprintf("[Title: %s]", cleanUTF8(r.Title)))
		}

		if config.ShowServer && r.Server != "" {
			parts = append(parts, fmt.Sprintf("[Server: %s]", cleanUTF8(r.Server)))
		}

		if config.ShowASN && r.ASN != "" {
			parts = append(parts, fmt.Sprintf("[ASN: %s]", r.ASN))
		}

		if config.TechDetect && len(r.Tech) > 0 {
			parts = append(parts, fmt.Sprintf("[Tech: %s]", strings.Join(r.Tech, ", ")))
		}

		if r.TakeoverVuln != "" {
			parts = append(parts, fmt.Sprintf("[%sVULN: %s%s]", colorRed, r.TakeoverVuln, colorReset))
		}

		fmt.Println(strings.Join(parts, " "))
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
