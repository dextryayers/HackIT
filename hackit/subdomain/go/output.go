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
	if config.Output != "" {
		saveJSON(results, config.Output)
	}

	cGreen := colorGreen
	cCyan := colorCyan
	cBlue := colorBlue
	cWhite := colorWhite
	cRed := colorRed
	cReset := colorReset

	for _, r := range results {
		// Silent Mode
		if !config.ShowIP && !config.ShowSC && !config.ShowTitle && !config.ShowServer && !config.ShowASN && !config.TechDetect && !config.Probe {
			fmt.Printf("%s%s%s\n", cCyan, r.Subdomain, cReset)
			continue
		}

		// > Subdomain : [sub.example.com]
		out := fmt.Sprintf("> Subdomain : [%s%s%s]", cGreen, r.Subdomain, cReset)

		// | IP [IP address]
		if config.ShowIP && len(r.IPs) > 0 {
			out += fmt.Sprintf(" | IP [%s%s%s]", cBlue, r.IPs[0], cReset) // taking first IP for neatness or join
		}

		// | SC : [200]
		if config.ShowSC && r.Status > 0 {
			color := getStatusColor(r.Status)
			out += fmt.Sprintf(" | SC : [%s%d%s]", color, r.Status, cReset)
		}

		// | Title : [title web]
		if config.ShowTitle && r.Title != "" {
			out += fmt.Sprintf(" | Title : [%s%s%s]", cWhite, cleanUTF8(r.Title), cReset)
		}

		// | Server/ASN : [ Nginx v.x.x ]
		serverAsnParts := []string{}
		if config.ShowServer && r.Server != "" {
			serverAsnParts = append(serverAsnParts, cleanUTF8(r.Server))
		}
		if config.ShowASN && r.ASN != "" {
			serverAsnParts = append(serverAsnParts, r.ASN)
		}
		if len(serverAsnParts) > 0 {
			out += fmt.Sprintf(" | Server/ASN : [%s%s%s]", cBlue, strings.Join(serverAsnParts, " - "), cReset)
		}

		if r.WAF != "" {
			out += fmt.Sprintf(" | WAF : [%s%s%s]", cRed, r.WAF, cReset)
		}

		if r.CNAME != "" {
			out += fmt.Sprintf(" | CNAME : [%s%s%s]", cCyan, r.CNAME, cReset)
		}

		if r.TakeoverVuln != "" {
			out += fmt.Sprintf(" | Takeover : [%s%s%s]", cRed, r.TakeoverVuln, cReset)
		}
		
		fmt.Println(out)
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
