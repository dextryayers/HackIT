package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func cleanUTF8(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}

func printResults(results []*Result, config Config) {
	if config.Output != "" {
		saveOutput(results, config)
	}
}

func saveOutput(results []*Result, config Config) {
	switch config.OutputFormat {
	case "json":
		saveJSON(results, config.Output)
	case "csv":
		saveCSV(results, config.Output)
	default:
		saveText(results, config.Output)
	}
}

func saveText(results []*Result, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[!] Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	for _, r := range results {
		ipStr := "-"
		if len(r.IPs) > 0 {
			ipStr = r.IPs[0]
		}
		titleStr := r.Title
		if titleStr == "" {
			titleStr = "-"
		}
		asnStr := r.ASN
		if asnStr == "" {
			asnStr = "-"
		}
		scStr := "-"
		if r.Status > 0 {
			scStr = fmt.Sprintf("%d", r.Status)
		}
		lenStr := "-"
		if r.ContentLength > 0 {
			lenStr = fmt.Sprintf("%d", r.ContentLength)
		}
		svrStr := r.Server
		if svrStr == "" {
			svrStr = "-"
		}
		timeStr := r.ResponseTime
		if timeStr == "" {
			timeStr = "-"
		}
		cdnStr := r.CDN
		if cdnStr == "" {
			cdnStr = "-"
		}
		techStr := "-"
		if len(r.Tech) > 0 {
			techStr = strings.Join(r.Tech, ",")
		}

		file.WriteString(fmt.Sprintf("[+] [sub] %s [ip] %s [title] %s [asn] %s [sc] %s [len] %s [server] %s [time] %s [cdn] %s [tech] %s\n",
			r.Subdomain, ipStr, titleStr, asnStr, scStr, lenStr, svrStr, timeStr, cdnStr, techStr))
	}
}

func saveJSON(results []*Result, filename string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("[!] Error marshaling JSON: %v\n", err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("[!] Error saving JSON: %v\n", err)
	} else {
		fmt.Printf("  [\033[1;32m+\033[0m] JSON saved: %s\n", filename)
	}
}

func saveCSV(results []*Result, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[!] Error creating CSV: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"subdomain", "ip", "source", "status", "title", "server", "tech", "asn", "cdn", "cname", "waf", "takeover", "content_length", "response_time"})

	for _, r := range results {
		ipStr := ""
		if len(r.IPs) > 0 {
			ipStr = r.IPs[0]
		}
		writer.Write([]string{
			r.Subdomain,
			ipStr,
			r.Source,
			fmt.Sprintf("%d", r.Status),
			r.Title,
			r.Server,
			strings.Join(r.Tech, ";"),
			r.ASN,
			r.CDN,
			r.CNAME,
			r.WAF,
			r.TakeoverVuln,
			fmt.Sprintf("%d", r.ContentLength),
			r.ResponseTime,
		})
	}
}
