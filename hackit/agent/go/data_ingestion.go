package main

import (
	"encoding/json"
	"fmt"
)

// RawPortScanResult represents the JSON output from `python main.py ports scan --json`
type RawPortScanResult struct {
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Ports []struct {
		Port    int    `json:"port"`
		State   string `json:"state"`
		Service string `json:"service"`
		Banner  string `json:"banner"`
		Risk    int    `json:"risk"`
	} `json:"ports"`
	TotalOpen int `json:"total_open"`
}

// SubdomainResult represents JSON output from the subdomain module
type SubdomainResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

// ParsePortScanJSON parses the JSON string into actionable structs
func ParsePortScanJSON(jsonData string) ([]string, error) {
	var result RawPortScanResult
	err := json.Unmarshal([]byte(jsonData), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port scan JSON: %v", err)
	}

	var openServices []string
	for _, p := range result.Ports {
		if p.State == "open" {
			// Attach banner for deeper correlation later
			svcInfo := fmt.Sprintf("%d/%s (Banner: %s)", p.Port, p.Service, p.Banner)
			openServices = append(openServices, svcInfo)
		}
	}

	return openServices, nil
}

// ParseSubdomainJSON parses the subdomain scanner JSON
func ParseSubdomainJSON(jsonData string) ([]string, error) {
	// The new Go engine outputs an array of Result structs
	type SubdomainResult struct {
		Subdomain string `json:"subdomain"`
	}
	var results []SubdomainResult

	err := json.Unmarshal([]byte(jsonData), &results)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subdomain JSON: %v", err)
	}

	var subs []string
	for _, r := range results {
		if r.Subdomain != "" {
			subs = append(subs, r.Subdomain)
		}
	}
	return subs, nil
}
