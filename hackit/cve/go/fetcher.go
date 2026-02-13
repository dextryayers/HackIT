package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"summary"` // mapped from cve.circl.lu response
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity,omitempty"`
}

type Result struct {
	Software    string `json:"software"`
	Version     string `json:"version"`
	Vulnerable  bool   `json:"vulnerable"`
	Count       int    `json:"count"`
	CVEs        []CVE  `json:"cves"`
}

type Fetcher struct {
	Client *http.Client
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (f *Fetcher) Fetch(software, version string) []CVE {
	// Real implementation would query an API.
	// For this demonstration/tool, let's use cve.circl.lu API
	// https://cve.circl.lu/api/search/software/version

	url := fmt.Sprintf("https://cve.circl.lu/api/search/%s/%s", software, version)
	
	resp, err := f.Client.Get(url)
	if err != nil {
		fmt.Printf("[!] Error querying API: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var rawCVEs []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawCVEs); err != nil {
		return nil
	}

	var cves []CVE
	for _, item := range rawCVEs {
		id, _ := item["id"].(string)
		summary, _ := item["summary"].(string)
		cvss, _ := item["cvss"].(float64)

		if id != "" {
			cves = append(cves, CVE{
				ID:          id,
				Description: summary,
				CVSS:        cvss,
			})
		}
	}

	return cves
}
