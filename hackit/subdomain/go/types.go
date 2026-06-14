package main

import (
	"fmt"
	"sync"
)

// Config holds the scan configuration
type Config struct {
	Domain       string
	Wordlist     string
	Concurrency  int
	Timeout      int
	PassiveOnly  bool
	ActiveOnly   bool
	Permutations bool
	Takeover     bool
	Recursive    bool
	Stealth      bool
	Fast         bool
	Deep         bool
	ShowSC       bool
	ShowIP       bool
	ShowTitle    bool
	ShowServer   bool
	TechDetect   bool
	ShowASN      bool
	Probe        bool
	FilterCodes  string
	Output       string
	Verbose      bool
	Common       bool
	All          bool
	NoWildcard   bool
	DNSOverHTTPS bool
	Resolve      bool
	OutputFormat string
	APIKeys      map[string]string
}

// Result represents a found subdomain
type Result struct {
	Subdomain     string   `json:"subdomain"`
	IPs           []string `json:"ips,omitempty"`
	Source        string   `json:"source"` // "active", "passive", "recursive"
	Status        int      `json:"status,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	Tech          []string `json:"tech,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	TakeoverVuln  string   `json:"takeover_vuln,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	CNAME         string   `json:"cname,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	ContentLength int      `json:"content_length,omitempty"`
	ResponseTime  string   `json:"response_time,omitempty"`
}

var (
	results      = make(map[string]*Result)
	resultsMutex sync.Mutex
	wg           sync.WaitGroup
)

func addResult(subdomain string, ips []string, source string) {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	if _, exists := results[subdomain]; !exists {
		results[subdomain] = &Result{
			Subdomain: subdomain,
			IPs:       ips,
			Source:    source,
		}
		// Real-time brief discovery output
		if len(ips) > 0 {
			fmt.Printf("\x1b[1;32m[+]\x1b[0m \x1b[1;36m[sub]\x1b[0m %s \x1b[1;36m[ip]\x1b[0m %s \x1b[1;33m[from]\x1b[0m %s\n",
				subdomain, ips[0], source)
		} else {
			fmt.Printf("\x1b[1;32m[+]\x1b[0m \x1b[1;36m[sub]\x1b[0m %s \x1b[1;33m[from]\x1b[0m %s\n",
				subdomain, source)
		}
	} else {
		existing := results[subdomain]
		if len(existing.IPs) == 0 && len(ips) > 0 {
			existing.IPs = ips
		}
	}
}

func getResults() []*Result {
	resultsMutex.Lock()
	defer resultsMutex.Unlock()

	var out []*Result
	for _, r := range results {
		out = append(out, r)
	}
	return out
}
