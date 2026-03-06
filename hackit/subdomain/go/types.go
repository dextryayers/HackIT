package main

import "sync"

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
	APIKeys      map[string]string
}

// Result represents a found subdomain
type Result struct {
	Subdomain    string   `json:"subdomain"`
	IPs          []string `json:"ips,omitempty"`
	Source       string   `json:"source"` // "active", "passive", "recursive"
	Status       int      `json:"status,omitempty"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	Tech         []string `json:"tech,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	TakeoverVuln string   `json:"takeover_vuln,omitempty"`
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
		// Basic print (detailed print will be handled by orchestrator/prober)
		// fmt.Printf("[+] Found: %s\n", subdomain)
	} else {
		// Merge IPs if needed
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
