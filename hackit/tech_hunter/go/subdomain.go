package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

// SubdomainResult stores findings for a specific subdomain
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"`
}

// PerformSubdomainRecon performs passive/active subdomain discovery
func PerformSubdomainRecon(domain string) []SubdomainResult {
	results := []SubdomainResult{}
	found := make(map[string]bool)

	// 1. HackerTarget Engine
	htSubs := fetchHackerTarget(domain)
	for _, s := range htSubs {
		if !found[s] {
			results = append(results, SubdomainResult{Subdomain: s, Source: "HackerTarget"})
			found[s] = true
		}
	}

	// 2. Crt.sh Engine (Certificate Transparency)
	crtSubs := fetchCrtsh(domain)
	for _, s := range crtSubs {
		if !found[s] {
			results = append(results, SubdomainResult{Subdomain: s, Source: "Crt.sh"})
			found[s] = true
		}
	}

	// 3. Local Common Subdomains (Quick Discovery)
	common := []string{"www", "dev", "staging", "api", "vpn", "mail", "admin"}
	for _, sub := range common {
		target := fmt.Sprintf("%s.%s", sub, domain)
		if !found[target] {
			ips, err := net.LookupHost(target)
			if err == nil {
				results = append(results, SubdomainResult{Subdomain: target, IPs: ips, Source: "Brute"})
				found[target] = true
			}
		}
	}
	
	return results
}

func fetchHackerTarget(domain string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := client.Get(url)
	if err != nil { return nil }
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	subs := []string{}
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			subs = append(subs, parts[0])
		}
	}
	return subs
}

func fetchCrtsh(domain string) []string {
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := client.Get(url)
	if err != nil { return nil }
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	raw := string(body)
	subs := []string{}
	// Find all common_name occurrences
	parts := strings.Split(raw, "common_name\":\"")
	for i, p := range parts {
		if i == 0 { continue }
		sub := strings.Split(p, "\"")[0]
		if strings.HasSuffix(sub, domain) && !strings.Contains(sub, "*") {
			subs = append(subs, sub)
		}
	}
	return subs
}

func (res *Result) AddSubdomains(domain string) {
	subs := PerformSubdomainRecon(domain)
	for _, s := range subs {
		res.Technologies[s.Subdomain] = TechInfo{
			Name: "Subdomain",
			Category: "Infrastructure",
			Confidence: 100,
			Version: s.Source,
		}
	}
}
