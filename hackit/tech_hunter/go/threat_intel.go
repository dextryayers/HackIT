package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ThreatIntelResult struct {
	VirusTotal struct {
		Detections int      `json:"detections"`
		Malicious  bool     `json:"malicious"`
		Categories []string `json:"categories"`
	} `json:"virustotal,omitempty"`
	AlienVault struct {
		PassiveDNS []string `json:"passive_dns"`
		URLs       []string `json:"urls"`
		Malware    bool     `json:"malware"`
	} `json:"alienvault,omitempty"`
	SecurityTrails struct {
		Subdomains []string `json:"subdomains"`
		Historical []string `json:"historical"`
	} `json:"securitytrails,omitempty"`
	HaveIBeenPwned   bool     `json:"haveibeenpwned"`
	Blacklisted      bool     `json:"blacklisted"`
	BlacklistSources []string `json:"blacklist_sources"`
	PhishingDetected bool     `json:"phishing_detected"`
	URLScanResults   []string `json:"urlscan,omitempty"`
}

func CollectThreatIntel(domain string) *ThreatIntelResult {
	res := &ThreatIntelResult{}

	// Check AlienVault OTX for passive DNS
	av := fetchAlienVaultOTX(domain)
	if av != nil {
		res.AlienVault = *av
	}

	// URLScan.io for recent screenshots/scan data
	scan := fetchURLScanIO(domain)
	if len(scan) > 0 {
		res.URLScanResults = scan
	}

	// Check blacklists
	blacklists := checkBlacklists(domain)
	if len(blacklists) > 0 {
		res.Blacklisted = true
		res.BlacklistSources = blacklists
	}

	return res
}

func fetchAlienVaultOTX(domain string) *struct {
	PassiveDNS []string `json:"passive_dns"`
	URLs       []string `json:"urls"`
	Malware    bool     `json:"malware"`
} {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=5", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	var urls []string
	for _, u := range result.URLList {
		if u.URL != "" {
			urls = append(urls, u.URL)
		}
	}
	return &struct {
		PassiveDNS []string `json:"passive_dns"`
		URLs       []string `json:"urls"`
		Malware    bool     `json:"malware"`
	}{
		URLs: urls,
	}
}

func checkBlacklists(domain string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	var sources []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Run checks in parallel
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, err := client.Get(fmt.Sprintf("https://www.google.com/safebrowsing/diagnostic?site=%s", domain))
		if err == nil && resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(strings.ToLower(string(body)), "dangerous") || strings.Contains(strings.ToLower(string(body)), "malware") {
				mu.Lock()
				sources = append(sources, "Google Safe Browsing")
				mu.Unlock()
			}
		}
	}()
	go func() {
		defer wg.Done()
		resp2, err := client.Get(fmt.Sprintf("https://checkurl.phishtank.com/checkurl/?url=%s", domain))
		if err == nil && resp2.StatusCode == 200 {
			mu.Lock()
			sources = append(sources, "PhishTank")
			mu.Unlock()
			resp2.Body.Close()
		}
	}()

	wg.Wait()
	return sources
}

func fetchURLScanIO(domain string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=5", domain))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	var urls []string
	for _, r := range result.Results {
		if r.Page.URL != "" {
			urls = append(urls, r.Page.URL)
		}
	}
	return urls
}
