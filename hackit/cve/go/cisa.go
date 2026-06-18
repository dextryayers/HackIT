package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CISAKEV struct {
	Title           string `json:"title"`
	VulnerabilityName string `json:"vulnerabilityName"`
	CVEID           string `json:"cveID"`
	ShortDescription string `json:"shortDescription"`
	RequiredAction  string `json:"requiredAction"`
	DueDate         string `json:"dueDate"`
	DateAdded       string `json:"dateAdded"`
}

type CISAResponse struct {
	Vulnerabilities []CISAKEV `json:"vulnerabilities"`
}

var (
	cisaCache     []CISAKEV
	cisaCacheMu   sync.Mutex
	cisaCacheTime time.Time
	cisaCacheTTL  = 1 * time.Hour
)

func loadCISACache() []CISAKEV {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	cachePath := filepath.Join(dir, "cisa_cache.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil
	}
	var resp CISAResponse
	if json.Unmarshal(data, &resp) != nil {
		return nil
	}
	return resp.Vulnerabilities
}

func saveCISACache(vulns []CISAKEV) {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	cachePath := filepath.Join(dir, "cisa_cache.json")
	resp := CISAResponse{Vulnerabilities: vulns}
	data, _ := json.Marshal(resp)
	os.WriteFile(cachePath, data, 0644)
}

func fetchCISAList() []CISAKEV {
	cisaCacheMu.Lock()
	if time.Since(cisaCacheTime) < cisaCacheTTL && len(cisaCache) > 0 {
		cached := cisaCache
		cisaCacheMu.Unlock()
		return cached
	}
	cisaCacheMu.Unlock()

	// Try cache file first
	if cached := loadCISACache(); len(cached) > 0 {
		cisaCacheMu.Lock()
		cisaCache = cached
		cisaCacheTime = time.Now()
		cisaCacheMu.Unlock()
		return cached
	}

	apiURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		debugCVE("CISA API error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var cisaResp CISAResponse
	if err := json.Unmarshal(body, &cisaResp); err != nil {
		debugCVE("CISA parse error: %v", err)
		return nil
	}

	// Cache
	cisaCacheMu.Lock()
	cisaCache = cisaResp.Vulnerabilities
	cisaCacheTime = time.Now()
	cisaCacheMu.Unlock()

	saveCISACache(cisaResp.Vulnerabilities)
	debugCVE("CISA KEV: loaded %d entries", len(cisaResp.Vulnerabilities))
	return cisaResp.Vulnerabilities
}

func CheckCISA(cveID string) string {
	list := fetchCISAList()
	if list == nil {
		return "CISA API unavailable (using cache)"
	}
	for _, kev := range list {
		if strings.EqualFold(kev.CVEID, cveID) {
			desc := kev.VulnerabilityName
			if desc == "" {
				desc = kev.ShortDescription
			}
			if len(desc) > 80 {
				desc = desc[:80] + "..."
			}
			action := kev.RequiredAction
			if action == "" {
				action = "Apply vendor mitigations"
			}
			if len(action) > 60 {
				action = action[:60] + "..."
			}
			return fmt.Sprintf("YES | %s | Due: %s | Action: %s",
				desc, kev.DueDate, action)
		}
	}
	return "No"
}

var cveDBg = false

func debugCVE(format string, args ...interface{}) {
	if cveDBg {
		fmt.Fprintf(os.Stderr, "[CVE-DBG] "+format+"\n", args...)
	}
}
