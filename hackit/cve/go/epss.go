package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type EPSSResponse struct {
	Data []struct {
		CVE   string `json:"cve"`
		EPSS  float64 `json:"epss"`
		Date  string  `json:"date"`
		Percentile float64 `json:"percentile,omitempty"`
	} `json:"data"`
	Status string `json:"status"`
}

var (
	epssCache   = make(map[string]float64)
	epssCacheMu sync.Mutex
	epssClient  = &http.Client{Timeout: 15 * time.Second}
	epssSema    = make(chan struct{}, 2)
)

func QueryEPSS(cveID string) float64 {
	epssCacheMu.Lock()
	if score, ok := epssCache[cveID]; ok {
		epssCacheMu.Unlock()
		return score
	}
	epssCacheMu.Unlock()

	epssSema <- struct{}{}
	defer func() { <-epssSema }()

	apiURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", url.QueryEscape(cveID))
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")
	req.Header.Set("Accept", "application/json")

	resp, err := epssClient.Do(req)
	if err != nil {
		debugCVE("EPSS error for %s: %v", cveID, err)
		return -1
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var epssResp EPSSResponse
	if err := json.Unmarshal(body, &epssResp); err != nil {
		return -1
	}

	if len(epssResp.Data) == 0 {
		return -1
	}

	score := epssResp.Data[0].EPSS
	epssCacheMu.Lock()
	epssCache[cveID] = score
	epssCacheMu.Unlock()

	return score
}

// Batch EPSS query for multiple CVEs
func BatchQueryEPSS(cveIDs []string) map[string]float64 {
	results := make(map[string]float64)
	var unique []string
	seen := make(map[string]bool)

	for _, cid := range cveIDs {
		if seen[cid] {
			continue
		}
		seen[cid] = true
		unique = append(unique, cid)
	}

	if len(unique) == 0 {
		return results
	}

	// Query in batches of 50
	batchSize := 50
	for i := 0; i < len(unique); i += batchSize {
		end := i + batchSize
		if end > len(unique) {
			end = len(unique)
		}
		batch := unique[i:end]
		apiURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s",
			url.QueryEscape(strings.Join(batch, ",")))

		req, _ := http.NewRequest("GET", apiURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (CVE Scanner)")
		req.Header.Set("Accept", "application/json")

		resp, err := epssClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var epssResp EPSSResponse
		if json.Unmarshal(body, &epssResp) != nil {
			continue
		}
		for _, d := range epssResp.Data {
			results[d.CVE] = d.EPSS
			epssCacheMu.Lock()
			epssCache[d.CVE] = d.EPSS
			epssCacheMu.Unlock()
		}
	}

	return results
}

func epssLabel(score float64) string {
	if score < 0 {
		return "N/A"
	}
	switch {
	case score >= 0.9:
		return "CRITICAL"
	case score >= 0.5:
		return "HIGH"
	case score >= 0.1:
		return "MEDIUM"
	case score >= 0.01:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
