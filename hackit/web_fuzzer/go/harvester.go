package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Harvester provides multi-source parameter discovery
type Harvester struct {
	Client *http.Client
}

func NewHarvester() *Harvester {
	return &Harvester{
		Client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (h *Harvester) fetchWithRetry(url string) (io.ReadCloser, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", GetRandomUA())
		
		resp, err := h.Client.Do(req)
		if err == nil {
			if resp.StatusCode == 200 {
				return resp.Body, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("status: %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		
		fmt.Fprintf(os.Stderr, "[!] GO: Error fetching %s. Retrying %d/3...\n", url, i+1)
		time.Sleep(5 * time.Second)
	}
	return nil, lastErr
}

// Harvest collects URLs from many public intelligence sources
func (h *Harvester) Harvest(domain string) []string {
	var wg sync.WaitGroup
	urlChan := make(chan string, 1000)
	results := make(map[string]bool)
	var mu sync.Mutex

	sources := []func(string, chan<- string){
		h.fetchWayback,
		h.fetchOTX,
		h.fetchCommonCrawl,
		h.fetchURLScan,
	}

	for _, source := range sources {
		wg.Add(1)
		go func(s func(string, chan<- string)) {
			defer wg.Done()
			s(domain, urlChan)
		}(source)
	}

	// Collector goroutine
	done := make(chan bool)
	go func() {
		for u := range urlChan {
			if (strings.Contains(u, "?") || strings.Contains(u, "=")) && !HasExtension(u) {
				cleaned := CleanURL(u)
				mu.Lock()
				results[cleaned] = true
				mu.Unlock()
			}
		}
		done <- true
	}()

	wg.Wait()
	close(urlChan)
	<-done

	final := make([]string, 0, len(results))
	for u := range results {
		final = append(final, u)
	}
	return final
}

func (h *Harvester) fetchWayback(domain string, out chan<- string) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey", domain)
	body, err := h.fetchWithRetry(url)
	if err != nil {
		return
	}
	defer body.Close()

	var data [][]string
	if err := json.NewDecoder(body).Decode(&data); err == nil {
		for i, row := range data {
			if i == 0 {
				continue
			}
			if len(row) > 2 {
				out <- row[2]
			}
		}
	}
}

func (h *Harvester) fetchOTX(domain string, out chan<- string) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500", domain)
	body, err := h.fetchWithRetry(url)
	if err != nil {
		return
	}
	defer body.Close()

	var data struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if err := json.NewDecoder(body).Decode(&data); err == nil {
		for _, item := range data.URLList {
			out <- item.URL
		}
	}
}

func (h *Harvester) fetchCommonCrawl(domain string, out chan<- string) {
	// Index for 2024
	url := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s/*&output=json", domain)
	body, err := h.fetchWithRetry(url)
	if err != nil {
		return
	}
	defer body.Close()

	scanner := regexp.MustCompile(`"url":\s*"([^"]+)"`)
	content, _ := io.ReadAll(body)
	matches := scanner.FindAllStringSubmatch(string(content), -1)
	for _, m := range matches {
		if len(m) > 1 {
			out <- m[1]
		}
	}
}

func (h *Harvester) fetchURLScan(domain string, out chan<- string) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	body, err := h.fetchWithRetry(url)
	if err != nil {
		return
	}
	defer body.Close()

	var data struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(body).Decode(&data); err == nil {
		for _, r := range data.Results {
			out <- r.Page.URL
		}
	}
}

// DeepScanJS crawls found JS files to find more endpoints/parameters
func (h *Harvester) DeepScanJS(urls []string) []string {
	var extraParams []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	sem := make(chan struct{}, 20) // High concurrency
	
	jsRegex := regexp.MustCompile(`(?i)\.js(\?|$)`)
	// Aggressive regex for params, endpoints, and secrets
	paramRegex := regexp.MustCompile(`(?i)(?:["']|&|\?|var |let |const )([a-z0-9_-]+)\s*[:=]\s*`)
	endpointRegex := regexp.MustCompile(`(?i)["'](\/[a-z0-9_\-\/]+(?:[\?\#][a-z0-9_\-\=\&]*)?)["']`)
	secretsRegex := regexp.MustCompile(`(?i)(api_key|token|secret|password|auth|creds|debug|admin|root|test)\b`)

	visited := make(map[string]bool)

	for _, u := range urls {
		if jsRegex.MatchString(u) && !visited[u] {
			visited[u] = true
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				
				resp, err := h.Client.Get(url)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				
				body, _ := io.ReadAll(resp.Body)
				content := string(body)

				// 1. Extract Parameters
				matches := paramRegex.FindAllStringSubmatch(content, -1)
				// 2. Extract Endpoints
				eMatches := endpointRegex.FindAllStringSubmatch(content, -1)
				// 3. Extract Vulnerable Markers
				sMatches := secretsRegex.FindAllString(content, -1)
				
				mu.Lock()
				for _, m := range matches { if len(m) > 1 { extraParams = append(extraParams, m[1]) } }
				for _, m := range eMatches { if len(m) > 1 { extraParams = append(extraParams, m[1]) } }
				for _, m := range sMatches { extraParams = append(extraParams, m) }
				mu.Unlock()
			}(u)
		}
	}
	wg.Wait()
	return extraParams
}

// ExtractForms visits the main page and extracts hidden input fields
func (h *Harvester) ExtractForms(domain string) []string {
	url := "http://" + domain
	if !strings.HasPrefix(domain, "http") {
		url = "http://" + domain
	} else {
		url = domain
	}

	resp, err := h.Client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	var params []string
	// Find name="..." or id="..." in input tags
	inputRegex := regexp.MustCompile(`(?i)<input[^>]+(?:name|id)=["']([^"']+)["']`)
	matches := inputRegex.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 {
			params = append(params, m[1])
		}
	}
	return params
}
