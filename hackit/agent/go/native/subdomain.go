package native

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SubdomainResult stores the enumerated subdomains
type SubdomainResult struct {
	Subdomains []string
}

// CrtShResult is the structure of crt.sh JSON output
type CrtShResult struct {
	NameValue string `json:"name_value"`
}

// EnumerateSubdomains performs passive OSINT to find subdomains
func EnumerateSubdomains(domain string) ([]string, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	subdomainMap := make(map[string]bool)

	// OSINT Sources
	sources := []func(string, *sync.WaitGroup, *sync.Mutex, map[string]bool){
		fetchCrtSh,
		fetchHackerTarget,
		fetchRapidDNS,
	}

	for _, source := range sources {
		wg.Add(1)
		go source(domain, &wg, &mu, subdomainMap)
	}

	wg.Wait()

	var results []string
	for sub := range subdomainMap {
		results = append(results, sub)
	}

	return results, nil
}

func fetchCrtSh(domain string, wg *sync.WaitGroup, mu *sync.Mutex, subMap map[string]bool) {
	defer wg.Done()
	
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var results []CrtShResult
	if err := json.Unmarshal(body, &results); err != nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()
	for _, entry := range results {
		// crt.sh can return multiple domains separated by newlines
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, domain) {
				subMap[name] = true
			}
		}
	}
}

func fetchHackerTarget(domain string, wg *sync.WaitGroup, mu *sync.Mutex, subMap map[string]bool) {
	defer wg.Done()
	
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	
	lines := strings.Split(string(body), "\n")
	
	mu.Lock()
	defer mu.Unlock()
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			name := strings.TrimSpace(parts[0])
			if name != "" && strings.HasSuffix(name, domain) {
				subMap[name] = true
			}
		}
	}
}

func fetchRapidDNS(domain string, wg *sync.WaitGroup, mu *sync.Mutex, subMap map[string]bool) {
	defer wg.Done()
	
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1#result", domain)
	
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	
	// Regex to find table cells that look like subdomains
	re := regexp.MustCompile(fmt.Sprintf(`(?i)<td>([a-z0-9.-]+\.%s)</td>`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)
	
	mu.Lock()
	defer mu.Unlock()
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.TrimSpace(match[1])
			if name != "" {
				subMap[name] = true
			}
		}
	}
}
