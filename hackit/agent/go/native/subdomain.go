package native

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var hostnamePattern = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`,
)

// normalizeSubdomain coerces a source value (which may be a URL, a wildcard or
// an error message containing the target) into a valid subdomain of domain.
func normalizeSubdomain(name, domain string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	if strings.Contains(name, "://") {
		if parsed, err := url.Parse(name); err == nil && parsed.Hostname() != "" {
			name = parsed.Hostname()
		}
	} else if strings.ContainsAny(name, "/?#") {
		if parsed, err := url.Parse("//" + name); err == nil && parsed.Hostname() != "" {
			name = parsed.Hostname()
		}
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || name == domain || net.ParseIP(name) != nil {
		return ""
	}
	if !hostnamePattern.MatchString(name) {
		return ""
	}
	if !strings.HasSuffix(name, "."+domain) {
		return ""
	}
	return name
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	if strings.Contains(domain, "://") {
		if parsed, err := url.Parse(domain); err == nil && parsed.Hostname() != "" {
			domain = parsed.Hostname()
		}
	}
	return strings.TrimSuffix(domain, ".")
}

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
	domain = normalizeDomain(domain)
	if domain == "" {
		return []string{}, nil
	}
	if net.ParseIP(domain) != nil || !hostnamePattern.MatchString(domain) {
		// IP addresses and single-label hosts cannot have public subdomains;
		// querying OSINT sources for them only produces noise.
		return []string{}, nil
	}

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

	seen := make(map[string]bool)
	var results []string
	for sub := range subdomainMap {
		normalized := normalizeSubdomain(sub, domain)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		results = append(results, normalized)
	}
	sort.Strings(results)

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
