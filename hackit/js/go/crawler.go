package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Crawler struct {
	BaseURL    string
	BaseHost   string
	BaseDomain string
	Client     *http.Client
	Scope      *Scope
	Filters    *Filters
	WG         sync.WaitGroup
	queueWg    sync.WaitGroup
	waybackWg  sync.WaitGroup
	mu         sync.Mutex
	queuedURLs chan urlQueue
	ShowCode   bool

	// Subdomain tracking
	Subdomains    map[string]bool
	subdomainURLs map[string]string
	subMu         sync.Mutex

	// Per-subdomain sequential crawl
	subdomainActive bool
	subdomainQueue  chan urlQueue
	subdomainWg     sync.WaitGroup
	subdomainWorkers int

	allCrawled []CrawlResult
	startTime  time.Time
}

func (c *Crawler) addQueueItem(item urlQueue) {
	if c.subdomainActive && c.subdomainQueue != nil {
		c.subdomainWg.Add(1)
		c.subdomainQueue <- item
		return
	}
	c.queueWg.Add(1)
	c.queuedURLs <- item
}

func NewCrawler(baseURL string, baseHost string, showCode bool) *Crawler {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 {
				for k, v := range via[0].Header {
					if k != "Authorization" && k != "Cookie" {
						req.Header[k] = v
					}
				}
			}
			return nil
		},
	}

	u, _ := url.Parse(baseURL)
	host := hostWithoutPort(u.Host)
	parts := hostParts(host)
	var baseDomain string
	if len(parts) >= 2 {
		baseDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
	} else {
		baseDomain = host
	}

	return &Crawler{
		BaseURL:    baseURL,
		BaseHost:   host,
		BaseDomain: baseDomain,
		Client:     client,
		Scope:      NewScope(baseURL, 3),
		Filters:    NewFilters(),
		queuedURLs: make(chan urlQueue, 10000),
		Subdomains: make(map[string]bool),
		subdomainURLs: make(map[string]string),
		ShowCode:   showCode,
		allCrawled: make([]CrawlResult, 0),
		startTime:  time.Now(),
		subdomainWorkers: 3,
	}
}

func hostWithoutPort(host string) string {
	for i, c := range host {
		if c == ':' {
			return host[:i]
		}
	}
	return host
}

func hostParts(host string) []string {
	return splitHost(host)
}

func splitHost(host string) []string {
	var parts []string
	current := ""
	for _, c := range host {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func (c *Crawler) setHeaders(req *http.Request) {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	}
	req.Header.Set("User-Agent", uas[rand.Intn(len(uas))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Referer", c.BaseURL)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", "\"Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"126\", \"Chromium\";v=\"126\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")
}

func (c *Crawler) Start() {
	// Start queue consumer first to prevent deadlock
	go c.crawlQueue()

	// ── PHASE 1: Main domain deep crawl ──
	c.performPassiveChecks()

	// Wayback Machine historical JS discovery
	c.waybackWg.Add(1)
	go func() {
		defer c.waybackWg.Done()
		c.queryWayback(c.BaseURL)
	}()

	// Active brute-force (common JS paths on main domain)
	c.performActiveBrute()

	// Queue base URL + trailing-slash variant (some servers treat them differently)
	if !c.Filters.HasSeen(c.BaseURL) {
		c.addQueueItem(urlQueue{url: c.BaseURL, source: "", depth: 0, phase: 1})
	}
	if c.BaseURL+"/" != c.BaseURL && !c.Filters.HasSeen(c.BaseURL+"/") {
		c.addQueueItem(urlQueue{url: c.BaseURL + "/", source: "", depth: 0, phase: 1})
	}

	// Wait for phase 1 crawl to complete
	c.queueWg.Wait()

	// Wait for wayback discovery to finish, then drain its items
	c.waybackWg.Wait()
	// Drain any remaining wayback-discovered URLs still in the queue
	c.queueWg.Wait()

	// ── PHASE 2: Sequential subdomain processing ──
	c.discoverAllSubdomains()
	c.crawlSubdomainsSequentially()

	// ── Cleanup ──
	close(c.queuedURLs)
	c.printSummary()
}

// discoverAllSubdomains collects subdomains from all sources
func (c *Crawler) discoverAllSubdomains() {
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); c.discoverCTLogs() }()
	go func() { defer wg.Done(); c.discoverAlienVault() }()
	go func() { defer wg.Done(); c.discoverGoogleCT() }()
	go func() { defer wg.Done(); c.discoverDNSBrute() }()
	wg.Wait()
	c.discoverSubdomainsFromJS()
}

// crawlSubdomainsSequentially processes each subdomain one at a time.
// A subdomain is fully crawled (including all discovered JS, sub-pages, etc.)
// before the next subdomain begins.
func (c *Crawler) crawlSubdomainsSequentially() {
	c.subMu.Lock()
	var subList []struct {
		name string
		url  string
	}
	for name, u := range c.subdomainURLs {
		if c.Filters.HasSeen(u) {
			continue
		}
		subList = append(subList, struct {
			name string
			url  string
		}{name, u})
	}
	c.subMu.Unlock()

	if len(subList) == 0 {
		return
	}

	// Create the per-subdomain work queue + workers
	c.subdomainQueue = make(chan urlQueue, 10000)
	c.subdomainActive = true

	// Start subdomain workers
	for i := 0; i < c.subdomainWorkers; i++ {
		go func() {
			for item := range c.subdomainQueue {
				c.crawlPage(item.url, item.source, item.depth)
				c.subdomainWg.Done()
			}
		}()
	}

	// Process each subdomain: queue its URL, wait for full drain, repeat
	for _, s := range subList {
		if c.Filters.HasSeen(s.url) {
			continue
		}
		writeOutput(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"sequential"}`+"\n", s.url, s.name)

		// Queue the subdomain main page
		c.subdomainWg.Add(1)
		c.subdomainQueue <- urlQueue{url: s.url, source: c.BaseURL, depth: 1, phase: 2}

		// Queue common brute paths for this subdomain
		for _, p := range getBrutePaths() {
			c.subdomainWg.Add(1)
			c.subdomainQueue <- urlQueue{url: s.url + p, source: s.url, depth: 2, phase: 2}
		}

		// Wait for ALL work for this subdomain to complete
		// (all pages, JS files, SSRF configs, etc.)
		c.subdomainWg.Wait()
	}

	// Cleanup subdomain channel
	close(c.subdomainQueue)
	c.subdomainActive = false
	c.subdomainQueue = nil
}

func (c *Crawler) printSummary() {
	c.mu.Lock()
	totalCrawled := len(c.allCrawled)
	jsCount := 0
	for _, r := range c.allCrawled {
		if r.Extension == "js" || r.Type == "JavaScript" {
			jsCount++
		}
	}
	subCount := len(c.Subdomains)
	elapsed := time.Since(c.startTime).Round(time.Millisecond)
	c.mu.Unlock()

	writeOutput(`{"type":"summary","total":%d,"js_files":%d,"subdomains":%d,"elapsed":"%s"}`,
		totalCrawled, jsCount, subCount, elapsed)
	writeOutput("\n")
}

var uaList = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
}
