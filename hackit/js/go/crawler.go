package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Crawler struct {
	Opts         *Options
	BaseURL      string
	BaseHost     string
	BaseHostPort string
	BaseDomain   string
	Client       *http.Client
	Scope        *Scope
	Filters      *Filters
	WG           sync.WaitGroup
	queueWg      sync.WaitGroup
	mu           sync.Mutex
	queuedURLs   chan urlQueue

	queuedCount  int64
	fetchedCount int64
	depthSkipped int64
	limitShown   int32

	activeHost string

	Subdomains    map[string]bool
	subdomainURLs map[string]string
	subMu         sync.Mutex

	hintsShown  map[string]bool
	seenStrings map[string]bool

	allCrawled []CrawlResult
	startTime  time.Time
	rateLimit  chan time.Time
}

func NewCrawler(opts *Options) *Crawler {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
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

	u, _ := url.Parse(opts.Target)
	host := hostWithoutPort(u.Host)
	baseDomain := strings.TrimPrefix(host, "www.")
	if baseDomain == host {
		baseDomain = host
	}

	c := &Crawler{
		Opts:          opts,
		BaseURL:       opts.Target,
		BaseHost:      host,
		BaseHostPort:  u.Host,
		BaseDomain:    baseDomain,
		activeHost:    host,
		Client:        client,
		Scope:         NewScope(opts.Target, opts.MaxDepth),
		Filters:       NewFilters(),
		queuedURLs:    make(chan urlQueue, 100000),
		Subdomains:    make(map[string]bool),
		subdomainURLs: make(map[string]string),
		hintsShown:    make(map[string]bool),
		seenStrings:   make(map[string]bool),
		allCrawled:    make([]CrawlResult, 0),
		startTime:     time.Now(),
	}

	if opts.RateLimit > 0 {
		c.rateLimit = make(chan time.Time, opts.RateLimit)
		go func() {
			ticker := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
			defer ticker.Stop()
			for t := range ticker.C {
				select {
				case c.rateLimit <- t:
				default:
				}
			}
		}()
	}

	return c
}

func (c *Crawler) addQueueItem(item urlQueue) {
	u, err := url.Parse(item.url)
	if err == nil && u.Host != "" {
		itemHost := hostWithoutPort(u.Host)
		if itemHost != c.activeHost && !isHostTwin(itemHost, c.activeHost) {
			if strings.HasSuffix(itemHost, c.BaseDomain) && itemHost != c.BaseHost {
				c.addSubdomain(itemHost, item.url)
			}
			return
		}
	}
	c.queueWg.Add(1)
	atomic.AddInt64(&c.queuedCount, 1)
	c.queuedURLs <- item
}

// isHostTwin treats apex <-> www as the same site for crawl purposes.
func isHostTwin(a, b string) bool {
	if a == b {
		return true
	}
	if strings.HasPrefix(a, "www.") && strings.TrimPrefix(a, "www.") == b {
		return true
	}
	if strings.HasPrefix(b, "www.") && strings.TrimPrefix(b, "www.") == a {
		return true
	}
	return false
}

func (c *Crawler) getDelay() time.Duration {
	if c.Opts.Delay > 0 {
		return time.Duration(c.Opts.Delay) * time.Millisecond
	}
	return 0
}

func (c *Crawler) applyRateLimit() {
	if c.rateLimit != nil {
		<-c.rateLimit
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

func (c *Crawler) setHeaders(req *http.Request) {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:126.0) Gecko/20100101 Firefox/126.0",
	}
	req.Header.Set("User-Agent", uas[rand.Intn(len(uas))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Referer", c.BaseURL)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Not/A)Brand";v="99", "Google Chrome";v="126", "Chromium";v="126"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
}

func (c *Crawler) Start() {
	go c.crawlQueue()

	// Live progress heartbeat: proves the crawl is advancing until exhausted.
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeOutput(`{"type":"progress","fetched":%d,"queued":%d,"elapsed":"%s"}`+"\n",
					atomic.LoadInt64(&c.fetchedCount), atomic.LoadInt64(&c.queuedCount),
					time.Since(c.startTime).Round(time.Second))
			case <-stopProgress:
				return
			}
		}
	}()

	if !c.Filters.HasSeen(c.BaseURL) {
		c.addQueueItem(urlQueue{url: c.BaseURL, source: "", depth: 0})
	}
	if !strings.HasSuffix(c.BaseURL, "/") && !c.Filters.HasSeen(c.BaseURL+"/") {
		c.addQueueItem(urlQueue{url: c.BaseURL + "/", source: "", depth: 0})
	}
	// Apex -> www fallback seed: if the apex is walled, the www twin
	// often answers (or vice versa). One extra request, big coverage win.
	if !strings.HasPrefix(c.BaseHost, "www.") {
		wwwURL := strings.Replace(c.BaseURL, "://"+c.BaseHost, "://www."+c.BaseHost, 1)
		if wwwURL != c.BaseURL && !c.Filters.HasSeen(wwwURL) {
			c.addQueueItem(urlQueue{url: wwwURL, source: "", depth: 0})
		}
	}

	var bgWg sync.WaitGroup

	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		c.performPassiveChecks()
	}()

	if c.Opts.Archive || c.Opts.Brute {
		if c.Opts.Archive {
			bgWg.Add(1)
			go func() {
				defer bgWg.Done()
				c.queryWayback(c.BaseURL)
				c.queryCommonCrawl(c.BaseURL)
			}()
		}
		if c.Opts.Brute {
			bgWg.Add(1)
			go func() {
				defer bgWg.Done()
				c.performActiveBrute()
			}()
		}
	}
	c.queueWg.Wait()
	bgWg.Wait()
	c.queueWg.Wait()

	if c.Opts.Subdomains {
		c.discoverAllSubdomains()
		subList := c.getSubdomainList()
		// Crawl every discovered subdomain until exhausted (safety-capped).
		maxSubs := c.Opts.MaxSubs
		if maxSubs <= 0 {
			maxSubs = 200
		}
		if len(subList) > maxSubs {
			writeOutput(`{"type":"limit","reason":"max-subs","found":%d,"max":%d}`+"\n", len(subList), maxSubs)
			subList = subList[:maxSubs]
		}
		for _, s := range subList {
			c.activeHost = s.host
			writeOutput(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"crawl"}`+"\n", s.url, s.name)
			if !c.Filters.HasSeen(s.url) {
				c.addQueueItem(urlQueue{url: s.url, source: c.BaseURL, depth: 1})
			}
			if c.Opts.Brute {
				for _, p := range getBrutePaths() {
					full := s.url + p
					if !c.Filters.HasSeen(full) {
						c.addQueueItem(urlQueue{url: full, source: s.url, depth: 2})
					}
				}
			}
			c.queueWg.Wait()
		}
	}

	c.activeHost = ""
	close(c.queuedURLs)
	close(stopProgress)
	c.printSummary()
}

type subEntry struct {
	name string
	host string
	url  string
}

func (c *Crawler) getSubdomainList() []subEntry {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	var list []subEntry
	for name, u := range c.subdomainURLs {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		list = append(list, subEntry{name: name, host: hostWithoutPort(parsed.Host), url: u})
	}
	return list
}

func (c *Crawler) crawlQueue() {
	workerLimit := make(chan struct{}, c.Opts.Concurrency)
	for q := range c.queuedURLs {
		workerLimit <- struct{}{}
		go func(q urlQueue) {
			defer func() { <-workerLimit; c.queueWg.Done() }()
			if delay := c.getDelay(); delay > 0 {
				time.Sleep(delay)
			}
			c.applyRateLimit()
			c.crawlPage(q.url, q.source, q.depth)
		}(q)
	}
}

func (c *Crawler) printSummary() {
	c.mu.Lock()
	total := len(c.allCrawled)
	jsCount := 0
	okCount := 0
	for _, r := range c.allCrawled {
		if r.Extension == "js" || r.Type == "JavaScript" {
			jsCount++
		}
		if r.StatusCode == 200 {
			okCount++
		}
	}
	subCount := len(c.Subdomains)
	elapsed := time.Since(c.startTime).Round(time.Millisecond)
	c.mu.Unlock()

	writeOutput(`{"type":"summary","total":%d,"js_files":%d,"files_200":%d,"subdomains":%d,"skipped_depth":%d,"elapsed":"%s"}`,
		total, jsCount, okCount, subCount, atomic.LoadInt64(&c.depthSkipped), elapsed)
	writeOutput("\n")
}

func (c *Crawler) addSubdomain(subdomain, fullURL string) bool {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.Subdomains[subdomain] {
		return false
	}
	c.Subdomains[subdomain] = true
	c.subdomainURLs[subdomain] = fullURL
	return true
}

var uaList = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
}

func (c *Crawler) setActiveHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeHost = host
}
