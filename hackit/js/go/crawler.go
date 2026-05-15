package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Task struct {
	URL   string
	Depth int
}

type Crawler struct {
	BaseURL    string
	Host       string
	Client     *http.Client
	Results    map[string]bool
	ResMux     sync.Mutex
	Visited    map[string]bool
	VisMux     sync.Mutex
	Workers    int
	MaxDepth   int
	Queue      chan Task
	WG         sync.WaitGroup
}

func NewCrawler(baseURL, host string) *Crawler {
	return &Crawler{
		BaseURL: baseURL,
		Host:    host,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 10 * time.Second,
		},
		Results:  make(map[string]bool),
		Visited:  make(map[string]bool),
		Workers:  40, // Increased for speed
		MaxDepth: 2,  // Prevent infinite crawl
		Queue:    make(chan Task, 5000),
	}
}

func (c *Crawler) Start() {
	c.performPassiveChecks()
	c.performActiveBrute()
	
	c.WG.Add(1)
	c.Queue <- Task{URL: c.BaseURL, Depth: 0}

	// Start workers
	for i := 0; i < c.Workers; i++ {
		go c.worker()
	}

	c.WG.Wait()
	close(c.Queue)
}

func (c *Crawler) worker() {
	for task := range c.Queue {
		c.process(task.URL, task.Depth)
		c.WG.Done()
	}
}

func (c *Crawler) process(targetURL string, depth int) {
	if depth > c.MaxDepth {
		return
	}

	c.VisMux.Lock()
	if c.Visited[targetURL] {
		c.VisMux.Unlock()
		return
	}
	c.Visited[targetURL] = true
	c.VisMux.Unlock()

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Referer", c.BaseURL)

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// --- Advanced Discovery Patterns (Katana Port) ---
	reBody := regexp.MustCompile(`(?i)(?:[\.]{1,2}/[A-Za-z0-9\-_/\\?&@\.?=%]+)|(https?://[A-Za-z0-9_\-\.]+([\.]{0,2})?\/[A-Za-z0-9\-_/\\?&@\.?=%]+)|(/[A-Za-z0-9\-_/\\?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))|([A-Za-z0-9\-_?&@\.%]+/[A-Za-z0-9/\\\-_?&@\.%]+\.(aspx?|action|cfm|cgi|do|pl|css|x?html?|js(p|on)?|pdf|php5?|py|rss))`)
	
	for _, m := range reBody.FindAllString(body, -1) {
		link := resolveURL(m, targetURL)
		if link == "" {
			continue
		}
		
		ext := getExtension(link)
		if ext == "js" {
			c.addResult(link, targetURL, TypeTag)
			c.checkSourceMap(link)
		} else {
			c.addResult(link, targetURL, TypeEndpoint)
			
			// Crawl deeper
			if depth < c.MaxDepth && isInternal(link, c.Host) && !strings.Contains(link, "#") && !strings.HasSuffix(link, ".png") && !strings.HasSuffix(link, ".jpg") {
				c.WG.Add(1)
				select {
				case c.Queue <- Task{URL: link, Depth: depth + 1}:
				default:
					c.WG.Done()
				}
			}
		}
	}

	// JS Discovery Patterns
	reTag := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	for _, m := range reTag.FindAllStringSubmatch(body, -1) {
		jsURL := m[1]
		c.addResult(jsURL, targetURL, TypeTag)
		
		absJS := resolveURL(jsURL, targetURL)
		if absJS != "" && isInternal(absJS, c.Host) {
			c.checkSourceMap(absJS)
			c.WG.Add(1)
			go c.deepScanJS(absJS)
		}
	}
}

func (c *Crawler) deepScanJS(jsURL string) {
	defer c.WG.Done()
	
	req, _ := http.NewRequest("GET", jsURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("Referer", c.BaseURL)

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	reJS := regexp.MustCompile(`(?i)(?:"|'|\s)((?:https?://[A-Za-z0-9_\-.]+(?:\:\d{1,5})?)+([\.]{1,2})?/[A-Za-z0-9/\-_\\.%]+(?:[\?|#][^"']+)?)?|((\.{1,2}/)?[a-zA-Z0-9\-_/\\%]+\.(aspx?|js(?:on|p)?|html|php5?|action|do)(?:[\?|#][^"']+)?)?|((\.{0,2}/)[a-zA-Z0-9\-_/\\%]+(?:/|\\)[a-zA-Z0-9\-_]{3,}(?:[\?|#][^"']+)?)?|((\.{0,2})[a-zA-Z0-9\-_/\\%]{3,}/)?(?:"|'|\s)`)
	
	for _, m := range reJS.FindAllString(body, -1) {
		clean := strings.Trim(m, "\"' \t\n")
		if clean == "" || len(clean) < 3 {
			continue
		}
		
		abs := resolveURL(clean, jsURL)
		if abs == "" {
			continue
		}
		
		ext := getExtension(abs)
		if ext == "js" {
			c.addResult(abs, jsURL, TypeNested)
		} else {
			c.addResult(abs, jsURL, TypeEndpoint)
		}
	}
}

func (c *Crawler) addResult(rawURL string, source string, dType DiscoveryType) {
	abs := resolveURL(rawURL, source)
	if abs == "" {
		return
	}

	c.ResMux.Lock()
	defer c.ResMux.Unlock()

	if _, exists := c.Results[abs]; !exists {
		c.Results[abs] = true
		
		// Stream to stdout immediately as JSON
		res := Result{
			SourceURL: source,
			URL:       abs,
			Type:      dType,
			Ext:       getExtension(abs),
		}
		out, _ := json.Marshal(res)
		fmt.Println(string(out))
	}
}
