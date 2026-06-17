package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	linkPattern     = regexp.MustCompile(`<a[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	scriptPattern   = regexp.MustCompile(`<script[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	linkTagPattern  = regexp.MustCompile(`<link[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	iframePattern   = regexp.MustCompile(`<iframe[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	formPattern     = regexp.MustCompile(`<form[^>]+action=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	imgPattern      = regexp.MustCompile(`<img[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	sourcePattern   = regexp.MustCompile(`<source[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	objectPattern   = regexp.MustCompile(`<object[^>]+data=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	embedPattern    = regexp.MustCompile(`<embed[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	jsonldPattern   = regexp.MustCompile(`"@(id|type|context)"\s*:\s*"([^"]+)"`)
	inlineJSVar     = regexp.MustCompile(`(?:var|let|const|window\.)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["'\` + "`" + `](https?://[^"'\` + "`" + `]+)["'\` + "`" + `]`)
	fetchPattern    = regexp.MustCompile(`(?:fetch|axios|xhr|XMLHttpRequest)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	ajaxPattern     = regexp.MustCompile(`\$.+(?:get|post|ajax|load)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
)

type CrawlResult struct {
	URL         string `json:"url"`
	SourceURL   string `json:"source_url"`
	Type        string `json:"type"`
	Extension   string `json:"extension"`
	StatusCode  int    `json:"status_code,omitempty"`
	Depth       int    `json:"depth"`
}

func (c *Crawler) crawlPage(pageURL string, sourceURL string, depth int) {
	if depth > c.Scope.MaxDepth {
		return
	}
	if c.Filters.Seen(pageURL) {
		return
	}

	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return
	}
	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return
	}
	body := string(bodyBytes)
	ct := resp.Header.Get("Content-Type")

	crawlType := "HTML"
	ext := getExtension(pageURL)

	if strings.Contains(ct, "javascript") || strings.HasSuffix(ext, "js") {
		crawlType = "JavaScript"
		c.parseJSSource(body, pageURL, depth)
	} else if strings.Contains(ct, "json") {
		crawlType = "JSON"
	}

	// Output JS source code when ShowCode is enabled
	if c.ShowCode && resp.StatusCode == 200 && crawlType == "JavaScript" {
		if len(body) > 0 && len(body) < 1024*1024 {
			bodyJSON, _ := json.Marshal(body)
			fmt.Printf(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":%s}`+"\n",
				pageURL, len(body), string(bodyJSON))
		} else {
			fmt.Printf(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":"[skipped: %d bytes]"}`+"\n",
				pageURL, len(body), len(body))
		}
	}

	result := CrawlResult{
		URL:        pageURL,
		SourceURL:  sourceURL,
		Type:       crawlType,
		Extension:  ext,
		StatusCode: resp.StatusCode,
		Depth:      depth,
	}
	c.mu.Lock()
	c.allCrawled = append(c.allCrawled, result)
	c.mu.Unlock()

	if depth < c.Scope.MaxDepth && strings.Contains(ct, "html") {
		// Full resource observation: scripts, styles, images, fonts, media, etc.
		c.captureHTMLResources(body, pageURL, depth)
		// Extract inline JS network calls (fetch, XHR, axios)
		c.extractInlineJS(body, pageURL, depth)
		c.extractFromHTML(body, pageURL, depth)
	}
}

func (c *Crawler) parseJSSource(body string, sourceURL string, depth int) {
	endpoints := extractEndpoints(body)
	for _, ep := range endpoints {
		absURL := resolveURL(ep.URL, c.BaseURL)
		if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.Seen(absURL) {
			c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1, phase: 1})
		}
		// Extract potential subdomains from every endpoint
		c.extractSubdomainFromURL(ep.URL)
	}

	imports := extractImports(body)
	for _, imp := range imports {
		absURL := resolveURL(imp, sourceURL)
		if absURL != "" && c.Scope.IsJS(absURL) && c.Scope.IsInScope(absURL, depth+1) {
			c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1, phase: 1})
		}
	}

	// Extract subdomains from JS content
	c.extractSubdomainsFromBody(body, sourceURL)

	findings := findSensitive(body, sourceURL)
	for _, f := range findings {
		fmt.Printf(`{"type":"sensitive","name":%q,"match":%q,"source":%q}`+"\n", f.Name, f.Match, sourceURL)
	}

	comments := findComments(body, sourceURL)
	for _, cm := range comments {
		fmt.Printf(`{"type":"comment","comment":%q,"source":%q}`+"\n", cm.Comment, cm.Source)
	}

	// Extract dependency tree (require/import/dynamic imports)
	c.extractDependencies(body, sourceURL, depth)

	// Capture all dynamic network calls from JS (fetch, XHR, WebSocket, etc.)
	c.captureJSNetwork(body, sourceURL, depth)

	if depth < c.Scope.MaxDepth {
		c.checkSourceMap(sourceURL)
	}
}

func (c *Crawler) extractFromHTML(body string, pageURL string, depth int) {
	patterns := []struct {
		re    *regexp.Regexp
		rtype string
	}{
		{linkPattern, "Link"},
		{scriptPattern, "Script"},
		{linkTagPattern, "Link Tag"},
		{iframePattern, "Iframe"},
		{formPattern, "Form"},
		{imgPattern, "Image"},
		{sourcePattern, "Source"},
		{objectPattern, "Object"},
		{embedPattern, "Embed"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				absURL := resolveURL(m[1], pageURL)
				if absURL == "" || !c.Scope.IsInScope(absURL, depth+1) {
					continue
				}
				if c.Filters.Seen(absURL) {
					continue
				}
				if p.rtype == "Script" || c.Scope.IsJS(absURL) {
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
				} else if isCrawable(absURL) && depth < c.Scope.MaxDepth {
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth, phase: 1})
				}
			}
		}
	}

	jsonld := jsonldPattern.FindAllStringSubmatch(body, -1)
	for _, m := range jsonld {
		if len(m) >= 3 {
			absURL := resolveURL(m[2], pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}
}

func (c *Crawler) extractInlineJS(body string, pageURL string, depth int) {
	fetchMatches := fetchPattern.FindAllStringSubmatch(body, -1)
	for _, m := range fetchMatches {
		if len(m) >= 2 {
			absURL := resolveURL(m[1], pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}

	ajaxMatches := ajaxPattern.FindAllStringSubmatch(body, -1)
	for _, m := range ajaxMatches {
		if len(m) >= 2 {
			absURL := resolveURL(m[1], pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}

	varMatches := inlineJSVar.FindAllStringSubmatch(body, -1)
	for _, m := range varMatches {
		if len(m) >= 3 {
			absURL := resolveURL(m[2], pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}
}

type urlQueue struct {
	url    string
	source string
	depth  int
	phase  int
}

func (c *Crawler) crawlQueue() {
	workerLimit := make(chan struct{}, 50)

	for q := range c.queuedURLs {
		workerLimit <- struct{}{}
		go func(q urlQueue) {
			defer func() { <-workerLimit; c.queueWg.Done() }()
			c.crawlPage(q.url, q.source, q.depth)
			time.Sleep(time.Duration(50+time.Now().UnixNano()%200) * time.Millisecond)
		}(q)
	}
}

func resolveJSImport(imp string, baseURL string, discoveryType string) string {
	if strings.HasPrefix(imp, "http://") || strings.HasPrefix(imp, "https://") {
		return imp
	}
	if strings.HasPrefix(imp, "//") {
		u, _ := url.Parse(baseURL)
		return u.Scheme + ":" + imp
	}
	if strings.HasPrefix(imp, "/") {
		u, _ := url.Parse(baseURL)
		return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, imp)
	}
	if strings.HasPrefix(imp, "./") || strings.HasPrefix(imp, "../") || !strings.Contains(imp, "/") {
		baseDir := baseURL
		if idx := strings.LastIndex(baseURL, "/"); idx > 8 {
			baseDir = baseURL[:idx]
		}
		cleaned := cleanPath(baseDir + "/" + imp)
		return cleaned
	}
	return imp
}

func cleanPath(p string) string {
	parts := strings.Split(p, "/")
	var result []string
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		if part == ".." && len(result) > 0 {
			result = result[:len(result)-1]
		} else {
			result = append(result, part)
		}
	}
	if len(result) < 2 {
		return p
	}
	scheme := result[0] + "//"
	return scheme + strings.Join(result[1:], "/")
}
