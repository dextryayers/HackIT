package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	linkPattern    = regexp.MustCompile(`<a[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	scriptPattern  = regexp.MustCompile(`<script[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	linkTagPattern = regexp.MustCompile(`<link[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	iframePattern  = regexp.MustCompile(`<iframe[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	formPattern    = regexp.MustCompile(`<form[^>]+action=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	imgPattern     = regexp.MustCompile(`<img[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	sourcePattern  = regexp.MustCompile(`<source[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	objectPattern  = regexp.MustCompile(`<object[^>]+data=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	embedPattern   = regexp.MustCompile(`<embed[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
)

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
		if c.Opts.JS {
			c.parseJSSource(body, pageURL, depth)
		}
	} else if strings.Contains(ct, "json") {
		crawlType = "JSON"
	}

	if crawlType == "HTML" && resp.StatusCode == 200 {
		if c.Opts.JS {
			deep := performDeepExtraction(body, pageURL)
			c.processDeepExtraction(deep, pageURL, depth)
		}
	}

	if c.Opts.ShowCode && resp.StatusCode == 200 && crawlType == "JavaScript" {
		if len(body) > 0 && len(body) < 1024*1024 {
			bodyJSON, _ := json.Marshal(body)
			writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":%s}`+"\n",
				pageURL, len(body), string(bodyJSON))
		} else {
			writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":"[skipped: %d bytes]"}`+"\n",
				pageURL, len(body), len(body))
		}
	}

	writeOutput(`{"type":"discovered","url":%q,"source":%q,"content_type":%q,"status":%d,"depth":%d}`+"\n",
		pageURL, sourceURL, crawlType, resp.StatusCode, depth)

	result := CrawlResult{
		URL:         pageURL,
		SourceURL:   sourceURL,
		Type:        crawlType,
		Extension:   ext,
		StatusCode:  resp.StatusCode,
		Depth:       depth,
		ContentType: ct,
	}
	if c.Opts.ShowCode && crawlType == "JavaScript" && len(body) < 1024*1024 {
		result.Body = body
	}
	c.mu.Lock()
	c.allCrawled = append(c.allCrawled, result)
	c.mu.Unlock()

	if c.Opts.Tech {
		c.detectTechnologies(body, pageURL, ct)
	}

	if resp.StatusCode == 200 && strings.Contains(ct, "html") && depth < c.Scope.MaxDepth {
		c.captureHTMLResources(body, pageURL, depth)
		c.extractInlineJS(body, pageURL, depth)
		c.extractFromHTML(body, pageURL, depth)
		configURLs := extractInlineJSONConfigs(body, pageURL)
		for _, cu := range configURLs {
			absURL := resolveURL(cu, pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
			}
		}
	}
}

func (c *Crawler) processDeepExtraction(deep DeepExtractResult, pageURL string, depth int) {
	for _, s := range deep.BootstrapConfigs {
		if s.IsURL || s.IsPath {
			absURL := resolveURL(s.Value, c.BaseURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
				writeOutput(`{"type":"ssr_url","url":%q,"source":%q,"ctx":%q}`+"\n", absURL, pageURL, s.Context)
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
			}
		} else {
			writeOutput(`{"type":"ssr_config","name":%q,"source":%q,"ctx":%q}`+"\n", s.Value, pageURL, s.Context)
		}
	}
	for _, s := range deep.ImportMapURLs {
		absURL := resolveURL(s.Value, c.BaseURL)
		if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
			writeOutput(`{"type":"importmap","url":%q,"source":%q,"ctx":%q}`+"\n", absURL, pageURL, s.Context)
			c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
		}
	}
}

func (c *Crawler) extractFromHTML(body string, pageURL string, depth int) {
	patterns := []struct {
		re    *regexp.Regexp
		rtype string
	}{
		{linkPattern, "Link"}, {scriptPattern, "Script"}, {linkTagPattern, "Link Tag"},
		{iframePattern, "Iframe"}, {formPattern, "Form"}, {imgPattern, "Image"},
		{sourcePattern, "Source"}, {objectPattern, "Object"}, {embedPattern, "Embed"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			absURL := resolveURL(m[1], pageURL)
			if absURL == "" || !c.Scope.IsInScope(absURL, depth+1) || c.Filters.HasSeen(absURL) {
				continue
			}
			if p.rtype == "Script" || c.Scope.IsJS(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
			} else if isCrawable(absURL) && depth < c.Scope.MaxDepth {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth})
			}
		}
	}
}

func (c *Crawler) extractInlineJS(body string, pageURL string, depth int) {
	fetchPattern := regexp.MustCompile(`(?:fetch|axios|xhr|XMLHttpRequest)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	ajaxPattern := regexp.MustCompile(`\$.+(?:get|post|ajax|load)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	inlineJSVar := regexp.MustCompile(`(?:var|let|const|window\.)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["'\` + "`" + `](https?://[^"'\` + "`" + `]+)["'\` + "`" + `]`)

	for _, re := range []*regexp.Regexp{fetchPattern, ajaxPattern} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				absURL := resolveURL(m[1], pageURL)
				if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
				}
			}
		}
	}

	for _, m := range inlineJSVar.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 {
			absURL := resolveURL(m[2], pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
			}
		}
	}
}

func extractInlineJSONConfigs(body string, sourceURL string) []string {
	var urls []string
	seen := make(map[string]bool)
	patterns := []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`<script id="__NEXT_DATA__"[^>]*type="application/json"[^>]*>({.*?})</script>`), "__NEXT_DATA__"},
		{regexp.MustCompile(`<script id="__NUXT__"[^>]*type="application/json"[^>]*>({.*?})</script>`), "__NUXT__"},
		{regexp.MustCompile(`<script id="__APOLLO_STATE__"[^>]*>({.*?})</script>`), "__APOLLO_STATE__"},
		{regexp.MustCompile(`<script id="__RSC__"[^>]*>({.*?})</script>`), "__RSC__"},
		{regexp.MustCompile(`<script id="__RELAY_DATA__"[^>]*>({.*?})</script>`), "__RELAY_DATA__"},
		{regexp.MustCompile(`<script id="__BOOTSTRAP_DATA__"[^>]*>({.*?})</script>`), "__BOOTSTRAP_DATA__"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			payload := m[1]
			var data interface{}
			if err := json.Unmarshal([]byte(payload), &data); err != nil {
				continue
			}
			writeOutput(`{"type":"ssr_config","name":%q,"source":%q,"size":%d}`+"\n", p.name, sourceURL, len(payload))
			extractStringsFromJSON(data, &urls, seen, sourceURL)
		}
	}
	return urls
}

func extractStringsFromJSON(data interface{}, urls *[]string, seen map[string]bool, sourceURL string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if s, ok := val.(string); ok {
				if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "/")) && !seen[s] {
					seen[s] = true
					*urls = append(*urls, s)
					writeOutput(`{"type":"ssr_url","url":%q,"source":%q,"field":%q}`+"\n", s, sourceURL, key)
				}
			} else {
				extractStringsFromJSON(val, urls, seen, sourceURL)
			}
		}
	case []interface{}:
		for _, item := range v {
			extractStringsFromJSON(item, urls, seen, sourceURL)
		}
	}
}
