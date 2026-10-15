package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	attrPattern     = regexp.MustCompile(`(?i)(href|src|data|action|formaction|content|poster|srcset|code|archive)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlTagPattern  = regexp.MustCompile(`(?i)<(a|script|link|img|iframe|form|video|audio|source|track|embed|object|area|frame|applet|input|button|meta)\b([^>]*)>`)
	metaRefreshPat  = regexp.MustCompile(`(?i)url\s*=\s*["']?([^"';]+)["']?`)
	tagRelPattern   = regexp.MustCompile(`(?i)rel\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	fetchPatternPre = regexp.MustCompile(`(?:fetch|axios|xhr|XMLHttpRequest)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	ajaxPatternPre  = regexp.MustCompile(`\$.+(?:get|post|ajax|load)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	inlineJSVarPre  = regexp.MustCompile(`(?:var|let|const|window\.)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["'` + "`" + `](https?://[^"'` + "`" + `]+)["'` + "`" + `]`)
)

var tagAttrs = map[string][]string{
	"a": {"href"}, "script": {"src"}, "link": {"href"},
	"img": {"src", "srcset"}, "iframe": {"src"}, "form": {"action"},
	"video": {"src", "poster"}, "audio": {"src"}, "source": {"src", "srcset"},
	"track": {"src"}, "embed": {"src"}, "object": {"data"},
	"area": {"href"}, "frame": {"src"}, "applet": {"code", "archive"},
	"input": {"src"}, "button": {"formaction"}, "meta": {"content"},
}

func tagRel(attrs string) string {
	m := tagRelPattern.FindStringSubmatch(attrs)
	if len(m) >= 2 {
		return strings.ToLower(strings.Trim(m[1], "\"'"))
	}
	return ""
}

func strSliceContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
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
		if c.Opts.JS {
			c.parseJSSource(body, pageURL, depth)
		}
		if resp.StatusCode == 200 {
			c.checkExternalSourceMap(body, pageURL)
		}
	} else if strings.Contains(ct, "css") || ext == "css" || ext == "scss" || ext == "less" {
		crawlType = "CSS"
		if resp.StatusCode == 200 {
			c.parseCSSResources(body, pageURL, depth)
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

	// Accurate verified file inventory: only real 200 OK responses land here,
	// so every filemap entry is directly openable.
	if resp.StatusCode == 200 {
		writeOutput(`{"type":"filemap","url":%q,"source":%q,"kind":%q,"ext":%q,"content_type":%q,"length":%d,"depth":%d}`+"\n",
			pageURL, sourceURL, crawlType, ext, ct, len(bodyBytes), depth)
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

	if resp.StatusCode == 200 && strings.Contains(ct, "html") {
		// Always extract (queueing itself stays depth-aware): even the
		// deepest fetched page must reveal every link it contains.
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

func (c *Crawler) queueHTMLRef(raw, tag, base, pageURL string, depth int) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return
	}
	low := strings.ToLower(raw)
	for _, p := range []string{"javascript:", "data:", "mailto:", "tel:", "blob:", "about:"} {
		if strings.HasPrefix(low, p) {
			return
		}
	}
	absURL := resolveURL(raw, base)
	if absURL == "" || !c.Scope.IsInScope(absURL, depth+1) || c.Filters.HasSeen(absURL) {
		return
	}
	if tag == "script" || c.Scope.IsJS(absURL) || c.Scope.IsCode(absURL) {
		c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
	} else if isCrawable(absURL) && depth < c.Scope.MaxDepth {
		c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth})
	}
}

func (c *Crawler) extractFromHTML(body string, pageURL string, depth int) {
	base := extractBaseHref(body, pageURL)
	for _, tm := range htmlTagPattern.FindAllStringSubmatch(body, -1) {
		if len(tm) < 3 {
			continue
		}
		tag := strings.ToLower(tm[1])
		attrs := tm[2]
		want, ok := tagAttrs[tag]
		if !ok {
			continue
		}
		if tag == "link" {
			rel := tagRel(attrs)
			if rel != "" && rel != "stylesheet" && !strings.Contains(rel, "preload") &&
				!strings.Contains(rel, "modulepreload") && !strings.Contains(rel, "prefetch") &&
				!strings.Contains(rel, "icon") && !strings.Contains(rel, "manifest") &&
				!strings.Contains(rel, "alternate") {
				continue
			}
		}
		for _, am := range attrPattern.FindAllStringSubmatch(attrs, -1) {
			if len(am) < 3 {
				continue
			}
			name := strings.ToLower(am[1])
			if !strSliceContains(want, name) {
				continue
			}
			val := strings.Trim(am[2], "\"'")
			if tag == "meta" {
				lower := strings.ToLower(attrs)
				if strings.Contains(lower, "refresh") {
					if m := metaRefreshPat.FindStringSubmatch(val); len(m) >= 2 {
						c.queueHTMLRef(strings.TrimSpace(m[1]), tag, base, pageURL, depth)
					}
					continue
				}
				if strings.Contains(lower, "og:image") || strings.Contains(lower, "twitter:image") ||
					strings.Contains(lower, "og:video") || strings.Contains(lower, "og:audio") {
					c.queueHTMLRef(val, tag, base, pageURL, depth)
				}
				continue
			}
			if name == "srcset" {
				for _, part := range parseSrcset(val) {
					c.queueHTMLRef(part, tag, base, pageURL, depth)
				}
				continue
			}
			c.queueHTMLRef(val, tag, base, pageURL, depth)
		}
	}
}

func (c *Crawler) extractInlineJS(body string, pageURL string, depth int) {
	for _, re := range []*regexp.Regexp{fetchPatternPre, ajaxPatternPre} {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				absURL := resolveURL(m[1], pageURL)
				if absURL != "" && c.Scope.IsInScope(absURL, depth+1) {
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
				}
			}
		}
	}

	for _, m := range inlineJSVarPre.FindAllStringSubmatch(body, -1) {
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
