package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var (
	attrPattern        = regexp.MustCompile(`(?i)(?:xlink:)?(href|src|data|action|formaction|content|poster|srcset|code|archive|ping|manifest)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlTagPattern     = regexp.MustCompile(`(?i)<(a|script|link|img|iframe|form|video|audio|source|track|embed|object|area|frame|applet|input|button|meta|portal|svg|use|image|html)\b([^>]*)>`)
	metaRefreshPat     = regexp.MustCompile(`(?i)url\s*=\s*["']?([^"';]+)["']?`)
	tagRelPattern      = regexp.MustCompile(`(?i)rel\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	fetchPatternPre    = regexp.MustCompile(`(?:fetch|axios|xhr|XMLHttpRequest)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	ajaxPatternPre     = regexp.MustCompile(`\$.+(?:get|post|ajax|load)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	inlineJSVarPre     = regexp.MustCompile(`(?:var|let|const|window\.)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["'` + "`" + `](https?://[^"'` + "`" + `]+)["'` + "`" + `]`)
	dataURLAttrPattern = regexp.MustCompile(`(?i)data-(?:src|href|url|background|image|video|link|uri|path)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlCommentPattern = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	commentURLPattern  = regexp.MustCompile(`(?:https?://[^\s"'<>]+|/(?:[\w\-.~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+(?:/(?:[\w\-.~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*)`)
	linkHeaderPattern  = regexp.MustCompile(`<([^<>]+)>\s*(?:;\s*rel\s*=\s*"?([^";,]+)"?)?`)
	nextBuildIDPattern = regexp.MustCompile(`"buildId"\s*:\s*"([^"]+)"`)
)

var tagAttrs = map[string][]string{
	"a": {"href", "ping"}, "script": {"src"}, "link": {"href"},
	"img": {"src", "srcset"}, "iframe": {"src"}, "form": {"action"},
	"video": {"src", "poster"}, "audio": {"src"}, "source": {"src", "srcset"},
	"track": {"src"}, "embed": {"src"}, "object": {"data"},
	"area": {"href"}, "frame": {"src"}, "applet": {"code", "archive"},
	"input": {"src", "formaction"}, "button": {"formaction"}, "meta": {"content"},
	"portal": {"src"}, "svg": {"href"}, "use": {"href"}, "image": {"href"},
	"html": {"manifest"},
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
		atomic.AddInt64(&c.depthSkipped, 1)
		return
	}
	if c.Filters.Seen(pageURL) {
		return
	}
	if c.Opts.MaxPages > 0 && atomic.LoadInt64(&c.fetchedCount) >= int64(c.Opts.MaxPages) {
		if atomic.CompareAndSwapInt32(&c.limitShown, 0, 1) {
			writeOutput(`{"type":"limit","reason":"max-pages","max":%d}`+"\n", c.Opts.MaxPages)
		}
		return
	}
	atomic.AddInt64(&c.fetchedCount, 1)

	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return
	}
	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		// Shallow https -> http fallback (once): some estates serve
		// plain HTTP on secondary hosts.
		if depth <= 1 && strings.HasPrefix(pageURL, "https://") {
			plain := "http://" + strings.TrimPrefix(pageURL, "https://")
			if !c.Filters.HasSeen(plain) {
				c.addQueueItem(urlQueue{url: plain, source: sourceURL, depth: depth})
			}
		}
		return
	}
	defer resp.Body.Close()

	// One polite retry on rate-limit/overload for real assets.
	if (resp.StatusCode == 429 || resp.StatusCode == 503) && depth <= 3 {
		resp.Body.Close()
		time.Sleep(2 * time.Second)
		resp2, err2 := c.Client.Do(req)
		if err2 != nil {
			return
		}
		resp = resp2
		defer resp.Body.Close()
	}

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
		base := extractBaseHref(body, pageURL)
		c.captureHTMLResources(body, pageURL, depth)
		c.extractInlineJS(body, pageURL, depth)
		c.extractFromHTML(body, pageURL, depth)
		c.extractCommentURLs(body, pageURL, base, depth)
		c.extractLinkHeader(resp, pageURL, depth)
		c.enqueueNextDataVariants(body, pageURL, depth)
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
	if absURL == "" || c.Filters.HasSeen(absURL) {
		return
	}
	if !c.Scope.IsInScope(absURL, depth+1) {
		// Out-of-scope/media assets still get reported, never fetched.
		key := "skip:" + absURL
		c.mu.Lock()
		if c.seenStrings[key] {
			c.mu.Unlock()
			return
		}
		c.seenStrings[key] = true
		c.mu.Unlock()
		writeOutput(`{"type":"network_entry","url":%q,"source_url":%q,"resource_type":"%s_skip"}`+"\n", absURL, pageURL, tag)
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
				!strings.Contains(rel, "alternate") && !strings.Contains(rel, "canonical") &&
				!strings.Contains(rel, "shortlink") && !strings.Contains(rel, "amphtml") &&
				!strings.Contains(rel, "dns-prefetch") && !strings.Contains(rel, "preconnect") {
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
		// data-* lazy-load attributes (data-src, data-href, data-url, ...).
		for _, dm := range dataURLAttrPattern.FindAllStringSubmatch(attrs, -1) {
			if len(dm) >= 2 {
				val := strings.Trim(dm[1], "\"'")
				if abs := resolveURL(val, base); abs != "" {
					writeOutput(`{"type":"lazy_ref","url":%q,"source":%q,"ctx":%q}`+"\n", abs, pageURL, tag+"[data]")
				}
				c.queueHTMLRef(val, tag+"[data]", base, pageURL, depth)
			}
		}
	}
}

// HTML comments often hide retired paths, internal URLs and TODO endpoints.
func (c *Crawler) extractCommentURLs(body, pageURL, base string, depth int) {
	emitComment := func(val string) {
		val = strings.TrimSpace(strings.Trim(val, "\"'"))
		if val == "" {
			return
		}
		absURL := resolveURL(val, base)
		if absURL == "" {
			return
		}
		writeOutput(`{"type":"comment_url","url":%q,"source":%q}`+"\n", absURL, pageURL)
		c.queueHTMLRef(val, "comment", base, pageURL, depth)
	}
	for _, m := range htmlCommentPattern.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		comment := m[1]
		for _, am := range attrPattern.FindAllStringSubmatch(comment, -1) {
			if len(am) >= 3 {
				emitComment(am[2])
			}
		}
		for _, um := range commentURLPattern.FindAllStringSubmatch(comment, -1) {
			if len(um) >= 1 {
				emitComment(um[0])
			}
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

// extractLinkHeader follows RFC 8288 Link headers (preload, pagination,
// API relations) that browsers use but tag scrapers miss.
func (c *Crawler) extractLinkHeader(resp *http.Response, pageURL string, depth int) {
	for _, h := range resp.Header["Link"] {
		for _, m := range linkHeaderPattern.FindAllStringSubmatch(h, -1) {
			if len(m) >= 2 {
				c.queueHTMLRef(strings.TrimSpace(m[1]), "link-header", pageURL, pageURL, depth)
			}
		}
	}
}

// enqueueNextDataVariants builds /_next/data/<buildId><route>.json URLs.
// These are first-class real files on every Next.js site.
func (c *Crawler) enqueueNextDataVariants(body, pageURL string, depth int) {
	m := nextBuildIDPattern.FindStringSubmatch(body)
	if len(m) < 2 || m[1] == "" {
		return
	}
	buildID := m[1]
	key := "nextdata:" + buildID
	c.mu.Lock()
	if c.seenStrings[key] {
		c.mu.Unlock()
		return
	}
	c.seenStrings[key] = true
	var routes []string
	seen := map[string]bool{}
	for _, r := range c.allCrawled {
		if r.Type != "HTML" || r.StatusCode != 200 {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || hostWithoutPort(u.Host) != c.BaseHost {
			continue
		}
		if !seen[u.Path] {
			seen[u.Path] = true
			routes = append(routes, u.Path)
		}
		if len(routes) >= 300 {
			break
		}
	}
	c.mu.Unlock()
	scheme := "https"
	if bu, err := url.Parse(c.BaseURL); err == nil && bu.Scheme != "" {
		scheme = bu.Scheme
	}
	for _, rt := range routes {
		dataURL := scheme + "://" + c.BaseHostPort + "/_next/data/" + buildID + rt
		if !strings.HasSuffix(dataURL, ".json") {
			dataURL += ".json"
		}
		if c.Scope.IsInScope(dataURL, depth+1) && !c.Filters.HasSeen(dataURL) {
			writeOutput(`{"type":"deep_extract","url":%q,"source":%q,"ctx":"next_data"}`+"\n", dataURL, pageURL)
			c.addQueueItem(urlQueue{url: dataURL, source: pageURL, depth: depth + 1})
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
