package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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

	// Template literal URL patterns
	templateURLPat  = regexp.MustCompile("`[^`]*(?:https?://[^`\"'\\\\${\\s]+)[^`]*`")
	templateRelPat  = regexp.MustCompile("`[^`]*(?:/[^`\"'\\\\${\\s]*(?:api|graphql|rest|v1|v2|v3|auth|oauth|token|login|register|users|admin|upload|download|webhook)[^`\"'\\\\${\\s]*)[^`]*`")

	// Inline JSON config patterns (SSR payloads)
	nextDataPattern = regexp.MustCompile(`<script id="__NEXT_DATA__"[^>]*type="application/json"[^>]*>({.*?})</script>`)
	nuxtDataPattern = regexp.MustCompile(`<script id="__NUXT__"[^>]*type="application/json"[^>]*>({.*?})</script>`)
	apolloStatePat  = regexp.MustCompile(`<script id="__APOLLO_STATE__"[^>]*>({.*?})</script>`)
	rscPayloadPat   = regexp.MustCompile(`<script id="__RSC__"[^>]*>({.*?})</script>`)
	relayDataPat    = regexp.MustCompile(`<script id="__RELAY_DATA__"[^>]*>({.*?})</script>`)
	bootstrapPat    = regexp.MustCompile(`<script id="__BOOTSTRAP_DATA__"[^>]*>({.*?})</script>`)

	// Template literal substring extraction
	absURLInTemplate = regexp.MustCompile(`(https?://[^"'\` + "`" + `\s]+)`)
	relURLInTemplate  = regexp.MustCompile(`(/\S+(?:api|graphql|rest|v1|v2|v3|auth|oauth|token|login|register|users|admin|upload|download|webhook|trpc)\S*)`)
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

	// Run deep extraction on HTML pages (SSR configs, import maps, webpack)
	if crawlType == "HTML" && resp.StatusCode == 200 {
		deep := performDeepExtraction(body, pageURL)
		for _, s := range deep.BootstrapConfigs {
			if s.IsURL || s.IsPath {
				absURL := resolveURL(s.Value, c.BaseURL)
				if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
					writeOutput(`{"type":"ssr_url","url":%q,"source":%q,"ctx":%q}`+"\n",
						absURL, pageURL, s.Context)
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
				}
			} else {
				writeOutput(`{"type":"ssr_config","name":%q,"source":%q,"ctx":%q}`+"\n",
					s.Value, pageURL, s.Context)
			}
		}
		for _, s := range deep.ImportMapURLs {
			absURL := resolveURL(s.Value, c.BaseURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
				writeOutput(`{"type":"importmap","url":%q,"source":%q,"ctx":%q}`+"\n",
					absURL, pageURL, s.Context)
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}

	// Output JS source code when ShowCode is enabled
	if c.ShowCode && resp.StatusCode == 200 && crawlType == "JavaScript" {
		if len(body) > 0 && len(body) < 1024*1024 {
			bodyJSON, _ := json.Marshal(body)
			writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":%s}`+"\n",
				pageURL, len(body), string(bodyJSON))
		} else {
			writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":"[skipped: %d bytes]"}`+"\n",
				pageURL, len(body), len(body))
		}
	}

	// Always emit discovered line for progress tracking
	writeOutput(`{"type":"discovered","url":%q,"source":%q,"content_type":%q,"status":%d,"depth":%d}`+"\n",
		pageURL, sourceURL, crawlType, resp.StatusCode, depth)

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

		// Extract inline JSON SSR configs (Next.js, Nuxt, Apollo, etc.)
		configURLs := extractInlineJSONConfigs(body, pageURL)
		for _, cu := range configURLs {
			absURL := resolveURL(cu, pageURL)
			if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1, phase: 1})
			}
		}
	}
}

func (c *Crawler) parseJSSource(body string, sourceURL string, depth int) {
	analysis := analyzeJS(body, sourceURL)

	// ── Helper: resolve + queue + emit NDJSON ──
	emitAndQueue := func(val, ndjsonType, ctx string, enqueueOnly bool) {
		absURL := resolveURL(val, c.BaseURL)
		if absURL == "" {
			return
		}
		if !enqueueOnly {
			writeOutput(`{"type":%q,"url":%q,"source":%q,"ctx":%q}`+"\n",
				ndjsonType, absURL, sourceURL, ctx)
		}
		if c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
			c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1, phase: 1})
		}
		c.extractSubdomainFromURL(val)
	}

	// ── Phase 1: All string literals ──
	for _, s := range analysis.Strings {
		emitAndQueue(s.Value, "js_string_url", s.Context, false)
	}

	// ── Phase 2: Module URLs (dynamic import, ESM export, webpack chunks) ──
	for _, s := range analysis.ModuleURLs {
		emitAndQueue(s.Value, "module_url", s.Context, false)
	}

	// ── Phase 3: Template literal interpolation parts ──
	for _, s := range analysis.TemplateParts {
		emitAndQueue(s.Value, "template_reconstructed", s.Context, false)
	}

	// ── Phase 4: CSS references (url(), @import from CSS-in-JS) ──
	for _, s := range analysis.CSSRefs {
		emitAndQueue(s.Value, "css_ref", s.Context, false)
	}

	// ── Phase 5: Environment URLs (Worker, SW, Wasm, Router, Window, Location) ──
	for _, s := range analysis.EnvURLs {
		emitAndQueue(s.Value, "env_url", s.Context, false)
	}

	// ── Phase 6: Concatenation patterns ──
	for _, s := range analysis.Concatenations {
		emitAndQueue(s.Value, "concat_url", s.Context, false)
	}

	// ── Phase 7: JSON config objects ──
	for _, s := range analysis.ConfigObjects {
		emitAndQueue(s.Value, "config_url", s.Context, false)
	}

	// ── Phase 8: SvelteKit load function URLs ──
	for _, s := range analysis.SvelteKitURLs {
		emitAndQueue(s.Value, "sveltekit_url", s.Context, false)
	}

	// ── Phase 8.5: Deep extraction (webpack, GraphQL, SW cache, SSR, etc.) ──
	deep := performDeepExtraction(body, sourceURL)
	for _, s := range deep.WebpackChunks {
		emitAndQueue(s.Value, "webpack_chunk", s.Context, false)
	}
	for _, s := range deep.GraphQLQueries {
		if s.IsURL || s.IsPath {
			emitAndQueue(s.Value, "graphql_url", s.Context, false)
		} else {
			writeOutput(`{"type":"graphql_op","name":%q,"source":%q}`+"\n", s.Value, sourceURL)
		}
	}
	for _, s := range deep.SWCacheURLs {
		emitAndQueue(s.Value, "sw_cache", s.Context, false)
	}
	for _, s := range deep.ConsoleURLs {
		emitAndQueue(s.Value, "console_url", s.Context, false)
	}
	for _, s := range deep.ImportMapURLs {
		emitAndQueue(s.Value, "importmap", s.Context, false)
	}
	for _, s := range deep.InlineWasmURLs {
		emitAndQueue(s.Value, "wasm_url", s.Context, false)
	}
	for _, s := range deep.JSONPEndpoints {
		emitAndQueue(s.Value, "jsonp_endpoint", s.Context, false)
	}
	for _, s := range deep.MinifiedHints {
		emitAndQueue(s.Value, "minified_hint", s.Context, false)
	}
	for _, s := range deep.BootstrapConfigs {
		if s.IsURL || s.IsPath {
			emitAndQueue(s.Value, "ssr_url", s.Context, false)
		} else {
			writeOutput(`{"type":"ssr_config","name":%q,"source":%q,"ctx":%q}`+"\n",
				s.Value, sourceURL, s.Context)
		}
	}

	// ── Phase 9: Standard endpoint patterns (legacy extractEndpoints) ──
	for _, ep := range analysis.Endpoints {
		emitAndQueue(ep.URL, "endpoint", "legacy_endpoint", false)
	}

	// ── Phase 10: Template literal URLs (legacy extractTemplateLiteralURLs) ──
	for _, tu := range extractTemplateLiteralURLs(body) {
		absURL := resolveURL(tu, sourceURL)
		if absURL != "" && c.Scope.IsInScope(absURL, depth+1) && !c.Filters.HasSeen(absURL) {
			writeOutput(`{"type":"template_url","url":%q,"source":%q}`+"\n", absURL, sourceURL)
			if c.Scope.IsJS(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1, phase: 1})
			}
		}
	}

	// ── Phase 11: Subdomain extraction ──
	c.extractSubdomainsFromBody(body, sourceURL)

	// ── Phase 12: Sensitive data ──
	for _, f := range analysis.Secrets {
		writeOutput(`{"type":"sensitive","name":%q,"match":%q,"source":%q}`+"\n",
			f.Name, f.Match, sourceURL)
	}

	// ── Phase 13: Comments ──
	for _, cm := range findComments(body, sourceURL) {
		writeOutput(`{"type":"comment","comment":%q,"source":%q}`+"\n", cm.Comment, cm.Source)
	}

	// ── Phase 14: Dependencies (legacy extractImports / extractDependencies) ──
	for _, imp := range extractImports(body) {
		absURL := resolveURL(imp, sourceURL)
		if absURL != "" && c.Scope.IsJS(absURL) && c.Scope.IsInScope(absURL, depth+1) {
			c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1, phase: 1})
		}
	}
	c.extractDependencies(body, sourceURL, depth)

	// ── Phase 15: Network calls ──
	c.captureJSNetwork(body, sourceURL, depth)

	// ── Phase 16: Source maps ──
	if depth < c.Scope.MaxDepth {
		c.extractInlineSourceMap(body, sourceURL)
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
				if c.Filters.HasSeen(absURL) {
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

// Extract URLs from template literals (backtick strings without interpolation)
func extractTemplateLiteralURLs(body string) []string {
	var urls []string
	seen := make(map[string]bool)

	// Absolute URLs in template literals
	tm := templateURLPat.FindAllString(body, -1)
	for _, t := range tm {
		m := absURLInTemplate.FindAllStringSubmatch(t, -1)
		for _, mm := range m {
			if len(mm) >= 2 && !seen[mm[1]] {
				seen[mm[1]] = true
				urls = append(urls, mm[1])
			}
		}
	}

	// Relative API/graphql paths in template literals
	tr := templateRelPat.FindAllString(body, -1)
	for _, t := range tr {
		m := relURLInTemplate.FindAllStringSubmatch(t, -1)
		for _, mm := range m {
			if len(mm) >= 2 && !seen[mm[1]] {
				seen[mm[1]] = true
				urls = append(urls, mm[1])
			}
		}
	}

	return urls
}

// Extract inline JSON config blobs (Next.js/Nuxt/Apollo SSR payloads)
func extractInlineJSONConfigs(body string, sourceURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	patterns := []struct {
		re    *regexp.Regexp
		name  string
	}{
		{nextDataPattern, "__NEXT_DATA__"},
		{nuxtDataPattern, "__NUXT__"},
		{apolloStatePat, "__APOLLO_STATE__"},
		{rscPayloadPat, "__RSC__"},
		{relayDataPat, "__RELAY_DATA__"},
		{bootstrapPat, "__BOOTSTRAP_DATA__"},
	}

	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			payload := m[1]

			// Try to parse as JSON and extract URLs
			var data interface{}
			if err := json.Unmarshal([]byte(payload), &data); err != nil {
				continue
			}

			writeOutput(`{"type":"ssr_config","name":%q,"source":%q,"size":%d}`+"\n",
				p.name, sourceURL, len(payload))

			// Extract all string values that look like URLs from the JSON
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
				if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
					strings.HasPrefix(s, "/")) && !seen[s] {
					seen[s] = true
					*urls = append(*urls, s)
					writeOutput(`{"type":"ssr_url","url":%q,"source":%q,"field":%q}`+"\n",
						s, sourceURL, key)
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

