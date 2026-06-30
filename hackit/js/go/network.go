package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	xhrPattern      = regexp.MustCompile(`(?:fetch|XMLHttpRequest|axios|xhr|ajax)\.?\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	axiosMethodPat  = regexp.MustCompile(`axios\.(?:get|post|put|patch|delete|head|options|request)\([` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	kyPattern       = regexp.MustCompile(`ky\.(?:get|post|put|patch|delete|head)\([` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	superagentPat   = regexp.MustCompile(`superagent\.(?:get|post|put|patch|delete)\([` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	wsPattern       = regexp.MustCompile(`["'\` + "`" + `](wss?://[^"'\` + "`" + `]+)["'\` + "`" + `]`)
	eventSourcePat  = regexp.MustCompile(`(?:EventSource|WebSocket)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	importCallPat   = regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`)
	scriptLoadPat   = regexp.MustCompile(`(?:createElement|appendChild|innerHTML|insertAdjacentHTML)\s*\(?[^)]*["'\` + "`" + `]([^"'\` + "`" + `]+\.(?:js|json))["'\` + "`" + `]`)
	dynamicSrcPat   = regexp.MustCompile(`\.src\s*=\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	serviceWorker   = regexp.MustCompile(`navigator\.serviceWorker\.register\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	useQueryPat     = regexp.MustCompile(`use(?:Query|Mutation|SWR)\s*\([^,]*[` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	apolloClientPat = regexp.MustCompile(`(?:apolloClient|client)\.(?:query|mutate)\s*\([^}]*[` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	useFetchPat     = regexp.MustCompile(`use(?:Fetch|AsyncData)\s*\([` + "`" + `"']([^` + "`" + `"']+)[` + "`" + `"']`)
	jqueryGetJSON   = regexp.MustCompile(`\$\.getJSON\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	navigatorBeacon = regexp.MustCompile(`navigator\.sendBeacon\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	newRequestPat   = regexp.MustCompile(`new\s+Request\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	xhrOpenPat      = regexp.MustCompile(`\.open\s*\(\s*["'\` + "`" + `](?:GET|POST|PUT|DELETE)[` + "`" + `"']\s*,\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
	postMessagePat  = regexp.MustCompile(`postMessage\s*\([^,]*,\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`)
)

func (c *Crawler) captureJSNetwork(body string, sourceURL string, depth int) {
	dynamicPatterns := []struct {
		re    *regexp.Regexp
		group int
		rtype string
	}{
		{xhrPattern, 1, "fetch"},
		{axiosMethodPat, 1, "axios"},
		{kyPattern, 1, "ky"},
		{superagentPat, 1, "superagent"},
		{wsPattern, 1, "websocket"},
		{eventSourcePat, 1, "eventsource"},
		{importCallPat, 1, "dynamic_import"},
		{scriptLoadPat, 1, "dom_script"},
		{dynamicSrcPat, 1, "dynamic_src"},
		{serviceWorker, 1, "service_worker"},
		{useQueryPat, 1, "react_query"},
		{apolloClientPat, 1, "apollo_client"},
		{useFetchPat, 1, "use_fetch"},
		{jqueryGetJSON, 1, "jquery_getjson"},
		{navigatorBeacon, 1, "send_beacon"},
		{newRequestPat, 1, "new_request"},
		{xhrOpenPat, 1, "xhr_open"},
		{postMessagePat, 1, "post_message"},
	}

	seen := make(map[string]bool)
	for _, p := range dynamicPatterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) <= p.group || seen[m[p.group]] {
				continue
			}
			seen[m[p.group]] = true
			absURL := resolveJSImport(strings.TrimSpace(m[p.group]), sourceURL, p.rtype)
			if absURL == "" {
				continue
			}
			if !strings.HasPrefix(absURL, "http") {
				continue
			}
			if !c.Scope.IsInScope(absURL, depth+1) {
				writeOutput(`{"type":"network_entry","url":%q,"source_url":%q,"resource_type":"%s_out"}`+"\n", absURL, sourceURL, p.rtype)
				continue
			}
			writeOutput(`{"type":"network_entry","url":%q,"source_url":%q,"resource_type":%q}`+"\n", absURL, sourceURL, p.rtype)
			if !c.Filters.HasSeen(absURL) && (strings.HasSuffix(absURL, ".js") || strings.HasSuffix(absURL, ".mjs") || strings.HasSuffix(absURL, ".cjs")) {
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: depth + 1})
			}
		}
	}
}

func (c *Crawler) captureHTMLResources(body string, pageURL string, depth int) {
	resourcePatterns := []struct {
		re    *regexp.Regexp
		group int
		rtype string
	}{
		{regexp.MustCompile(`<script[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "script"},
		{regexp.MustCompile(`<link[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `][^>]*rel=["'\` + "`" + `]?(?:stylesheet|preload|prefetch|modulepreload|icon|apple-touch-icon)["'\` + "`" + `]?`), 1, "stylesheet"},
		{regexp.MustCompile(`<img[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "image"},
		{regexp.MustCompile(`<source[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "media"},
		{regexp.MustCompile(`<iframe[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "iframe"},
		{regexp.MustCompile(`<form[^>]+action=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "form"},
		{regexp.MustCompile(`<video[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "video"},
		{regexp.MustCompile(`<audio[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "audio"},
		{regexp.MustCompile(`<object[^>]+data=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "object"},
		{regexp.MustCompile(`<embed[^>]+src=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "embed"},
		{regexp.MustCompile(`@import\s+(?:url\s*)?\(?\s*["'\` + "`" + `]?([^"'\` + "`" + `)]+)["'\` + "`" + `]?\s*\)?\s*;`), 1, "css_import"},
		{regexp.MustCompile(`url\(["'\` + "`" + `]?([^"'\` + "`" + `)]+)["'\` + "`" + `]?\)`), 1, "css_url"},
		{regexp.MustCompile(`<a[^>]+href=["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`), 1, "link"},
	}

	seen := make(map[string]bool)
	for _, p := range resourcePatterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) <= p.group {
				continue
			}
			rawURL := strings.TrimSpace(m[p.group])
			if rawURL == "" || strings.HasPrefix(rawURL, "#") || strings.HasPrefix(rawURL, "javascript:") || strings.HasPrefix(rawURL, "data:") || strings.HasPrefix(rawURL, "mailto:") || strings.HasPrefix(rawURL, "tel:") || seen[rawURL] {
				continue
			}
			seen[rawURL] = true
			absURL := resolveURL(rawURL, pageURL)
			if absURL == "" || !c.Scope.IsInScope(absURL, depth+1) || c.Filters.HasSeen(absURL) {
				continue
			}
			writeOutput(`{"type":"network_entry","url":%q,"source_url":%q,"resource_type":%q}`+"\n", absURL, pageURL, p.rtype)
			if p.rtype == "script" || strings.HasSuffix(absURL, ".js") || strings.HasSuffix(absURL, ".mjs") || strings.HasSuffix(absURL, ".cjs") {
				if depth < c.Scope.MaxDepth {
					c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth + 1})
				}
			} else if isCrawable(absURL) && depth < c.Scope.MaxDepth {
				c.addQueueItem(urlQueue{url: absURL, source: pageURL, depth: depth})
			}
		}
	}
}

func (c *Crawler) fetchAndReport(url string, source string, rtype string) {
	req, _ := http.NewRequest("GET", url, nil)
	c.setHeaders(req)
	req.Header.Set("Accept", "*/*")
	resp, err := c.Client.Do(req)
	if err != nil {
		writeOutput(`{"type":"network_result","url":%q,"source_url":%q,"resource_type":%q,"status":0,"error":%q}`+"\n", url, source, rtype, err.Error())
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	ct := resp.Header.Get("Content-Type")
	bodyJSON, _ := json.Marshal(string(bodyBytes))
	writeOutput(`{"type":"network_result","url":%q,"source_url":%q,"resource_type":%q,"status":%d,"content_type":%q,"length":%d,"body":%s}`+"\n", url, source, rtype, resp.StatusCode, ct, len(bodyBytes), string(bodyJSON))
	if (strings.Contains(ct, "javascript") || strings.HasSuffix(url, ".js")) && resp.StatusCode == 200 {
		if c.Opts.ShowCode && len(bodyBytes) < 512*1024 {
			writeOutput(`{"type":"js_source","url":%q,"status":200,"length":%d,"body":%s,"method":"network"}`+"\n", url, len(bodyBytes), string(bodyJSON))
		}
		c.parseJSSource(string(bodyBytes), url, 2)
	}
}
