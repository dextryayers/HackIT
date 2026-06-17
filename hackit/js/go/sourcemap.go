package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *Crawler) checkSourceMap(jsURL string) {
	mapURL := jsURL + ".map"
	if c.Filters.Seen(mapURL) {
		return
	}
	req, _ := http.NewRequest("GET", mapURL, nil)
	c.setHeaders(req)
	req.Header.Set("Referer", jsURL)
	req.Header.Set("Accept", "*/*")
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf(`{"type":"sourcemap","url":%q,"source":%q,"status":200}`+"\n", mapURL, jsURL)

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		body := string(bodyBytes)

		// Extract original source files from source map
		c.parseSourceMap(body, mapURL)
	}
}

func (c *Crawler) parseSourceMap(body string, sourceURL string) {
	// Extract "sources" array from source map JSON
	sources := extractSourceMapSources(body)
	for _, src := range sources {
		if src == "" || strings.HasPrefix(src, "webpack://") || strings.HasPrefix(src, "webpack-internal://") {
			continue
		}
		absURL := resolveURL(src, sourceURL)
		if absURL != "" && !c.Filters.Seen(absURL) {
			fmt.Printf(`{"type":"sourcemap_source","url":%q,"source":%q}`+"\n", absURL, sourceURL)
			if c.Scope.IsCode(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: 2, phase: 1})
			}
		}
	}
}

func extractSourceMapSources(body string) []string {
	var sources []string
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "{") {
		return sources
	}

	// Simple JSON parser for "sources" array
	idx := strings.Index(body, `"sources"`)
	if idx < 0 {
		return sources
	}
	body = body[idx:]
	start := strings.Index(body, "[")
	if start < 0 {
		return sources
	}
	body = body[start:]
	end := strings.Index(body, "]")
	if end < 0 {
		return sources
	}
	arr := body[:end+1]

	// Parse string array
	arr = strings.TrimPrefix(arr, "[")
	arr = strings.TrimSuffix(arr, "]")
	parts := splitSourceMapStrings(arr)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"")
		if p != "" {
			sources = append(sources, p)
		}
	}
	return sources
}

func splitSourceMapStrings(s string) []string {
	var parts []string
	var current strings.Builder
	inString := false
	escape := false

	for _, ch := range s {
		if escape {
			current.WriteRune(ch)
			escape = false
			continue
		}
		if ch == '\\' {
			current.WriteRune(ch)
			escape = true
			continue
		}
		if ch == '"' {
			inString = !inString
			if !inString {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}
		if ch == ',' && !inString {
			continue
		}
		if inString {
			current.WriteRune(ch)
		}
	}
	return parts
}
