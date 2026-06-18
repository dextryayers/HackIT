package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	inlineSourceMapRe = regexp.MustCompile(`//#?\s*sourceMappingURL=data:application/json;base64,([a-zA-Z0-9+/=]+)`)
	externalSourceMap = regexp.MustCompile(`//#?\s*sourceMappingURL=(.+\.map)`)
)

func (c *Crawler) checkSourceMap(jsURL string) {
	// Check for inline source map first, then external
	// This is called from parseJSSource, so we don't have the body here.
	// Inline source maps are handled via parseJSSource -> extractInlineSourceMap.
	// External source maps are checked here.

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
		writeOutput(`{"type":"sourcemap","url":%q,"source":%q,"status":200}`+"\n", mapURL, jsURL)

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		body := string(bodyBytes)

		// Parse source map and extract sources + sourcesContent
		c.parseSourceMap(body, mapURL, jsURL)
	}
}

// extractInlineSourceMap finds and decodes inline base64 source maps from JS source
func (c *Crawler) extractInlineSourceMap(jsBody string, jsURL string) {
	matches := inlineSourceMapRe.FindStringSubmatch(jsBody)
	if len(matches) < 2 {
		return
	}

	b64data := matches[1]
	decoded, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return
	}

	writeOutput(`{"type":"sourcemap","url":%q,"source":%q,"status":200,"method":"inline"}`+"\n", jsURL+"#inline", jsURL)

	// Parse the inline source map as if it were an external file
	c.parseSourceMap(string(decoded), jsURL+"#inline", jsURL)
}

// parseSourceMap parses a source map JSON and extracts sources + sourcesContent
func (c *Crawler) parseSourceMap(body string, sourceURL string, originalJS string) {
	type SourceMap struct {
		Version        int      `json:"version"`
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
		Mappings       string   `json:"mappings"`
	}

	var sm SourceMap
	if err := json.Unmarshal([]byte(body), &sm); err != nil {
		return
	}

	// Extract source file names
	for _, src := range sm.Sources {
		if src == "" || strings.HasPrefix(src, "webpack://") || strings.HasPrefix(src, "webpack-internal://") {
			continue
		}
		absURL := resolveURL(src, sourceURL)
		if absURL != "" && !c.Filters.HasSeen(absURL) {
			writeOutput(`{"type":"sourcemap_source","url":%q,"source":%q}`+"\n", absURL, sourceURL)
			if c.Scope.IsCode(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: 2, phase: 1})
			}
		}
	}

	// Extract and analyze sourcesContent (original source code embedded in source map)
	if len(sm.SourcesContent) > 0 {
		writeOutput(`{"type":"sourcemap_content","sources":%d,"size":%d,"source":%q}`+"\n",
			len(sm.SourcesContent), len(body), sourceURL)

		for idx, content := range sm.SourcesContent {
			if content == "" {
				continue
			}
			if idx < len(sm.Sources) {
				srcName := sm.Sources[idx]
				writeOutput(`{"type":"sourcemap_content_source","index":%d,"name":%q,"size":%d,"source":%q}`+"\n",
					idx, srcName, len(content), sourceURL)

				// Analyze the original source code for endpoints and secrets
				result := analyzeJS(content, sourceURL+"|"+srcName)

				// Emit endpoints found in sourcesContent
				for _, s := range extractJSStringURLs(result) {
					absURL := resolveURL(s.Value, sourceURL)
					if absURL != "" && !c.Filters.HasSeen(absURL) && c.Scope.IsInScope(absURL, 2) {
						writeOutput(`{"type":"sourcemap_find","url":%q,"source":%q,"context":%q}`+"\n",
							absURL, sourceURL+"|"+srcName, s.Context)
						if c.Scope.IsJS(absURL) {
							c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: 2, phase: 1})
						}
					}
				}

				// Emit sensitive findings from sourcesContent
				for _, f := range result.Secrets {
					writeOutput(`{"type":"sensitive","name":%q,"match":%q,"source":%q}`+"\n",
						f.Name, f.Match, sourceURL+"|"+srcName)
				}
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
