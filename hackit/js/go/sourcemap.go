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
		c.parseSourceMap(string(bodyBytes), mapURL, jsURL)
	}
}

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
	c.parseSourceMap(string(decoded), jsURL+"#inline", jsURL)
}

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
	for _, src := range sm.Sources {
		if src == "" || strings.HasPrefix(src, "webpack://") || strings.HasPrefix(src, "webpack-internal://") {
			continue
		}
		absURL := resolveURL(src, sourceURL)
		if absURL != "" && !c.Filters.HasSeen(absURL) {
			writeOutput(`{"type":"sourcemap_source","url":%q,"source":%q}`+"\n", absURL, sourceURL)
			if c.Scope.IsCode(absURL) {
				c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: 2})
			}
		}
	}
	if len(sm.SourcesContent) > 0 {
		writeOutput(`{"type":"sourcemap_content","sources":%d,"size":%d,"source":%q}`+"\n", len(sm.SourcesContent), len(body), sourceURL)
		for idx, content := range sm.SourcesContent {
			if content == "" {
				continue
			}
			if idx < len(sm.Sources) {
				srcName := sm.Sources[idx]
				writeOutput(`{"type":"sourcemap_content_source","index":%d,"name":%q,"size":%d,"source":%q}`+"\n", idx, srcName, len(content), sourceURL)
				result := analyzeJS(content, sourceURL+"|"+srcName)
				for _, s := range extractJSStringURLs(result) {
					absURL := resolveURL(s.Value, sourceURL)
					if absURL != "" && !c.Filters.HasSeen(absURL) && c.Scope.IsInScope(absURL, 2) {
						writeOutput(`{"type":"sourcemap_find","url":%q,"source":%q,"context":%q}`+"\n", absURL, sourceURL+"|"+srcName, s.Context)
						if c.Scope.IsJS(absURL) {
							c.addQueueItem(urlQueue{url: absURL, source: sourceURL, depth: 2})
						}
					}
				}
				for _, f := range result.Secrets {
					writeOutput(`{"type":"sensitive","name":%q,"match":%q,"source":%q}`+"\n", f.Name, f.Match, sourceURL+"|"+srcName)
				}
			}
		}
	}
}

func extractJSStringURLs(result JSAnalysisResult) []ExtractedString {
	var urls []ExtractedString
	seen := make(map[string]bool)
	sources := [][]ExtractedString{result.Strings, result.ModuleURLs, result.TemplateParts, result.CSSRefs, result.EnvURLs, result.Concatenations, result.ConfigObjects, result.SvelteKitURLs}
	for _, list := range sources {
		for _, s := range list {
			if (s.IsURL || s.IsPath) && !seen[s.Value] {
				seen[s.Value] = true
				urls = append(urls, s)
			}
		}
	}
	return urls
}
