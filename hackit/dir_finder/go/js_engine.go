package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var (
	jsURLPattern   = regexp.MustCompile(`(?:['"`+"`"+`])(/[^'"`+"`"+`\s]+?)(?:['"`+"`"+`])`)
	jsImportPattern = regexp.MustCompile(`(?:import|require)\s*\(?\s*['"]([^'"]+)['"]`)
	jsFetchPattern  = regexp.MustCompile(`(?:fetch|axios|ajax|getJSON|postJSON)\s*\(\s*['"]([^'"]+)['"]`)
	jsConcatPattern = regexp.MustCompile(`['"]([^'"]+)['"]\s*\+`)
	jsEndpointPattern = regexp.MustCompile(`['"`+"`"+`](/[a-zA-Z0-9_\-./?&=%]+)['"`+"`"+`]`)
)

func ExtractJSEndpoints(target string, client *http.Client) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Common JS file paths
	jsFiles := []string{
		"/main.js", "/app.js", "/bundle.js", "/index.js",
		"/script.js", "/scripts.js", "/common.js",
		"/static/js/main.js", "/static/js/app.js",
		"/assets/js/main.js", "/assets/js/app.js",
		"/js/app.js", "/js/main.js",
	}

	for _, jsPath := range jsFiles {
		fullURL := buildFullURL(target, jsPath)
		resp, err := client.Get(fullURL)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 512*1024)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		jsContent := string(body[:n])
		urls := parseJSContent(jsContent, target)

		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				endpoints = append(endpoints, u)
			}
		}
	}

	return endpoints
}

func DeepJSAnalysis(target string, client *http.Client, depth int) []string {
	if depth <= 0 {
		return nil
	}

	var allEndpoints []string
	seen := make(map[string]bool)

	jsFiles := ExtractJSEndpoints(target, client)
	for _, js := range jsFiles {
		if !strings.HasSuffix(js, ".js") && !strings.HasSuffix(js, ".jsx") {
			continue
		}
		fullURL := buildFullURL(target, js)
		resp, err := client.Get(fullURL)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 512*1024)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		jsContent := string(body[:n])
		urls := parseJSContent(jsContent, target)

		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				allEndpoints = append(allEndpoints, u)
			}
		}

		// Recursively analyze imported JS files
		imports := jsImportPattern.FindAllStringSubmatch(jsContent, -1)
		for _, m := range imports {
			if len(m) > 1 && !seen[m[1]] {
				impURL := buildFullURL(target, m[1])
				if strings.HasSuffix(impURL, ".js") {
					impResp, err := client.Get(impURL)
					if err == nil && impResp != nil {
						impBody := make([]byte, 256*1024)
						impN, _ := impResp.Body.Read(impBody)
						impResp.Body.Close()
						impURLs := parseJSContent(string(impBody[:impN]), target)
						for _, u := range impURLs {
							if !seen[u] {
								seen[u] = true
								allEndpoints = append(allEndpoints, u)
							}
						}
					}
				}
			}
		}
	}

	return allEndpoints
}

func parseJSContent(js string, baseURL string) []string {
	var urls []string
	seen := make(map[string]bool)

	allMatches := jsURLPattern.FindAllStringSubmatch(js, -1)
	for _, m := range allMatches {
		if len(m) > 1 {
			url := m[1]
			if !seen[url] && isValidJSPath(url) {
				seen[url] = true
				urls = append(urls, url)
			}
		}
	}

	fetchMatches := jsFetchPattern.FindAllStringSubmatch(js, -1)
	for _, m := range fetchMatches {
		if len(m) > 1 {
			url := m[1]
			if !seen[url] {
				seen[url] = true
				if strings.HasPrefix(url, "/") || strings.HasPrefix(url, "http") {
					urls = append(urls, url)
				}
			}
		}
	}

	return urls
}

func isValidJSPath(path string) bool {
	if strings.HasPrefix(path, "#") || strings.HasPrefix(path, "?") {
		return false
	}
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return false
	}
	if strings.HasPrefix(path, "data:") || strings.HasPrefix(path, "javascript:") {
		return false
	}
	if len(path) < 2 {
		return false
	}
	return true
}

func PrintJSEndpoints(endpoints []string) {
	if len(endpoints) > 0 {
		fmt.Fprintf(color.Output, "%s Found %d JS endpoints\n", color.GreenString("[+]"), len(endpoints))
	}
}
