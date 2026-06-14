package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type APIEndpoint struct {
	Method      string
	Path        string
	Params      []string
	ContentType string
	Auth        string
	Source      string
	Confidence  float64
}

var apiPatterns = []struct {
	pattern *regexp.Regexp
	method  string
	confidence float64
}{
	{regexp.MustCompile(`(?i)(?:["'`+"`"+`](https?://[^"'`+"`"+`\s]+/api/[^"'`+"`"+`\s]*)["'`+"`"+`])`), "GET", 0.9},
	{regexp.MustCompile(`(?i)(?:["'`+"`"+`](/api/[^"'`+"`"+`\s]+)["'`+"`"+`])`), "GET", 0.8},
	{regexp.MustCompile(`(?i)(?:fetch\(['"]([^'"]+)['"]\))`), "GET", 0.7},
	{regexp.MustCompile(`(?i)(?:axios\.(get|post|put|delete|patch)\(['"]([^'"]+)['"]\))`), "GET", 0.8},
	{regexp.MustCompile(`(?i)(?:\$\.(get|post|ajax)\(['"]([^'"]+)['"]\))`), "GET", 0.7},
	{regexp.MustCompile(`(?i)(?:XMLHttpRequest\.open\(['"](GET|POST|PUT|DELETE)['"],\s*['"]([^'"]+)['"]\))`), "GET", 0.85},
	{regexp.MustCompile(`(?i)(?:url:\s*['"]([^'"]*(?:api|v[0-9]+)[^'"]*)['"])`), "GET", 0.75},
	{regexp.MustCompile(`(?i)(?:path:\s*['"]([^'"]*(?:api|v[0-9]+)[^'"]*)['"])`), "GET", 0.7},
	{regexp.MustCompile(`(?i)(?:endpoint['"\s:=]+['"]([^'"]+)['"])`), "GET", 0.6},
	{regexp.MustCompile(`(?i)(?:["'`+"`"+`](?:/v[0-9]+/[a-z]+(?:/[a-z]+)*)["'`+"`"+`])`), "GET", 0.6},
	{regexp.MustCompile(`(?i)(?:swagger|openapi|api-docs|api/documentation)`), "GET", 0.5},
}

var commonAPIPaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/graphql", "/rest", "/soap",
	"/swagger.json", "/swagger.yaml", "/swagger.yml",
	"/openapi.json", "/api-docs", "/api/documentation",
	"/.well-known/openid-configuration",
	"/health", "/healthz", "/ready", "/live",
	"/metrics", "/info", "/status",
	"/api/health", "/api/info", "/api/status",
	"/api/users", "/api/login", "/api/auth",
	"/api/admin", "/api/config", "/api/settings",
}

func DiscoverAPIs(body, sourceURL string) []APIEndpoint {
	var endpoints []APIEndpoint
	seen := make(map[string]bool)

	// Pattern-based detection
	for _, ap := range apiPatterns {
		matches := ap.pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			var path string
			if len(m) >= 3 {
				path = m[2]
			} else if len(m) >= 2 {
				path = m[1]
			} else {
				continue
			}
			key := ap.method + ":" + path
			if seen[key] { continue }
			seen[key] = true

			fmt.Fprintf(os.Stderr, "  %s Discovered API: %s %s (%.0f%%)\n",
				SColor(ColorGreen, "[+]"),
				SColor(ColorCyan, ap.method),
				SColor(ColorBWhite, path),
				ap.confidence*100)

			endpoints = append(endpoints, APIEndpoint{
				Method:     ap.method,
				Path:       path,
				Source:     "pattern",
				Confidence: ap.confidence,
			})
		}
	}

	return endpoints
}

func ProbeCommonAPIs(baseURL string, client *http.Client) []APIEndpoint {
	var found []APIEndpoint
	for _, path := range commonAPIPaths {
		u := strings.TrimRight(baseURL, "/") + path
		resp, err := SendRequest(client, u, "GET", "", nil)
		if err != nil { continue }
		if resp.StatusCode < 500 {
			ct := resp.ContentType
			isAPI := strings.Contains(ct, "json") || strings.Contains(ct, "yaml") ||
				resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403
			if isAPI {
				found = append(found, APIEndpoint{
					Method: "GET", Path: path, ContentType: ct, Source: "probe", Confidence: 0.7,
				})
			}
		}
	}
	return found
}

func ScanDiscoveredAPIs(baseURL string, discovered []APIEndpoint, scanner *Scanner) {
	if len(discovered) == 0 { return }
	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "SCANNING DISCOVERED API ENDPOINTS"))
	for _, ep := range discovered {
		fullURL := strings.TrimRight(baseURL, "/") + ep.Path
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			SColor(ColorCyan, "→"),
			SColor(ColorBWhite, ep.Method),
			SColor(ColorDim, fullURL))
		results := scanner.Scan(fullURL)
		_ = results
	}
}

type APIReport struct {
	EndpointsFound int
	OpenEndpoints  int
	AuthEndpoints  int
	SwaggerFound   bool
	GraphQLFound   bool
}

func AnalyzeAPIEndpoints(endpoints []APIEndpoint) *APIReport {
	r := &APIReport{
		EndpointsFound: len(endpoints),
	}
	for _, ep := range endpoints {
		if strings.HasSuffix(ep.Path, "/swagger.json") || strings.Contains(ep.Path, "openapi") {
			r.SwaggerFound = true
		}
		if strings.Contains(ep.Path, "graphql") {
			r.GraphQLFound = true
		}
		if strings.Contains(ep.Path, "auth") || strings.Contains(ep.Path, "login") || strings.Contains(ep.Path, "token") {
			r.AuthEndpoints++
		}
	}
	return r
}

func PrintAPIReport(report *APIReport) {
	if noColor {
		fmt.Printf("\nAPI Discovery Report:\n")
		fmt.Printf("  Endpoints: %d\n", report.EndpointsFound)
		fmt.Printf("  Auth: %d\n", report.AuthEndpoints)
		if report.SwaggerFound { fmt.Printf("  Swagger/OpenAPI: found\n") }
		if report.GraphQLFound { fmt.Printf("  GraphQL: found\n") }
		return
	}
	fmt.Printf("\n%s %s\n",
		SColor(ColorBCyan, "═══"),
		SColor(ColorBWhite, "API DISCOVERY REPORT"))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Endpoints:"),
		SColor(ColorGreen, fmt.Sprintf("%d", report.EndpointsFound)))
	fmt.Printf("  %s %s\n",
		SColor(ColorBWhite, "Auth endpoints:"),
		SColor(ColorYellow, fmt.Sprintf("%d", report.AuthEndpoints)))
	if report.SwaggerFound {
		fmt.Printf("  %s %s\n",
			SColor(ColorBWhite, "Swagger:"),
			SColor(ColorGreen, "detected"))
	}
	if report.GraphQLFound {
		fmt.Printf("  %s %s\n",
			SColor(ColorBWhite, "GraphQL:"),
			SColor(ColorGreen, "detected"))
	}
	fmt.Println()
}

func ExtractEndpointsFromJSON(body string) []string {
	var endpoints []string
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil
	}
	var extractPaths func(prefix string, obj map[string]interface{})
	extractPaths = func(prefix string, obj map[string]interface{}) {
		for k, v := range obj {
			fullPath := prefix + "/" + k
			if sub, ok := v.(map[string]interface{}); ok {
				extractPaths(fullPath, sub)
			} else if arr, ok := v.([]interface{}); ok && len(arr) > 0 {
				endpoints = append(endpoints, fullPath)
				_ = arr
			} else {
				endpoints = append(endpoints, fullPath)
			}
		}
	}
	extractPaths("", data)
	return endpoints
}
