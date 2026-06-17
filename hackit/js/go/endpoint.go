package main

import "regexp"

var endpointPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"API Route",              regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]+api[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"API Route (relative)",   regexp.MustCompile(`["'\` + "`" + `](/api/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL Endpoint",       regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(graphql|gql|query)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"GraphQL (relative)",     regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(graphql|gql)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"WebSocket",              regexp.MustCompile(`["'\` + "`" + `](wss?://[^"'\` + "`" + `\s]+)["'\` + "`" + `]`)},
	{"WebSocket (relative)",   regexp.MustCompile(`["'\` + "`" + `](/ws[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"RPC Endpoint",           regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(rpc|jsonrpc|xmlrpc|grpc)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"REST Resource",          regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:users|admin|auth|login|register|oauth|token|v1|v2|v3|rest|soap)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"S3 Bucket URL",          regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Firebase URL",           regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.firebase(?:io|app)\.com[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Internal Host",          regexp.MustCompile(`["'\` + "`" + `](https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Absolute URL",           regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s/]+/[^"'\` + "`" + `\s"']+)["'\` + "`" + `]`)},
	{"Relative Path",          regexp.MustCompile(`["'\` + "`" + `](/[a-zA-Z][a-zA-Z0-9\-_./]+)["'\` + "`" + `]`)},
	{"CDN URL",                regexp.MustCompile(`["'\` + "`" + `](https?://[a-zA-Z0-9.\-_]+\.(?:cloudfront|cdn|akamai|fastly)\.net[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Callback URL",            regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:callback|redirect|return|continue|next|goto)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Webhook URL",            regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:webhook|hook|callback|notify)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"OAuth URL",              regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*(?:oauth|authorize|authenticate|sso|saml|openid)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Upload Endpoint",        regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:upload|download|file|media|attach|image)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Proxy Endpoint",         regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:proxy|redirect|forward|fetch|cors)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
	{"Debug Endpoint",         regexp.MustCompile(`["'\` + "`" + `](/[^"'\` + "`" + `\s]*(?:debug|dev|test|staging|sandbox|swagger|docs|health|status|metrics)[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)},
}

type EndpointResult struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

func extractEndpoints(content string) []EndpointResult {
	var results []EndpointResult
	seen := make(map[string]bool)
	for _, ep := range endpointPatterns {
		matches := ep.Pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				u := m[1]
				if !seen[u] {
					seen[u] = true
					results = append(results, EndpointResult{URL: u, Type: ep.Name})
				}
			}
		}
	}
	return results
}

var importPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:import|require)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)?`),
	regexp.MustCompile(`(?:from|import)\s+["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`new\s+(?:Worker|SharedWorker)\s*\(?\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
	regexp.MustCompile(`import\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]\s*\)`),
	regexp.MustCompile(`new\s+URL\s*\(\s*["'\` + "`" + `]([^"'\` + "`" + `]+)["'\` + "`" + `]`),
}

func extractImports(content string) []string {
	var results []string
	seen := make(map[string]bool)
	for _, re := range importPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				p := m[1]
				if !seen[p] {
					seen[p] = true
					results = append(results, p)
				}
			}
		}
	}
	return results
}
