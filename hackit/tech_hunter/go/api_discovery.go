package main

import (
	"regexp"
	"strings"
)

type APIEndpoint struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Source  string `json:"source"`
	Params  string `json:"params,omitempty"`
	Auth    string `json:"auth,omitempty"`
}

type APIDiscoveryResult struct {
	Endpoints    []APIEndpoint `json:"endpoints"`
	SpecFiles    []string      `json:"spec_files"`
	GraphQL      bool          `json:"graphql"`
	RESTFul      bool          `json:"restful"`
	AuthMechanisms []string   `json:"auth_mechanisms"`
	APIVersions  []string      `json:"api_versions"`
}

func DiscoverAPIs(body string, headers map[string]string, domain string) *APIDiscoveryResult {
	res := &APIDiscoveryResult{}

	// Detect API spec files in body
	specPatterns := []string{
		`/swagger\.json`,
		`/swagger\.yaml`,
		`/swagger\.yml`,
		`/api-docs`,
		`/openapi\.json`,
		`/openapi\.yaml`,
		`/graphql`,
		`/graphiql`,
		`/playground`,
		`/api/v\d+/`,
		`/v\d+/api/`,
		`/docs`,
		`/redoc`,
	}
	for _, pat := range specPatterns {
		if strings.Contains(strings.ToLower(body), pat) {
			res.SpecFiles = append(res.SpecFiles, pat)
		}
	}

	// Detect GraphQL
	if strings.Contains(body, "graphql") || strings.Contains(body, "GraphQL") || strings.Contains(body, "__typename") {
		res.GraphQL = true
	}

	// Detect RESTful patterns
	restIndicators := []string{"/api/", "/rest/", "/v1/", "/v2/", "/v3/", "method: 'GET'", "method: 'POST'", "method:'GET'", "method:'POST'"}
	for _, ind := range restIndicators {
		if strings.Contains(body, ind) {
			res.RESTFul = true
			break
		}
	}

	// Extract API endpoints from JS/HTML
	endpointPattern := regexp.MustCompile(`["'\` + "`" + `](https?://[^"'\` + "`" + `\s]*api[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)
	matches := endpointPattern.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			res.Endpoints = append(res.Endpoints, APIEndpoint{
				Path:   m[1],
				Source: "JS/HTML URL",
			})
			seen[m[1]] = true
		}
	}

	// Pattern: /api/v1/users, /api/v2/products, etc
	apiPathPattern := regexp.MustCompile(`["'\` + "`" + `](/api/[^"'\` + "`" + `\s]*)["'\` + "`" + `]`)
	apiMatches := apiPathPattern.FindAllStringSubmatch(body, -1)
	for _, m := range apiMatches {
		if len(m) > 1 && !seen[m[1]] {
			res.Endpoints = append(res.Endpoints, APIEndpoint{
				Path:   m[1],
				Source: "JS/HTML path",
			})
			seen[m[1]] = true
		}
	}

	// Detect auth mechanisms
	if strings.Contains(body, "Bearer") || strings.Contains(body, "bearer") {
		res.AuthMechanisms = append(res.AuthMechanisms, "JWT/Bearer Token")
	}
	if strings.Contains(body, "OAuth") || strings.Contains(body, "oauth") {
		res.AuthMechanisms = append(res.AuthMechanisms, "OAuth2")
	}
	if strings.Contains(body, "apiKey") || strings.Contains(body, "api_key") || strings.Contains(body, "x-api-key") {
		res.AuthMechanisms = append(res.AuthMechanisms, "API Key")
	}
	if strings.Contains(body, "Basic ") || strings.Contains(body, "basicAuth") {
		res.AuthMechanisms = append(res.AuthMechanisms, "Basic Auth")
	}
	if _, ok := headers["Authorization"]; ok {
		auth := headers["Authorization"]
		if strings.HasPrefix(auth, "Bearer") {
			res.AuthMechanisms = append(res.AuthMechanisms, "JWT/Bearer Token")
		} else if strings.HasPrefix(auth, "Basic") {
			res.AuthMechanisms = append(res.AuthMechanisms, "Basic Auth")
		} else {
			res.AuthMechanisms = append(res.AuthMechanisms, "Custom Auth")
		}
	}

	// Detect API versions
	versionPattern := regexp.MustCompile(`/api/v(\d+)/`)
	verMatches := versionPattern.FindAllStringSubmatch(body, -1)
	verSeen := make(map[string]bool)
	for _, m := range verMatches {
		if len(m) > 1 && !verSeen[m[1]] {
			res.APIVersions = append(res.APIVersions, "v"+m[1])
			verSeen[m[1]] = true
		}
	}
	if len(res.APIVersions) == 0 && res.RESTFul {
		res.APIVersions = append(res.APIVersions, "v1 (inferred)")
	}

	return res
}
