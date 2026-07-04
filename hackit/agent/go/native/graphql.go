package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type GraphQLResult struct {
	Endpoint      string `json:"endpoint"`
	Query         string `json:"query"`
	Vulnerable    bool   `json:"vulnerable"`
	VulnType      string `json:"vuln_type,omitempty"`
	Evidence      string `json:"evidence"`
}

func TestGraphQL(baseURL string) []GraphQLResult {
	graphqlEndpoints := []string{
		"/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/graph",
		"/gql",
		"/api/graphql",
		"/query",
	}

	introspectionQuery := `{"query":"{__schema{types{name fields{name}}}}"}`

	mutationQueries := []string{
		`{"query":"mutation{__typename}"}`,
		`{"query":"{__typename}"}`,
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []GraphQLResult

	for _, ep := range graphqlEndpoints {
		url := strings.TrimRight(baseURL, "/") + ep

		req, err := http.NewRequest("POST", url, bytes.NewBufferString(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()

		var gqlResp map[string]interface{}
		if err := json.Unmarshal(body, &gqlResp); err != nil {
			continue
		}

		if data, ok := gqlResp["data"].(map[string]interface{}); ok {
			if schema, ok := data["__schema"].(map[string]interface{}); ok {
				if types, ok := schema["types"].([]interface{}); ok {
					typeNames := make([]string, 0)
					for _, t := range types {
						if tmap, ok := t.(map[string]interface{}); ok {
							if name, ok := tmap["name"].(string); ok {
								typeNames = append(typeNames, name)
							}
						}
					}

					if len(typeNames) > 5 {
						results = append(results, GraphQLResult{
							Endpoint:   url,
							Query:      "Introspection query",
							Vulnerable: true,
							VulnType:   "Introspection Enabled",
							Evidence:   fmt.Sprintf("GraphQL introspection returned %d types including: %s", len(typeNames), strings.Join(typeNames[:min(8, len(typeNames))], ", ")),
						})
					} else {
						results = append(results, GraphQLResult{
							Endpoint:   url,
							Query:      "Introspection query",
							Vulnerable: false,
							Evidence:   fmt.Sprintf("GraphQL endpoint found but introspection restricted (%d types)", len(typeNames)),
						})
					}
				}
			}
		} else if errors, ok := gqlResp["errors"].([]interface{}); ok {
			errMsgs := make([]string, 0)
			for _, e := range errors {
				if emap, ok := e.(map[string]interface{}); ok {
					if msg, ok := emap["message"].(string); ok {
						errMsgs = append(errMsgs, msg)
					}
				}
			}
			if len(errMsgs) > 0 {
				results = append(results, GraphQLResult{
					Endpoint:   url,
					Query:      "Introspection query",
					Vulnerable: true,
					VulnType:   "Error Disclosure",
					Evidence:   fmt.Sprintf("GraphQL errors disclosed: %s", strings.Join(errMsgs, "; ")),
				})
			}
		}

		for _, mq := range mutationQueries {
			req, _ := http.NewRequest("POST", url, bytes.NewBufferString(mq))
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			var mqResp map[string]interface{}
			if json.Unmarshal(body, &mqResp) == nil {
				if _, ok := mqResp["data"]; ok {
					results = append(results, GraphQLResult{
						Endpoint:   url,
						Query:      "Mutation test",
						Vulnerable: true,
						VulnType:   "Mutations Allowed",
						Evidence:   "GraphQL mutations are accepted (potential for data manipulation)",
					})
				}
			}
		}
	}

	if len(results) == 0 {
		results = append(results, GraphQLResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   "No GraphQL endpoints detected on common paths",
		})
	}

	return results
}
