package main

import "strings"

func AuditCORS(headers map[string][]string) []Finding {
	var findings []Finding
	
	allowOrigin := strings.Join(headers["Access-Control-Allow-Origin"], "")
	allowMethods := strings.Join(headers["Access-Control-Allow-Methods"], "")

	if allowOrigin == "*" {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Origin",
			Description:    "Wildcard CORS policy detected. Allows any domain to read response data.",
			Recommendation: "Specify allowed domains instead of using '*'.",
			Severity:       "High",
		})
	}

	if strings.Contains(allowMethods, "DELETE") || strings.Contains(allowMethods, "PUT") {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Methods",
			Description:    "Dangerous HTTP methods allowed via CORS (PUT/DELETE).",
			Recommendation: "Restrict CORS methods to only necessary ones (GET/POST).",
			Severity:       "Medium",
		})
	}

	return findings
}
