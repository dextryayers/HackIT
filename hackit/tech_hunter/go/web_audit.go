package main

import (
	"strings"
)

type WebAudit struct {
	Headers          map[string]string `json:"headers"`
	SecurityPolicies map[string]string `json:"security_policies"`
	Cookies          []string          `json:"cookies"`
	Unexpected       []string          `json:"unexpected"`
}

func AuditWebApplication(headers map[string]string) *WebAudit {
	audit := &WebAudit{
		Headers:          make(map[string]string),
		SecurityPolicies: make(map[string]string),
		Cookies:          []string{},
		Unexpected:       []string{},
	}

	securityKeys := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"X-Permitted-Cross-Domain-Policies",
		"Expect-CT",
		"Feature-Policy",
	}

	for k, v := range headers {
		audit.Headers[k] = v
		
		isSecurity := false
		lowerK := strings.ToLower(k)
		for _, sk := range securityKeys {
			if strings.EqualFold(k, sk) {
				audit.SecurityPolicies[k] = v
				isSecurity = true
				break
			}
		}

		if strings.EqualFold(k, "Set-Cookie") {
			audit.Cookies = append(audit.Cookies, v)
		}

		// Detect unexpected headers (Framework leaks, debug tokens, generators)
		if !isSecurity && (strings.HasPrefix(lowerK, "x-") || 
			strings.Contains(lowerK, "debug") || 
			strings.Contains(lowerK, "generator") ||
			strings.Contains(lowerK, "powered-by") ||
			strings.Contains(lowerK, "drupal") ||
			strings.Contains(lowerK, "wp-")) {
			audit.Unexpected = append(audit.Unexpected, k+": "+v)
		}
	}

	return audit
}
