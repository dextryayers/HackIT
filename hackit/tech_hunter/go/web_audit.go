package main

import (
	"fmt"
	"strings"
)

type WebAudit struct {
	Headers          map[string]string `json:"headers"`
	SecurityPolicies map[string]string `json:"security_policies"`
	Cookies          []string          `json:"cookies"`
	Unexpected       []string          `json:"unexpected"`
	Score            int               `json:"score"`
	Grade            string            `json:"grade"`
	Findings         []string          `json:"findings"`
}

func AuditWebApplication(headers map[string]string) *WebAudit {
	audit := &WebAudit{
		Headers:          make(map[string]string),
		SecurityPolicies: make(map[string]string),
		Cookies:          []string{},
		Unexpected:       []string{},
		Findings:         []string{},
	}

	for k, v := range headers {
		audit.Headers[k] = v
		lowerK := strings.ToLower(k)

		switch lowerK {
		case "strict-transport-security":
			audit.SecurityPolicies["HSTS"] = v
			if strings.Contains(v, "max-age=") {
				if strings.Contains(v, "includeSubDomains") {
					audit.Findings = append(audit.Findings, "HSTS: configured with subdomains")
				} else {
					audit.Findings = append(audit.Findings, "HSTS: configured without subdomains")
				}
			}
		case "content-security-policy":
			audit.SecurityPolicies["CSP"] = v
			if strings.Contains(v, "unsafe-inline") {
				audit.Findings = append(audit.Findings, "CSP WARNING: allows unsafe-inline scripts")
			}
			if strings.Contains(v, "unsafe-eval") {
				audit.Findings = append(audit.Findings, "CSP WARNING: allows unsafe-eval")
			}
			if !strings.Contains(v, "default-src") && !strings.Contains(v, "script-src") {
				audit.Findings = append(audit.Findings, "CSP: missing script-source/default-src")
			}
		case "x-frame-options":
			audit.SecurityPolicies["XFO"] = v
			if !strings.EqualFold(v, "DENY") && !strings.EqualFold(v, "SAMEORIGIN") {
				audit.Findings = append(audit.Findings, "XFO: weak value - recommend DENY")
			}
		case "x-content-type-options":
			audit.SecurityPolicies["XCTO"] = v
			if !strings.EqualFold(v, "nosniff") {
				audit.Findings = append(audit.Findings, "XCTO: should be 'nosniff'")
			}
		case "referrer-policy":
			audit.SecurityPolicies["Referrer-Policy"] = v
		case "permissions-policy", "feature-policy":
			audit.SecurityPolicies[k] = v
		case "access-control-allow-origin":
			audit.SecurityPolicies["CORS"] = v
			if v == "*" {
				audit.Findings = append(audit.Findings, "CORS: wildcard origin - review necessity")
			}
		case "access-control-allow-credentials":
			if v == "true" && audit.SecurityPolicies["CORS"] == "*" {
				audit.Findings = append(audit.Findings, "CRITICAL: CORS wildcard with credentials")
			}
		case "set-cookie":
			audit.Cookies = append(audit.Cookies, v)
			if !strings.Contains(strings.ToLower(v), "httponly") {
				audit.Findings = append(audit.Findings, "Cookie missing HttpOnly flag")
			}
			if !strings.Contains(strings.ToLower(v), "secure") {
				audit.Findings = append(audit.Findings, "Cookie missing Secure flag")
			}
			if !strings.Contains(strings.ToLower(v), "samesite") {
				audit.Findings = append(audit.Findings, "Cookie missing SameSite attribute")
			}
		}

		if strings.HasPrefix(lowerK, "x-") ||
			strings.Contains(lowerK, "debug") ||
			strings.Contains(lowerK, "generator") ||
			strings.Contains(lowerK, "powered-by") ||
			strings.Contains(lowerK, "drupal") ||
			strings.Contains(lowerK, "wp-") {
			isSecurity := false
			for _, sk := range []string{"x-frame-options", "x-content-type-options", "x-xss-protection"} {
				if lowerK == sk {
					isSecurity = true
					break
				}
			}
			if !isSecurity {
				audit.Unexpected = append(audit.Unexpected, fmt.Sprintf("%s: %s", k, v))
			}
		}
	}

	// Scoring
	score := 0
	if _, ok := audit.SecurityPolicies["HSTS"]; ok {
		score += 20
	}
	if _, ok := audit.SecurityPolicies["CSP"]; ok {
		score += 25
	}
	if _, ok := audit.SecurityPolicies["XFO"]; ok {
		score += 15
	}
	if _, ok := audit.SecurityPolicies["XCTO"]; ok {
		score += 10
	}
	if _, ok := audit.SecurityPolicies["Referrer-Policy"]; ok {
		score += 10
	}
	if _, ok := audit.SecurityPolicies["Permissions-Policy"]; ok {
		score += 5
	}

	audit.Score = score
	switch {
	case score >= 80:
		audit.Grade = "A"
	case score >= 60:
		audit.Grade = "B"
	case score >= 40:
		audit.Grade = "C"
	case score >= 20:
		audit.Grade = "D"
	default:
		audit.Grade = "F"
	}

	return audit
}
