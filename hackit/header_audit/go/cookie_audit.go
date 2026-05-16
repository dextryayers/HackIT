package main

import (
	"strings"
)

type CookieFinding struct {
	Name     string   `json:"name"`
	Issues   []string `json:"issues"`
	Severity string   `json:"severity"`
}

func AuditCookies(headers map[string][]string) []CookieFinding {
	var findings []CookieFinding
	cookies := headers["Set-Cookie"]

	for _, c := range cookies {
		issues := []string{}
		severity := "Low"
		
		name := strings.Split(c, "=")[0]
		
		if !strings.Contains(strings.ToLower(c), "httponly") {
			issues = append(issues, "Missing HttpOnly flag (XSS risk)")
			severity = "Medium"
		}
		if !strings.Contains(strings.ToLower(c), "secure") {
			issues = append(issues, "Missing Secure flag (MITM risk)")
			severity = "Medium"
		}
		if !strings.Contains(strings.ToLower(c), "samesite") {
			issues = append(issues, "Missing SameSite attribute (CSRF risk)")
		}

		if len(issues) > 0 {
			findings = append(findings, CookieFinding{
				Name:     name,
				Issues:   issues,
				Severity: severity,
			})
		}
	}
	return findings
}
