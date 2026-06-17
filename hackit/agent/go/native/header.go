package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HeaderAuditResult struct {
	Header         string `json:"header"`
	Present        bool   `json:"present"`
	Value          string `json:"value"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

func AuditHeaders(targetURL string) []HeaderAuditResult {
	securityHeaders := map[string]struct {
		Severity       string
		Recommendation string
	}{
		"Strict-Transport-Security": {
			Severity: "HIGH",
			Recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
		},
		"Content-Security-Policy": {
			Severity: "HIGH",
			Recommendation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
		},
		"X-Content-Type-Options": {
			Severity: "MEDIUM",
			Recommendation: "Add: X-Content-Type-Options: nosniff",
		},
		"X-Frame-Options": {
			Severity: "MEDIUM",
			Recommendation: "Add: X-Frame-Options: DENY or SAMEORIGIN",
		},
		"X-XSS-Protection": {
			Severity: "LOW",
			Recommendation: "Add: X-XSS-Protection: 1; mode=block",
		},
		"Referrer-Policy": {
			Severity: "LOW",
			Recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
		},
		"Permissions-Policy": {
			Severity: "LOW",
			Recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
		},
		"Access-Control-Allow-Origin": {
			Severity: "MEDIUM",
			Recommendation: "Restrict CORS to specific origins, not '*'",
		},
		"Set-Cookie": {
			Severity: "MEDIUM",
			Recommendation: "Ensure cookies have Secure, HttpOnly, and SameSite flags",
		},
		"Server": {
			Severity: "LOW",
			Recommendation: "Remove or obfuscate Server header to prevent version disclosure",
		},
		"X-Powered-By": {
			Severity: "LOW",
			Recommendation: "Remove X-Powered-By header to prevent technology disclosure",
		},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIt Security Scanner; +https://hackit.com)")

	resp, err := client.Do(req)
	if err != nil {
		return []HeaderAuditResult{{
			Header:   "connection",
			Present:  false,
			Severity: "HIGH",
			Recommendation: fmt.Sprintf("Failed to connect: %v", err),
		}}
	}
	defer resp.Body.Close()

	var results []HeaderAuditResult
	for header, info := range securityHeaders {
		value := resp.Header.Get(header)
		present := value != ""

		audit := HeaderAuditResult{
			Header:         header,
			Present:        present,
			Value:          value,
			Severity:       info.Severity,
			Recommendation: info.Recommendation,
		}

		if header == "Access-Control-Allow-Origin" && present {
			if value == "*" {
				audit.Severity = "HIGH"
				audit.Recommendation = "CRITICAL: CORS allows all origins (*). Restrict to specific trusted domains."
			}
		}

		if header == "Set-Cookie" && present {
			if !strings.Contains(strings.ToLower(value), "secure") {
				audit.Severity = "HIGH"
				audit.Recommendation = "Cookie missing Secure flag: " + value
			} else if !strings.Contains(strings.ToLower(value), "httponly") {
				audit.Severity = "MEDIUM"
				audit.Recommendation = "Cookie missing HttpOnly flag: " + value
			}
		}

		results = append(results, audit)
	}

	return results
}
