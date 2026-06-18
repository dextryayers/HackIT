package main

import (
	"net/http"
	"strings"
)

func AuditCORS(headers map[string][]string) []Finding {
	var findings []Finding

	allowOrigin := strings.Join(headers["Access-Control-Allow-Origin"], "")
	allowMethods := strings.Join(headers["Access-Control-Allow-Methods"], "")
	allowCredentials := strings.Join(headers["Access-Control-Allow-Credentials"], "")
	allowHeaders := strings.Join(headers["Access-Control-Allow-Headers"], "")
	exposeHeaders := strings.Join(headers["Access-Control-Expose-Headers"], "")
	maxAge := strings.Join(headers["Access-Control-Max-Age"], "")
	allowPrivateNetwork := strings.Join(headers["Access-Control-Allow-Private-Network"], "")

	if allowOrigin == "" {
		return findings
	}

	if allowOrigin == "*" {
		if strings.EqualFold(allowCredentials, "true") {
			findings = append(findings, Finding{
				Header:         "Access-Control-Allow-Origin + Credentials",
				Value:          allowOrigin,
				Description:    "CRITICAL: Wildcard origin (*) with credentials=true. This is a security violation per CORS spec.",
				Recommendation: "Use a specific origin instead of '*' when credentials are enabled",
				Severity:       SeverityCritical,
				Category:       "CORS",
			})
		} else {
			findings = append(findings, Finding{
				Header:         "Access-Control-Allow-Origin",
				Value:          "*",
				Description:    "Wildcard CORS policy allows any domain to read response data",
				Recommendation: "Specify allowed domains instead of using '*'",
				Severity:       SeverityHigh,
				Category:       "CORS",
			})
		}
	}

	if strings.EqualFold(allowCredentials, "true") && allowOrigin != "*" {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Credentials",
			Value:          "true",
			Description:    "Credentials allowed via CORS - cookies and auth headers can be read cross-origin",
			Recommendation: "Only enable if absolutely necessary and ensure specific origins",
			Severity:       SeverityMedium,
			Category:       "CORS",
		})
	}

	if strings.Contains(allowMethods, "DELETE") || strings.Contains(allowMethods, "PUT") || strings.Contains(allowMethods, "PATCH") {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Methods",
			Value:          allowMethods,
			Description:    "Dangerous HTTP methods allowed via CORS (PUT/DELETE/PATCH)",
			Recommendation: "Restrict CORS methods to only necessary ones (GET/POST)",
			Severity:       SeverityMedium,
			Category:       "CORS",
		})
	}

	if strings.Contains(allowHeaders, "authorization") || strings.Contains(allowHeaders, "x-api-key") {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Headers",
			Value:          allowHeaders,
			Description:    "Sensitive headers (Authorization, API key) exposed via CORS",
			Recommendation: "Ensure these headers are only sent to trusted origins",
			Severity:       SeverityMedium,
			Category:       "CORS",
		})
	}

	if exposeHeaders != "" {
		if strings.Contains(exposeHeaders, "*") {
			findings = append(findings, Finding{
				Header:         "Access-Control-Expose-Headers",
				Value:          exposeHeaders,
				Description:    "Wildcard expose-headers may leak sensitive response headers",
				Recommendation: "Specify only required headers",
				Severity:       SeverityLow,
				Category:       "CORS",
			})
		}
	}

	if maxAge != "" {
		maxAgeInt := 0
		if m, err := parseInt(maxAge); err == nil {
			maxAgeInt = m
		}
		if maxAgeInt > 86400 {
			findings = append(findings, Finding{
				Header:         "Access-Control-Max-Age",
				Value:          maxAge,
				Description:    "Preflight cache duration is very long (>24h), changes take effect slowly",
				Recommendation: "Keep max-age under 86400 for flexibility",
				Severity:       SeverityLow,
				Category:       "CORS",
			})
		}
	}

	if allowPrivateNetwork != "" && strings.EqualFold(allowPrivateNetwork, "true") {
		findings = append(findings, Finding{
			Header:         "Access-Control-Allow-Private-Network",
			Value:          "true",
			Description:    "Private network access allowed via CORS - potential internal network exposure",
			Recommendation: "Restrict to trusted origins only",
			Severity:       SeverityHigh,
			Category:       "CORS",
		})
	}

	return findings
}

func AuditCORSOriginReflection(headers map[string][]string, origin string) *Finding {
	allowOrigin := strings.Join(headers["Access-Control-Allow-Origin"], "")
	if allowOrigin == "" {
		return nil
	}
	if allowOrigin == origin {
		return &Finding{
			Header:         "Access-Control-Allow-Origin (Origin Reflection)",
			Value:          origin + " (echoed back)",
			Description:    "Server reflects back the Origin header value - any website can make authenticated CORS requests",
			Recommendation: "Use a whitelist of allowed origins instead of reflecting the request origin",
			Severity:       SeverityHigh,
			Category:       "CORS",
		}
	}
	return nil
}

func AuditCORSPreflight(resp *http.Response, origin string) []Finding {
	var findings []Finding
	if resp == nil {
		return findings
	}

	headers := resp.Header
	allowOrigin := strings.Join(headers["Access-Control-Allow-Origin"], "")

	if allowOrigin == "" {
		findings = append(findings, Finding{
			Header:         "Preflight OPTIONS",
			Description:    "Preflight request returned no CORS headers - CORS may not be properly configured",
			Recommendation: "Ensure preflight responses include proper CORS headers (Access-Control-Allow-*)",
			Severity:       SeverityMedium,
			Category:       "CORS",
		})
		return findings
	}

	if allowOrigin == origin {
		findings = append(findings, Finding{
			Header:         "Preflight Origin Reflection",
			Value:          origin + " (echoed back)",
			Description:    "Preflight response reflects back the Origin header - confirms origin reflection vulnerability",
			Recommendation: "Implement strict origin whitelist for preflight responses",
			Severity:       SeverityHigh,
			Category:       "CORS",
		})
	}

	allowCredentials := strings.Join(headers["Access-Control-Allow-Credentials"], "")
	if strings.EqualFold(allowCredentials, "true") && allowOrigin == "*" {
		findings = append(findings, Finding{
			Header:         "Preflight Credentials + Wildcard",
			Description:    "Preflight allows credentials with wildcard origin - CORS spec violation",
			Recommendation: "Use specific origin when credentials=true",
			Severity:       SeverityCritical,
			Category:       "CORS",
		})
	}

	return findings
}
