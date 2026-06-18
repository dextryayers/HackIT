package main

import "strings"

type HeaderCheck struct {
	Name           string
	Description    string
	Recommendation string
	Severity       Severity
	Category       string
	ValidateValue  func(value string) []string
	SafeHint       string
}

var SecurityHeaderChecks = []HeaderCheck{
	{
		Name: "Strict-Transport-Security", Description: "Enforces HTTPS connections",
		Recommendation: "max-age=31536000; includeSubDomains; preload",
		Severity: SeverityHigh, Category: "Security",
		ValidateValue: validateHSTS,
		SafeHint: "max-age >= 31536000",
	},
	{
		Name: "Content-Security-Policy", Description: "Prevents XSS and injection attacks by controlling allowed resources",
		Recommendation: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
		Severity: SeverityHigh, Category: "Security",
		ValidateValue: validateCSP,
		SafeHint: "Restrictive policy without unsafe-*",
	},
	{
		Name: "X-Frame-Options", Description: "Prevents clickjacking by controlling framing",
		Recommendation: "DENY or SAMEORIGIN",
		Severity: SeverityMedium, Category: "Security",
		ValidateValue: validateXFrameOptions,
	},
	{
		Name: "X-Content-Type-Options", Description: "Prevents MIME-sniffing attacks",
		Recommendation: "nosniff",
		Severity: SeverityLow, Category: "Security",
		ValidateValue: func(v string) []string {
			if strings.ToLower(v) != "nosniff" {
				return []string{"Value should be 'nosniff'"}
			}
			return nil
		},
		SafeHint: "nosniff",
	},
	{
		Name: "Referrer-Policy", Description: "Controls how much referrer information is sent with requests",
		Recommendation: "strict-origin-when-cross-origin or stricter",
		Severity: SeverityLow, Category: "Security",
		ValidateValue: validateReferrerPolicy,
	},
	{
		Name: "Permissions-Policy", Description: "Controls which browser features and APIs can be used",
		Recommendation: "Restrict unnecessary features: geolocation=(), microphone=(), camera=()",
		Severity: SeverityMedium, Category: "Security",
	},
	{
		Name: "X-XSS-Protection", Description: "Legacy XSS filter (deprecated but still widely checked)",
		Recommendation: "0 (disable) or 1; mode=block (legacy)",
		Severity: SeverityLow, Category: "Security",
	},
	{
		Name: "Cross-Origin-Embedder-Policy", Description: "Requires cross-origin resources to be explicitly granted (Spectre mitigation)",
		Recommendation: "require-corp or credentialless",
		Severity: SeverityMedium, Category: "Security",
	},
	{
		Name: "Cross-Origin-Opener-Policy", Description: "Controls cross-origin window interactions (Spectre mitigation)",
		Recommendation: "same-origin or same-origin-allow-popups",
		Severity: SeverityMedium, Category: "Security",
	},
	{
		Name: "Cross-Origin-Resource-Policy", Description: "Controls which origins can load this resource",
		Recommendation: "same-origin or same-site",
		Severity: SeverityMedium, Category: "Security",
	},
	{
		Name: "Access-Control-Allow-Origin", Description: "Controls CORS access - should be specific origin, not wildcard",
		Recommendation: "Specific origin instead of *",
		Severity: SeverityMedium, Category: "Security/CORS",
	},
	{
		Name: "X-DNS-Prefetch-Control", Description: "Controls DNS prefetching for performance/security",
		Recommendation: "off for sensitive pages",
		Severity: SeverityLow, Category: "Security",
	},
}

func validateHSTS(value string) []string {
	var issues []string
	v := strings.ToLower(value)
	if !strings.Contains(v, "max-age=") {
		issues = append(issues, "Missing max-age directive")
		return issues
	}
	maxAge := extractHSTSMaxAge(v)
	if maxAge < 31536000 {
		issues = append(issues, "max-age should be at least 31536000 (1 year)")
	}
	if strings.Contains(v, "includesubdomains") {
		if !strings.Contains(v, "preload") {
			issues = append(issues, "Consider adding 'preload' for browser preload lists")
		}
	} else {
		issues = append(issues, "Missing 'includeSubDomains' directive")
	}
	return issues
}

func validateCSP(value string) []string {
	var issues []string
	v := strings.ToLower(value)
	if strings.Contains(v, "unsafe-inline") {
		issues = append(issues, "CSP uses 'unsafe-inline' - weakens XSS protection")
	}
	if strings.Contains(v, "unsafe-eval") {
		issues = append(issues, "CSP uses 'unsafe-eval' - allows eval() execution")
	}
	if strings.Contains(v, "*") && !strings.Contains(v, "*.cdn") {
		issues = append(issues, "CSP uses wildcard (*) - consider restricting to specific origins")
	}
	if !strings.Contains(v, "default-src") {
		issues = append(issues, "No default-src directive - consider setting a fallback policy")
	}
	if strings.Contains(v, "https:") && strings.Contains(v, "http:") {
		issues = append(issues, "CSP allows both http: and https: schemes")
	}
	return issues
}

func validateXFrameOptions(value string) []string {
	v := strings.ToUpper(value)
	if v == "DENY" || v == "SAMEORIGIN" {
		return nil
	}
	if v == "ALLOW-FROM" {
		return []string{"ALLOW-FROM is deprecated, use Content-Security-Policy: frame-ancestors instead"}
	}
	return []string{"Should be DENY or SAMEORIGIN, got: " + value}
}

func validateReferrerPolicy(value string) []string {
	safe := map[string]bool{
		"no-referrer": true, "same-origin": true,
		"strict-origin": true, "strict-origin-when-cross-origin": true,
		"no-referrer-when-downgrade": true,
	}
	v := strings.ToLower(value)
	if safe[v] {
		return nil
	}
	if v == "unsafe-url" {
		return []string{"unsafe-url leaks full URL to all origins"}
	}
	return nil
}

var DangerousHeaderChecks = []HeaderCheck{
	{
		Name: "Server", Description: "Exposes server software and version information",
		Recommendation: "Remove or obscure this header",
		Severity: SeverityMedium, Category: "Information Leak",
	},
	{
		Name: "X-Powered-By", Description: "Exposes underlying technology stack (PHP, ASP.NET, etc.)",
		Recommendation: "Remove this header",
		Severity: SeverityLow, Category: "Information Leak",
	},
	{
		Name: "X-AspNet-Version", Description: "Exposes specific ASP.NET version",
		Recommendation: "Remove this header via web.config",
		Severity: SeverityMedium, Category: "Information Leak",
	},
	{
		Name: "X-AspNetMvc-Version", Description: "Exposes ASP.NET MVC version",
		Recommendation: "Remove this header",
		Severity: SeverityMedium, Category: "Information Leak",
	},
	{
		Name: "X-Generator", Description: "Exposes CMS/framework generator version",
		Recommendation: "Remove this header",
		Severity: SeverityLow, Category: "Information Leak",
	},
	{
		Name: "X-Debug-Token", Description: "Exposes Symfony debug token (dev mode leak)",
		Recommendation: "Disable debug mode in production",
		Severity: SeverityHigh, Category: "Information Leak",
	},
	{
		Name: "X-Debug-Exception", Description: "Exposes debug exception information",
		Recommendation: "Disable debug mode in production",
		Severity: SeverityCritical, Category: "Information Leak",
	},
	{
		Name: "X-Debug-Exception-Message", Description: "Exposes exception message",
		Recommendation: "Disable debug mode in production",
		Severity: SeverityCritical, Category: "Information Leak",
	},
	{
		Name: "Via", Description: "Exposes proxy server information",
		Recommendation: "Remove or sanitize this header",
		Severity: SeverityLow, Category: "Information Leak",
	},
	{
		Name: "X-Served-By", Description: "Exposes hostname/internal server info",
		Recommendation: "Remove this header",
		Severity: SeverityMedium, Category: "Information Leak",
	},
	{
		Name: "X-Runtime", Description: "Exposes Ruby/Rails request processing time",
		Recommendation: "Remove this header",
		Severity: SeverityLow, Category: "Information Leak",
	},
	{
		Name: "X-Version", Description: "Exposes application version",
		Recommendation: "Remove this header",
		Severity: SeverityLow, Category: "Information Leak",
	},
}
