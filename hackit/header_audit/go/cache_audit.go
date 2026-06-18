package main

import (
	"regexp"
	"strconv"
	"strings"
)

func AuditCachePolicy(headers map[string][]string) *CacheAudit {
	result := &CacheAudit{
		Directives: []CacheDirective{},
		Findings:   []Finding{},
	}

	cacheControl := strings.Join(headers["Cache-Control"], ", ")
	pragma := strings.Join(headers["Pragma"], "")
	expires := strings.Join(headers["Expires"], "")
	age := strings.Join(headers["Age"], "")

	if cacheControl == "" && pragma == "" && expires == "" {
		result.Findings = append(result.Findings, Finding{
			Header:         "Cache-Control",
			Description:    "No caching headers set - responses may be cached by proxies and browsers unpredictably",
			Recommendation: "Set Cache-Control header with appropriate directives",
			Severity:       SeverityMedium,
			Category:       "Caching",
		})
		return result
	}

	result.Present = true

	if strings.Contains(strings.ToLower(pragma), "no-cache") {
		result.HasPragmaNoCache = true
	}

	if expires != "" {
		result.HasExpires = true
	}

	if cacheControl != "" {
		directives := strings.Split(cacheControl, ",")
		for _, d := range directives {
			d = strings.TrimSpace(d)
			dLower := strings.ToLower(d)
			dir := CacheDirective{Directive: d}

			switch {
			case dLower == "no-store":
				dir.Safe = true
				result.NoStorePresent = true
			case dLower == "no-cache":
				dir.Safe = true
			case dLower == "private":
				dir.Safe = true
			case dLower == "public":
				result.PublicPresent = true
				dir.Safe = false
			case strings.HasPrefix(dLower, "max-age="):
				result.MaxAgeSet = true
				ageStr := strings.TrimPrefix(dLower, "max-age=")
				age, err := strconv.Atoi(ageStr)
				if err == nil {
					result.MaxAge = age
					if age > 86400 {
						dir.Safe = false
					} else {
						dir.Safe = true
					}
				}
			case dLower == "must-revalidate":
				dir.Safe = true
			case dLower == "proxy-revalidate":
				dir.Safe = true
			case dLower == "immutable":
				dir.Safe = true
			case dLower == "s-maxage=":
				dir.Safe = true
			default:
				dir.Safe = true
			}
			result.Directives = append(result.Directives, dir)
		}
	}

	if result.PublicPresent && !result.NoStorePresent {
		result.Findings = append(result.Findings, Finding{
			Header:         "Cache-Control",
			Value:          cacheControl,
			Description:    "Cache-Control has 'public' without 'no-store' - sensitive data may be cached by shared caches/proxies",
			Recommendation: "Add 'no-store' for sensitive responses, or remove 'public'",
			Severity:       SeverityMedium,
			Category:       "Caching",
		})
	}

	if result.MaxAgeSet && result.MaxAge > 86400 {
		result.Findings = append(result.Findings, Finding{
			Header:         "Cache-Control",
			Value:          cacheControl,
			Description:    "max-age is very long (>24h) - users may see stale content after updates",
			Recommendation: "Reduce max-age or use versioned URLs for long-lived assets",
			Severity:       SeverityLow,
			Category:       "Caching",
		})
	}

	if result.MaxAgeSet && result.MaxAge <= 0 {
		result.Findings = append(result.Findings, Finding{
			Header:         "Cache-Control",
			Value:          cacheControl,
			Description:    "max-age=0 or negative - disables caching entirely (performance impact)",
			Recommendation: "Use no-cache or no-store instead of max-age=0",
			Severity:       SeverityLow,
			Category:       "Caching",
		})
	}

	if age != "" {
		ageInt, err := strconv.Atoi(strings.TrimSpace(age))
		if err == nil && ageInt > 86400 {
			result.Findings = append(result.Findings, Finding{
				Header:         "Age",
				Value:          age,
				Description:    "Response has been cached for a very long time (>24h)",
				Recommendation: "Verify cache invalidation strategy",
				Severity:       SeverityLow,
				Category:       "Caching",
			})
		}
	}

	return result
}

var noCachePaths = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(login|logout|session|token|auth|password|secret|api[-_]?key|csrf|credit.c|ssn|bank)`),
}

func IsSensitivePath(path string) bool {
	for _, re := range noCachePaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
