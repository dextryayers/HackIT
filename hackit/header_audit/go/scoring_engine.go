package main

import "strings"

func CalculateGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	case score >= 20:
		return "E"
	default:
		return "F"
	}
}

type ScoreBreakdown struct {
	SecurityHeaders int `json:"security_headers"`
	DangerousLeaks  int `json:"dangerous_leaks"`
	CookieAudit     int `json:"cookie_audit"`
	CorsAudit       int `json:"cors_audit"`
	CacheAudit      int `json:"cache_audit"`
	TLSAudit        int `json:"tls_audit"`
}

func CalculateScore(
	missingSecurity []Finding,
	dangerous []Finding,
	cookieFindings []CookieFinding,
	corsFindings []Finding,
	cacheAudit *CacheAudit,
	tlsFindings []Finding,
) (int, map[string]int) {
	score := 100
	breakdown := make(map[string]int)

	secPenalty := 0
	for _, f := range missingSecurity {
		switch f.Severity {
		case SeverityCritical:
			secPenalty += 25
		case SeverityHigh:
			secPenalty += 20
		case SeverityMedium:
			secPenalty += 10
		case SeverityLow:
			secPenalty += 5
		}
	}
	breakdown["security_headers"] = secPenalty
	score -= secPenalty

	dangerousPenalty := 0
	for _, f := range dangerous {
		switch f.Severity {
		case SeverityCritical:
			dangerousPenalty += 25
		case SeverityHigh:
			dangerousPenalty += 15
		case SeverityMedium:
			dangerousPenalty += 10
		case SeverityLow:
			dangerousPenalty += 5
		}
	}
	breakdown["dangerous_leaks"] = dangerousPenalty
	score -= dangerousPenalty

	cookiePenalty := 0
	for _, c := range cookieFindings {
		switch c.Severity {
		case SeverityMedium:
			cookiePenalty += 8
		case SeverityLow:
			cookiePenalty += 3
		default:
			cookiePenalty += 5
		}
	}
	breakdown["cookie_audit"] = cookiePenalty
	score -= cookiePenalty

	corsPenalty := 0
	for _, f := range corsFindings {
		switch f.Severity {
		case SeverityCritical:
			corsPenalty += 30
		case SeverityHigh:
			corsPenalty += 20
		case SeverityMedium:
			corsPenalty += 10
		case SeverityLow:
			corsPenalty += 3
		}
	}
	breakdown["cors_audit"] = corsPenalty
	score -= corsPenalty

	cachePenalty := 0
	if cacheAudit != nil {
		for _, f := range cacheAudit.Findings {
			switch f.Severity {
			case SeverityMedium:
				cachePenalty += 5
			case SeverityLow:
				cachePenalty += 2
			}
		}
	}
	breakdown["cache_audit"] = cachePenalty
	score -= cachePenalty

	tlsPenalty := 0
	for _, f := range tlsFindings {
		switch f.Severity {
		case SeverityCritical:
			tlsPenalty += 30
		case SeverityHigh:
			tlsPenalty += 20
		case SeverityMedium:
			tlsPenalty += 10
		case SeverityLow:
			tlsPenalty += 3
		}
	}
	breakdown["tls_audit"] = tlsPenalty
	score -= tlsPenalty

	if score < 0 {
		score = 0
	}

	return score, breakdown
}

func AnalyzeHSTSValue(value string) string {
	v := strings.ToLower(value)
	if strings.Contains(v, "preload") && strings.Contains(v, "includesubdomains") && strings.Contains(v, "max-age=") {
		return "HSTS with preload ready"
	}
	if strings.Contains(v, "includesubdomains") && strings.Contains(v, "max-age=") {
		return "HSTS configured (consider adding preload)"
	}
	if strings.Contains(v, "max-age=") {
		return "HSTS configured (add includeSubDomains)"
	}
	return "HSTS misconfigured"
}
