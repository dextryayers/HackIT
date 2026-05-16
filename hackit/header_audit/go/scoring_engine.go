package main

func CalculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func AuditSecurityHeaders(headers map[string][]string) ([]Finding, int) {
	var missing []Finding
	penalty := 0

	targets := []struct {
		Name string
		Desc string
		Rec  string
		Sev  string
	}{
		{"Strict-Transport-Security", "Missing HSTS", "max-age=31536000; includeSubDomains", "High"},
		{"Content-Security-Policy", "Missing CSP", "default-src 'self'", "High"},
		{"X-Frame-Options", "Missing Clickjacking protection", "DENY or SAMEORIGIN", "Medium"},
		{"X-Content-Type-Options", "Missing MIME sniffing protection", "nosniff", "Low"},
		{"Referrer-Policy", "Missing Referrer control", "strict-origin-when-cross-origin", "Low"},
	}

	for _, t := range targets {
		if len(headers[t.Name]) == 0 {
			missing = append(missing, Finding{
				Header:         t.Name,
				Description:    t.Desc,
				Recommendation: t.Rec,
				Severity:       t.Sev,
			})
			penalty += 15
		}
	}

	return missing, penalty
}

func AuditDangerousHeaders(headers map[string][]string) ([]Finding, int) {
	var dangerous []Finding
	penalty := 0

	targets := []struct {
		Name string
		Desc string
		Sev  string
	}{
		{"Server", "Exposes server software version", "Medium"},
		{"X-Powered-By", "Exposes underlying technology stack", "Low"},
		{"X-AspNet-Version", "Exposes specific .NET version", "Medium"},
	}

	for _, t := range targets {
		if val := headers[t.Name]; len(val) > 0 {
			dangerous = append(dangerous, Finding{
				Header:      t.Name,
				Value:       val[0],
				Description: t.Desc,
				Severity:    t.Sev,
			})
			penalty += 5
		}
	}

	return dangerous, penalty
}
