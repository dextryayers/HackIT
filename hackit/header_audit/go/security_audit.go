package main

import (
	"regexp"
	"strconv"
)

func AuditSecurityHeaders(headers map[string][]string) ([]Finding, int) {
	var findings []Finding
	penalty := 0

	for _, check := range SecurityHeaderChecks {
		values := headers[check.Name]
		if len(values) == 0 {
			findings = append(findings, Finding{
				Header:         check.Name,
				Description:    "Missing: " + check.Description,
				Recommendation: check.Recommendation,
				Severity:       check.Severity,
				Category:       check.Category,
			})
			switch check.Severity {
			case SeverityCritical:
				penalty += 25
			case SeverityHigh:
				penalty += 20
			case SeverityMedium:
				penalty += 10
			case SeverityLow:
				penalty += 5
			}
			continue
		}

		if check.ValidateValue != nil {
			issues := check.ValidateValue(values[0])
			for _, issue := range issues {
				findings = append(findings, Finding{
					Header:         check.Name,
					Value:          values[0],
					Description:    "Weak configuration: " + issue,
					Recommendation: check.Recommendation,
					Severity:       SeverityLow,
					Category:       check.Category,
				})
				penalty += 3
			}
		}
	}

	return findings, penalty
}

func AuditDangerousHeaders(headers map[string][]string) ([]Finding, int) {
	var findings []Finding
	penalty := 0

	for _, check := range DangerousHeaderChecks {
		values := headers[check.Name]
		if len(values) > 0 {
			finding := Finding{
				Header:         check.Name,
				Value:          values[0],
				Description:    check.Description,
				Recommendation: check.Recommendation,
				Severity:       check.Severity,
				Category:       check.Category,
			}
			findings = append(findings, finding)
			switch check.Severity {
			case SeverityCritical:
				penalty += 25
			case SeverityHigh:
				penalty += 20
			case SeverityMedium:
				penalty += 10
			case SeverityLow:
				penalty += 5
			}
		}
	}

	return findings, penalty
}

func extractHSTSMaxAge(value string) int {
	re := regexp.MustCompile(`max-age=(\d+)`)
	matches := re.FindStringSubmatch(value)
	if len(matches) >= 2 {
		age, err := strconv.Atoi(matches[1])
		if err == nil {
			return age
		}
	}
	return 0
}
