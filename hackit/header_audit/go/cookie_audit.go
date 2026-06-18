package main

import (
	"regexp"
	"strings"
)

func AuditCookies(headers map[string][]string) []CookieFinding {
	var findings []CookieFinding
	cookies := headers["Set-Cookie"]

	for _, c := range cookies {
		parts := strings.Split(c, ";")
		nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		name := nameValue[0]
		value := ""
		if len(nameValue) > 1 {
			value = nameValue[1]
		}

		var issues []string
		severity := SeverityLow
		domain := ""
		path := "/"
		hasSecure := false
		hasHttpOnly := false
		hasSameSite := false
		sameSiteValue := ""

		for _, attr := range parts[1:] {
			attr = strings.TrimSpace(attr)
			attrLower := strings.ToLower(attr)

			if strings.HasPrefix(attrLower, "secure") {
				hasSecure = true
			}
			if strings.HasPrefix(attrLower, "httponly") {
				hasHttpOnly = true
			}
			if strings.HasPrefix(attrLower, "samesite") {
				hasSameSite = true
				ssParts := strings.SplitN(attr, "=", 2)
				if len(ssParts) > 1 {
					sameSiteValue = strings.TrimSpace(ssParts[1])
				}
			}
			if strings.HasPrefix(attrLower, "domain=") {
				domainParts := strings.SplitN(attr, "=", 2)
				if len(domainParts) > 1 {
					domain = strings.TrimSpace(domainParts[1])
				}
			}
			if strings.HasPrefix(attrLower, "path=") {
				pathParts := strings.SplitN(attr, "=", 2)
				if len(pathParts) > 1 {
					path = strings.TrimSpace(pathParts[1])
				}
			}
		}

		if !hasSecure {
			issues = append(issues, "Missing 'Secure' flag - cookie sent over unencrypted HTTP (MITM risk)")
			severity = SeverityMedium
		}
		if !hasHttpOnly {
			issues = append(issues, "Missing 'HttpOnly' flag - cookie accessible via JavaScript (XSS risk)")
			severity = SeverityMedium
		}
		if !hasSameSite {
			issues = append(issues, "Missing 'SameSite' attribute - vulnerable to CSRF attacks")
		} else {
			ss := strings.ToLower(sameSiteValue)
			if ss == "none" && !hasSecure {
				issues = append(issues, "SameSite=None requires Secure flag (browsers reject it otherwise)")
				severity = SeverityMedium
			}
			if ss == "lax" || ss == "" {
				issues = append(issues, "SameSite=Lax allows top-level GET CSRF - consider 'Strict' for sensitive cookies")
			}
		}

		if domain != "" {
			if strings.HasPrefix(domain, ".") {
				issues = append(issues, "Cookie domain starts with '.' - cookie sent to all subdomains")
			}
		}

		if path != "/" {
			issues = append(issues, "Cookie scoped to specific path '"+path+"' instead of '/', may indicate design issue")
		}

		if strings.HasPrefix(name, "__Host-") {
			if !hasSecure || path != "/" || domain != "" {
				issues = append(issues, "__Host- prefix requires Secure flag, Path=/, and no Domain")
				severity = SeverityMedium
			}
		}

		if strings.HasPrefix(name, "__Secure-") {
			if !hasSecure {
				issues = append(issues, "__Secure- prefix requires Secure flag")
				severity = SeverityMedium
			}
		}

		if len(issues) > 0 {
			findings = append(findings, CookieFinding{
				Name:     name,
				Value:    maskCookieValue(value),
				Domain:   domain,
				Path:     path,
				Issues:   issues,
				Severity: severity,
			})
		}
	}
	return findings
}

var sessionCookiePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(session|sess|token|auth|sid|jwt|bearer|api[_-]?key)`),
}

func maskCookieValue(value string) string {
	if len(value) > 8 {
		return value[:4] + "..." + value[len(value)-4:]
	}
	return value
}
