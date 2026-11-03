package native

import (
	"fmt"
	"net/url"
	"strings"
)

// ActiveScan runs the injection / misconfiguration detectors that were written
// but never invoked by any swarm agent: SQLi, SSTI, LFI, command injection,
// CORS, CSRF, TLS and security-header auditing. Every result is only reported
// when the underlying detector produced positive evidence.
//
// ScanTarget is one injection-testable URL plus the parameters to mutate.
// Endpoints without a query string get candidate parameter names so the
// detectors have something to attack.
type ScanTarget struct {
	URL    string
	Params map[string]string
}

// Common query parameters worth fuzzing when an endpoint has no query string.
var candidateParams = []string{"id", "q", "search", "name", "file", "path", "page", "url"}

// webBases are base URLs (no trailing slash). subdomains feed takeover checks.
// tlsTargets are host:port pairs to audit.
func ActiveScan(webBases []string, subdomains []string, tlsTargets []HostPort) []*VerifiedFinding {
	targets := make([]ScanTarget, 0, len(webBases))
	for _, b := range webBases {
		targets = append(targets, ScanTarget{URL: b})
	}
	return ActiveScanTargets(targets, subdomains, tlsTargets)
}

// ActiveScanTargets is ActiveScan with explicit injection parameters.
func ActiveScanTargets(targets []ScanTarget, subdomains []string, tlsTargets []HostPort) []*VerifiedFinding {
	var out []*VerifiedFinding
	// Collapse payload-level duplicates: one vulnerable parameter is one
	// finding, not one per injection string.
	seen := map[string]bool{}
	add := func(key string, f *VerifiedFinding) {
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, f)
	}

	for _, tgt := range targets {
		base := tgt.URL
		if base == "" {
			continue
		}
		params := tgt.Params
		if len(params) == 0 {
			params = guessParams(base)
		}
		if len(params) == 0 {
			// No query string: probe conventional parameter names.
			strip := base
			if i := strings.Index(strip, "?"); i > 0 {
				strip = strip[:i]
			}
			params = map[string]string{}
			for _, p := range candidateParams {
				params[p] = "1"
			}
			base = strip
		}

		for _, r := range TestSQLi(base, params, 5) {
			if !r.Vulnerable {
				continue
			}
			add("INJ-SQLI|"+r.Endpoint+"|"+r.Parameter, &VerifiedFinding{
				ID: "INJ-SQLI", Name: "SQL Injection",
				Severity: "Critical", CVSS: 9.8, Port: endpointPort(base),
				Description: fmt.Sprintf("Parameter %q injectable at %s", r.Parameter, r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Use parameterized queries; never concatenate input into SQL.",
				Category:    "injection",
				Reproduce:   fmt.Sprintf("curl -s %q", r.Endpoint),
			})
		}

		for _, r := range TestSSTI(base, params) {
			if !r.Vulnerable {
				continue
			}
			add("INJ-SSTI|"+r.Endpoint+"|"+r.Parameter, &VerifiedFinding{
				ID: "INJ-SSTI", Name: "Server-Side Template Injection",
				Severity: "Critical", CVSS: 9.1, Port: endpointPort(base),
				Description: fmt.Sprintf("Template expression evaluated in %q at %s", r.Parameter, r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Do not render user input as template source; use sandboxed contexts.",
				Category:    "injection",
				Reproduce:   fmt.Sprintf("curl -s %q", r.Endpoint),
			})
		}

		for _, r := range TestLFI(base, params) {
			if !r.Vulnerable {
				continue
			}
			add("INJ-LFI|"+r.Endpoint+"|"+r.Parameter, &VerifiedFinding{
				ID: "INJ-LFI", Name: "Local File Inclusion",
				Severity: "High", CVSS: 8.6, Port: endpointPort(base),
				Description: fmt.Sprintf("File inclusion in %q at %s", r.Parameter, r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Resolve includes against an allowlist; never accept paths from input.",
				Category:    "injection",
				Reproduce:   fmt.Sprintf("curl -s %q", r.Endpoint),
			})
		}

		for _, r := range TestCmdInjection(base, params) {
			if !r.Vulnerable {
				continue
			}
			add("INJ-CMD|"+r.Endpoint+"|"+r.Parameter, &VerifiedFinding{
				ID: "INJ-CMD", Name: "OS Command Injection",
				Severity: "Critical", CVSS: 9.8, Port: endpointPort(base),
				Description: fmt.Sprintf("Command injection in %q at %s", r.Parameter, r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Avoid shell invocation; use exec with fixed argv and validate input.",
				Category:    "injection",
				Reproduce:   fmt.Sprintf("curl -s %q", r.Endpoint),
			})
		}

		for _, r := range TestCORS(base) {
			if !r.Vulnerable {
				continue
			}
			add("MISCONF-CORS|"+r.Endpoint, &VerifiedFinding{
				ID: "MISCONF-CORS", Name: "CORS Misconfiguration (" + r.VulnerabilityType + ")",
				Severity: "High", CVSS: 7.4, Port: endpointPort(base),
				Description: fmt.Sprintf("Cross-origin credential exposure at %s", r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Allowlist exact origins; never reflect Origin with credentials.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s -H 'Origin: https://evil.com' -D- %q", r.Endpoint),
			})
		}

		for _, r := range TestCSRF(base) {
			if !r.Vulnerable {
				continue
			}
			add("MISCONF-CSRF|"+r.Endpoint, &VerifiedFinding{
				ID: "MISCONF-CSRF", Name: "Missing CSRF Protection",
				Severity: "Medium", CVSS: 6.5, Port: endpointPort(base),
				Description: fmt.Sprintf("State-changing form without anti-CSRF token at %s", r.Endpoint),
				Evidence:    r.Evidence,
				Remediation: "Require a per-session anti-CSRF token and enforce SameSite cookies.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s %q", r.Endpoint),
			})
		}

		missing := 0
		var headerEvidence []string
		for _, h := range AuditHeaders(base) {
			if h.Present || h.Severity == "" || strings.EqualFold(h.Severity, "info") {
				continue
			}
			missing++
			// Quote every missing header: the description states a count, so
			// truncating the list here made the evidence contradict it.
			headerEvidence = append(headerEvidence, h.Header)
		}
		if missing > 0 {
			// Headers are a host-level property, not per-path.
			hostKey := base
			if u, err := url.Parse(base); err == nil && u.Host != "" {
				hostKey = u.Host
			}
			add("MISCONF-HEADERS|"+hostKey, &VerifiedFinding{
				ID: "MISCONF-HEADERS", Name: "Missing Security Headers",
				Severity: "Low", CVSS: 3.1, Port: endpointPort(base),
				Description: fmt.Sprintf("%d security headers absent at %s", missing, base),
				Evidence:    "Missing: " + strings.Join(headerEvidence, ", "),
				Remediation: "Set HSTS, CSP, X-Content-Type-Options and frame-ancestors.",
				Category:    "misconfiguration",
				Reproduce:   fmt.Sprintf("curl -s -D- %q | head -30", base),
			})
		}
	}

	for _, t := range TakeoverCheck(subdomains) {
		if !t.Vulnerable {
			continue
		}
		add("MISCONF-TAKEOVER|"+t.Subdomain, &VerifiedFinding{
			ID: "MISCONF-TAKEOVER", Name: "Subdomain Takeover (" + t.Platform + ")",
			Severity: "High", CVSS: 8.2, Port: 443,
			Description: fmt.Sprintf("%s points at an unclaimed %s resource", t.Subdomain, t.Platform),
			Evidence:    fmt.Sprintf("Provider takeover signature served by %s", t.Subdomain),
			Remediation: "Remove the dangling DNS record or claim the resource.",
			Category:    "misconfiguration",
			Reproduce:   fmt.Sprintf("curl -s http://%s/ | head -20", t.Subdomain),
		})
	}

	for _, svc := range tlsTargets {
		res := AuditSSL(svc.IP, svc.Port)
		if res == nil {
			continue
		}
		for _, v := range res.Vulnerabilities {
			add("TLS-WEAK|"+svc.IP+"|"+v, &VerifiedFinding{
				ID: "TLS-WEAK", Name: "Weak TLS: " + v,
				Severity: "Medium", CVSS: 5.9, Port: svc.Port,
				Description: fmt.Sprintf("TLS audit of %s:%d reported: %s", svc.IP, svc.Port, v),
				Evidence:    fmt.Sprintf("Issuer=%s Subject=%s Expires=%s TLS=%s", res.Issuer, res.Subject, res.ExpiryDate.Format("2006-01-02"), res.TLSVersion),
				Remediation: "Disable legacy TLS versions and renew/align certificates.",
				Category:    "tls",
				Reproduce:   fmt.Sprintf("openssl s_client -connect %s:%d -servername %s </dev/null 2>/dev/null | openssl x509 -noout -dates", svc.IP, svc.Port, svc.IP),
			})
		}
	}

	return out
}

// HostPort is a minimal dial target for the native package, which must not
// depend on swarm/core.
type HostPort struct {
	IP   string
	Port int
}

// guessParams pulls query parameters from a URL so injection tests have
// something to mutate. Duplicate keys are collapsed.
func guessParams(base string) map[string]string {
	params := map[string]string{}
	idx := strings.Index(base, "?")
	if idx < 0 {
		return params
	}
	for _, pair := range strings.Split(base[idx+1:], "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			params[kv[0]] = kv[1]
		}
	}
	return params
}

// TakeoverCheck adapts CheckSubdomainTakeover to the native result type.
func TakeoverCheck(subdomains []string) []TakeoverResult {
	if len(subdomains) == 0 {
		return nil
	}
	return CheckSubdomainTakeover(subdomains, 10)
}
