package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Passive audit: built-in checks that need no templates. Used automatically
// when the template library is empty (or filters exclude everything) and
// explicitly via --passive. Each finding is a direct observation with high
// confidence, not a heuristic guess.

func passiveClient(cfg *ScanConfig) *http.Client {
	if cfg != nil {
		return NewConfiguredClient(cfg)
	}
	return NewHTTPClient(30)
}

func passiveResult(id, name, severity, confidence, url, matcher, desc, tags string) Result {
	return Result{
		TemplateID:   id,
		TemplateName: name,
		Severity:     severity,
		Type:         "passive",
		MatcherName:  matcher,
		URL:          url,
		Matched:      matcher,
		Extracted:    "",
		Description:  desc,
		Tags:         tags,
		Confidence:   confidence,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Request:      "GET " + url,
	}
}

// RunPassiveAudit executes built-in passive checks against one target.
// Typically 3 requests. Returns findings sorted by severity.
func RunPassiveAudit(target string, cfg *ScanConfig) []Result {
	client := passiveClient(cfg)
	headers := map[string]string{}
	if cfg != nil {
		if cfg.CustomAgent != "" {
			headers["User-Agent"] = cfg.CustomAgent
		}
		for _, h := range ParseCustomHeaders(cfg) {
			if h.Name != "" {
				headers[h.Name] = h.Value
			}
		}
		ApplyAuthHeaders(headers, cfg)
	}

	var out []Result

	// 1) Base page: security headers + CSP + clickjacking in one request.
	resp, err := SendRequestWithRetry(client, target, "GET", "", headers, 1)
	if err != nil {
		if cfg == nil || !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Passive audit: %s unreachable (%v)\n",
				SColor(ColorYellow, "[!]"), target, err)
		}
		return nil
	}
	hdrLower := strings.ToLower(resp.Headers)
	has := func(s string) bool { return strings.Contains(hdrLower, strings.ToLower(s)) }

	missing := []string{}
	for _, h := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"} {
		if !has(h) && !has("frame-ancestors") {
			if h == "X-Frame-Options" && has("frame-ancestors") {
				continue
			}
			missing = append(missing, h)
		}
	}
	isHTTPS := strings.HasPrefix(strings.ToLower(target), "https")
	if isHTTPS && !has("Strict-Transport-Security") {
		missing = append(missing, "Strict-Transport-Security")
	}
	for _, m := range missing {
		out = append(out, passiveResult(
			"atomix-missing-header", "Missing Security Header", "low", "high",
			target, "missing:"+m,
			fmt.Sprintf("Response does not set %s", m),
			"passive,headers,hardening",
		))
	}
	if !has("X-Frame-Options") && !has("frame-ancestors") {
		out = append(out, passiveResult(
			"atomix-clickjacking", "Clickjacking Protection Missing", "medium", "high",
			target, "missing-frame-protection",
			"No X-Frame-Options header and no frame-ancestors directive",
			"passive,clickjacking,ui-redress",
		))
	}
	if !has("Content-Security-Policy") {
		out = append(out, passiveResult(
			"atomix-csp-missing", "Content-Security-Policy Missing", "low", "high",
			target, "missing-csp",
			"No Content-Security-Policy header present",
			"passive,csp,policy",
		))
	} else if has("unsafe-inline") || has("unsafe-eval") {
		out = append(out, passiveResult(
			"atomix-csp-weak", "Content-Security-Policy Allows Unsafe Code", "medium", "high",
			target, "csp-unsafe",
			"CSP present but allows unsafe-inline or unsafe-eval",
			"passive,csp,policy",
		))
	}

	// 2) CORS preflight: reflect a foreign origin.
	corsHeaders := map[string]string{
		"Origin":                        "https://atomix-probe.invalid",
		"Access-Control-Request-Method": "GET",
	}
	for k, v := range headers {
		corsHeaders[k] = v
	}
	if cresp, err := SendRequestWithRetry(client, target, "OPTIONS", "", corsHeaders, 1); err == nil {
		acao := ""
		for _, line := range strings.Split(cresp.Headers, "\n") {
			if idx := strings.Index(line, ":"); idx > 0 &&
				strings.EqualFold(strings.TrimSpace(line[:idx]), "Access-Control-Allow-Origin") {
				acao = strings.TrimSpace(line[idx+1:])
				break
			}
		}
		if acao == "*" || strings.Contains(acao, "atomix-probe.invalid") {
			out = append(out, passiveResult(
				"atomix-cors-wildcard", "CORS Origin Reflection", "medium", "high",
				target, "cors-reflected",
				fmt.Sprintf("Server reflects arbitrary origins (Access-Control-Allow-Origin: %s)", acao),
				"passive,cors,misconfig",
			))
		}
	}

	// 3) Dangerous HTTP methods advertised via Allow header.
	if mresp, err := SendRequestWithRetry(client, target, "OPTIONS", "", headers, 1); err == nil {
		allow := ""
		for _, line := range strings.Split(mresp.Headers, "\n") {
			if idx := strings.Index(line, ":"); idx > 0 {
				name := strings.ToLower(strings.TrimSpace(line[:idx]))
				if name == "allow" || name == "access-control-allow-methods" {
					allow += " " + strings.ToUpper(line[idx+1:])
				}
			}
		}
		risky := []string{}
		for _, m := range []string{"PUT", "DELETE", "TRACE", "TRACK", "CONNECT"} {
			if strings.Contains(allow, m) {
				risky = append(risky, m)
			}
		}
		if len(risky) > 0 {
			out = append(out, passiveResult(
				"atomix-risky-methods", "Risky HTTP Methods Enabled", "low", "medium",
				target, "methods:"+strings.Join(risky, ","),
				fmt.Sprintf("Server advertises risky methods: %s", strings.Join(risky, ", ")),
				"passive,http,methods",
			))
		}
	}

	SortResults(out)
	return out
}
