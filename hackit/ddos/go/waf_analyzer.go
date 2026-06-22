package main

import (
	"strings"
	"sync"
)

type WAFSignature struct {
	Name       string
	Patterns   []string
	Headers    map[string]string
	Confidence int
	Type       string
}

type WAFResult struct {
	Detected     bool
	Name         string
	Confidence   int
	Signatures   []string
	BypassScore  int
}

type WafAnalyzer struct {
	signatures []WAFSignature
	results    []WAFResult
	mu         sync.RWMutex
}

func NewWafAnalyzer() *WafAnalyzer {
	w := &WafAnalyzer{}
	w.LoadDefault()
	return w
}

func (w *WafAnalyzer) LoadDefault() {
	w.signatures = []WAFSignature{
		{
			Name: "Cloudflare",
			Headers: map[string]string{
				"server":   "cloudflare",
				"cf-ray":   "",
				"set-cookie": "__cfduid",
			},
			Patterns:   []string{"Attention Required!", "Cloudflare", "cf-error"},
			Confidence: 95,
			Type:       "CDN",
		},
		{
			Name: "AkamaiGHost",
			Headers: map[string]string{
				"server": "AkamaiGHost",
			},
			Patterns:   []string{"akamai", "Akamai"},
			Confidence: 90,
			Type:       "CDN",
		},
		{
			Name: "Imperva",
			Headers: map[string]string{
				"x-cdn":      "Imperva",
				"x-iinfo":    "",
				"set-cookie": "incap_ses",
			},
			Patterns:   []string{"Incapsula", "_incap_", "imperva"},
			Confidence: 90,
			Type:       "WAF",
		},
		{
			Name: "F5 BIG-IP ASM",
			Headers: map[string]string{
				"x-wa-ident":     "",
				"x-asm-version":  "",
				"x-asm-policy":   "",
				"set-cookie":     "TS",
			},
			Patterns:   []string{"F5", "BigIP", "The requested URL was rejected"},
			Confidence: 85,
			Type:       "WAF",
		},
		{
			Name: "AWS WAF",
			Headers: map[string]string{
				"x-amz-cf-id": "",
				"x-amzn-":     "",
				"x-amz-":      "",
			},
			Patterns:   []string{"AWS", "awswaf", "Request blocked"},
			Confidence: 85,
			Type:       "WAF",
		},
		{
			Name: "ModSecurity",
			Headers: map[string]string{
				"x-mod-sec": "",
			},
			Patterns:   []string{"ModSecurity", "Not Acceptable", "406 Not Acceptable"},
			Confidence: 80,
			Type:       "WAF",
		},
		{
			Name: "Sucuri",
			Headers: map[string]string{
				"x-sucuri-id":    "",
				"x-sucuri-cache": "",
			},
			Patterns:   []string{"Sucuri", "sucuri.net", "cloudproxy"},
			Confidence: 80,
			Type:       "WAF",
		},
		{
			Name: "Barracuda",
			Headers: map[string]string{
				"x-barracuda": "",
			},
			Patterns:   []string{"Barracuda", "barracuda"},
			Confidence: 75,
			Type:       "WAF",
		},
		{
			Name: "Fortinet FortiWeb",
			Headers: map[string]string{
				"x-fortinet": "",
			},
			Patterns:   []string{"FortiWeb", "fortiwaf", "fgd_"},
			Confidence: 80,
			Type:       "WAF",
		},
		{
			Name: "Citrix NetScaler",
			Headers: map[string]string{
				"x-netscaler": "",
				"via":         "NS-CACHE",
			},
			Patterns:   []string{"NetScaler", "Citrix"},
			Confidence: 75,
			Type:       "ADC",
		},
		{
			Name: "Radware",
			Headers: map[string]string{
				"x-radware": "",
			},
			Patterns:   []string{"Radware", "AppWall", "Unauthorized"},
			Confidence: 75,
			Type:       "WAF",
		},
		{
			Name: "AQTRONIX",
			Headers: map[string]string{
				"x-aqtonix": "",
			},
			Patterns:   []string{"AQTRONIX", "aqtronix"},
			Confidence: 70,
			Type:       "WAF",
		},
		{
			Name: "Comodo WAF",
			Headers: map[string]string{
				"x-cwaf": "",
			},
			Patterns:   []string{"Comodo", "cWAF"},
			Confidence: 70,
			Type:       "WAF",
		},
		{
			Name: "Sophos UTM",
			Headers: map[string]string{
				"x-sophos": "",
			},
			Patterns:   []string{"Sophos", "UTM", "Blocked"},
			Confidence: 70,
			Type:       "UTM",
		},
		{
			Name: "Safe3 WAF",
			Headers: map[string]string{
				"x-safe3": "",
			},
			Patterns:   []string{"Safe3", "safe3waf"},
			Confidence: 65,
			Type:       "WAF",
		},
		{
			Name: "WebKnight",
			Headers: map[string]string{
				"x-webknight": "",
			},
			Patterns:   []string{"WebKnight", "webknight"},
			Confidence: 65,
			Type:       "WAF",
		},
		{
			Name: "URLScan",
			Headers: map[string]string{
				"x-urlscan": "",
			},
			Patterns:   []string{"URLScan", "urlscan"},
			Confidence: 60,
			Type:       "Security",
		},
		{
			Name: "StackPath",
			Headers: map[string]string{
				"x-stackpath": "",
				"server":      "StackPath",
			},
			Patterns:   []string{"StackPath", "stackpath"},
			Confidence: 70,
			Type:       "CDN",
		},
	}
}

func (w *WafAnalyzer) AnalyzeResponse(statusCode int, headers map[string][]string, body string) WAFResult {
	w.mu.Lock()
	defer w.mu.Unlock()

	bestConfidence := 0
	bestName := ""
	var matchedSignatures []string

	for _, sig := range w.signatures {
		matched := false
		reason := ""

		for headerName, expectedValue := range sig.Headers {
			if values, ok := headers[headerName]; ok {
				if expectedValue == "" {
					matched = true
					reason = headerName
					break
				}
				for _, v := range values {
					if strings.Contains(strings.ToLower(v), strings.ToLower(expectedValue)) {
						matched = true
						reason = headerName + ": " + v
						break
					}
				}
				if matched {
					break
				}
			}
		}

		if !matched && len(sig.Patterns) > 0 {
			lowerBody := strings.ToLower(body)
			for _, pattern := range sig.Patterns {
				if strings.Contains(lowerBody, strings.ToLower(pattern)) {
					matched = true
					reason = "body: " + pattern
					break
				}
			}
		}

		if matched {
			matchStr := sig.Name
			if reason != "" {
				matchStr += " (" + reason + ")"
			}
			matchedSignatures = append(matchedSignatures, matchStr)

			if sig.Confidence > bestConfidence {
				bestConfidence = sig.Confidence
				bestName = sig.Name
			}
		}
	}

	result := WAFResult{
		Detected:   bestConfidence > 0,
		Name:       bestName,
		Confidence: bestConfidence,
		Signatures: matchedSignatures,
	}
	w.results = append(w.results, result)
	return result
}

func (w *WafAnalyzer) SuggestBypass(wafName string) []string {
	bypasses := []string{
		"HTTP/1.0 downgrade",
		"chunked transfer encoding",
		"header padding",
		"method override",
		"parameter pollution",
		"case switching",
		"encoding bypass",
		"SSL/TLS version switching",
	}

	name := strings.ToLower(wafName)
	switch {
	case strings.Contains(name, "cloudflare"):
		return append(bypasses, "origin IP discovery via DNS history", "Cloudscraper/cloudscalpel")
	case strings.Contains(name, "akamai"):
		return append(bypasses, "akamai header stripping", "cookie manipulation")
	case strings.Contains(name, "imperva"):
		return append(bypasses, "X-Forwarded-For spoofing", "session fixation")
	case strings.Contains(name, "f5") || strings.Contains(name, "big-ip"):
		return append(bypasses, "X-Forwarded-For bypass", "HTTP method fuzzing")
	case strings.Contains(name, "aws"):
		return append(bypasses, "AWS WAF rate limit evasion", "token bypass")
	case strings.Contains(name, "modsecurity"):
		return append(bypasses, "CRS rule exclusion", "request smuggling")
	case strings.Contains(name, "sucuri"):
		return append(bypasses, "Sucuri IP whitelisting bypass", "PHP parameter pollution")
	default:
		return bypasses
	}
}

func (w *WafAnalyzer) AddCustomSignature(sig WAFSignature) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.signatures = append(w.signatures, sig)
}

func (w *WafAnalyzer) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = nil
}
