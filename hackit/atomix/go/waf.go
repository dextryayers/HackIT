package main

import (
	"fmt"
	"net/http"
	"strings"
)

type WAFInfo struct {
	Name        string
	Detected    bool
	Product     string
	BlockedCode int
	BlockedBody string
	Signatures  []string
}

func DetectWAF(target string, client *http.Client) *WAFInfo {
	payloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"../../../etc/passwd",
		"${jndi:ldap://127.0.0.1/a}",
	}
	signatures := map[string][]string{
		"cloudflare": {"Cloudflare", "cf-ray", "__cfduid"},
		"akamai":     {"AkamaiGHost", "Akamai"},
		"modsecurity":{"ModSecurity", "NOYB"},
		"aws-waf":    {"AWS", "aws-waf"},
		"imperva":    {"imperva", "Incapsula"},
		"f5-bigip":   {"BigIP", "F5"},
		"barracuda":  {"Barracuda"},
		"sucuri":     {"Sucuri", "X-Sucuri-ID"},
	}

	waf := &WAFInfo{Detected: false}

	// Check response headers for WAF signatures
	resp, err := SendRequest(client, target, "GET", "", nil)
	if err != nil { return waf }

	for product, sigs := range signatures {
		for _, sig := range sigs {
			if strings.Contains(resp.Headers, sig) {
				waf.Detected = true
				waf.Product = product
				waf.Signatures = append(waf.Signatures, sig)
				break
			}
		}
		if waf.Detected { break }
	}

	// Test with malicious payload
	for _, pay := range payloads {
		u := target + "?q=" + pay
		resp2, err := SendRequest(client, u, "GET", "", nil)
		if err != nil { continue }
		if resp2.StatusCode == 403 || resp2.StatusCode == 406 || resp2.StatusCode == 429 {
			waf.Detected = true
			waf.BlockedCode = resp2.StatusCode
			break
		}
	}

	return waf
}

func WafBypassPayloads(base string) []string {
	bypasses := []string{
		base,
		strings.ToUpper(base),
		strings.ToLower(base),
		"/*!*/" + base,
		"/**/" + base,
		fmt.Sprintf("// %s ", base),
		base + "--+-",
		base + "%00",
		base + "||'1'='1",
		base + "'/*",
	}
	return bypasses
}
