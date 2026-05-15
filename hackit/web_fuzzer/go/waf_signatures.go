package main

import "strings"

type WAFSignature struct {
	Name    string
	Pattern string
}

var Signatures = []WAFSignature{
	{"Cloudflare", "cloudflare"},
	{"Akamai", "akamai"},
	{"Imperva", "imperva"},
	{"Incapsula", "incapsula"},
	{"ModSecurity", "mod_security"},
	{"Sucuri", "sucuri"},
	{"Barracuda", "barracuda"},
	{"F5 BIG-IP", "f5 big-ip"},
	{"AWS WAF", "awswaf"},
}

func CheckWAF(body string, headers map[string][]string) string {
	bodyLow := strings.ToLower(body)
	for _, sig := range Signatures {
		if strings.Contains(bodyLow, sig.Pattern) {
			return sig.Name
		}
	}

	for _, values := range headers {
		for _, v := range values {
			vLow := strings.ToLower(v)
			for _, sig := range Signatures {
				if strings.Contains(vLow, sig.Pattern) {
					return sig.Name
				}
			}
		}
	}
	return ""
}
