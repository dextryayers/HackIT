package modules

import (
	"strings"
)

// WAFDetector handles web application firewall detection
type WAFDetector struct {
	Engine EngineInterface
}

func NewWAFDetector(e EngineInterface) *WAFDetector {
	return &WAFDetector{Engine: e}
}

type WAFInfo struct {
	Detected bool
	Name     string
}

func DetectWAF(headers map[string][]string, body string) WAFInfo {
	// Cloudflare
	if _, ok := headers["Cf-Ray"]; ok {
		return WAFInfo{Detected: true, Name: "Cloudflare"}
	}
	if strings.Contains(body, "cloudflare-nginx") {
		return WAFInfo{Detected: true, Name: "Cloudflare"}
	}

	// Akamai
	if _, ok := headers["X-Akamai-Transformed"]; ok {
		return WAFInfo{Detected: true, Name: "Akamai"}
	}

	// ModSecurity
	if server, ok := headers["Server"]; ok {
		for _, s := range server {
			if strings.Contains(s, "Mod_Security") || strings.Contains(s, "NOYB") {
				return WAFInfo{Detected: true, Name: "ModSecurity"}
			}
		}
	}

	// FortiWeb
	if _, ok := headers["FortiWeb"]; ok {
		return WAFInfo{Detected: true, Name: "FortiWeb"}
	}

	return WAFInfo{Detected: false, Name: "Unknown / None"}
}
