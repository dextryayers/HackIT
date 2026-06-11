package native

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WAFResult holds WAF detection findings
type WAFResult struct {
	Detected bool
	WAFName  string
}

// DetectWAF tries to identify if a Web Application Firewall is protecting the target
func DetectWAF(ip string, port int, isHTTPS bool) WAFResult {
	protocol := "http"
	if isHTTPS {
		protocol = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d/", protocol, ip, port)

	// Malicious payload to trigger WAF
	maliciousURL := fmt.Sprintf("%s?id=1'%%20OR%%201=1--&exec=/bin/bash", targetURL)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// Request 1: Normal request to check headers
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)

	wafName := ""
	if err == nil {
		defer resp.Body.Close()
		server := strings.ToLower(resp.Header.Get("Server"))
		if strings.Contains(server, "cloudflare") {
			wafName = "Cloudflare"
		} else if strings.Contains(server, "sucuri") || resp.Header.Get("X-Sucuri-ID") != "" {
			wafName = "Sucuri"
		} else if strings.Contains(server, "akamai") {
			wafName = "Akamai"
		} else if resp.Header.Get("X-Amz-Cf-Id") != "" {
			wafName = "AWS WAF / CloudFront"
		} else if resp.Header.Get("X-CDN") == "Incapsula" {
			wafName = "Imperva Incapsula"
		}
	}

	// Request 2: Malicious request
	if wafName == "" {
		reqMal, _ := http.NewRequest("GET", maliciousURL, nil)
		reqMal.Header.Set("User-Agent", "Mozilla/5.0")
		respMal, errMal := client.Do(reqMal)

		if errMal == nil {
			defer respMal.Body.Close()
			if respMal.StatusCode == 403 || respMal.StatusCode == 406 || respMal.StatusCode == 501 {
				// Read body to find signature
				bodyBytes, _ := io.ReadAll(io.LimitReader(respMal.Body, 8192))
				bodyStr := strings.ToLower(string(bodyBytes))

				if strings.Contains(bodyStr, "cloudflare") {
					wafName = "Cloudflare"
				} else if strings.Contains(bodyStr, "wordfence") {
					wafName = "Wordfence"
				} else if strings.Contains(bodyStr, "sucuri") {
					wafName = "Sucuri"
				} else {
					wafName = "Generic WAF (Blocked Payload)"
				}
			}
		}
	}

	return WAFResult{
		Detected: wafName != "",
		WAFName:  wafName,
	}
}
