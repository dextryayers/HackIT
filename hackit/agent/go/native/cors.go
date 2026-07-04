package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CORSResult struct {
	Endpoint          string `json:"endpoint"`
	Origin            string `json:"origin"`
	AllowsCredentials bool   `json:"allows_credentials"`
	VulnerabilityType string `json:"vulnerability_type"`
	Evidence          string `json:"evidence"`
	Vulnerable        bool   `json:"vulnerable"`
}

func TestCORS(baseURL string) []CORSResult {
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://evil.com.evildomain.com",
		"http://evil.com",
		"https://evil.com%2F@good.com",
		"https://good.com.evil.com",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []CORSResult

	for _, origin := range testOrigins {
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", "https://evil.com/")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

		if allowOrigin == "" {
			continue
		}

		hasCredentials := strings.EqualFold(allowCredentials, "true")
		vulnType := ""
		evidence := ""

		if allowOrigin == "*" && hasCredentials {
			vulnType = "Wildcard+Credentials"
			evidence = fmt.Sprintf("Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true")
		} else if allowOrigin == "*" {
			vulnType = "Wildcard"
			evidence = fmt.Sprintf("Access-Control-Allow-Origin: * (any origin allowed)")
		} else if allowOrigin == origin {
			if hasCredentials {
				vulnType = "Reflected+Credentials"
				evidence = fmt.Sprintf("Origin reflected with credentials enabled")
			} else {
				vulnType = "Reflected"
				evidence = fmt.Sprintf("Origin '%s' is reflected verbatim", origin)
			}
		} else if allowOrigin == "null" {
			vulnType = "Null Origin"
			evidence = "Access-Control-Allow-Origin: null (sandboxed iframes can access)"
		} else if strings.Contains(allowOrigin, "evil") {
			vulnType = "Insecure Prefix Match"
			evidence = fmt.Sprintf("Origin '%s' matched to '%s'", origin, allowOrigin)
		}

		if vulnType != "" {
			results = append(results, CORSResult{
				Endpoint:          baseURL,
				Origin:            origin,
				AllowsCredentials: hasCredentials,
				VulnerabilityType: vulnType,
				Evidence:          evidence,
				Vulnerable:        true,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CORSResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   "No CORS misconfigurations detected",
		})
	}

	return results
}
