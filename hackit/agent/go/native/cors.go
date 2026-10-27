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

// TestCORS reports exploitable CORS misconfigurations only.  A wildcard
// Access-Control-Allow-Origin without credentials is not a vulnerability, and
// reflecting an origin without credentials does not expose authenticated data.
// Both were previously reported as high-risk findings.
func TestCORS(baseURL string) []CORSResult {
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://evil.com.evildomain.com",
		"http://evil.com",
		"https://good.com.evil.com",
	}

	client := scanClient(10 * time.Second)
	results := make([]CORSResult, 0)

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

		allowOrigin := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
		if allowOrigin == "" {
			continue
		}

		hasCredentials := strings.EqualFold(allowCredentials, "true")
		vulnType := ""
		evidence := ""

		switch {
		case allowOrigin == "*" && hasCredentials:
			// Browsers reject this combination, but it reveals that the app
			// intends to share credentials with every origin.
			vulnType = "Wildcard+Credentials"
			evidence = "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true"
		case hasCredentials && strings.EqualFold(allowOrigin, "null"):
			vulnType = "Null Origin + Credentials"
			evidence = "Null origin is allowed with credentials (sandboxed iframe attack)"
		case hasCredentials && isExternalAttackerHost(allowOrigin):
			vulnType = "Reflected Attacker Origin + Credentials"
			evidence = fmt.Sprintf("Attacker origin %q is allowed with credentials", allowOrigin)
		}

		if vulnType == "" {
			continue
		}
		results = append(results, CORSResult{
			Endpoint:          baseURL,
			Origin:            origin,
			AllowsCredentials: hasCredentials,
			VulnerabilityType: vulnType,
			Evidence:          evidence,
			Vulnerable:        true,
		})
	}

	if len(results) == 0 {
		results = append(results, CORSResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   "No exploitable CORS misconfiguration detected",
		})
	}

	return results
}
