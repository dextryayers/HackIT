package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func trimSpace(s string) string { return strings.TrimSpace(s) }

func indexColon(s string) int { return strings.Index(s, ":") }

func splitHeaderRaw(raw string) []string {
	// Support both newline-separated and comma-separated repeat usage.
	lines := strings.Split(raw, "\n")
	var out []string
	for _, l := range lines {
		for _, p := range strings.Split(l, ",") {
			if strings.Contains(p, ":") {
				out = append(out, p)
			} else if strings.TrimSpace(p) != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

type AuthProvider struct {
	Type    string
	Creds   string
	Token   string
	Headers map[string]string
}

func NewAuthProvider(config *ScanConfig) *AuthProvider {
	ap := &AuthProvider{Headers: make(map[string]string)}
	if config.BasicAuth != "" {
		ap.Type = "basic"
		ap.Creds = config.BasicAuth
		encoded := base64.StdEncoding.EncodeToString([]byte(config.BasicAuth))
		ap.Headers["Authorization"] = "Basic " + encoded
	}
	if config.Bearer != "" {
		ap.Type = "bearer"
		ap.Token = config.Bearer
		ap.Headers["Authorization"] = "Bearer " + config.Bearer
	}
	if config.APIKey != "" {
		ap.Type = "apikey"
		ap.Headers["X-API-Key"] = config.APIKey
	}
	if config.AuthURL != "" && config.AuthData != "" {
		ap.Type = "oauth2"
		token, err := fetchOAuthToken(config.AuthURL, config.AuthData)
		if err == nil {
			ap.Headers["Authorization"] = "Bearer " + token
		}
	}
	return ap
}

func fetchOAuthToken(url, data string) (string, error) {
	client := NewHTTPClient(10)
	resp, err := SendRequest(client, url, "POST", data, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil { return "", err }
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("oauth failed: status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func (ap *AuthProvider) Apply(req *http.Request) {
	for k, v := range ap.Headers {
		req.Header.Set(k, v)
	}
}

func ParseCookieString(s string) []string {
	if s == "" { return nil }
	return []string{s}
}

type CustomHeader struct {
	Name  string
	Value string
}

// ParseCustomHeaders parses -H "Name: Value" (comma or newline separated).
func ParseCustomHeaders(cfg *ScanConfig) []CustomHeader {
	if cfg == nil {
		return nil
	}
	raw := cfg.HeaderStr
	if raw == "" && cfg.HeadersFile != "" {
		return nil
	}
	if raw == "" {
		return nil
	}
	var out []CustomHeader
	parts := splitHeaderRaw(raw)
	for _, p := range parts {
		idx := indexColon(p)
		if idx <= 0 {
			continue
		}
		name := trimSpace(p[:idx])
		val := trimSpace(p[idx+1:])
		if name != "" {
			out = append(out, CustomHeader{Name: name, Value: val})
		}
	}
	return out
}

// ApplyAuthHeaders merges Basic/Bearer/API-Key auth into the header map
// without overwriting an explicit Authorization header.
func ApplyAuthHeaders(headers map[string]string, cfg *ScanConfig) {
	if cfg == nil || headers == nil {
		return
	}
	ap := NewAuthProvider(cfg)
	for k, v := range ap.Headers {
		if _, exists := headers[k]; !exists {
			headers[k] = v
		}
	}
}

func LoadCookieJar(path string) (map[string][]string, error) {
	cookies := make(map[string][]string)
	return cookies, nil
}
