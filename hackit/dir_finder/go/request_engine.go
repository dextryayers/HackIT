package main

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"strings"
)

type RequestBuilder struct {
	Method  string
	URL     string
	Body    io.Reader
	Headers map[string]string
	Auth    string
	AuthType string
	Cookie  string
	UA      string
}

func BuildHTTPRequest(config *ScanConfig, fullURL string, reqBody io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(config.Method, fullURL, reqBody)
	if err != nil {
		return nil, err
	}

	ApplyCustomHeaders(req, config)
	ApplyAuthHeader(req, config)
	ApplyUserAgent(req, config)
	ApplyCookie(req, config)

	if config.FollowRedirect {
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
	}

	return req, nil
}

func ApplyCustomHeaders(req *http.Request, config *ScanConfig) {
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}
	if config.HeadersFile != "" {
		hdrs := LoadHeadersFromFile(config.HeadersFile)
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
	}
}

func ApplyAuthHeader(req *http.Request, config *ScanConfig) {
	if config.Auth == "" {
		return
	}
	switch config.AuthType {
	case "basic":
		parts := strings.SplitN(config.Auth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	case "bearer", "jwt":
		req.Header.Set("Authorization", "Bearer "+config.Auth)
	case "digest":
		req.Header.Set("Authorization", "Digest "+config.Auth)
	case "ntlm":
		req.Header.Set("Authorization", "NTLM "+config.Auth)
	default:
		if strings.Contains(config.Auth, ":") {
			parts := strings.SplitN(config.Auth, ":", 2)
			req.SetBasicAuth(parts[0], parts[1])
		} else {
			req.Header.Set("Authorization", "Bearer "+config.Auth)
		}
	}
}

func ApplyUserAgent(req *http.Request, config *ScanConfig) {
	if config.UserAgent != "" {
		req.Header.Set("User-Agent", config.UserAgent)
	}
}

func ApplyRandomUA(req *http.Request, uaList []string) {
	if len(uaList) > 0 && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", strings.TrimSpace(uaList[hashPath(req.URL.Path)%uint64(len(uaList))]))
	}
}

func hashPath(path string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(path); i++ {
		h ^= uint64(path[i])
		h *= 1099511628211
	}
	return h
}

func ApplyCookie(req *http.Request, config *ScanConfig) {
	if config.Cookie != "" {
		req.Header.Set("Cookie", config.Cookie)
	}
}

func LoadHeadersFromFile(path string) map[string]string {
	headers := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return headers
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}
	return headers
}
