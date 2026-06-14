package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

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

func LoadCookieJar(path string) (map[string][]string, error) {
	cookies := make(map[string][]string)
	return cookies, nil
}
