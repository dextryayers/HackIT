package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient *http.Client

func InitClient(timeout int) {
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
}

func FuzzURL(url string, bypass bool) (Result, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "HackIt-Fuzzer/2.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	// Read minimal body for title extraction
	bodyStart := make([]byte, 2048)
	n, _ := io.ReadFull(resp.Body, bodyStart)
	bodyStr := string(bodyStart[:n])
	
	title := ExtractTitle(bodyStr)
	redirect := ""
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		redirect = resp.Header.Get("Location")
	}

	res := Result{
		Status:   resp.StatusCode,
		Length:   resp.ContentLength,
		URL:      url,
		Title:    title,
		Redirect: redirect,
	}
	
	// Handle -1 content length
	if res.Length == -1 {
		res.Length = int64(n) // Approximation
	}

	// 403 Bypass Check
	if bypass && resp.StatusCode == 403 {
		bypassRes := TryBypass(url)
		if bypassRes.IsBypass {
			return bypassRes, nil
		}
	}

	return res, nil
}

func ExtractTitle(body string) string {
	low := strings.ToLower(body)
	start := strings.Index(low, "<title>")
	if start == -1 {
		return ""
	}
	end := strings.Index(low[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start+7 : start+end])
}

func TryBypass(url string) Result {
	// Common 403 bypass headers
	headers := map[string]string{
		"X-Forwarded-For": "127.0.0.1",
		"X-Original-URL":  url,
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Remote-IP": "127.0.0.1",
		"X-Client-IP": "127.0.0.1",
		"X-Host": "127.0.0.1",
	}

	for k, v := range headers {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set(k, v)
		resp, err := httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return Result{
					Status:   200,
					URL:      url,
					IsBypass: true,
					Payload:  fmt.Sprintf("%s: %s", k, v),
					Title:    "BYPASSED via Headers",
				}
			}
		}
	}
	
	// Try methods
	methods := []string{"POST", "TRACE", "OPTIONS", "PUT"}
	for _, m := range methods {
		req, _ := http.NewRequest(m, url, nil)
		resp, err := httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return Result{
					Status:   200,
					URL:      url,
					IsBypass: true,
					Payload:  "Method: " + m,
					Title:    "BYPASSED via Method",
				}
			}
		}
	}

	return Result{}
}
