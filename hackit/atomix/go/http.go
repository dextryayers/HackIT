package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.91",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile",
	"curl/8.4.0",
	"Wget/1.21.4",
	"Go-http-client/2.0",
}

func NewHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
			MaxIdleConns:    200,
			MaxConnsPerHost: 100,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func NewConfiguredClient(config *ScanConfig) *http.Client {
	timeout := config.Timeout
	if timeout <= 0 { timeout = 60 }

	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		MaxIdleConns:       200,
		MaxConnsPerHost:    100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	if config.HTTP2 {
		transport.ForceAttemptHTTP2 = true
	}
	if config.DisableHTTP2 {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	if !config.KeepAlive {
		transport.DisableKeepAlives = true
	}
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	maxRedir := config.MaxRedirects
	if maxRedir <= 0 { maxRedir = 10 }

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedir {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func RandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func ResolveURL(baseURL string, pathTmpl string, payload string) string {
	result := strings.ReplaceAll(pathTmpl, "{{BaseURL}}", strings.TrimRight(baseURL, "/"))
	result = strings.ReplaceAll(result, "{{URL}}", baseURL)
	if payload != "" {
		result = strings.ReplaceAll(result, "{{payload}}", url.QueryEscape(payload))
	}
	return result
}

func SendRequest(client *http.Client, reqURL, method, body string, headers map[string]string) (*ResponseInfo, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	if method == "" { method = "GET" }

	req, err := http.NewRequest(method, reqURL, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", RandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var headerStr strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			headerStr.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}

	contentType := resp.Header.Get("Content-Type")

	return &ResponseInfo{
		StatusCode:  resp.StatusCode,
		Headers:     headerStr.String(),
		Body:        string(respBody),
		BodyLen:     len(respBody),
		Duration:    duration,
		ContentType: contentType,
	}, nil
}

func SendRequestWithRetry(client *http.Client, reqURL, method, body string, headers map[string]string, maxRetries int) (*ResponseInfo, error) {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i*i) * time.Second)
		}
		resp, err := SendRequest(client, reqURL, method, body, headers)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
