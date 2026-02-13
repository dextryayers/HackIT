package main

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var defaultTransport = &http.Transport{
	MaxIdleConns:        200,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     30 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

var defaultClient = &http.Client{
	Transport: defaultTransport,
}

// cleanSubdomain cleans and validates a subdomain
func cleanSubdomain(sub, rootDomain string) string {
	sub = strings.ToLower(strings.TrimSpace(sub))
	sub = strings.TrimSuffix(sub, ".")
	sub = strings.TrimPrefix(sub, "*.")
	sub = strings.TrimPrefix(sub, ".")

	// Remove protocol if present (some sources return full URLs)
	if idx := strings.Index(sub, "://"); idx != -1 {
		sub = sub[idx+3:]
	}
	// Remove path
	if idx := strings.Index(sub, "/"); idx != -1 {
		sub = sub[:idx]
	}
	// Remove port
	if idx := strings.Index(sub, ":"); idx != -1 {
		sub = sub[:idx]
	}

	if strings.HasSuffix(sub, "."+rootDomain) || sub == rootDomain {
		return sub
	}
	return ""
}

// unique deduplicates a string slice
func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// getRandomUserAgent returns a random User-Agent string
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
	}
	// Note: rand.Seed is deprecated in newer Go, but for simple needs it's fine
	// or just use crypto/rand if absolute randomness is needed.
	return userAgents[rand.Intn(len(userAgents))]
}

// safeGet performs an HTTP GET with better reliability headers
func safeGet(url string, timeout time.Duration) (*http.Response, error) {
	client := defaultClient
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	return client.Do(req)
}
