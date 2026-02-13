package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func runProbe(results []*Result, config Config) {
	actualConcurrency := config.Concurrency
	if len(results) > 500 {
		actualConcurrency = config.Concurrency / 2 // Reduce slightly for probing to avoid mass blocking
		if actualConcurrency < 50 {
			actualConcurrency = 50
		}
	}
	sem := make(chan bool, actualConcurrency)
	var wg sync.WaitGroup

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, r := range results {
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			// Probe HTTPS first (modern standard)
			probeURL(client, res, "https", config)
			if res.Status == 0 {
				probeURL(client, res, "http", config)
			}
		}(r)
	}
	wg.Wait()
}

func probeURL(client *http.Client, res *Result, scheme string, config Config) {
	url := fmt.Sprintf("%s://%s", scheme, res.Subdomain)

	// Try with retries and exponential backoff
	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		method := "HEAD"
		if config.ShowTitle || config.TechDetect {
			method = "GET"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout+i*5)*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, method, url, nil)
		if reqErr != nil {
			cancel()
			err = reqErr
			time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
			continue
		}
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		resp, err = client.Do(req)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}

	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	// Update result
	res.Status = resp.StatusCode
	res.Server = resp.Header.Get("Server")

	// Read body for title
	if config.ShowTitle || config.TechDetect {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			body := string(bodyBytes)
			// Extract Title
			m := titleRegex.FindStringSubmatch(body)
			if len(m) > 1 {
				res.Title = strings.TrimSpace(m[1])
			}

			// Tech Detect
			if config.TechDetect {
				res.Tech = detectTech(resp.Header, body)
			}
		}
	}
}
