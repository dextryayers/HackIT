package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func runProbe(results []*Result, config Config) {
	// Adaptive Concurrency: Scale up for large result sets but cap to prevent OS resource exhaustion
	actualConcurrency := config.Concurrency
	if len(results) > 500 {
		actualConcurrency = config.Concurrency * 2
		if actualConcurrency > 1000 {
			actualConcurrency = 1000
		}
	}
	
	sem := make(chan bool, actualConcurrency)
	var wg sync.WaitGroup

	// Optimized Transport for mass probing
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		// Smart Redirect Handling: Don't auto-follow, we want to see the 301/302
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, r := range results {
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			// Parallel HTTP/HTTPS Probing for maximum speed
			var pWg sync.WaitGroup
			schemes := []string{"https", "http"}

			for _, scheme := range schemes {
				pWg.Add(1)
				go func(s string) {
					defer pWg.Done()
					probeURL(client, res, s, config)
				}(scheme)
			}
			pWg.Wait()
		}(r)
	}
	wg.Wait()
}

func probeURL(client *http.Client, res *Result, scheme string, config Config) {
	// Optimization: If HTTPS already gave us a 200, skip HTTP
	if res.Status == 200 && scheme == "http" {
		return
	}

	url := fmt.Sprintf("%s://%s", scheme, res.Subdomain)
	
	// Professional Probing: Use HEAD first for speed, GET if metadata is needed
	method := "HEAD"
	if config.ShowTitle || config.TechDetect {
		method = "GET"
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")

	// Industrial-Grade Retry Logic (Aurat Presisi)
	var resp *http.Response
	maxRetries := 2
	if config.Stealth {
		maxRetries = 1
	}

	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
		}
	}

	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	// Capture Status & Server (Professional Precision)
	isSuccessful := resp.StatusCode >= 200 && resp.StatusCode < 400
	if res.Status == 0 || (isSuccessful && res.Status >= 400) {
		res.Status = resp.StatusCode
		res.Server = resp.Header.Get("Server")
		if res.Server == "" {
			res.Server = resp.Header.Get("X-Powered-By")
		}
	}

	// Metadata Extraction (Title & Tech)
	if (config.ShowTitle || config.TechDetect) && method == "GET" {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			body := string(bodyBytes)
			
			// 1. Title Extraction (FFI Rust -> Go Fallback)
			if config.ShowTitle {
				if rustGetTitle != nil && rustGetTitle.Find() == nil {
					cURL := []byte(url + "\x00")
					ptr, _, _ := rustGetTitle.Call(uintptr(unsafe.Pointer(&cURL[0])))
					if ptr != 0 {
						rustTitle := strings.TrimSpace(CStrToGo(ptr))
						if rustTitle != "" && rustTitle != "ERROR" {
							res.Title = rustTitle
						}
					}
				}
				
				if res.Title == "" {
					m := titleRegex.FindStringSubmatch(body)
					if len(m) > 1 {
						res.Title = strings.TrimSpace(m[1])
					}
				}
			}

			// 2. Technology Fingerprinting
			if config.TechDetect {
				res.Tech = detectTech(resp.Header, body)
			}
		}
	}
}
