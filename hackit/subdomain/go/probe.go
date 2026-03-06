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
	actualConcurrency := config.Concurrency
	if len(results) > 1000 {
		actualConcurrency = config.Concurrency * 2
		if actualConcurrency > 1000 {
			actualConcurrency = 1000
		}
	}
	sem := make(chan bool, actualConcurrency)
	var wg sync.WaitGroup

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true, // Close connections immediately for probing
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
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

			// Parallel HTTP/HTTPS Probing
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
	// If already probed by another scheme successfully, don't overwrite if it's 200
	if res.Status == 200 && scheme == "http" {
		return
	}

	url := fmt.Sprintf("%s://%s", scheme, res.Subdomain)

	method := "HEAD"
	if config.ShowTitle || config.TechDetect {
		method = "GET"
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Update result (Locking not strictly necessary if we only update Status/Server/Title)
	// but let's be careful. Status 200 is preferred.
	if res.Status == 0 || resp.StatusCode == 200 {
		res.Status = resp.StatusCode
		res.Server = resp.Header.Get("Server")
	} else {
		// Keep existing if it's already set and new is not 200
		return
	}

	// Read body for title
	if config.ShowTitle || config.TechDetect {
		// Try Rust extraction first (Regex in Rust is much faster)
		if config.ShowTitle && rustGetTitle != nil && rustGetTitle.Find() == nil {
			cURL := []byte(url + "\x00")
			ptr, _, _ := rustGetTitle.Call(uintptr(unsafe.Pointer(&cURL[0])))
			if ptr != 0 {
				rustTitle := string(CStrToGo(ptr))
				if rustTitle != "" {
					res.Title = rustTitle
				}
			}
		}

		// Go Fallback
		if res.Title == "" || config.TechDetect {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				body := string(bodyBytes)
				if res.Title == "" && config.ShowTitle {
					m := titleRegex.FindStringSubmatch(body)
					if len(m) > 1 {
						res.Title = strings.TrimSpace(m[1])
					}
				}
				if config.TechDetect {
					res.Tech = detectTech(resp.Header, body)
				}
			}
		}
	}
}
