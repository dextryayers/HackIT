package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Type      string `json:"type"` // reflected
}

type Scanner struct {
	Client *http.Client
}

func NewScanner(timeout int) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (s *Scanner) Scan(targetURL string) []Result {
	results := make([]Result, 0)
	u, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	params := u.Query()
	if len(params) == 0 {
		return results
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Limit concurrency to avoid overwhelming the server
	sem := make(chan struct{}, 10) 

	for param := range params {
		for _, payload := range Payloads {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				// Construct URL
				newParams := make(url.Values)
				for k, v := range params {
					if k == p {
						newParams.Set(k, pay)
					} else {
						newParams[k] = v
					}
				}
				u.RawQuery = newParams.Encode()
				attackURL := u.String()

				req, err := http.NewRequest("GET", attackURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "HackIt-XSS/1.0")

				resp, err := s.Client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				if strings.Contains(string(body), pay) {
					mutex.Lock()
					results = append(results, Result{
						URL:       attackURL,
						Parameter: p,
						Payload:   pay,
						Type:      "Reflected",
					})
					mutex.Unlock()
				}
			}(param, payload)
		}
	}
	wg.Wait()
	return results
}
