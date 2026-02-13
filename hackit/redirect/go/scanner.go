package main

import (
	"crypto/tls"
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
	Type      string `json:"type"`
	Location  string `json:"location"`
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
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
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
	sem := make(chan struct{}, 10)

	for param := range params {
		for _, pay := range Payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

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

				resp, err := s.Client.Get(attackURL)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				loc := resp.Header.Get("Location")
				if loc != "" && (strings.Contains(loc, "google.com")) {
					mutex.Lock()
					results = append(results, Result{
						URL:       attackURL,
						Parameter: p,
						Payload:   pay,
						Type:      "Open Redirect",
						Location:  loc,
					})
					mutex.Unlock()
				}
			}(param, pay)
		}
	}
	wg.Wait()
	return results
}
