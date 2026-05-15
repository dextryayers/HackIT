package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// BruteHarvester performs targeted parameter discovery using a smart wordlist
type BruteHarvester struct {
	Client *http.Client
}

func NewBruteHarvester() *BruteHarvester {
	return &BruteHarvester{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (b *BruteHarvester) QuickBrute(domain string) []string {
	params := []string{
		"id", "page", "file", "url", "path", "dir", "cmd", "exec", "query", "q",
		"search", "debug", "test", "dev", "admin", "config", "cfg", "show", "view",
		"download", "token", "auth", "secret", "user", "username", "email", "pass",
	}

	var wg sync.WaitGroup
	results := make(chan string, len(params))
	
	for _, p := range params {
		wg.Add(1)
		go func(param string) {
			defer wg.Done()
			url := fmt.Sprintf("http://%s/?%s=HACKIT_PROBE", domain, param)
			resp, err := b.Client.Get(url)
			if err == nil {
				defer resp.Body.Close()
				// If status is 200 or 403, the parameter likely exists/is processed
				if resp.StatusCode == 200 || resp.StatusCode == 403 {
					results <- param
				}
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var discovered []string
	for p := range results {
		discovered = append(discovered, p)
	}
	return discovered
}
