package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ScanResult represents a single finding
type ScanResult struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
}

func main() {
	config := parseFlags()

	if config.Target == "" {
		color.Red("[!] Target URL is required")
		os.Exit(1)
	}

	color.Cyan("[*] Go Core Scanner starting on: %s", config.Target)

	// Default patterns if wordlist is empty
	if len(config.Paths) == 0 {
		config.Paths = []string{
			".env", ".git/config", "admin/", "login/", "config.php",
			"wp-config.php", ".htaccess", "robots.txt", "backup.sql",
		}
	}

	// Load Smart Analysis if exists
	if _, err := os.Stat("../smart_analysis.json"); err == nil {
		data, _ := os.ReadFile("../smart_analysis.json")
		var smart struct {
			Endpoints []string `json:"endpoints"`
		}
		if err := json.Unmarshal(data, &smart); err == nil {
			config.Paths = append(config.Paths, smart.Endpoints...)
			color.Green("[+] Injected %d endpoints from Smart Analysis", len(smart.Endpoints))
		}
	}

	results := make(chan ScanResult)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Threads)

	// Result collector
	go func() {
		for res := range results {
			statusColor := color.New(color.FgWhite)
			if res.Status >= 200 && res.Status < 300 {
				statusColor = color.New(color.FgGreen)
			} else if res.Status >= 300 && res.Status < 400 {
				statusColor = color.New(color.FgCyan)
			} else if res.Status >= 400 && res.Status < 500 {
				statusColor = color.New(color.FgYellow)
			}

			fmt.Printf("[+] %-30s | %s | %10d bytes | %s\n",
				res.Path,
				statusColor.Sprintf("%d", res.Status),
				res.Size,
				res.ContentType,
			)
		}
	}()

	client := &http.Client{
		Timeout: time.Duration(config.TimeoutMS) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.FollowRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	// Rate Limiter
	var ticker *time.Ticker
	if config.RateLimit != nil && *config.RateLimit > 0 {
		interval := time.Duration(float64(time.Second) / *config.RateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	// Main scan loop
	for _, path := range config.Paths {
		if ticker != nil {
			<-ticker.C
		}
		wg.Add(1)
		semaphore <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			fullURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.Target, "/"), strings.TrimPrefix(p, "/"))

			req, err := http.NewRequest(config.Method, fullURL, nil)
			if err != nil {
				return
			}

			// Add headers
			for k, v := range config.Headers {
				req.Header.Set(k, v)
			}
			if config.UserAgent != nil {
				req.Header.Set("User-Agent", *config.UserAgent)
			} else {
				req.Header.Set("User-Agent", "HackIt-Core-Scanner/v3")
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Filtering logic
			shouldShow := true
			for _, ex := range config.ExcludeStatus {
				if resp.StatusCode == ex {
					shouldShow = false
					break
				}
			}

			if shouldShow && resp.StatusCode != 404 {
				results <- ScanResult{
					Path:        p,
					Status:      resp.StatusCode,
					Size:        resp.ContentLength,
					ContentType: resp.Header.Get("Content-Type"),
				}
			}
		}(path)
	}

	wg.Wait()
	close(results)
	color.Cyan("\n[*] Core Scan Complete.")
}
