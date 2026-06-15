package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var sensitivePaths = []string{
	// Config files
	"/.env", "/.env.production", "/.env.local",
	"/.git/config", "/.git/HEAD",
	"/config.json", "/config.php",
	"/wp-config.php",
	"/appsettings.json",
	"/web.config",
	// Package files
	"/package.json",
	"/composer.json",
	"/go.mod", "/go.sum",
	"/Gemfile",
	"/requirements.txt",
	// Infrastructure
	"/docker-compose.yml", "/Dockerfile",
	"/Jenkinsfile", "/.gitlab-ci.yml",
	"/.github/workflows/main.yml",
	// Backup files
	"/backup.sql",
	"/db.sql",
	// Debug & Admin paths
	"/phpinfo.php", "/info.php",
	"/actuator", "/actuator/health",
	"/admin", "/admin/", "/administrator",
	"/manager/html",
	// API docs
	"/swagger.json", "/openapi.json",
	"/graphql", "/graphiql",
	// CMS paths
	"/wp-json/wp/v2/users",
	"/wp-admin",
	// Security
	"/robots.txt", "/sitemap.xml",
	"/.well-known/security.txt",
	"/.htaccess",
	// Auth paths
	"/login", "/signin", "/signup",
	"/forgot-password",
	"/api/health", "/api/status",
	"/api/users", "/api/admin", "/api/config",
}

var interestingStatuses = []int{200, 201, 401, 403, 405, 500, 302, 301, 307}

func isInterestingStatus(code int) bool {
	for _, s := range interestingStatuses {
		if code == s {
			return true
		}
	}
	return false
}

type FuzzResult struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
	Type   string `json:"type"`
}

func ActiveFuzz(baseURL string, timeout time.Duration) []string {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	for _, path := range sensitivePaths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			targetURL := baseURL + p
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				return
			}

			status := resp.StatusCode
			if !isInterestingStatus(status) {
				resp.Body.Close()
				return
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			size := len(bodyBytes)

			// Filter false positives for 200 responses
			if status == 200 {
				if size < 20 {
					return
				}
				ct := resp.Header.Get("Content-Type")
				if strings.Contains(ct, "text/html") && size > 100 && size < 3000 {
					bodyLower := strings.ToLower(string(bodyBytes))
					if strings.Contains(bodyLower, "<!doctype") || strings.Contains(bodyLower, "<html") {
						return
					}
				}
			}

			finding := fmt.Sprintf("[%d] %dB %s", status, size, p)
			mu.Lock()
			results = append(results, finding)
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	return results
}
