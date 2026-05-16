package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var sensitivePaths = []string{
	"/.env",
	"/.git/config",
	"/.svn/entries",
	"/.DS_Store",
	"/package.json",
	"/yarn.lock",
	"/package-lock.json",
	"/composer.json",
	"/composer.lock",
	"/docker-compose.yml",
	"/Dockerfile",
	"/serverless.yml",
	"/terraform.tfstate",
	"/.npmrc",
	"/.pypirc",
	"/web.config",
	"/robots.txt",
	"/sitemap.xml",
	"/crossdomain.xml",
	"/clientaccesspolicy.xml",
	"/.well-known/security.txt",
	"/humans.txt",
	"/backup.sql",
	"/dump.zip",
	"/phpinfo.php",
	"/info.php",
	"/server-status",
	"/server-info",
	"/actuator/health",
	"/actuator/mappings",
	"/wp-json/wp/v2/users",
	"/graphql",
	"/api-docs",
	"/swagger.json",
	"/debug",
	"/console",
	"/shell",
}

// ActiveFuzz performs concurrent HTTP GET requests to common sensitive files
func ActiveFuzz(baseURL string, timeout time.Duration) []string {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects to avoid false positives
		},
	}

	// Remove trailing slash if present
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	for _, path := range sensitivePaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			targetURL := baseURL + p
			
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "TechHunter/3.0 (Fuzzer)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			status := resp.StatusCode
			
			// We only care about 200 OK, 401 Unauthorized, or 403 Forbidden for sensitive files
			if status == 200 || status == 401 || status == 403 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				size := len(bodyBytes)
				
				// Basic false-positive filtering (ignore standard 404 pages returning 200)
				if status == 200 && size < 50 {
					return // Too small to be a real config file in most cases, or just a blank page
				}

				finding := fmt.Sprintf("[status] %d [size] %d [path] %s", status, size, p)
				
				mu.Lock()
				results = append(results, finding)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return results
}
