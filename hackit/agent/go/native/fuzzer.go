package native

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FuzzResult struct {
	Path       string
	StatusCode int
}

// Critical sensitive files and directories
var sensitivePaths = []string{
	"/.git/", "/.git/config", "/.env", "/.env.backup", "/.env.dev", "/.env.local",
	"/wp-config.php.bak", "/wp-config.php.save", "/config.php.bak", "/backup.zip",
	"/backup.tar.gz", "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
	"/.svn/", "/.idea/", "/.vscode/", "/server-status", "/phpinfo.php", "/info.php",
	"/admin/", "/administrator/", "/login/", "/dashboard/", "/api/v1/users",
	"/api/v1/users.json", "/swagger-ui.html", "/v2/api-docs", "/graphql",
	"/actuator/env", "/actuator/health", "/wp-admin/admin-ajax.php",
}

// FuzzDirectories concurrently checks for sensitive files/directories
func FuzzDirectories(baseURL string, concurrency int) []FuzzResult {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	pathsChan := make(chan string, len(sensitivePaths))
	resultsChan := make(chan FuzzResult, len(sensitivePaths))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go fuzzWorker(baseURL, pathsChan, resultsChan, &wg)
	}

	for _, path := range sensitivePaths {
		// Remove leading slash to avoid double slashes with baseURL
		cleanPath := strings.TrimPrefix(path, "/")
		pathsChan <- cleanPath
	}
	close(pathsChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []FuzzResult
	for res := range resultsChan {
		if res.StatusCode == 200 || res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 403 {
			// 403 means it exists but forbidden (good to know for directory existence)
			results = append(results, res)
		}
	}

	return results
}

func fuzzWorker(baseURL string, paths <-chan string, results chan<- FuzzResult, wg *sync.WaitGroup) {
	defer wg.Done()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects to capture 301/302
		},
	}

	for path := range paths {
		targetURL := baseURL + path
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		statusCode := resp.StatusCode
		resp.Body.Close()

		results <- FuzzResult{
			Path:       "/" + path,
			StatusCode: statusCode,
		}
	}
}
