package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

func RunScan(config *ScanConfig) ([]DirResult, *ScanStats) {
	stats := &ScanStats{StartTime: time.Now()}

	mu := &sync.Mutex{}
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Threads)

	client := CreateClient(config)

	uaList := []string{}
	if config.RandomAgent {
		uaList = LoadUserAgents(findDBDir())
	}

	var ticker *time.Ticker
	if config.MaxRate > 0 {
		interval := time.Duration(float64(time.Second) / config.MaxRate)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	results := make([]DirResult, 0)
	sizeFrequency := make(map[string]int)
	seenPaths := make(map[string]bool)
	pathCount := len(config.Paths)

	// Max-time timeout
	var timedOut int32
	if config.MaxTime > 0 {
		time.AfterFunc(time.Duration(config.MaxTime)*time.Second, func() {
			atomic.StoreInt32(&timedOut, 1)
		})
	}

	// Live progress — prints every 3 seconds (uses \n for pipe/terminal compatibility)
	done := make(chan bool)
	var completed int32
	lastProgress := time.Now()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c := atomic.LoadInt32(&completed)
				if c > 0 && !config.Quiet && time.Since(lastProgress) > 2*time.Second {
					mu.Lock()
					f := stats.Found
					e := stats.Errors
					elapsed := time.Since(stats.StartTime).Seconds()
					pct := int(float64(c) / float64(pathCount) * 100)
					rate := float64(c) / elapsed
					remaining := int(float64(pathCount-int(c)) / rate)
					rm, rs := remaining/60, remaining%60
					if rm > 99 { rm = 99; rs = 59 }
					mu.Unlock()
					if atomic.LoadInt32(&timedOut) == 1 {
						fmt.Fprintf(color.Output, "\n%s [%d/%d] %d%% | TIMEOUT | Found: %d | Errors: %d",
							color.CyanString("[*]"), c, pathCount, pct, f, e)
					} else {
						fmt.Fprintf(color.Output, "\n%s [%d/%d] %d%% | Found: %d | Errors: %d | Rate: %.0f/s | ETA: %dm%ds",
							color.CyanString("[*]"), c, pathCount, pct, f, e, rate, rm, rs)
					}
					lastProgress = time.Now()
				}
			case <-done:
				return
			}
		}
	}()

	for _, path := range config.Paths {
		if atomic.LoadInt32(&timedOut) == 1 {
			break
		}

		if ticker != nil {
			<-ticker.C
		}

		wg.Add(1)
		semaphore <- struct{}{}
		stats.TotalRequests++

		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			defer atomic.AddInt32(&completed, 1)

			res := scanPath(config, client, p, uaList)
			mu.Lock()
			if res != nil {
				if !seenPaths[res.Path] {
					seenPaths[res.Path] = true
					if config.SmartFilter {
						sizeKey := fmt.Sprintf("%d-%d", res.Status, res.Size)
						sizeFrequency[sizeKey]++
						if sizeFrequency[sizeKey] > 15 {
							mu.Unlock()
							return
						}
						if sizeFrequency[sizeKey] == 15 {
							fmt.Fprintf(color.Output, "\n%s High frequency (%s). Suppressing...\n",
								color.YellowString("[!]"), sizeKey)
						}
					}
					if !ShouldFilter(res, config) {
						results = append(results, *res)
						stats.Found++
						// Print result immediately
						if !config.Quiet {
							printSingleResult(res, config)
						}
					} else {
						stats.Filtered++
					}
				}
			} else {
				stats.Errors++
			}
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	close(done)
	stats.EndTime = time.Now()
	if !config.Quiet {
		fmt.Println()
	}
	return results, stats
}

func printSingleResult(res *DirResult, config *ScanConfig) {
	statusStr := fmt.Sprintf("%d", res.Status)
	var statusColored string
	switch {
	case res.Status >= 200 && res.Status < 300:
		statusColored = color.New(color.FgGreen).Add(color.Bold).Sprint(statusStr)
	case res.Status >= 300 && res.Status < 400:
		statusColored = color.New(color.FgYellow).Sprint(statusStr)
	case res.Status == 403:
		statusColored = color.New(color.FgBlue).Add(color.Bold).Sprint(statusStr)
	case res.Status == 401:
		statusColored = color.New(color.FgHiYellow).Add(color.Bold).Sprint(statusStr)
	case res.Status >= 400 && res.Status < 500:
		statusColored = color.New(color.FgHiYellow).Sprint(statusStr)
	case res.Status >= 500:
		statusColored = color.New(color.FgHiRed).Add(color.Bold).Sprint(statusStr)
	default:
		statusColored = color.New(color.FgWhite).Sprint(statusStr)
	}
	sizeStr := fmt.Sprintf("%7s", FormatSize(res.Size))
	redirectStr := ""
	if res.Redirect != "" {
		redirectStr = cHiBlack.Sprint(" -> " + res.Redirect)
	}
	titleStr := ""
	if res.Title != "" {
		titleStr = cHiBlack.Sprint(" /* " + res.Title + " */")
	}
	displayPath := "/" + strings.TrimPrefix(res.Path, "/")
	if config.FullURL {
		displayPath = buildURL(config.Target, displayPath)
	}
	// Print a newline first to move past any progress line, then print the result
	fmt.Fprintf(color.Output, "\n[%s] %s - %s - %s%s%s",
		cYellow.Sprint(time.Now().Format("15:04:05")),
		statusColored, sizeStr,
		cBlue.Sprint(displayPath), redirectStr, titleStr)
}

func scanPath(config *ScanConfig, client *http.Client, path string, uaList []string) *DirResult {
	fullURL := buildURL(config.Target, path)

	var resp *http.Response
	var err error
	var timeMs int64

	for retry := 0; retry <= config.Retries; retry++ {
		start := time.Now()

		req, err := http.NewRequest(config.Method, fullURL, nil)
		if err != nil {
			return nil
		}

		for k, v := range config.Headers {
			req.Header.Set(k, v)
		}

		if config.UserAgent != "" {
			req.Header.Set("User-Agent", config.UserAgent)
		} else if len(uaList) > 0 {
			ua := strings.TrimSpace(uaList[time.Now().UnixNano()%int64(len(uaList))])
			req.Header.Set("User-Agent", ua)
		}

		if config.Cookie != "" {
			req.Header.Set("Cookie", config.Cookie)
		}

		if config.Auth != "" && config.AuthType == "basic" {
			parts := strings.SplitN(config.Auth, ":", 2)
			if len(parts) == 2 {
				req.SetBasicAuth(parts[0], parts[1])
			}
		}

		resp, err = client.Do(req)
		timeMs = time.Since(start).Milliseconds()

		if err == nil {
			break
		}

		if retry < config.Retries {
			time.Sleep(time.Duration(500*(retry+1)) * time.Millisecond)
		}
	}

	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	finalStatus := resp.StatusCode
	redirectURL := ""
	if finalStatus >= 300 && finalStatus < 400 {
		redirectURL = resp.Header.Get("Location")
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	finalSize := int64(len(body))

	if finalStatus == 200 && finalSize == 0 {
		return nil
	}

	if finalStatus == 200 && config.SmartFilter {
		bodyLower := strings.ToLower(string(body))
		soft404Keywords := []string{
			"not found", "error 404", "page not found", "doesn't exist",
			"no results", "nothing found", "404 error", "page unavailable",
			"this page could not be found", "http 404", "not available",
			"content not found", "no such page", "404 not found",
			"the requested url was not found", "page does not exist",
		}
		for _, kw := range soft404Keywords {
			if strings.Contains(bodyLower, kw) {
				finalStatus = 404
				break
			}
		}
	}

	if config.ExcludeResponse != "" && config.ReferenceResponse != nil {
		if finalSize == config.ReferenceResponse.Size && finalStatus == config.ReferenceResponse.Status {
			return nil
		}
	}

	contentType := resp.Header.Get("Content-Type")
	title := extractTitle(string(body))
	words := countWords(string(body))
	lines := countLines(string(body))

	res := &DirResult{
		Path:        path,
		Status:      finalStatus,
		Size:        finalSize,
		ContentType: contentType,
		Redirect:    redirectURL,
		Title:       title,
		Words:       words,
		Lines:       lines,
		TimeMs:      timeMs,
	}

	if ShouldFilter(res, config) {
		return nil
	}
	if ShouldFilterBody(body, res, config) {
		return nil
	}
	if ShouldFilterRedirect(res, config) {
		return nil
	}
	if ShouldFilterHeaders(headerMapToString(resp.Header), config) {
		return nil
	}

	return res
}

func buildURL(target, path string) string {
	target = strings.TrimSuffix(target, "/")
	path = strings.TrimPrefix(path, "/")
	return target + "/" + path
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := body[start : start+end]
	title = strings.TrimSpace(title)
	if len(title) > 100 {
		title = title[:100] + "..."
	}
	return title
}

func headerMapToString(headers http.Header) string {
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(v, ", "))
		sb.WriteString("\n")
	}
	return sb.String()
}

func findDBDir() string {
	// Try relative to CWD
	cwdCandidates := []string{
		"db",
		"../db",
		"../../db",
		"hackit/dir_finder/db",
		"dir_finder/db",
	}
	for _, p := range cwdCandidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	// Try relative to executable
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		exeCandidates := []string{
			filepath.Join(exeDir, "..", "db"),
			filepath.Join(exeDir, "..", "..", "db"),
			filepath.Join(exeDir, "..", "..", "..", "db"),
		}
		for _, p := range exeCandidates {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				return p
			}
		}
	}
	// Try HackIT project structure
	home, _ := os.Getwd()
	for i := 0; i < 4; i++ {
		p := filepath.Join(home, "hackit", "dir_finder", "db")
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
		home = filepath.Dir(home)
	}
	return "db"
}
