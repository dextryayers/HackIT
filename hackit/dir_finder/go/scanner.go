package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)



func RunScan(config *ScanConfig) ([]DirResult, *ScanStats) {
	stats := &ScanStats{StartTime: time.Now()}
	outputEngine.SetNoColor(config.NoColor)

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

	if config.SmartFilter {
		for i := 0; i < 5; i++ {
			_ = compareEngine.AddResponse(&DirResult{
				Path: fmt.Sprintf("__wildcard_probe_%d__", i),
				Status: config.WildcardStatus,
				Size: config.WildcardSize,
				BodyHash: "wildcard",
			})
		}
	}

	results := make([]DirResult, 0)
	fpFrequency := make(map[string]int)
	seenPaths := make(map[string]bool)
	pathCount := len(config.Paths)

	adaptiveRate := NewAdaptiveRateController(config)
	recursionPlan := BuildRecursionPlan(config)

	// Max-time timeout
	var timedOut int32
	if config.MaxTime > 0 {
		time.AfterFunc(time.Duration(config.MaxTime)*time.Second, func() {
			atomic.StoreInt32(&timedOut, 1)
		})
	}

	// Live progress — single line at bottom using \r
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
					elapsed := time.Since(stats.StartTime).Seconds()
					rate := float64(c) / elapsed
					remaining := int(float64(pathCount-int(c)) / rate)
					rm, rs := remaining/60, remaining%60
					if rm > 99 { rm = 99; rs = 59 }
					if atomic.LoadInt32(&timedOut) == 1 {
						outputEngine.PrintProgress(int(c), pathCount, stats.Found, stats.Errors, rate, rm, rs, true)
					} else {
						outputEngine.PrintProgress(int(c), pathCount, stats.Found, stats.Errors, rate, rm, rs, false)
					}
					lastProgress = time.Now()
				}
			case <-done:
				return
			}
		}
	}()

	prioQueue := NewPrioritizedQueue(config.Paths)

	for {
		if atomic.LoadInt32(&timedOut) == 1 {
			break
		}

		path := prioQueue.Next()
		if path == "" {
			break
		}

		if ticker != nil {
			<-ticker.C
		}

		if config.Scheduler != nil {
			config.Scheduler.AdjustIfNeeded()
			if config.Scheduler.ErrorRate() > 0.1 {
				time.Sleep(time.Duration(150+time.Now().UnixNano()%150) * time.Millisecond)
			}
		}

		wg.Add(1)
		semaphore <- struct{}{}
		stats.TotalRequests++

		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			defer atomic.AddInt32(&completed, 1)

			isErr := true
			scanStart := time.Now()
			sr := scanPath(config, client, p, uaList)
			scanElapsed := time.Since(scanStart)
			if sr != nil && sr.res != nil {
				isErr = false
			}
			if config.Scheduler != nil {
				defer func() {
					config.Scheduler.RecordRequest(isErr)
				}()
			}
			adaptiveRate.RecordResult(isErr)

			mu.Lock()
			if sr != nil && sr.res != nil {
				if sr.filtered {
					stats.Filtered++
					mu.Unlock()
					return
				}
				if !seenPaths[sr.res.Path] {
					seenPaths[sr.res.Path] = true

					// Classify response (login, API)
					ClassifyResponse(sr.res, sr.body)

					// SmartFilter: false-positive suppression
					if SmartFilterResult(sr.res, config, fpFrequency) {
						stats.Filtered++
						mu.Unlock()
						return
					}

					// Advanced filtering via filter_engine + match_engine + text_engine
					filterRes := FilterResponseAdvanced(sr.res, config)
					textRes := ExcludeByText(config.ExcludeText, sr.body)
					regexRes := ExcludeByRegex(config.ExcludeRegex, sr.body)
					redirectRes := ExcludeByRedirect(config.ExcludeRedirect, sr.res.Redirect)
					refRes := ExcludeByReference(sr.res, config.ReferenceResponse)
					matchRes := MatchResponseAdvanced(sr.res, sr.body, sr.header, config)

					// Legacy filter integration
					isRedirect := sr.res.Status >= 300 && sr.res.Status < 400
					legacyFiltered := ShouldFilter(sr.res, config) ||
						ShouldFilterBody([]byte(sr.body), sr.res, config) ||
						ShouldFilterRedirect(sr.res, config) ||
						ShouldFilterHeaders(sr.header, config)
					if isRedirect && legacyFiltered && sr.res.Status == config.WildcardStatus && sr.res.Size == config.WildcardSize {
						legacyFiltered = false
					}

					filtered := legacyFiltered || filterRes.Filtered || textRes.Filtered ||
						regexRes.Filtered || redirectRes.Filtered || refRes.Filtered ||
						matchRes.Filtered

					if !config.Quiet {
						printAttempt(sr.res, config, filtered)
					}
					if !filtered {
						results = append(results, *sr.res)
						stats.Found++
					} else {
						stats.Filtered++
					}

					// Recursion check
					if ShouldRecurse(sr.res, recursionPlan) {
						recursionPlan.Level++
					}
				}
			} else {
				stats.Errors++
				isErr = true
				if !config.Quiet {
					errTag := "ERR"
					if scanElapsed >= 9*time.Second {
						errTag = "TIMEOUT"
					} else if scanElapsed >= 3*time.Second {
						errTag = "SLOW"
					}
					fmt.Fprintf(color.Output, "%s[%s] %s %s\n",
						ANSI_CLEAR_LINE,
						time.Now().Format("15:04:05"),
						color.RedString(errTag),
						"/"+strings.TrimPrefix(p, "/"))
				}
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
		statusColored = cGreen.Sprint(statusStr)
	case res.Status >= 300 && res.Status < 400:
		statusColored = cYellow.Sprint(statusStr)
	case res.Status >= 400 && res.Status < 500:
		statusColored = cOrange.Sprint(statusStr)
	case res.Status >= 500:
		statusColored = color.New(color.FgRed).Add(color.Bold).Sprint(statusStr)
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
	fmt.Fprintf(color.Output, "%s[%s] %s %7s %s%s%s\n",
		ANSI_CLEAR_LINE,
		cYellow.Sprint(time.Now().Format("15:04:05")),
		statusColored, sizeStr,
		cBlue.Sprint(displayPath), redirectStr, titleStr)
}

func printAttempt(res *DirResult, config *ScanConfig, filtered bool) {
	statusStr := fmt.Sprintf("%d", res.Status)
	var statusColored string
	switch {
	case res.Status >= 200 && res.Status < 300:
		statusColored = cGreen.Sprint(statusStr)
	case res.Status >= 300 && res.Status < 400:
		statusColored = cYellow.Sprint(statusStr)
	case res.Status >= 400 && res.Status < 500:
		statusColored = cOrange.Sprint(statusStr)
	case res.Status >= 500:
		statusColored = color.New(color.FgRed).Add(color.Bold).Sprint(statusStr)
	default:
		statusColored = color.New(color.FgWhite).Sprint(statusStr)
	}
	mark := " "
	if filtered {
		mark = color.HiBlackString("-")
	}
	sizeStr := FormatSize(res.Size)
	displayPath := "/" + strings.TrimPrefix(res.Path, "/")
	if config.FullURL {
		displayPath = buildURL(config.Target, displayPath)
	}
	redirectStr := ""
	if res.Redirect != "" {
		redirectStr = color.HiBlackString(" -> " + res.Redirect)
	}
	titleStr := ""
	if res.Title != "" {
		titleStr = color.HiBlackString(" /* " + res.Title + " */")
	}
	fmt.Fprintf(color.Output, "%s[%s] %s%s %7s %s%s%s\n",
		ANSI_CLEAR_LINE,
		time.Now().Format("15:04:05"),
		mark, statusColored, sizeStr, cCyan.Sprint(displayPath),
		redirectStr, titleStr)
}

var skipPathRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f]`)

func shortContentType(ct string) string {
	switch {
	case strings.Contains(ct, "text/html"):
		return "html"
	case strings.Contains(ct, "application/json"):
		return "json"
	case strings.Contains(ct, "application/xml"), strings.Contains(ct, "text/xml"):
		return "xml"
	case strings.Contains(ct, "text/plain"):
		return "txt"
	case strings.Contains(ct, "text/css"):
		return "css"
	case strings.Contains(ct, "application/javascript"), strings.Contains(ct, "text/javascript"):
		return "js"
	case strings.Contains(ct, "image/"):
		return "img"
	case strings.Contains(ct, "application/pdf"):
		return "pdf"
	case strings.Contains(ct, "application/zip"), strings.Contains(ct, "application/x-gzip"):
		return "zip"
	case strings.Contains(ct, "application/octet-stream"):
		return "bin"
	case ct != "":
		return "?"
	default:
		return ""
	}
}

type scanResult struct {
	res      *DirResult
	body     string
	header   string
	filtered bool
}

func scanPath(config *ScanConfig, client *http.Client, path string, uaList []string) *scanResult {
	if skipPathRe.MatchString(path) {
		return nil
	}
	fullURL := buildURL(config.Target, path)
	if len(fullURL) > 4096 {
		return nil
	}

	// Pre-compute body string (doesn't change per retry)
	var bodyStrInit string
	if config.Data != "" {
		bodyStrInit = config.Data
		if config.GraphQL {
			bodyStrInit = `{"query":"` + strings.ReplaceAll(bodyStrInit, `"`, `\"`) + `"}`
		}
	} else if config.DataFile != "" {
		if dataBytes, err := os.ReadFile(config.DataFile); err == nil {
			bodyStrInit = string(dataBytes)
			if config.GraphQL {
				bodyStrInit = `{"query":"` + strings.ReplaceAll(strings.ReplaceAll(bodyStrInit, `\`, `\\`), `"`, `\"`) + `"}`
			}
		}
	} else if config.JSONBody {
		bodyStrInit = "{}"
	}

	// Pre-hash UA index for consistent selection
	uaIdx := 0
	if len(uaList) > 0 {
		uaIdx = int(hashPath(path) % uint64(len(uaList)))
	}

	var resp *http.Response
	var err error
	var timeMs int64

	headerSetup := func(req *http.Request) {
		for k, v := range config.Headers {
			req.Header.Set(k, v)
		}
		if config.JSONBody && config.Data == "" {
			req.Header.Set("Content-Type", "application/json")
		} else if config.GraphQL {
			req.Header.Set("Content-Type", "application/json")
		}
		if config.APIMode && req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json, text/plain, */*")
		}
		if config.UserAgent != "" {
			req.Header.Set("User-Agent", config.UserAgent)
		} else if len(uaList) > 0 {
			req.Header.Set("User-Agent", strings.TrimSpace(uaList[uaIdx]))
		}
		if config.Cookie != "" {
			req.Header.Set("Cookie", config.Cookie)
		}
		if config.Auth != "" {
			switch config.AuthType {
			case "basic":
				if parts := strings.SplitN(config.Auth, ":", 2); len(parts) == 2 {
					req.SetBasicAuth(parts[0], parts[1])
				}
			case "bearer", "jwt":
				req.Header.Set("Authorization", "Bearer "+config.Auth)
			case "digest":
				req.Header.Set("Authorization", "Digest "+config.Auth)
			case "ntlm":
				req.Header.Set("Authorization", "NTLM "+config.Auth)
			}
		}
	}

	for retry := 0; retry <= config.Retries; retry++ {
		start := time.Now()
		var bodyReader io.Reader
		if bodyStrInit != "" {
			bodyReader = strings.NewReader(bodyStrInit)
		}
		req, err := http.NewRequest(config.Method, fullURL, bodyReader)
		if err != nil {
			return nil
		}
		headerSetup(req)

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

	finalStatus := resp.StatusCode
	redirectURL := ""
	if finalStatus >= 300 && finalStatus < 400 {
		redirectURL = resp.Header.Get("Location")
		if redirectURL != "" && !strings.HasPrefix(redirectURL, "http") {
			baseURL := config.Target
			if strings.HasPrefix(redirectURL, "/") {
				redirectURL = strings.TrimRight(baseURL, "/") + redirectURL
			} else {
				redirectURL = strings.TrimRight(baseURL, "/") + "/" + redirectURL
			}
		}
		if redirectURL != "" {
			followReq, _ := http.NewRequest("GET", redirectURL, nil)
			if followReq != nil {
				if config.UserAgent != "" {
					followReq.Header.Set("User-Agent", config.UserAgent)
				} else if len(uaList) > 0 {
					followReq.Header.Set("User-Agent", strings.TrimSpace(uaList[uaIdx]))
				}
				if followResp, followErr := client.Do(followReq); followErr == nil && followResp != nil {
					resp.Body.Close()
					resp = followResp
					finalStatus = followResp.StatusCode
				}
			}
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	finalSize := int64(len(body))

	if finalSize == 0 && (finalStatus == 200 || finalStatus == 301 || finalStatus == 302) {
		return nil
	}

	bodyStr := string(body)

	contentType := resp.Header.Get("Content-Type")
	title := extractTitle(bodyStr)
	words := countWords(bodyStr)
	lines := countLines(bodyStr)
	hdrStr := headerMapToString(resp.Header)
	bodyHash := fmt.Sprintf("%x", sha1.Sum(body))[:16]

	if config.SmartFilter && CheckSoft404(bodyStr, title) {
		return &scanResult{
			res: &DirResult{
				Path: path, Status: 404, Size: finalSize,
				ContentType: contentType, Title: title,
				Redirect: redirectURL, Words: words, Lines: lines,
				BodyHash: bodyHash, TimeMs: timeMs,
			},
			body:     bodyStr,
			header:   hdrStr,
			filtered: true,
		}
	}

	if config.ExcludeResponse != "" && config.ReferenceResponse != nil {
		if finalSize == config.ReferenceResponse.Size && finalStatus == config.ReferenceResponse.Status {
			return nil
		}
	}

	return &scanResult{
		res: &DirResult{
			Path: path, Status: finalStatus, Size: finalSize,
			ContentType: contentType, Redirect: redirectURL, Title: title,
			BodyHash: bodyHash, Words: words, Lines: lines, TimeMs: timeMs,
		},
		body:   bodyStr,
		header: hdrStr,
	}
}

func buildURL(target, path string) string {
	target = strings.TrimSuffix(target, "/")
	path = strings.TrimPrefix(path, "/")
	base, err := url.Parse(target)
	if err != nil {
		return target + "/" + path
	}
	// Preserve the raw path if it's already percent-encoded
	joined := base.JoinPath(path)
	if joined != nil {
		return joined.String()
	}
	return target + "/" + path
}

func extractTitle(body string) string {
	clean := body
	// Strip HTML comments
	for {
		idx := strings.Index(clean, "<!--")
		if idx == -1 {
			break
		}
		end := strings.Index(clean[idx:], "-->")
		if end == -1 {
			break
		}
		clean = clean[:idx] + clean[idx+end+3:]
	}
	lower := strings.ToLower(clean)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Skip past <title ... >  (handles attributes like <title data-react-helmet="true">)
	tagEnd := strings.Index(clean[start:], ">")
	if tagEnd == -1 {
		return ""
	}
	start += tagEnd + 1
	closeTag := strings.Index(lower[start:], "</title>")
	if closeTag == -1 {
		// No close tag, try <title>...</title> within the same line
		return ""
	}
	title := clean[start : start+closeTag]
	title = strings.TrimSpace(title)
	// Collapse whitespace
	title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")
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

func ParseRawRequest(filePath string) (*RawRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read raw file: %w", err)
	}
	text := string(data)
	lines := strings.SplitN(text, "\n", 2)
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid raw request: missing headers")
	}
	// Parse request line: METHOD PATH HTTP/1.1
	reqLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", reqLine)
	}
	method := parts[0]
	rawPath := parts[1]

	// Split headers and body
	rest := lines[1]
	headerBody := strings.SplitN(rest, "\n\n", 2)
	headerLines := strings.Split(strings.TrimSpace(headerBody[0]), "\n")

	headers := make(map[string]string)
	var host string
	var target string
	for _, h := range headerLines {
		h = strings.TrimSpace(h)
		if idx := strings.Index(h, ":"); idx > 0 {
			key := strings.TrimSpace(h[:idx])
			val := strings.TrimSpace(h[idx+1:])
			headers[key] = val
			if strings.EqualFold(key, "host") {
				host = val
			}
		}
	}

	var body string
	if len(headerBody) > 1 {
		body = strings.TrimSpace(headerBody[1])
	}

	// Determine scheme
	scheme := "https"
	if strings.HasPrefix(rawPath, "http") {
		parsed, err := url.Parse(rawPath)
		if err == nil {
			target = rawPath
			rawPath = parsed.Path
			if parsed.RawQuery != "" {
				rawPath += "?" + parsed.RawQuery
			}
		}
	} else {
		scheme = "https"
		if strings.HasPrefix(rawPath, "/") {
			target = scheme + "://" + host + rawPath
		} else {
			target = scheme + "://" + host + "/" + rawPath
		}
	}

	return &RawRequest{
		Method:  method,
		Path:    rawPath,
		Headers: headers,
		Body:    body,
		Target:  target,
	}, nil
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
