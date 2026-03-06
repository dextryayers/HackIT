package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

func printHeader(target string) {
	cGreen := color.New(color.FgGreen)
	cCyan := color.New(color.FgCyan)
	cYellow := color.New(color.FgYellow)
	cRed := color.New(color.FgRed)
	cWhite := color.New(color.FgWhite)

	fmt.Println(cCyan.Sprint(" ┌──────────────────────────────────────────────────────────┐"))
	fmt.Printf(" │ %-15s : %-38s │\n", cCyan.Sprint("SYSTEM STATUS"), "")
	fmt.Printf(" │ %-15s : %-38s │\n", cWhite.Sprint("User IP"), cGreen.Sprint("203.78.113.10"))
	fmt.Printf(" │ %-15s : %-38s │\n", cWhite.Sprint("Geo Location"), cGreen.Sprint("Malang, Indonesia"))
	fmt.Printf(" │ %-15s : %-38s │\n", cWhite.Sprint("Website"), cGreen.Sprint("haniipp.space"))
	fmt.Printf(" │ %-15s : %-38s │\n", cWhite.Sprint("Device Name"), cGreen.Sprint("Dextry"))
	fmt.Printf(" │ %-15s : %-38s │\n", cWhite.Sprint("Exploit Engine"), cGreen.Sprint("ONLINE"))
	fmt.Println(cCyan.Sprint(" └──────────────────────────────────────────────────────────┘"))
	fmt.Println()

	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("%s Session: 10984 | User: anonim | %s\n", cGreen.Sprint("[+]"), now)
	fmt.Printf("%s \"Exploiting the impossible.\"\n", cYellow.Sprint("[!]"))
	fmt.Println(cCyan.Sprint(" ────────────────────────────────────────────────────────────"))
	fmt.Printf("%s %s | %s\n", cRed.Sprint("▲"), cWhite.Sprint("AUTHORIZED USE ONLY"), cGreen.Sprint("HackIt v2.0"))
	fmt.Println()

	fmt.Println(cCyan.Sprint(" ╔══════════════════════════════════════════════════════════╗"))
	fmt.Printf(" ║ %-56s ║\n", cWhite.Sprint("DIR FINDER (EXPERT ENGINE)"))
	fmt.Println(cCyan.Sprint(" ╚══════════════════════════════════════════════════════════╝"))
	fmt.Printf(" %s %s\n", cWhite.Sprint(">"), cGreen.Sprint("MODULE LOADED: SUCCESS"))
	fmt.Println()

	fmt.Printf("%s Target: %s\n", cWhite.Sprint("[*]"), cCyan.Sprint(target))
	fmt.Printf("%s Engine: %s\n", cWhite.Sprint("[*]"), cGreen.Sprint("Rust (Async Core) + Go (Orchestrator)"))
	fmt.Printf("%s Threads: %d | Timeout: %ds\n", cWhite.Sprint("[*]"), 50, 10)
	fmt.Println()
	fmt.Printf("%s Starting Expert Scan...\n", cGreen.Sprint("[+]"))
	fmt.Println()
}

func main() {
	// 1. Parse CLI Flags
	config := parseFlags()

	if config.Target == "" {
		color.Red("[!] Target URL is required")
		os.Exit(1)
	}

	// 1. Banner
	printHeader(config.Target)

	// 2. Load Wordlist from db/ recursively
	// Try multiple possible paths for db/
	dbPaths := []string{"db", "../db", "../../db", "hackit/dir_finder/db"}
	var foundDb string
	for _, p := range dbPaths {
		if _, err := os.Stat(p); err == nil {
			foundDb = p
			break
		}
	}

	if foundDb == "" {
		// Try to find it relative to the executable
		exePath, _ := os.Executable()
		exeDir := filepath.Dir(exePath)
		p := filepath.Join(exeDir, "..", "db")
		if _, err := os.Stat(p); err == nil {
			foundDb = p
		}
	}

	if len(config.Paths) == 0 {
		paths, err := LoadAllPayloads(foundDb)
		if err == nil && len(paths) > 0 {
			config.Paths = paths
			color.Green("[+] Loaded %d total payloads from %s directory recursively", len(paths), foundDb)
		} else {
			// Fallback if db is empty or error
			config.Paths = []string{
				".env", ".git/config", "admin/", "login/", "config.php",
				"wp-config.php", ".htaccess", "robots.txt", "backup.sql",
			}
			color.Yellow("[!] No wordlists found in db/, using %d default paths", len(config.Paths))
		}
	}

	// 3. Load Smart Analysis if exists
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

	results := make(chan DirResult)
	var wg sync.WaitGroup
	var collectorWg sync.WaitGroup
	semaphore := make(chan struct{}, config.Threads)

	// 3.5. Wildcard Detection (Ensure "Real" status codes)
	wildcardStatus := 404
	wildcardSize := int64(-1)

	fmt.Printf("%s Detecting Wildcard / Soft-404 status...\n", color.CyanString("[*]"))
	tempClient := CreateClient(int(config.TimeoutMS), config.FollowRedirects)

	// Test 1: Random path
	randomPath := fmt.Sprintf("hackit_%d_random", time.Now().UnixNano())
	testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.Target, "/"), randomPath)
	if resp, err := tempClient.Get(testURL); err == nil {
		wildcardStatus = resp.StatusCode
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		wildcardSize = int64(len(body))
		resp.Body.Close()
		fmt.Printf("%s Wildcard detected (Random Path): Status %s, Size %d\n",
			color.YellowString("[!]"), color.RedString(fmt.Sprintf("%d", wildcardStatus)), wildcardSize)
	}

	// Test 2: Traversal wildcard
	traversalWildcardStatus := 400
	traversalWildcardSize := int64(-1)
	testURL = fmt.Sprintf("%s/../../hackit_traversal", strings.TrimSuffix(config.Target, "/"))
	if resp, err := tempClient.Get(testURL); err == nil {
		traversalWildcardStatus = resp.StatusCode
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		traversalWildcardSize = int64(len(body))
		resp.Body.Close()
		fmt.Printf("%s Wildcard detected (Traversal): Status %s, Size %d\n",
			color.YellowString("[!]"), color.RedString(fmt.Sprintf("%d", traversalWildcardStatus)), traversalWildcardSize)
	}

	// 3.6. WAF Detection (Expert Feature)
	wafDetected := "None"
	if config.DetectWAF {
		fmt.Printf("%s Performing WAF Fingerprinting...\n", color.CyanString("[*]"))
		wafPayloads := map[string]string{
			"Cloudflare":  "?id=' OR '1'='1",
			"Akamai":      "?path=../../etc/passwd",
			"ModSecurity": "?id=<script>alert(1)</script>",
			"AWS WAF":     "?query=UNION SELECT NULL,NULL,NULL--",
		}

		for _, payload := range wafPayloads {
			testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.Target, "/"), payload)
			if resp, err := tempClient.Get(testURL); err == nil {
				// WAF usually blocks with 403, 406, 429, or 501
				if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 501 {
					serverHeader := resp.Header.Get("Server")
					if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
						wafDetected = "Cloudflare"
					} else if strings.Contains(strings.ToLower(serverHeader), "akamai") {
						wafDetected = "Akamai"
					} else {
						wafDetected = fmt.Sprintf("Generic WAF (Blocked: %d)", resp.StatusCode)
					}
					fmt.Printf("%s WAF Detected: %s\n", color.RedString("[!]"), color.YellowString(wafDetected))
					resp.Body.Close()
					break
				}
				resp.Body.Close()
			}
		}
	}

	// 3.7. JS Spidering (Expert Feature)
	if config.ExtractJS {
		fmt.Printf("%s Extracting endpoints from JavaScript files...\n", color.CyanString("[*]"))

		// Find common JS files
		commonJS := []string{"main.js", "app.js", "index.js", "script.js", "bundle.js", "vendor.js"}
		for _, js := range commonJS {
			jsURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.Target, "/"), js)
			if resp, err := tempClient.Get(jsURL); err == nil && resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // Limit 2MB
				resp.Body.Close()

				// Very basic regex-like logic to find paths starting with /
				// e.g. "/api/v1/user" or "endpoint: '/admin'"
				content := string(body)
				words := strings.FieldsFunc(content, func(r rune) bool {
					return r == '"' || r == '\'' || r == ' ' || r == '\n' || r == '\t'
				})

				count := 0
				for _, w := range words {
					if strings.HasPrefix(w, "/") && len(w) > 2 && !strings.ContainsAny(w, "<>{};()[]") {
						config.Paths = append(config.Paths, strings.TrimPrefix(w, "/"))
						count++
					}
				}
				if count > 0 {
					fmt.Printf("%s Found %d endpoints in %s\n", color.GreenString("[+]"), count, js)
				}
			}
		}
	}

	// 3.8. Backup Detection (Expert Feature)
	if config.DetectBackup {
		fmt.Printf("%s Adding backup & config pattern detection...\n", color.CyanString("[*]"))
		backupExts := []string{".bak", ".old", ".tmp", ".zip", ".tar.gz", ".sql", ".conf"}
		newPaths := []string{}
		for _, p := range config.Paths {
			// Only add for files, not directories
			if !strings.HasSuffix(p, "/") {
				for _, ext := range backupExts {
					newPaths = append(newPaths, p+ext)
				}
			}
		}
		config.Paths = append(config.Paths, newPaths...)
		fmt.Printf("%s Added %d backup patterns to scan queue\n", color.GreenString("[+]"), len(newPaths))
	}

	// 4. Result collector (Expert Style)
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for res := range results {
			// Cross-Check: Skip if it matches wildcard profile (optional, maybe just highlight?)
			// For now, let's just show everything as requested by user, but with correct colors

			timestamp := time.Now().Format("15:04:05")
			statusStr := fmt.Sprintf("%d", res.Status)

			var statusColored string
			switch {
			case res.Status >= 200 && res.Status < 300:
				statusColored = color.New(color.FgGreen).Add(color.Bold).Sprint(statusStr)
			case res.Status >= 300 && res.Status < 400:
				statusColored = color.New(color.FgYellow).Sprint(statusStr)
			case res.Status == 401 || res.Status == 403:
				statusColored = color.New(color.FgMagenta).Add(color.Bold).Sprint(statusStr)
			case res.Status == 404:
				statusColored = color.New(color.FgRed).Sprint(statusStr)
			case res.Status == 400:
				statusColored = color.New(color.FgHiBlack).Sprint(statusStr) // Gray for 400
			case res.Status >= 500:
				statusColored = color.New(color.FgBlue).Sprint(statusStr)
			default:
				statusColored = color.New(color.FgWhite).Sprint(statusStr)
			}

			sizeStr := fmt.Sprintf("%7s", FormatSize(int64(res.Size)))

			// Format: [15:04:05] 200 -    178B - /admin
			fmt.Printf("[%s] %s - %s - %s\n",
				color.WhiteString(timestamp),
				statusColored,
				color.WhiteString(sizeStr),
				color.CyanString("/"+strings.TrimPrefix(res.Path, "/")),
			)
		}
	}()

	// 5. Engine Creation
	client := CreateClient(int(config.TimeoutMS), config.FollowRedirects)

	// Rate Limiter
	var ticker *time.Ticker
	if config.RateLimit != nil && *config.RateLimit > 0 {
		interval := time.Duration(float64(time.Second) / *config.RateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	// Load User Agents once
	var uaList []string
	uaPath := filepath.Join(foundDb, "user-agents.txt")
	if content, err := os.ReadFile(uaPath); err == nil {
		uaList = strings.Split(string(content), "\n")
	}

	// 6. Main scan loop
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

			// Strong Anonymity: Rotate User-Agent from db
			ua := "HackIt-Expert-Scanner/v2.0"
			if len(uaList) > 0 {
				ua = strings.TrimSpace(uaList[time.Now().UnixNano()%int64(len(uaList))])
			}
			req.Header.Set("User-Agent", ua)

			// 6. Real-time Cross Check (Double verification for accuracy)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			finalStatus := resp.StatusCode
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Read up to 1MB
			finalSize := int64(len(body))

			// Check for Soft 404 (keywords in body if status is 200)
			if finalStatus == 200 {
				bodyLower := strings.ToLower(string(body))
				soft404Keywords := []string{"not found", "error 404", "page not found", "doesn't exist"}
				for _, kw := range soft404Keywords {
					if strings.Contains(bodyLower, kw) {
						finalStatus = 404 // Mark as 404
						break
					}
				}
			}

			// Cross Check against Wildcards (Normal and Traversal)
			isWildcard := (finalStatus == wildcardStatus && finalSize == wildcardSize) ||
				(strings.Contains(p, "..") && finalStatus == traversalWildcardStatus && finalSize == traversalWildcardSize)

			if isWildcard {
				return
			}

			results <- DirResult{
				Path:   p,
				Status: finalStatus,
				Size:   uint64(finalSize),
			}
		}(path)
	}

	wg.Wait()
	close(results)
	collectorWg.Wait()

	// 5. Final Report
	color.White("\n[*] HackIt Scan Complete.")
}
