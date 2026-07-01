package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	cMagenta = color.New(color.FgMagenta).Add(color.Bold)
	cCyan    = color.New(color.FgCyan)
	cYellow  = color.New(color.FgYellow)
	cWhite   = color.New(color.FgWhite)
	cBlue    = color.New(color.FgBlue)
	cRed     = color.New(color.FgRed)
	cGreen   = color.New(color.FgGreen).Add(color.Bold)
	cHiBlack = color.New(color.FgHiBlack)
)

func main() {
	config := parseFlags()

	if config.Target == "" && config.URLsFile == "" {
		fmt.Println(cRed.Sprint("[!] Target URL (-u) is required"))
		os.Exit(1)
	}

	if config.NoColor {
		color.NoColor = true
	}

	if !config.Quiet {
		printHeader(config)
	}

	if config.Target != "" {
		orchestrate(config)
	}
}

func printHeader(config *ScanConfig) {
	fmt.Println(cMagenta.Sprint(`
    ____  _      _______           __
   / __ \(_)____/ ____(_)___  ____/ /__  _____
  / / / / / ___/ /_  / / __ \/ __  / _ \/ ___/
 / /_/ / / /  / __/ / / / / / /_/ /  __/ /
/_____/_/_/  /_/   /_/_/ /_/\__,_/\___/_/      v3.0.0
`))

	extsStr := "None"
	if len(config.Extensions) > 0 {
		extsStr = strings.Join(config.Extensions, ", ")
	}
	fmt.Printf("%s %s | %s %s | %s %d | %s %s\n",
		cYellow.Add(color.Bold).Sprint("Extensions:"), cCyan.Sprint(extsStr),
		cYellow.Add(color.Bold).Sprint("HTTP Method:"), cCyan.Sprint(config.Method),
		cYellow.Add(color.Bold).Sprint("Threads:"), config.Threads,
		cYellow.Add(color.Bold).Sprint("Wordlist:"), cCyan.Sprint(formatWordlistInfo(config)),
	)

	modes := []string{}
	if config.Recursive {
		modes = append(modes, "Recursive")
	}
	if config.Crawl {
		modes = append(modes, "Crawl")
	}
	if config.DetectWAF {
		modes = append(modes, "WAF Detect")
	}
	if config.ExtractJS {
		modes = append(modes, "JS Extract")
	}
	if len(modes) > 0 {
		fmt.Printf("%s %s\n", cYellow.Add(color.Bold).Sprint("Modes:"), cCyan.Sprint(strings.Join(modes, ", ")))
	}

	fmt.Printf("%s %s\n", cYellow.Add(color.Bold).Sprint("Target:"), cBlue.Sprint(config.Target))
	fmt.Println()
}

func checkConnectivity(target string, client *http.Client) bool {
	// First try GET with a short timeout
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

func formatWordlistInfo(config *ScanConfig) string {
	if len(config.WordlistCategories) > 0 {
		return "cat:" + strings.Join(config.WordlistCategories, ",")
	}
	if len(config.Wordlists) > 0 {
		return strings.Join(config.Wordlists, ",")
	}
	return "auto (db/)"
}

func orchestrate(config *ScanConfig) {
	startTime := time.Now()
	foundDB := findDBDir()

	// Phase 0: Load wordlist
	if !config.Quiet {
		fmt.Printf("%s Loading wordlists...\n", cCyan.Sprint("[*]"))
	}

	if len(config.Paths) == 0 {
		var paths []string
		var err error

		if len(config.WordlistCategories) > 0 {
			paths, err = LoadWordlistByCategory(foundDB, config.WordlistCategories)
		} else if len(config.Wordlists) > 0 {
			for _, wl := range config.Wordlists {
				p, e := LoadWordlist(wl)
				if e == nil {
					paths = append(paths, p...)
				}
			}
		} else {
			paths, err = LoadAllPayloads(foundDB)
		}

		if err == nil && len(paths) > 0 {
			config.Paths = paths
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s Loaded %d payloads from %s\n",
					cGreen.Sprint("[+]"), len(paths), foundDB)
			}
		} else {
			config.Paths = []string{
				".env", ".git/config", "admin", "login", "wp-admin",
				"backup", "config", "robots.txt", "sitemap.xml",
			}
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s Using %d default paths\n",
					cYellow.Sprint("[!]"), len(config.Paths))
			}
		}
	}

	// Process paths (extensions, prefixes, suffixes, case)
	if len(config.Extensions) > 0 || len(config.Prefixes) > 0 || len(config.Suffixes) > 0 ||
		config.Uppercase || config.Lowercase || config.Capital {
		config.Paths = ProcessPaths(config.Paths, config)
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Processed to %d paths (ext/prefix/suffix/case)\n",
				cGreen.Sprint("[+]"), len(config.Paths))
		}
	}

	// Load blacklists
	config.Blacklists = LoadBlacklists(foundDB)
	if config.Blacklists != nil && !config.Quiet {
		fmt.Fprintf(color.Output, "%s Loaded %d status blacklists\n",
			cGreen.Sprint("[+]"), len(config.Blacklists))
	}

	// Load user agents
	var uaList []string
	if config.RandomAgent {
		uaList = LoadUserAgents(foundDB)
		if uaList != nil && !config.Quiet {
			fmt.Fprintf(color.Output, "%s Loaded %d User-Agents for rotation\n",
				cGreen.Sprint("[+]"), len(uaList))
		}
	}

	client := CreateClient(config)

	// Phase 1: Connectivity check
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Checking target connectivity...\n", cCyan.Sprint("[*]"))
	}
	connOK := checkConnectivity(config.Target, client)
	if !connOK {
		fmt.Fprintf(color.Output, "\n%s Cannot reach target: %s\n", cRed.Sprint("[!]"), cYellow.Sprint(config.Target))
		fmt.Fprintf(color.Output, "%s Check the URL, network, or use a proxy.\n", cYellow.Sprint("[*]"))
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Starting scan anyway (might get errors)...\n", cYellow.Sprint("[!]"))
		}
		if config.ExitOnError {
			os.Exit(1)
		}
	}
	// Phase 2: Pre-scan detection
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Pre-scan detection phase...\n", cCyan.Sprint("[*]"))
	}

	// Wildcard detection
	wildcardStatus, wildcardSize := config.WildcardStatus, config.WildcardSize
	if wildcardStatus == 0 || config.AutoCalibration {
		s, sz := DetectWildcard(config.Target, client)
		wildcardStatus = s
		wildcardSize = sz
		config.WildcardStatus = s
		config.WildcardSize = sz
		wildcardInfo := ""
		if wildcardSize < 0 {
			wildcardInfo = " (request failed - run without filter: -x '')"
		}
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Wildcard: Status=%d, Size=%d%s\n",
				cYellow.Sprint("[!]"), wildcardStatus, wildcardSize, wildcardInfo)
		}
	}

	// WAF detection
	if config.DetectWAF {
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Detecting WAF...\n", cCyan.Sprint("[*]"))
		}
		waf := DetectWAF(config.Target, client)
		config.DetectedWAF = waf
		if waf != "" {
			fmt.Fprintf(color.Output, "%s WAF Detected: %s\n", cRed.Sprint("[!]"), cYellow.Sprint(waf))
		} else {
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s No WAF detected\n", cGreen.Sprint("[+]"))
			}
		}
	}

	// Load smart analysis
	if _, err := os.Stat(filepath.Join(filepath.Dir(foundDB), "smart_analysis.json")); err == nil {
		endpoints, info := LoadSmartAnalysis(filepath.Join(filepath.Dir(foundDB), "smart_analysis.json"))
		if len(endpoints) > 0 {
			config.Paths = append(config.Paths, endpoints...)
			config.Paths = Deduplicate(config.Paths)
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s Injected %d endpoints from Smart Analysis\n",
					cGreen.Sprint("[+]"), len(endpoints))
			}
		}
		if info != "" && config.DetectedWAF == "" {
			config.DetectedWAF = info
		}
	}

	// JS spidering
	if config.ExtractJS {
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Extracting endpoints from JavaScript...\n", cCyan.Sprint("[*]"))
		}
		jsEndpoints := ExtractJSEndpoints(config.Target, client)
		if len(jsEndpoints) > 0 {
			config.Paths = append(config.Paths, jsEndpoints...)
			config.Paths = Deduplicate(config.Paths)
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s Found %d JS endpoints\n", cGreen.Sprint("[+]"), len(jsEndpoints))
			}
		}
	}

	// Backup detection
	if config.DetectBackup {
		backupExts := []string{".bak", ".old", ".tmp", ".zip", ".tar.gz", ".sql", ".conf", ".save", ".backup"}
		backupPaths := make([]string, 0)
		for _, p := range config.Paths {
			if !strings.HasSuffix(p, "/") {
				for _, ext := range backupExts {
					backupPaths = append(backupPaths, p+ext)
				}
			}
		}
		config.Paths = append(config.Paths, backupPaths...)
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Added %d backup patterns\n", cGreen.Sprint("[+]"), len(backupPaths))
		}
	}

	// Exclude response reference
	if config.ExcludeResponse != "" {
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Loading reference response from %s...\n", cCyan.Sprint("[*]"), config.ExcludeResponse)
		}
		refURL := buildURL(config.Target, config.ExcludeResponse)
		resp, err := client.Get(refURL)
		if err == nil && resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			config.ReferenceResponse = &DirResult{
				Status: resp.StatusCode,
				Size:   int64(len(body)),
			}
			resp.Body.Close()
		}
	}

	// Subdirs handling
	if len(config.Subdirs) > 0 {
		expanded := make([]string, 0)
		for _, sd := range config.Subdirs {
			sd = strings.Trim(sd, "/")
			if sd != "" {
				for _, p := range config.Paths {
					expanded = append(expanded, sd+"/"+p)
				}
			}
		}
		config.Paths = append(config.Paths, expanded...)
		config.Paths = Deduplicate(config.Paths)
	}

	// Phase 2: Main scan
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Starting scan with %d paths (%d threads)...\n",
			cCyan.Sprint("[*]"), len(config.Paths), config.Threads)
		fmt.Println()
	}

	results, stats := RunScan(config)

	// Phase 3: Recursive scan
	var recursiveResults []DirResult
	var recursiveStats *ScanStats

	if config.Recursive || config.DeepRecursive || config.ForceRecursive {
		if !config.Quiet {
			fmt.Fprintf(color.Output, "\n%s Starting recursive scan (depth: %d)...\n",
				cCyan.Sprint("[*]"), config.MaxDepth)
		}
		recursiveResults, recursiveStats = RunRecursiveScan(config, results)
	}

	// Phase 4: Output
	fmt.Println()
	printResults(config, results, recursiveResults, stats, recursiveStats, startTime)

	// Save session
	if config.SaveSession {
		saveSessionData(config, results, stats)
	}

	// Save report
	if config.OutputFile != "" {
		saveReport(config, results, recursiveResults, stats, recursiveStats)
	}

	elapsed := time.Since(startTime).Round(time.Second)
	if !config.Quiet {
		fmt.Fprintf(color.Output, "\n%s Scan completed in %s\n", cGreen.Sprint("[+]"), elapsed)
	}
}

func printResults(config *ScanConfig, results, recursiveResults []DirResult, stats *ScanStats, recursiveStats *ScanStats, startTime time.Time) {
	allResults := results
	if recursiveResults != nil {
		allResults = append(allResults, recursiveResults...)
	}

	if len(allResults) == 0 {
		fmt.Fprintf(color.Output, "%s No results found\n", cYellow.Sprint("[!]"))
		return
	}

	fmt.Fprintf(color.Output, "%s Results (%d found):\n\n", cGreen.Sprint("[+]"), len(allResults))

	for _, res := range allResults {
		timestamp := time.Now().Format("15:04:05")
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

		displayPath := res.Path
		if config.FullURL {
			displayPath = buildURL(config.Target, displayPath)
		}

		fmt.Fprintf(color.Output, "[%s] %s - %s - %s%s%s\n",
			cYellow.Sprint(timestamp),
			statusColored,
			sizeStr,
			cBlue.Sprint("/"+strings.TrimPrefix(displayPath, "/")),
			redirectStr,
			titleStr,
		)
	}

	// Stats - leader to separate from progress lines
	fmt.Println()
	fmt.Println()
	if stats != nil {
		fmt.Fprintf(color.Output, "%s Requests: %d | Found: %d | Filtered: %d | Errors: %d\n",
			cCyan.Sprint("[*]"),
			stats.TotalRequests, stats.Found, stats.Filtered, stats.Errors)
	}
	if recursiveStats != nil {
		fmt.Fprintf(color.Output, "%s Recursive requests: %d | Found: %d | Errors: %d\n",
			cCyan.Sprint("[*]"),
			recursiveStats.TotalRequests, recursiveStats.Found, recursiveStats.Errors)
	}
}

func saveSessionData(config *ScanConfig, results []DirResult, stats *ScanStats) {
	session := SessionData{
		Target:    config.Target,
		Remaining: config.Paths,
		Found:     results,
		Stats:     *stats,
		Timestamp: time.Now(),
	}

	sessionDir := "sessions"
	os.MkdirAll(sessionDir, 0755)
	sessionFile := filepath.Join(sessionDir, fmt.Sprintf("session_%d.json", time.Now().Unix()))

	data, _ := json.MarshalIndent(session, "", "  ")
	os.WriteFile(sessionFile, data, 0644)

	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Session saved to %s\n", cGreen.Sprint("[+]"), sessionFile)
	}
}

func saveReport(config *ScanConfig, results, recursiveResults []DirResult, stats, recursiveStats *ScanStats) {
	allResults := results
	if recursiveResults != nil {
		allResults = append(allResults, recursiveResults...)
	}

	for _, format := range config.OutputFormats {
		format = strings.TrimSpace(strings.ToLower(format))
		var data []byte
		var err error
		ext := "txt"

		switch format {
		case "json":
			ext = "json"
			report := map[string]interface{}{
				"target":        config.Target,
				"timestamp":     time.Now(),
				"total_requests": stats.TotalRequests,
				"found":         len(allResults),
				"results":       allResults,
				"waf":           config.DetectedWAF,
			}
			data, err = json.MarshalIndent(report, "", "  ")
		case "simple":
			ext = "txt"
			var sb strings.Builder
			for _, r := range allResults {
				sb.WriteString(fmt.Sprintf("%s %d %s\n", r.Path, r.Status, FormatSize(r.Size)))
			}
			data = []byte(sb.String())
		case "plain":
			ext = "txt"
			var sb strings.Builder
			for _, r := range allResults {
				sb.WriteString(fmt.Sprintf("%s/%s\n", strings.TrimRight(config.Target, "/"), strings.TrimLeft(r.Path, "/")))
			}
			data = []byte(sb.String())
		case "csv":
			ext = "csv"
			var sb strings.Builder
			sb.WriteString("path,status,size,redirect,title\n")
			for _, r := range allResults {
				sb.WriteString(fmt.Sprintf("%s,%d,%d,%s,%s\n", r.Path, r.Status, r.Size, r.Redirect, r.Title))
			}
			data = []byte(sb.String())
		case "md":
			ext = "md"
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("# Dir Finder Report - %s\n\n", config.Target))
			sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("**Found:** %d URLs\n\n", len(allResults)))
			sb.WriteString("| Path | Status | Size | Redirect | Title |\n")
			sb.WriteString("|------|--------|------|----------|-------|\n")
			for _, r := range allResults {
				sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s |\n", r.Path, r.Status, FormatSize(r.Size), r.Redirect, r.Title))
			}
			data = []byte(sb.String())
		default:
			if !config.Quiet {
				fmt.Fprintf(color.Output, "%s Unknown format: %s\n", cYellow.Sprint("[!]"), format)
			}
			continue
		}

		if err != nil {
			continue
		}

		outputPath := config.OutputFile
		if !strings.HasSuffix(outputPath, "."+ext) {
			outputPath = outputPath + "." + ext
		}
		os.WriteFile(outputPath, data, 0644)
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Report saved: %s\n", cGreen.Sprint("[+]"), outputPath)
		}
	}
}
