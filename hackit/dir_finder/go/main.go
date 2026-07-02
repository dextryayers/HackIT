package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	cOrange  = color.New(color.Attribute(38), color.Attribute(5), color.Attribute(208))
)

const (
	ANSI_RESET       = "\033[0m"
	ANSI_GREEN       = "\033[1;32m"
	ANSI_YELLOW      = "\033[33m"
	ANSI_ORANGE      = "\033[38;5;208m"
	ANSI_RED         = "\033[1;31m"
	ANSI_CYAN        = "\033[36m"
	ANSI_BLUE        = "\033[34m"
	ANSI_MAGENTA     = "\033[1;35m"
	ANSI_GRAY        = "\033[90m"
	ANSI_CLEAR_LINE  = "\033[2K\r"
)

func main() {
	config := parseFlags()
	color.NoColor = false

	if config.NoColor {
		color.NoColor = true
	}

	// Handle --raw: parse raw HTTP request file
	if config.RawFile != "" {
		rawReq, err := ParseRawRequest(config.RawFile)
		if err != nil {
			fmt.Fprintf(color.Output, "%s Cannot parse raw request: %v\n", cRed.Sprint("[!]"), err)
			os.Exit(1)
		}
		if config.Target == "" {
			config.Target = rawReq.Target
		}
		if config.Method == "GET" || config.Method == "" {
			config.Method = rawReq.Method
		}
		if config.Data == "" {
			config.Data = rawReq.Body
		}
		for k, v := range rawReq.Headers {
			if config.Headers == nil {
				config.Headers = make(map[string]string)
			}
			kLower := strings.ToLower(k)
			if kLower == "host" || kLower == "content-length" {
				continue
			}
			if _, exists := config.Headers[k]; !exists {
				config.Headers[k] = v
			}
		}
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Loaded raw request: %s %s\n",
				cGreen.Sprint("[+]"), rawReq.Method, rawReq.Path)
		}
	}

	// Handle --session / --session-id: resume from session
	var sessionResume *SessionData
	if config.SessionFile != "" {
		sessionResume, _ = LoadSession(config.SessionFile)
	} else if config.SessionID > 0 {
		sessions := ListSessions()
		for _, s := range sessions {
			var id int
			fmt.Sscanf(s, "session_%d.json", &id)
			if id == config.SessionID {
				sessionResume, _ = LoadSession(filepath.Join("sessions", s))
				break
			}
		}
		if sessionResume == nil {
			fmt.Fprintf(color.Output, "%s No session found with ID %d\n", cRed.Sprint("[!]"), config.SessionID)
			if len(sessions) > 0 {
				fmt.Fprintf(color.Output, "%s Available sessions:\n", cYellow.Sprint("[*]"))
				for _, s := range sessions {
					fmt.Fprintf(color.Output, "  %s\n", s)
				}
			}
			os.Exit(1)
		}
	}

	// Apply session restore
	if sessionResume != nil {
		config.Target = sessionResume.Target
		config.RestoredPaths = sessionResume.Remaining
		config.RestoredResults = sessionResume.Found
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Resumed session: %d remaining, %d found\n",
				cGreen.Sprint("[+]"), len(sessionResume.Remaining), len(config.RestoredResults))
		}
	}

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
/_____/_/_/  /_/   /_/_/ /_/\__,_/\___/_/      HackIT DirFInder V2.1
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

	// Session resume: use restored paths
	if len(config.RestoredPaths) > 0 {
		config.Paths = config.RestoredPaths
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Resuming scan with %d remaining paths\n",
				cGreen.Sprint("[+]"), len(config.Paths))
		}
	}

	// API mode presets
	if config.APIMode {
		if len(config.Extensions) == 0 {
			config.Extensions = []string{"json", "xml", "php"}
		}
		if config.Headers == nil {
			config.Headers = make(map[string]string)
		}
		if config.Headers["Accept"] == "" {
			config.Headers["Accept"] = "application/json, text/plain, */*"
		}
		config.DetectTech = true
		config.DetectWAF = true
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s API mode: exts=%s\n",
				cGreen.Sprint("[+]"), strings.Join(config.Extensions, ","))
		}
	}

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
	connOK, connInfo := checkConnectivity(config.Target, client)
	if !connOK {
		fmt.Fprintf(color.Output, "\n%s Cannot reach target: %s\n", cRed.Sprint("[!]"), cYellow.Sprint(config.Target))
		fmt.Fprintf(color.Output, "%s %s\n", cYellow.Sprint("[*]"), connInfo)
		if strings.Contains(connInfo, "DNS lookup failed") {
			fmt.Fprintf(color.Output, "%s The domain does not resolve. Check your DNS or internet connection.\n", cYellow.Sprint("[!]"))
		} else if strings.Contains(connInfo, "timeout") {
			fmt.Fprintf(color.Output, "%s Connection timed out. The server may be down or blocking your IP.\n", cYellow.Sprint("[!]"))
			fmt.Fprintf(color.Output, "%s Try: --proxy http://your-proxy:port\n", cYellow.Sprint("[*]"))
		} else if strings.Contains(connInfo, "refused") {
			fmt.Fprintf(color.Output, "%s Connection refused. The server is rejecting connections.\n", cYellow.Sprint("[!]"))
		} else if strings.Contains(connInfo, "reset") {
			fmt.Fprintf(color.Output, "%s Connection reset. The server closed the connection.\n", cYellow.Sprint("[!]"))
			fmt.Fprintf(color.Output, "%s Reduce threads: -t 5 or use a proxy.\n", cYellow.Sprint("[*]"))
		}
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Starting scan anyway (might get errors)...\n", cYellow.Sprint("[!]"))
		}
		if config.ExitOnError {
			os.Exit(1)
		}
	} else if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Target is reachable: %s\n", cGreen.Sprint("[+]"), connInfo)
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

	// Phase 2a: Signature Engine — Fingerprint target
	var fingerprint FingerprintResult
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Fingerprinting target...\n", cCyan.Sprint("[*]"))
	}
	resp, err := client.Get(config.Target)
	if err == nil && resp != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		fingerprint = FingerprintResponse(&resp.Header, string(body))
		resp.Body.Close()
	}
	if fingerprint.Server != "" || fingerprint.CMS != "" || fingerprint.WAF != "" {
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Server: %s", cGreen.Sprint("[+]"), fingerprint.Server)
			if fingerprint.CMS != "" {
				fmt.Fprintf(color.Output, " | CMS: %s", cYellow.Sprint(fingerprint.CMS))
			}
			if fingerprint.WAF != "" {
				fmt.Fprintf(color.Output, " | WAF: %s", cRed.Sprint(fingerprint.WAF))
			}
			if fingerprint.Framework != "" {
				fmt.Fprintf(color.Output, " | Framework: %s", cCyan.Sprint(fingerprint.Framework))
			}
			if fingerprint.Language != "" {
				fmt.Fprintf(color.Output, " | Lang: %s", cGreen.Sprint(fingerprint.Language))
			}
			fmt.Println()
		}
	}

	// Auto-suggest wordlist categories from fingerprint
	if config.AutoWordlist && fingerprint.Tech != nil {
		suggested := SuggestWordlistCategories(fingerprint)
		if len(suggested) > 0 {
			config.WordlistCategories = append(config.WordlistCategories, suggested...)
			config.Paths = nil
			paths, err := LoadWordlistByCategory(foundDB, config.WordlistCategories)
			if err == nil && len(paths) > 0 {
				config.Paths = paths
				if !config.Quiet {
					fmt.Fprintf(color.Output, "%s Auto-loaded %d payloads (tech-based)\n",
						cGreen.Sprint("[+]"), len(paths))
				}
			}
		}
	}

	// Phase 2b: Parser Engine — Crawl homepage, robots.txt, sitemap
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Crawling target sources...\n", cCyan.Sprint("[*]"))
	}
	var crawledPaths []string
	seenCrawled := make(map[string]bool)

	// Parse homepage
	if resp != nil {
		homeBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = homeBody
	}
	homeResp, err := client.Get(config.Target)
	if err == nil && homeResp != nil {
		homeBody, _ := io.ReadAll(io.LimitReader(homeResp.Body, 512*1024))
		homeLinks := ParseHTMLLinks(string(homeBody), config.Target)
		for _, l := range homeLinks {
			if !seenCrawled[l] {
				seenCrawled[l] = true
				crawledPaths = append(crawledPaths, l)
			}
		}
		formActions := ExtractFormActions(string(homeBody), config.Target)
		for _, f := range formActions {
			if !seenCrawled[f] {
				seenCrawled[f] = true
				crawledPaths = append(crawledPaths, f)
			}
		}
		jsEndpoints := ParseJSEndpoints(string(homeBody))
		for _, j := range jsEndpoints {
			if !seenCrawled[j] {
				seenCrawled[j] = true
				crawledPaths = append(crawledPaths, j)
			}
		}
		homeResp.Body.Close()
	}

	// Parse robots.txt
	robotsPaths := ParseRobots(config.Target, client)
	for _, p := range robotsPaths {
		if !seenCrawled[p] {
			seenCrawled[p] = true
			crawledPaths = append(crawledPaths, p)
		}
	}

	// Parse sitemap.xml
	sitemapPaths := ParseSitemap(config.Target, client)
	for _, p := range sitemapPaths {
		if !seenCrawled[p] {
			seenCrawled[p] = true
			crawledPaths = append(crawledPaths, p)
		}
	}

	if len(crawledPaths) > 0 {
		config.Paths = append(crawledPaths, config.Paths...)
		config.Paths = Deduplicate(config.Paths)
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Found %d endpoints via crawling\n",
				cGreen.Sprint("[+]"), len(crawledPaths))
		}
	}

	// JS spidering (additional JS-specific crawl)
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

	// Phase 2c: Create scheduler
	config.Scheduler = NewScheduler(config.Threads)
	if config.Delay > 0 || config.MaxRate > 0 {
		config.Scheduler.EnableJitter(config.Delay, config.Delay+100)
	}

	// Phase 3: Main scan
	if !config.Quiet {
		fmt.Fprintf(color.Output, "%s Starting scan with %d paths (%d threads)...\n",
			cCyan.Sprint("[*]"), len(config.Paths), config.Threads)
		fmt.Println()
	}

	results, stats := RunScan(config)
	if config.Scheduler != nil {
		_, _, finalErrRate := config.Scheduler.Stats()
		if finalErrRate > 0.1 && !config.Quiet {
			fmt.Fprintf(color.Output, "\n%s Error rate: %.1f%% — server may be throttling\n",
				cYellow.Sprint("[!]"), finalErrRate*100)
		}
	}

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

	// Merge restored results (from session resume)
	allResults := results
	if len(config.RestoredResults) > 0 {
		allResults = append(config.RestoredResults, results...)
		stats.Found += len(config.RestoredResults)
		if !config.Quiet {
			fmt.Fprintf(color.Output, "%s Restored %d previous results from session\n",
				cGreen.Sprint("[+]"), len(config.RestoredResults))
		}
	}

	// Phase 4: Output
	fmt.Println()
	printResults(config, allResults, recursiveResults, stats, recursiveStats, startTime)

	// Save session
	if config.SaveSession {
		saveSessionData(config, allResults, stats)
	}

	// Save report
	if config.OutputFile != "" {
		saveReport(config, allResults, recursiveResults, stats, recursiveStats)
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

func LoadSession(path string) (*SessionData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func ListSessions() []string {
	sessionDir := "sessions"
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return nil
	}
	var sessions []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "session_") && strings.HasSuffix(e.Name(), ".json") {
			sessions = append(sessions, e.Name())
		}
	}
	return sessions
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
