package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func parseFlags() *ScanConfig {
	config := &ScanConfig{
		Headers:  make(map[string]string),
		Paths:    []string{},
		Method:   "GET",
		Threads:  5,
		Timeout:  5,
		Retries:  1,
		MaxDepth: 3,
	}

	// Target options
	target := flag.String("u", "", "Target URL")
	urlsFile := flag.String("l", "", "URL list file")
	rawFile := flag.String("raw", "", "Load raw HTTP request from file (Burp-style)")
	stdin := flag.Bool("stdin", false, "Read URL(s) from STDIN")
	sessionFile := flag.String("session", "", "Session file to resume")
	sessionID := flag.Int("session-id", 0, "Resume session by ID")

	// Dictionary settings
	wordlists := flag.String("w", "", "Wordlist files or directories (comma separated)")
	wordlistCategories := flag.String("wordlist-categories", "", "Wordlist category names (comma separated)")
	extensions := flag.String("e", "", "Extensions (comma separated, e.g. php,asp)")
	forceExtensions := flag.Bool("f", false, "Force extensions on every wordlist entry")
	overwriteExtensions := flag.Bool("overwrite-extensions", false, "Overwrite existing extensions")
	excludeExtensions := flag.String("exclude-extensions", "", "Exclude extensions (comma separated)")
	prefixes := flag.String("prefixes", "", "Add prefixes to all entries (comma separated)")
	suffixes := flag.String("suffixes", "", "Add suffixes to all entries (comma separated)")
	uppercase := flag.Bool("U", false, "Uppercase wordlist")
	lowercase := flag.Bool("L", false, "Lowercase wordlist")
	capital := flag.Bool("C", false, "Capital wordlist")
	showWordlistStatus := flag.Bool("wordlist-status", false, "Show wordlist info and exit")

	// General settings
	threads := flag.Int("t", 5, "Number of threads (default: 5)")
	listSessions := flag.Bool("list-sessions", false, "List resumable sessions")
	recursive := flag.Bool("r", false, "Recursive brute-force")
	deepRecursive := flag.Bool("deep-recursive", false, "Deep recursive scan")
	forceRecursive := flag.Bool("force-recursive", false, "Force recursive on all found paths")
	maxRecursionDepth := flag.Int("R", 3, "Max recursion depth")
	recursionStatus := flag.String("recursion-status", "", "Status codes for recursion (comma separated)")
	subdirs := flag.String("subdirs", "", "Scan sub-directories (comma separated)")
	excludeSubdirs := flag.String("exclude-subdirs", "", "Exclude subdirs during recursive scan (comma separated)")
	includeStatus := flag.String("i", "", "Include status codes (comma separated, supports ranges)")
	excludeStatus := flag.String("x", "", "Exclude status codes (comma separated, supports ranges)")
	excludeSizes := flag.String("exclude-sizes", "", "Exclude response sizes (comma separated, e.g. 0,0B,4KB)")
	excludeText := flag.String("exclude-text", "", "Exclude responses containing text")
	excludeRegex := flag.String("exclude-regex", "", "Exclude responses matching regex")
	excludeRedirect := flag.String("exclude-redirect", "", "Exclude redirects matching regex")
	excludeResponse := flag.String("exclude-response", "", "Exclude responses similar to this path")
	skipOnStatus := flag.String("skip-on-status", "", "Skip target on status codes")
	minResponseSize := flag.String("min-response-size", "", "Minimum response size")
	maxResponseSize := flag.String("max-response-size", "", "Maximum response size")
	maxTime := flag.Int("max-time", 0, "Maximum scan time in seconds")
	exitOnError := flag.Bool("exit-on-error", false, "Exit on error")

	// Advanced filtering
	autoCalibration := flag.Bool("auto-calibration", false, "Force wildcard calibration")
	matchStatus := flag.String("match-status", "", "Match status codes (advanced)")
	filterStatus := flag.String("filter-status", "", "Filter status codes (advanced)")
	matchSize := flag.String("match-size", "", "Match response size (advanced)")
	filterSize := flag.String("filter-size", "", "Filter response size (advanced)")
	matchWords := flag.String("match-words", "", "Match word count (advanced)")
	filterWords := flag.String("filter-words", "", "Filter word count (advanced)")
	matchLines := flag.String("match-lines", "", "Match line count (advanced)")
	filterLines := flag.String("filter-lines", "", "Filter line count (advanced)")
	matchRegex := flag.String("match-regex", "", "Match body regex (advanced)")
	filterRegex := flag.String("filter-regex", "", "Filter body regex (advanced)")
	matchHeader := flag.String("match-header", "", "Match response header text")
	filterHeader := flag.String("filter-header", "", "Filter response header text")

	// Request settings
	method := flag.String("m", "GET", "HTTP method")
	bodyData := flag.String("d", "", "HTTP request data")
	dataFile := flag.String("data-file", "", "File with HTTP request data")
	headers := flag.String("H", "", "Custom headers (Key:Val,Key2:Val2)")
	headersFile := flag.String("headers-file", "", "File with HTTP headers")
	followRedirect := flag.Bool("F", false, "Follow redirects")
	randomAgent := flag.Bool("random-agent", false, "Use random User-Agent")
	auth := flag.String("auth", "", "Authentication credentials (user:pass or bearer token)")
	authType := flag.String("auth-type", "", "Auth type: basic, digest, bearer, ntlm, jwt")
	userAgent := flag.String("user-agent", "", "Custom User-Agent")
	cookie := flag.String("cookie", "", "HTTP Cookie")

	// Connection settings
	timeout := flag.Int("timeout", 5, "Connection timeout in seconds")
	delay := flag.Int("delay", 0, "Delay between requests in ms")
	proxy := flag.String("p", "", "Proxy URL (http:// or socks5://)")
	proxiesFile := flag.String("proxies-file", "", "File with proxy servers")
	proxyAuth := flag.String("proxy-auth", "", "Proxy authentication")
	tor := flag.Bool("tor", false, "Use Tor network")
	scheme := flag.String("scheme", "", "URL scheme override")
	maxRate := flag.Float64("max-rate", 0, "Max requests per second")
	retries := flag.Int("retries", 1, "Number of retries")
	ip := flag.String("ip", "", "Server IP address")
	iface := flag.String("interface", "", "Network interface")

	// Advanced settings
	crawl := flag.Bool("crawl", false, "Crawl for new paths in responses")

	// View settings
	fullURL := flag.Bool("full-url", false, "Show full URLs in output")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("q", false, "Quiet mode")
	verbose := flag.Bool("v", false, "Verbose output")

	// Output settings
	outputFormats := flag.String("O", "", "Output formats (simple,plain,json,xml,md,csv,html)")
	outputFile := flag.String("o", "", "Output file")
	logFile := flag.String("log", "", "Log file")

	// Our custom detection features
	detectWAF := flag.Bool("detect-waf", false, "Detect WAF (20+ signatures)")
	detectTech := flag.Bool("detect-tech", false, "Detect technology stack (50+ signatures)")
	detectCMS := flag.Bool("detect-cms", false, "Detect CMS (WordPress, Joomla, Drupal, etc)")
	detectBackup := flag.Bool("detect-backup", false, "Search backup files (.bak, .old, .zip, .tar.gz, .sql)")
	smartFilter := flag.Bool("smart-filter", true, "Smart false-positive filtering (soft-404, wildcard suppression)")
	extractJS := flag.Bool("extract-js", false, "Extract endpoints from JS files")
	autoWordlist := flag.Bool("auto-wordlist", false, "Auto wordlist generation from target fingerprint")
	saveSession := flag.Bool("save-session", false, "Save scan session for resume")
	http2 := flag.Bool("http2", false, "Enable HTTP/2")
	apiMode := flag.Bool("api-mode", false, "API mode: presets for API scanning")
	jsonBody := flag.Bool("json-body", false, "Send JSON body (Content-Type: application/json)")
	graphql := flag.Bool("graphql", false, "GraphQL mode: wraps body in {query} format")
	adaptiveRate := flag.Bool("adaptive-rate", false, "Dynamically adjust scan rate based on server response")
	detectLogin := flag.Bool("detect-login", false, "Detect login/admin pages")
	detectAPI := flag.Bool("detect-api", false, "Detect API endpoints")
	jsDeep := flag.Bool("js-deep", false, "Deep JavaScript analysis (follows imports, evaluates dynamic URLs)")
	swagger := flag.Bool("swagger", false, "Detect Swagger/OpenAPI documentation")
	similarity := flag.Int("similarity", 0, "Response similarity threshold (0-100) for filtering")
	reportFile := flag.String("report", "", "Generate scan report file (JSON format)")

	flag.Parse()

	// Handle help
	if *listSessions {
		fmt.Println("Sessions: (not yet implemented)")
		os.Exit(0)
	}

	if *showWordlistStatus {
		dbDir := findDBDir()
		paths, err := LoadAllPayloads(dbDir)
		if err != nil {
			fmt.Printf("Error loading wordlists: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wordlist directory: %s\n", dbDir)
		fmt.Printf("Total entries: %d\n", len(paths))
		// Count per category
		categories := []string{"common", "conf", "web", "db", "keys", "logs", "backups", "extensions", "vcs"}
		for _, cat := range categories {
			catDir := dbDir + "/categories/" + cat
			if cat+".txt" == cat {
				continue
			}
			_ = catDir
		}
		os.Exit(0)
	}

	config.Target = *target
	config.URLsFile = *urlsFile
	config.RawFile = *rawFile
	config.Stdin = *stdin
	config.SessionFile = *sessionFile
	config.SessionID = *sessionID

	if *target == "" && *urlsFile == "" && !*stdin {
		if len(os.Args) > 1 {
			arg := os.Args[1]
			if !strings.HasPrefix(arg, "-") {
				config.Target = arg
			}
		}
	}

	// Dictionary
	if *wordlists != "" {
		config.Wordlists = strings.Split(*wordlists, ",")
	}
	if *wordlistCategories != "" {
		config.WordlistCategories = strings.Split(*wordlistCategories, ",")
	}
	if *extensions != "" {
		config.Extensions = strings.Split(*extensions, ",")
	}
	config.ForceExtensions = *forceExtensions
	config.OverwriteExtensions = *overwriteExtensions
	if *excludeExtensions != "" {
		config.ExcludeExtensions = strings.Split(*excludeExtensions, ",")
	}
	if *prefixes != "" {
		config.Prefixes = strings.Split(*prefixes, ",")
	}
	if *suffixes != "" {
		config.Suffixes = strings.Split(*suffixes, ",")
	}
	config.Uppercase = *uppercase
	config.Lowercase = *lowercase
	config.Capital = *capital

	// General
	config.Threads = *threads
	config.Recursive = *recursive
	config.DeepRecursive = *deepRecursive
	config.ForceRecursive = *forceRecursive
	config.MaxDepth = *maxRecursionDepth
	if *recursionStatus != "" {
		config.RecursionStatus = parseStatusList(*recursionStatus)
	}
	if *subdirs != "" {
		config.Subdirs = strings.Split(*subdirs, ",")
	}
	if *excludeSubdirs != "" {
		config.ExcludeSubdirs = strings.Split(*excludeSubdirs, ",")
	}
	if *includeStatus != "" {
		config.IncludeStatus = parseStatusList(*includeStatus)
	}
	if *excludeStatus != "" {
		config.ExcludeStatus = parseStatusList(*excludeStatus)
	}
	if *excludeSizes != "" {
		config.ExcludeSizes = strings.Split(*excludeSizes, ",")
	}
	if *excludeText != "" {
		config.ExcludeText = strings.Split(*excludeText, ",")
	}
	config.ExcludeRegex = *excludeRegex
	config.ExcludeRedirect = *excludeRedirect
	config.ExcludeResponse = *excludeResponse
	if *skipOnStatus != "" {
		config.SkipOnStatus = parseStatusList(*skipOnStatus)
	}
	if *minResponseSize != "" {
		config.MinResponseSize = parseSize(*minResponseSize)
	}
	if *maxResponseSize != "" {
		config.MaxResponseSize = parseSize(*maxResponseSize)
	}
	config.MaxTime = *maxTime
	config.ExitOnError = *exitOnError

	// Advanced filtering
	config.AutoCalibration = *autoCalibration
	if *matchStatus != "" {
		config.MatchStatus = parseStatusList(*matchStatus)
	}
	if *filterStatus != "" {
		config.FilterStatus = parseStatusList(*filterStatus)
	}
	if *matchSize != "" {
		config.MatchSize = parseSizeRangeList(*matchSize)
	}
	if *filterSize != "" {
		config.FilterSize = parseSizeRangeList(*filterSize)
	}
	if *matchWords != "" {
		config.MatchWords = parseSizeRangeList(*matchWords)
	}
	if *filterWords != "" {
		config.FilterWords = parseSizeRangeList(*filterWords)
	}
	if *matchLines != "" {
		config.MatchLines = parseSizeRangeList(*matchLines)
	}
	if *filterLines != "" {
		config.FilterLines = parseSizeRangeList(*filterLines)
	}
	config.MatchRegex = *matchRegex
	config.FilterRegex = *filterRegex
	if *matchHeader != "" {
		config.MatchHeader = strings.Split(*matchHeader, ",")
	}
	if *filterHeader != "" {
		config.FilterHeader = strings.Split(*filterHeader, ",")
	}

	// Request
	config.Method = *method
	config.Data = *bodyData
	config.DataFile = *dataFile
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				config.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}
	config.HeadersFile = *headersFile
	config.FollowRedirect = *followRedirect
	config.RandomAgent = *randomAgent
	config.Auth = *auth
	config.AuthType = *authType
	config.UserAgent = *userAgent
	config.Cookie = *cookie

	// Connection
	config.Timeout = *timeout
	config.Delay = *delay
	config.Proxy = *proxy
	config.ProxiesFile = *proxiesFile
	config.ProxyAuth = *proxyAuth
	config.Tor = *tor
	config.Scheme = *scheme
	config.MaxRate = *maxRate
	config.Retries = *retries
	config.IP = *ip
	config.Interface = *iface

	// Advanced
	config.Crawl = *crawl

	// View
	config.FullURL = *fullURL
	config.NoColor = *noColor
	config.Quiet = *quiet
	config.Verbose = *verbose

	// Output
	if *outputFormats != "" {
		config.OutputFormats = strings.Split(*outputFormats, ",")
	}
	config.OutputFile = *outputFile
	config.LogFile = *logFile

	// Our features
	config.DetectWAF = *detectWAF
	config.DetectTech = *detectTech
	config.DetectCMS = *detectCMS
	config.DetectBackup = *detectBackup
	config.SmartFilter = *smartFilter
	config.ExtractJS = *extractJS
	config.AutoWordlist = *autoWordlist
	config.SaveSession = *saveSession
	config.HTTP2 = *http2
	config.APIMode = *apiMode
	config.JSONBody = *jsonBody
	config.GraphQL = *graphql
	config.AdaptiveRate = *adaptiveRate
	config.DetectLogin = *detectLogin
	config.DetectAPI = *detectAPI
	config.JSDeep = *jsDeep
	config.Swagger = *swagger
	config.Similarity = *similarity
	config.ReportFile = *reportFile

	// Compile regex patterns
	if config.ExcludeRegex != "" {
		config.ExcludeRegexCompiled, _ = regexp.Compile(config.ExcludeRegex)
	}
	if config.MatchRegex != "" {
		config.MatchRegexCompiled, _ = regexp.Compile(config.MatchRegex)
	}
	if config.ExcludeRedirect != "" {
		config.ExcludeRedirectCompiled, _ = regexp.Compile(config.ExcludeRedirect)
	}

	// Disable color if requested
	if config.NoColor {
		// Handled at print time
	}

	return config
}

func parseInt(s string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(s))
	return i
}
