package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseFlags() *ScanConfig {
	config := &ScanConfig{
		Headers:       make(map[string]string),
		Extensions:    []string{},
		ExcludeStatus: []int{},
		IncludeStatus: []int{},
		ExcludeLength: []uint64{},
		IncludeLength: []uint64{},
		Paths:         []string{},
	}

	// TARGET OPTIONS
	target := flag.String("u", "", "Target URL")
	wordlistStr := flag.String("w", "", "Wordlist (comma separated or file)")
	method := flag.String("method", "GET", "HTTP method")
	data := flag.String("data", "", "POST body data")
	headerStr := flag.String("H", "", "Custom headers (Key:Val,Key2:Val2)")
	cookie := flag.String("cookie", "", "Set cookie")
	auth := flag.String("auth", "", "Basic auth (user:pass)")
	proxy := flag.String("proxy", "", "Proxy URL (or file path for rotation)")
	userAgent := flag.String("user-agent", "", "Custom User-Agent")

	// PERFORMANCE OPTIONS
	threads := flag.Int("t", 50, "Number of threads")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	delay := flag.Int("delay", 0, "Delay between requests in ms")
	retries := flag.Int("retries", 2, "Number of retries")
	randomAgent := flag.Bool("random-agent", false, "Use random User-Agent")
	http2 := flag.Bool("http2", false, "Enable HTTP/2")
	followRedirect := flag.Bool("follow-redirect", false, "Follow redirects")
	maxRedirect := flag.Int("max-redirect", 5, "Max redirects")

	// SCANNING OPTIONS
	exts := flag.String("e", "", "Extensions (comma separated)")
	recursive := flag.Bool("recursive", false, "Recursive scanning")
	depth := flag.Int("depth", 2, "Max recursion depth")
	excludeStatus := flag.String("exclude-status", "404", "Exclude status codes")
	includeStatus := flag.String("include-status", "", "Include status codes")
	excludeLength := flag.String("exclude-length", "", "Exclude response lengths")
	includeLength := flag.String("include-length", "", "Include response lengths")

	// DETECTION OPTIONS
	detectWaf := flag.Bool("detect-waf", false, "Detect WAF")
	detectTech := flag.Bool("detect-tech", false, "Detect technology")
	detectCms := flag.Bool("detect-cms", false, "Detect CMS")
	detectBackup := flag.Bool("detect-backup", false, "Search backup files")
	smartFilter := flag.Bool("smart-filter", false, "Enable smart filtering")

	// ADVANCED OPTIONS
	fuzz := flag.String("fuzz", "", "Fuzz parameter")
	apiMode := flag.Bool("api-mode", false, "API mode")
	jsonBody := flag.Bool("json-body", false, "Send JSON body")
	graphql := flag.Bool("graphql", false, "GraphQL mode")
	rateLimit := flag.Float64("rate-limit", 0, "Max requests per second (0 = unlimited)")

	// OSINT / SMART MODE
	autoWordlist := flag.Bool("auto-wordlist", false, "Auto wordlist generation")
	crawl := flag.Bool("crawl", false, "Crawl target")
	extractJs := flag.Bool("extract-js", false, "Extract endpoints from JS")

	flag.Parse()

	if *target == "" {
		fmt.Println("Error: Target URL (-u) is required")
		flag.Usage()
		os.Exit(1)
	}

	config.Target = *target
	config.Method = *method
	if *data != "" {
		config.Data = data
	}
	if *cookie != "" {
		config.Cookie = cookie
	}
	if *auth != "" {
		config.Auth = auth
	}
	if *proxy != "" {
		config.Proxy = proxy
	}
	if *userAgent != "" {
		config.UserAgent = userAgent
	}

	// Parse Headers
	if *headerStr != "" {
		parts := strings.Split(*headerStr, ",")
		for _, p := range parts {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) == 2 {
				config.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	// Performance
	config.Threads = *threads
	config.TimeoutMS = uint64(*timeout * 1000)
	config.DelayMS = uint64(*delay)
	config.Retries = *retries
	config.RandomAgent = *randomAgent
	config.HTTP2 = *http2
	config.FollowRedirects = *followRedirect
	config.MaxRedirects = *maxRedirect

	// Scanning
	if *wordlistStr != "" {
		config.Paths = strings.Split(*wordlistStr, ",")
	}
	if *exts != "" {
		config.Extensions = strings.Split(*exts, ",")
	}
	config.Recursive = *recursive
	config.Depth = *depth
	config.ExcludeStatus = parseToIntSlice(*excludeStatus)
	config.IncludeStatus = parseToIntSlice(*includeStatus)
	config.ExcludeLength = parseToUint64Slice(*excludeLength)
	config.IncludeLength = parseToUint64Slice(*includeLength)

	// Detection
	config.DetectWAF = *detectWaf
	config.DetectTech = *detectTech
	config.DetectCMS = *detectCms
	config.DetectBackup = *detectBackup
	config.SmartFilter = *smartFilter

	// Advanced
	if *fuzz != "" {
		config.FuzzParam = fuzz
	}
	config.APIMode = *apiMode
	config.JSONBody = *jsonBody
	config.GraphQL = *graphql
	if *rateLimit > 0 {
		config.RateLimit = rateLimit
	}

	// OSINT
	config.AutoWordlist = *autoWordlist
	config.Crawl = *crawl
	config.ExtractJS = *extractJs

	return config
}

func parseToIntSlice(s string) []int {
	if s == "" {
		return []int{}
	}
	var res []int
	for _, p := range strings.Split(s, ",") {
		if i, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			res = append(res, i)
		}
	}
	return res
}

func parseToUint64Slice(s string) []uint64 {
	if s == "" {
		return []uint64{}
	}
	var res []uint64
	for _, p := range strings.Split(s, ",") {
		if i, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64); err == nil {
			res = append(res, i)
		}
	}
	return res
}
