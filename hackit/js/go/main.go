package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func main() {
	targetFlag := flag.String("url", "", "Target Website URL")
	deepFlag := flag.Int("depth", 3, "Max crawl depth")
	codeFlag := flag.Bool("code", false, "Show full JS source code in output")
	concurrencyFlag := flag.Int("concurrency", 50, "Max concurrent requests")
	timeoutFlag := flag.Int("timeout", 30, "Request timeout in seconds")
	delayFlag := flag.Int("delay", 0, "Delay between requests in ms")
	proxyFlag := flag.String("proxy", "", "HTTP proxy URL")
	crawlFlag := flag.Bool("crawl", true, "Enable page crawling")
	jsAnalysisFlag := flag.Bool("js", true, "Enable JS analysis")
	secretsFlag := flag.Bool("secrets", true, "Scan for secrets")
	subdomainsFlag := flag.Bool("subdomains", true, "Discover subdomains")
	archiveFlag := flag.Bool("archive", true, "Query archives (Wayback, CommonCrawl)")
	bruteFlag := flag.Bool("brute", true, "Brute force common paths")
	sourcemapFlag := flag.Bool("sourcemap", true, "Parse source maps")
	techDetectFlag := flag.Bool("tech", true, "Detect technologies")
	endpointFlag := flag.Bool("endpoints", true, "Extract endpoints")
	networkFlag := flag.Bool("network", true, "Extract network calls")
	jsonOutFlag := flag.Bool("json", false, "Output raw JSON to stdout")
	rateLimitFlag := flag.Int("rate-limit", 0, "Max requests per second")
	flag.Parse()

	target := *targetFlag
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}
	if target == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <target_url>\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"Invalid URL: %v"}`, err)
		os.Exit(1)
	}

	opts := &Options{
		Target:      target,
		Host:        u.Host,
		MaxDepth:    *deepFlag,
		ShowCode:    *codeFlag,
		Concurrency: *concurrencyFlag,
		Timeout:     *timeoutFlag,
		Delay:       *delayFlag,
		Proxy:       *proxyFlag,
		Crawl:       *crawlFlag,
		JS:          *jsAnalysisFlag,
		Secrets:     *secretsFlag,
		Subdomains:  *subdomainsFlag,
		Archive:     *archiveFlag,
		Brute:       *bruteFlag,
		Sourcemap:   *sourcemapFlag,
		Tech:        *techDetectFlag,
		Endpoints:   *endpointFlag,
		Network:     *networkFlag,
		JSON:        *jsonOutFlag,
		RateLimit:   *rateLimitFlag,
	}

	NewCrawler(opts).Start()
}
