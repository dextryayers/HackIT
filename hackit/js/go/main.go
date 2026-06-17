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
	flag.Parse()

	target := *targetFlag

	// If -url not provided, use first non-flag argument
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	// Still empty? Show usage
	if target == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-url] <target_url>\n", os.Args[0])
		os.Exit(1)
	}

	// Auto-add https:// if no scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"Invalid URL: %v"}`, err)
		os.Exit(1)
	}

	crawler := NewCrawler(target, u.Host, *codeFlag)
	crawler.Scope.MaxDepth = *deepFlag
	crawler.Start()
}
