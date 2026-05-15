package main

import (
	"flag"
	"fmt"
	"net/url"
)

func main() {
	targetFlag := flag.String("url", "", "Target Website URL")
	flag.Parse()

	if *targetFlag == "" {
		fmt.Println(`{"error": "URL required"}`)
		return
	}

	u, err := url.Parse(*targetFlag)
	if err != nil {
		fmt.Printf(`{"error": "Invalid URL: %v"}`, err)
		return
	}

	crawler := NewCrawler(*targetFlag, u.Host)
	crawler.Start()
}
