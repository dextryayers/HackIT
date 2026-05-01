package main

import (
	"encoding/json"
	"flag"
	"fmt"
)

func main() {
	urlFlag := flag.String("url", "", "Target URL")
	timeoutFlag := flag.Int("timeout", 10, "Request timeout in seconds")
	payloadsFlag := flag.String("payloads", "", "Path to external payloads file")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Println(`{"error": "URL required"}`)
		return
	}

	scanner := NewScanner(*timeoutFlag)
	if *payloadsFlag != "" {
		_ = scanner.LoadPayloads(*payloadsFlag)
	}
	results := scanner.Scan(*urlFlag)

	jsonOut, _ := json.Marshal(results)
	fmt.Println(string(jsonOut))
}
