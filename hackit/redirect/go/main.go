package main

import (
	"encoding/json"
	"flag"
	"fmt"
)

func main() {
	urlFlag := flag.String("url", "", "Target URL")
	timeoutFlag := flag.Int("timeout", 10, "Request timeout in seconds")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Println(`{"error": "URL required"}`)
		return
	}

	scanner := NewScanner(*timeoutFlag)
	results := scanner.Scan(*urlFlag)

	jsonOut, _ := json.Marshal(results)
	fmt.Println(string(jsonOut))
}
