package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"sync"
)

type Result struct {
	Status   int    `json:"status"`
	Length   int64  `json:"length"`
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	IsBypass bool   `json:"is_bypass,omitempty"`
	Payload  string `json:"payload,omitempty"`
}

func main() {
	urlFlag := flag.String("url", "", "Target URL")
	wordlistFlag := flag.String("wordlist", "", "Wordlist path")
	extensionsFlag := flag.String("extensions", "", "Comma separated extensions")
	statusFlag := flag.String("status", "200,204,301,302,307,401,403", "Status codes to match")
	threadsFlag := flag.Int("threads", 50, "Number of threads")
	bypassFlag := flag.Bool("bypass", false, "Enable 403 bypass")
	flag.Parse()

	if *urlFlag == "" || *wordlistFlag == "" {
		fmt.Println(`{"error": "URL and Wordlist required"}`)
		return
	}

	InitClient(10) // 10s timeout

	// Load resources
	words, err := LoadWordlist(*wordlistFlag)
	if err != nil {
		fmt.Printf(`{"error": "Failed to load wordlist: %v"}`, err)
		return
	}

	var exts []string
	if *extensionsFlag != "" {
		exts = strings.Split(*extensionsFlag, ",")
	}

	statusCodes := parseStatusCodes(*statusFlag)

	// Generate tasks
	targetURLs := GenerateURLs(*urlFlag, words, exts)

	// Worker pool
	results := make(chan Result, len(targetURLs))
	sem := make(chan struct{}, *threadsFlag)
	var wg sync.WaitGroup

	for _, u := range targetURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			res, err := FuzzURL(target, *bypassFlag)
			if err == nil {
				if statusCodes[res.Status] || res.IsBypass {
					results <- res
				}
			}
		}(u)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var finalResults []Result
	for res := range results {
		finalResults = append(finalResults, res)
	}

	jsonOut, _ := json.Marshal(finalResults)
	fmt.Println(string(jsonOut))
}

func parseStatusCodes(s string) map[int]bool {
	codes := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		var code int
		fmt.Sscanf(strings.TrimSpace(part), "%d", &code)
		codes[code] = true
	}
	return codes
}
