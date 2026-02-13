package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	targetURL  string
	params     string
	method     string
	payloads   string
	threads    int
	timeout    int
	outputFile string
)

func main() {
	flag.StringVar(&targetURL, "url", "", "Target URL")
	flag.StringVar(&params, "params", "", "Parameters to fuzz (comma separated)")
	flag.StringVar(&method, "method", "GET", "HTTP Method")
	flag.StringVar(&payloads, "payloads", "", "Custom payloads file")
	flag.IntVar(&threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&timeout, "timeout", 10, "Request timeout")
	flag.StringVar(&outputFile, "output", "", "Save results to JSON file")
	flag.Parse()

	if targetURL == "" || params == "" {
		fmt.Println("Error: --url and --params are required")
		os.Exit(1)
	}

	paramList := strings.Split(params, ",")
	var payloadList []string

	if payloads != "" {
		file, err := os.Open(payloads)
		if err != nil {
			fmt.Printf("Error loading payloads: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				payloadList = append(payloadList, line)
			}
		}
	} else {
		// Default payloads if none provided
		payloadList = []string{
			"<script>alert(1)</script>",
			"' OR '1'='1",
			"\" OR \"1\"=\"1",
			"../../etc/passwd",
			"{{7*7}}",
		}
	}

	fuzzer := NewFuzzer(timeout)
	results := make(chan Result, len(paramList)*len(payloadList))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	fmt.Printf("[*] Target: %s\n", targetURL)
	fmt.Printf("[*] Method: %s\n", method)
	fmt.Printf("[*] Params: %d, Payloads: %d\n", len(paramList), len(payloadList))

	for _, param := range paramList {
		param = strings.TrimSpace(param)
		for _, payload := range payloadList {
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				res := fuzzer.Fuzz(targetURL, p, pay, method)
				if res.Reflected || res.Error != "" {
					results <- res
				}
			}(param, payload)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var finalResults []Result
	var reflectedCount, errorCount int

	for res := range results {
		finalResults = append(finalResults, res)
		if res.Reflected {
			reflectedCount++
			fmt.Printf("\n[+] Found Reflected Param: %s\n    Payload: %s\n    Context: %s\n", res.Param, res.Payload, res.Context)
		}
		if res.Error != "" {
			errorCount++
			fmt.Printf("\n[!] Possible Error/SQLi in Param: %s\n    Error: %s\n", res.Param, res.Error)
		}
	}

	if reflectedCount == 0 && errorCount == 0 {
		fmt.Println("\n[-] No interesting behavior detected.")
	} else {
		fmt.Printf("\nSummary: %d Reflected, %d Errors found.\n", reflectedCount, errorCount)
	}

	if outputFile != "" {
		data, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		} else {
			err = os.WriteFile(outputFile, data, 0644)
			if err != nil {
				fmt.Printf("Error writing file: %v\n", err)
			} else {
				fmt.Printf("[+] Results saved to %s\n", outputFile)
			}
		}
	}
}
