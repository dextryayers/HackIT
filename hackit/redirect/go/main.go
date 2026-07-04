package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var banner = `
  ===================================
  >>>>  R  E  D  I  R  E  C  T  <<<<
  >>>>  H  a  c  k  I  T  V  2  <<<<
  ===================================
  [*] PARAMETERS LOADED: 25
  [*] BYPASS TECHNIQUES: ACTIVE
  [*] TARGET: [ PARAM REDIRECT ]
  ===================================
  [01] Query Param    [02] Body POST
  [03] Header Inject  [04] Path Inject
  [05] DOM/Client     [06] WAF Bypass
  [07] Blind Redirect [08] Deep Payload
  [09] Cookie Inject  [10] Encoding Matrix
  ===================================
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--json" {
		runFlagMode()
		return
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print(banner)
	fmt.Println("\n  Example: https://example.com/?view=")
	fmt.Println()

	for {
		fmt.Print("  Input Target: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			fmt.Println("  [!] Exiting...")
			return
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" || input == "q" {
			fmt.Println("  [!] Exiting...")
			return
		}

		timeout := 15
		if len(os.Args) > 2 && os.Args[1] == "-timeout" {
			if t, err := strconv.Atoi(os.Args[2]); err == nil && t > 0 {
				timeout = t
			}
		}

		start := time.Now()
		scanner := NewScanner(timeout)
		results := scanner.Scan(input)
		duration := time.Since(start)

		if len(results) > 0 {
			PrintSummary(input, results, duration, scanner.RequestCount)
			PrintDetailed("", results)
		} else {
			fmt.Printf("\n  \033[31m[-] NOT FOUND\033[0m > %s", input)
		}

		fmt.Printf("\n\n  Duration: %v | Requests: %d\n", duration.Round(time.Millisecond), scanner.RequestCount)
		fmt.Println("\n  Press Enter to scan again, or type exit to quit.")
	}
}

func runFlagMode() {
	var targetURL string
	var timeout int

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
		case "-url", "--url":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		case "-timeout", "--timeout":
			if i+1 < len(args) {
				timeout, _ = strconv.Atoi(args[i+1])
				i++
			}
		}
	}

	if targetURL == "" {
		fmt.Println(`{"error":"URL required"}`)
		os.Exit(1)
	}
	if timeout <= 0 {
		timeout = 15
	}

	scanner := NewScanner(timeout)
	results := scanner.Scan(targetURL)
	jsonOut, err := json.Marshal(results)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"json marshal: %v"}`, err)
		os.Exit(1)
	}
	fmt.Println(string(jsonOut))
}
