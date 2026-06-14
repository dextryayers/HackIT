package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"encoding/json"
	"bufio"
)

type CheckResult struct {
	Platform     string  `json:"platform"`
	Category     string  `json:"category"`
	Url          string  `json:"url"`
	Status       string  `json:"status"`
	HttpStatus   int     `json:"http_status"`
	Title        string  `json:"title"`
	Description  string  `json:"description"`
	Confidence   int     `json:"confidence"`
	Note         string  `json:"note"`
	ResponseTime float64 `json:"response_time"`
}

type FinalSummary struct {
	Username  string `json:"username"`
	Total     int    `json:"total"`
	Hits      int    `json:"hits"`
	Possible  int    `json:"possible"`
	Unknown   int    `json:"unknown"`
}

var rustBinDir string

func init() {
	if runtime.GOOS == "linux" {
		rustBinDir = filepath.Join("rust_engine", "target", "release")
	}
}

func getRustBinPath() string {
	if rustBinDir == "" {
		return ""
	}
	return filepath.Join(rustBinDir, "osint_checker")
}

func callRustChecker(username string, proxy string, retry int, timeout int, workers int) ([]CheckResult, *FinalSummary, error) {
	binPath := getRustBinPath()
	if binPath == "" {
		return nil, nil, fmt.Errorf("Rust bridge not available on %s", runtime.GOOS)
	}

	args := []string{username}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	if retry > 0 {
		args = append(args, "--retry", fmt.Sprintf("%d", retry))
	}
	if timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", timeout))
	}
	if workers > 0 {
		args = append(args, "--workers", fmt.Sprintf("%d", workers))
	}

	cmd := exec.Command(binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var results []CheckResult
	var summary *FinalSummary

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "RESULT:") {
			var result CheckResult
			if err := json.Unmarshal([]byte(line[7:]), &result); err == nil {
				results = append(results, result)
			}
		} else if strings.HasPrefix(line, "FINAL:") {
			var s FinalSummary
			if err := json.Unmarshal([]byte(line[6:]), &s); err == nil {
				summary = &s
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		return results, summary, err
	}

	return results, summary, nil
}

func main() {
	username := flag.String("u", "", "Username to search")
	proxy := flag.String("proxy", "", "Proxy URL (socks5://... or http://...)")
	retry := flag.Int("retry", 1, "Number of retries on failure")
	timeout := flag.Int("timeout", 15, "HTTP timeout in seconds")
	workers := flag.Int("workers", 50, "Concurrent workers")
	jsonOut := flag.Bool("json", false, "Output as JSON")
	flag.Parse()

	if *username == "" && len(flag.Args()) > 0 {
		*username = flag.Args()[0]
	}

	if *username == "" {
		fmt.Fprintln(os.Stderr, "Usage: osint -u <username> [--proxy ...] [--retry N] [--timeout N] [--workers N] [--json]")
		os.Exit(1)
	}

	results, summary, err := callRustChecker(*username, *proxy, *retry, *timeout, *workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	// Also run Python fallback for email/breach/phone/domain checks if available
	// (future enhancement)

	if *jsonOut {
		output := map[string]interface{}{
			"username": *username,
			"results":  results,
			"summary":  summary,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(output)
		return
	}

	fmt.Printf("\n=== OSINT Check Results for '%s' ===\n\n", *username)
	if summary != nil {
		fmt.Printf("Total sites: %d | Hits: %d | Possible: %d | Unknown: %d\n\n",
			summary.Total, summary.Hits, summary.Possible, summary.Unknown)
	}

	fmt.Println("--- FOUND ACCOUNTS ---")
	for _, r := range results {
		if r.Status == "hit" {
			fmt.Printf("[+] %s (%s) - %s\n", r.Platform, r.Category, r.Url)
			if r.Title != "" {
				fmt.Printf("    Title: %s\n", r.Title)
			}
		}
	}

	fmt.Println("\n--- POSSIBLE ---")
	for _, r := range results {
		if r.Status == "possible" {
			fmt.Printf("[?] %s - %s\n", r.Platform, r.Url)
		}
	}

	fmt.Println("\n--- NOT FOUND ---")
	for _, r := range results {
		if r.Status == "miss" {
			fmt.Printf("[-] %s - %s\n", r.Platform, r.Url)
		}
	}
}
