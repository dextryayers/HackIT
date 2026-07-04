package main

import (
	"fmt"
	"strings"
	"time"
)

type ScanReport struct {
	Target      string   `json:"target"`
	Timestamp   string   `json:"timestamp"`
	Duration    string   `json:"duration"`
	TotalTests  int      `json:"total_tests"`
	Found       int      `json:"found"`
	Results     []Result `json:"results"`
	EnginesUsed []string `json:"engines_used"`
	Summary     string   `json:"summary"`
}

func GenerateReport(target string, results []Result, duration time.Duration, requestCount int) ScanReport {
	engines := []string{
		"Query Params", "Body POST", "Header Inject",
		"Path Inject", "DOM/Client", "Bypass",
		"Blind Redirect", "Deep Payload",
		"Cookie Redirect", "Encoding Matrix",
	}

	r := ScanReport{
		Target:      target,
		Timestamp:   time.Now().Format(time.RFC3339),
		Duration:    duration.Round(time.Millisecond).String(),
		TotalTests:  requestCount,
		Found:       len(results),
		Results:     results,
		EnginesUsed: engines,
	}

	if len(results) > 0 {
		r.Summary = fmt.Sprintf("VULNERABLE: %d open redirect(s) found across %d engine(s)", len(results), countUsedEngines(results))
	} else {
		r.Summary = "NOT VULNERABLE: No open redirect vulnerabilities detected"
	}

	return r
}

func countUsedEngines(results []Result) int {
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.Engine] = true
	}
	return len(seen)
}

func PrintSummary(target string, results []Result, duration time.Duration, requestCount int) {
	fmt.Printf("\n  %s", strings.Repeat("=", 55))
	fmt.Printf("\n  REDIRECT SCAN SUMMARY")
	fmt.Printf("\n  %s", strings.Repeat("=", 55))
	fmt.Printf("\n  Target    : %s", target)
	fmt.Printf("\n  Duration  : %v", duration.Round(time.Millisecond))
	fmt.Printf("\n  Requests  : %d", requestCount)
	fmt.Printf("\n  Found     : %d vulnerabilities", len(results))

	if len(results) > 0 {
		fmt.Printf("\n  %s", strings.Repeat("-", 55))
		fmt.Printf("\n  ENGINES WITH FINDINGS:")
		engineMap := make(map[string][]Result)
		for _, r := range results {
			engineMap[r.Engine] = append(engineMap[r.Engine], r)
		}
		for eng, res := range engineMap {
			fmt.Printf("\n    \033[32m[+]\033[0m %s: %d finding(s)", eng, len(res))
		}
	}

	fmt.Printf("\n  %s\n", strings.Repeat("=", 55))
}

func PrintDetailed(engines string, results []Result) {
	if len(results) == 0 {
		return
	}

	fmt.Printf("\n  %s", strings.Repeat("=", 55))
	fmt.Printf("\n  OPEN REDIRECT VULNERABILITIES DETAILED")
	fmt.Printf("\n  %s", strings.Repeat("=", 55))

	engineMap := make(map[string][]Result)
	for _, r := range results {
		engineMap[r.Engine] = append(engineMap[r.Engine], r)
	}

	for eng, res := range engineMap {
		fmt.Printf("\n\n  \033[1m[%s]\033[0m (%d):", eng, len(res))
		for _, r := range res {
			fmt.Printf("\n    \033[32m[+] FOUND VULNERABILITY\033[0m > %s", r.URL)
			if r.Parameter != "" {
				fmt.Printf("\n        Parameter : %s", r.Parameter)
			}
			if r.Payload != "" {
				fmt.Printf("\n        Payload   : %s", r.Payload)
			}
			if r.Location != "" {
				fmt.Printf("\n        Redirects : %s", r.Location)
			}
			if r.HTTPStatus > 0 {
				fmt.Printf("\n        Status    : %d", r.HTTPStatus)
			}
			if r.BodyCheck != "" {
				fmt.Printf("\n        Detection : %s", r.BodyCheck)
			}
			fmt.Printf("\n        Engine    : %s", eng)
		}
	}
}
