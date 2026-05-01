package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hackit/sqli/go/core"
	"os"
	"strings"
)

func main() {
	opts := &core.Options{}

	flag.StringVar(&opts.URL, "u", "", "URL target")
	flag.StringVar(&opts.Data, "data", "", "Raw POST body")
	flag.StringVar(&opts.Cookie, "cookie", "", "Custom cookie")
	var headers string
	flag.StringVar(&headers, "header", "", "Custom headers (comma separated)")
	flag.StringVar(&opts.Agent, "agent", "HackIt/2.0", "Custom user-agent")
	flag.StringVar(&opts.Referer, "referer", "", "Custom referer")
	flag.StringVar(&opts.Method, "method", "GET", "HTTP method")
	flag.IntVar(&opts.Timeout, "timeout", 10, "Timeout request")
	flag.StringVar(&opts.Proxy, "proxy", "", "Proxy support")
	flag.BoolVar(&opts.FollowRedirect, "follow-redirect", false, "Auto follow redirect")

	flag.StringVar(&opts.Mode, "mode", "auto", "Injection mode")
	flag.IntVar(&opts.RiskLevel, "risk-level", 1, "Risk level")
	flag.IntVar(&opts.Depth, "depth", 2, "Scan depth")
	flag.IntVar(&opts.Threads, "threads", 10, "Concurrent workers")
	flag.IntVar(&opts.Delay, "delay", 0, "Delay in ms")
	flag.BoolVar(&opts.RandomCase, "randomize-case", false, "Random case payload")
	flag.BoolVar(&opts.BypassWAF, "bypass-waf", false, "Enable WAF evasion")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Stealth mode")

	flag.BoolVar(&opts.Fingerprint, "fingerprint", false, "Detect DB engine")
	flag.BoolVar(&opts.BannerGrab, "banner-grab", false, "Extract DB banner")
	flag.BoolVar(&opts.OSDetect, "os-detect", false, "Detect OS backend")
	flag.BoolVar(&opts.WAFDetect, "waf-detect", false, "Detect WAF")
	flag.BoolVar(&opts.SmartDiff, "smart-diff", false, "Smart response compare")
	flag.BoolVar(&opts.TechDetect, "tech-detect", false, "Detect all backend tech")

	flag.BoolVar(&opts.ListDBs, "list-dbs", false, "Enumerate databases")
	flag.BoolVar(&opts.ListTables, "list-tables", false, "Enumerate tables")
	flag.BoolVar(&opts.ListColumns, "list-columns", false, "Enumerate columns")
	flag.StringVar(&opts.Database, "db", "", "Target database")
	flag.StringVar(&opts.Table, "table", "", "Target table")
	flag.StringVar(&opts.Column, "column", "", "Target column")
	flag.BoolVar(&opts.Schema, "schema", false, "Dump structure only")
	flag.StringVar(&opts.DumpTable, "dump-table", "", "Dump specific table")
	flag.BoolVar(&opts.DumpAll, "dump-all", false, "Dump everything")

	flag.IntVar(&opts.Verbose, "verbose", 0, "Verbose level")
	flag.BoolVar(&opts.NoColor, "no-color", false, "Disable color")
	flag.IntVar(&opts.Retry, "retry", 3, "Retry count")

	flag.Parse()

	if opts.URL == "" {
		fmt.Println(`{"error": "URL is required"}`)
		os.Exit(1)
	}

	if headers != "" {
		opts.Header = strings.Split(headers, ",")
	}

	// Execute actual engine logic
	engine := core.NewEngine(opts)
	results := engine.Start()

	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}
