package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hackit/sqli/go/core"
	"hackit/sqli/go/crawl"
	"os"
	"strings"
)

func main() {
	opts := &core.Options{}
	var outputFormat, tamperList string

	// === BASIC ===
	flag.StringVar(&opts.URL, "u", "", "Target URL")
	flag.StringVar(&opts.Data, "data", "", "POST body")
	flag.StringVar(&opts.Cookie, "cookie", "", "Cookie header")
	flag.StringVar(&tamperList, "header", "", "Custom headers (k1:v1,k2:v2)")
	flag.StringVar(&opts.Agent, "agent", "HackIT/4.0", "User-Agent")
	flag.StringVar(&opts.Referer, "referer", "", "Referer header")
	flag.StringVar(&opts.Method, "method", "GET", "HTTP method")
	flag.IntVar(&opts.Timeout, "timeout", 10, "Request timeout (s)")
	flag.StringVar(&opts.Proxy, "proxy", "", "Proxy URL")
	flag.BoolVar(&opts.FollowRedirect, "follow-redirect", false, "Follow redirects")

	// === INJECTION ===
	flag.StringVar(&opts.Mode, "mode", "auto", "Injection mode")
	flag.IntVar(&opts.RiskLevel, "risk-level", 1, "Risk level (1-3)")
	flag.IntVar(&opts.Depth, "depth", 2, "Scan depth")
	flag.IntVar(&opts.Threads, "threads", 10, "Concurrent workers")
	flag.IntVar(&opts.Delay, "delay", 0, "Delay (ms)")
	flag.BoolVar(&opts.RandomCase, "randomize-case", false, "Random case")
	flag.StringVar(&tamperList, "tamper", "", "Tamper scripts (comma)")
	flag.StringVar(&opts.Encode, "encode", "", "Encoding (url/double/base64)")
	flag.BoolVar(&opts.BypassWAF, "bypass-waf", false, "WAF bypass")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Stealth mode")

	// === DETECTION ===
	flag.BoolVar(&opts.Fingerprint, "fingerprint", false, "DB fingerprint")
	flag.BoolVar(&opts.BannerGrab, "banner-grab", false, "Banner grab")
	flag.BoolVar(&opts.OSDetect, "os-detect", false, "OS detection")
	flag.BoolVar(&opts.WAFDetect, "waf-detect", false, "WAF detection")
	flag.BoolVar(&opts.SmartDiff, "smart-diff", false, "Smart diff")
	flag.BoolVar(&opts.Baseline, "baseline", false, "Baseline request")
	flag.BoolVar(&opts.TechDetect, "tech-detect", false, "Tech detection")

	// === ENUMERATION ===
	flag.BoolVar(&opts.ListDBs, "list-dbs", false, "List databases")
	flag.BoolVar(&opts.ListTables, "list-tables", false, "List tables")
	flag.BoolVar(&opts.ListColumns, "list-columns", false, "List columns")
	flag.StringVar(&opts.Database, "db", "", "Database name")
	flag.StringVar(&opts.Table, "table", "", "Table name")
	flag.StringVar(&opts.Column, "column", "", "Column name")
	flag.BoolVar(&opts.Schema, "schema", false, "Dump schema")
	flag.BoolVar(&opts.CountRows, "count-rows", false, "Count rows")
	flag.StringVar(&opts.Search, "search", "", "Search keyword")
	flag.StringVar(&opts.DumpTable, "dump-table", "", "Dump table")
	flag.BoolVar(&opts.DumpAll, "dump-all", false, "Dump all")

	// === EXPLOIT ===
	flag.BoolVar(&opts.PrivEsc, "priv-esc", false, "Privilege escalation")
	flag.BoolVar(&opts.OSAccess, "os-access", false, "OS access")
	flag.BoolVar(&opts.ExfilDNS, "exfil-dns", false, "DNS exfiltration")
	flag.BoolVar(&opts.ExfilHTTP, "exfil-http", false, "HTTP exfiltration")

	// === CRAWL ===
	flag.StringVar(&opts.CrawlMode, "crawl", "", "Crawl mode (full/schema/sensitive/system)")
	flag.IntVar(&opts.CrawlDepth, "crawl-depth", 5, "Crawl depth")
	flag.IntVar(&opts.CrawlThreads, "crawl-threads", 10, "Crawl workers")
	flag.BoolVar(&opts.CrawlExtract, "crawl-extract", true, "Extract data")
	flag.BoolVar(&opts.CrawlSensitive, "crawl-sensitive", true, "Scan sensitive")
	flag.BoolVar(&opts.CrawlProcs, "crawl-procs", true, "Extract procedures")
	flag.BoolVar(&opts.CrawlViews, "crawl-views", true, "Extract views")
	flag.BoolVar(&opts.CrawlIndexes, "crawl-indexes", true, "Extract indexes")
	flag.BoolVar(&opts.CrawlSystem, "crawl-system", true, "Extract system info")
	flag.StringVar(&opts.CrawlOutput, "crawl-output", "crawl_output", "Output dir")
	flag.StringVar(&opts.CrawlReport, "crawl-report", "json", "Report format")

	// === EXTRACTION ===
	flag.StringVar(&opts.ExtractTechnique, "extract-technique", "auto", "Extraction technique")
	flag.StringVar(&opts.ExtractCharset, "extract-charset", "common", "Charset for blind")
	flag.IntVar(&opts.ExtractWorkers, "extract-workers", 5, "Extraction workers")
	flag.IntVar(&opts.ExtractBatchSize, "extract-batch", 100, "Batch size")

	// === NETWORK ===
	flag.BoolVar(&opts.NetworkScan, "network-scan", false, "Network scan")
	flag.StringVar(&opts.ScanTarget, "scan-target", "", "Scan target IP")
	flag.StringVar(&opts.ScanPorts, "scan-ports", "", "Ports to scan")

	// === AUTH ===
	flag.BoolVar(&opts.AuthBypass, "auth-bypass", false, "Auth bypass")
	flag.StringVar(&opts.AuthUser, "auth-user", "admin", "Auth username")
	flag.StringVar(&opts.AuthPass, "auth-pass", "password", "Auth password")

	// === FILE OPS ===
	flag.StringVar(&opts.FileRead, "file-read", "", "Read file")
	flag.StringVar(&opts.FileWrite, "file-write", "", "Write file")
	flag.StringVar(&opts.FileExec, "file-exec", "", "Execute command")

	// === OOB ===
	flag.StringVar(&opts.OOBChannel, "oob-channel", "dns", "OOB channel")
	flag.StringVar(&opts.OOBDomain, "oob-domain", "", "OOB domain")

	// === MISC ===
	flag.BoolVar(&opts.NoColor, "no-color", false, "No color output")
	flag.IntVar(&opts.Verbose, "verbose", 1, "Verbose level")
	flag.IntVar(&opts.Verbose, "v", 1, "Verbose (shorthand)")
	flag.IntVar(&opts.Retry, "retry", 3, "Retry count")
	flag.StringVar(&outputFormat, "output-format", "json", "Output format")

	flag.Parse()

	if tamperList != "" {
		opts.Tamper = strings.Split(tamperList, ",")
		opts.Header = strings.Split(tamperList, ",")
	}

	if opts.URL == "" && !opts.NetworkScan {
		fmt.Println(`{"error": "URL is required (use -u)"}`)
		os.Exit(1)
	}

	// Initialize engine
	engine := core.NewEngine(opts)

	// === CRAWL MODE ===
	if opts.CrawlMode != "" {
		cfg := crawl.DefaultCrawlConfig()
		cfg.MaxDepth = opts.CrawlDepth
		cfg.MaxThreads = opts.CrawlThreads
		cfg.ExtractData = opts.CrawlExtract
		cfg.ExtractSensitive = opts.CrawlSensitive
		cfg.ExtractProcs = opts.CrawlProcs
		cfg.ExtractViews = opts.CrawlViews
		cfg.ExtractIndexes = opts.CrawlIndexes
		cfg.ExtractSystem = opts.CrawlSystem
		cfg.OutputDir = opts.CrawlOutput

		master := crawl.NewCrawlMaster(engine, cfg)

		param := "id"
		dbms := "MySQL"
		if opts.Fingerprint {
			detector := engine.Start()
			for _, r := range detector {
				if r.Type == "fingerprint" {
					dbms = r.DBMS
				}
			}
		}
		if opts.Database != "" {
			results, err := master.Run(param, dbms, nil)
			if err != nil {
				fmt.Printf(`{"error": "%v"}`, err)
				os.Exit(1)
			}
			out, _ := json.Marshal(results)
			fmt.Println(string(out))
			return
		}

		results, err := master.Run(param, dbms, nil)
		if err != nil {
			fmt.Printf(`{"error": "%v"}`, err)
			os.Exit(1)
		}

		// Generate report
		report := crawl.NewCrawlReport(results, engine.GetLogger(), nil)
		report.PrintToConsole()

		out, _ := json.Marshal(results)
		fmt.Println(string(out))
		return
	}

	// === NORMAL MODE ===
	results := engine.Start()
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}
