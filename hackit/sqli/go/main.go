package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"hackit/sqli/go/core"
	"hackit/sqli/go/crawl"
)

func main() {
	opts := &core.Options{}
	var headerList, tamperList, outputFormat string

	// Basic request options.
	flag.StringVar(&opts.URL, "u", "", "Target URL")
	flag.StringVar(&opts.URL, "url", "", "Target URL (long form)")
	flag.StringVar(&opts.Data, "data", "", "Request body (form or JSON)")
	flag.StringVar(&opts.Cookie, "cookie", "", "Cookie header")
	flag.StringVar(&headerList, "header", "", "Custom headers, comma separated (Name:Value,Name:Value)")
	flag.StringVar(&opts.Agent, "agent", "HackIT/4.0", "User-Agent")
	flag.StringVar(&opts.Referer, "referer", "", "Referer header")
	flag.StringVar(&opts.Method, "method", "GET", "HTTP method")
	flag.IntVar(&opts.Timeout, "timeout", 15, "Request timeout in seconds")
	flag.StringVar(&opts.Proxy, "proxy", "", "Proxy URL")
	flag.BoolVar(&opts.FollowRedirect, "follow-redirect", false, "Follow redirects")

	// Injection options.
	flag.StringVar(&opts.Mode, "mode", "auto", "Injection mode")
	flag.StringVar(&opts.Technique, "technique", "auto", "Technique: auto, union, error, boolean, time, stacked")
	flag.StringVar(&opts.DBMS, "dbms", "", "Force DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, ClickHouse, DuckDB, CockroachDB, Snowflake, BigQuery, Firebird, Sybase, H2")
	flag.IntVar(&opts.Level, "level", 1, "Injection level (1-3): 1 query/body, 2 adds cookies, 3 adds headers")
	flag.IntVar(&opts.RiskLevel, "risk-level", 1, "Risk level (1-3)")
	flag.IntVar(&opts.Depth, "depth", 2, "Scan depth")
	flag.IntVar(&opts.Threads, "threads", 10, "Concurrent workers")
	flag.IntVar(&opts.Delay, "delay", 0, "Delay in milliseconds")
	flag.BoolVar(&opts.RandomCase, "randomize-case", false, "Randomize payload case")
	flag.StringVar(&tamperList, "tamper", "", "Tamper scripts, comma separated")
	flag.StringVar(&opts.Encode, "encode", "", "Encoding: url, double, base64")
	flag.BoolVar(&opts.BypassWAF, "bypass-waf", false, "Enable WAF bypass")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Stealth mode")
	flag.StringVar(&opts.Param, "param", "", "Only test these parameters, comma separated")
	flag.StringVar(&opts.SkipParam, "skip-param", "", "Skip these parameters, comma separated")
	flag.StringVar(&opts.Prefix, "prefix", "", "Force injection prefix")
	flag.StringVar(&opts.Suffix, "suffix", "", "Force injection suffix")

	// Detection options.
	flag.BoolVar(&opts.Fingerprint, "fingerprint", false, "Fingerprint the DBMS")
	flag.BoolVar(&opts.BannerGrab, "banner-grab", false, "Grab the DBMS banner")
	flag.BoolVar(&opts.OSDetect, "os-detect", false, "Detect the operating system")
	flag.BoolVar(&opts.WAFDetect, "waf-detect", false, "Detect WAF/IPS")
	flag.BoolVar(&opts.SmartDiff, "smart-diff", false, "Use smart response diffing")
	flag.BoolVar(&opts.Baseline, "baseline", false, "Collect baseline responses")
	flag.BoolVar(&opts.TechDetect, "tech-detect", false, "Detect backend technology")

	// Enumeration options.
	flag.BoolVar(&opts.ListDBs, "list-dbs", false, "List databases")
	flag.BoolVar(&opts.ListTables, "list-tables", false, "List tables")
	flag.BoolVar(&opts.ListColumns, "list-columns", false, "List columns")
	flag.StringVar(&opts.Database, "db", "", "Database name")
	flag.StringVar(&opts.Table, "table", "", "Table name")
	flag.StringVar(&opts.Column, "column", "", "Column name")
	flag.BoolVar(&opts.Schema, "schema", false, "Dump schema")
	flag.BoolVar(&opts.CountRows, "count-rows", false, "Count rows")
	flag.StringVar(&opts.Search, "search", "", "Search table and column names")
	flag.StringVar(&opts.DumpTable, "dump-table", "", "Dump table")
	flag.BoolVar(&opts.DumpAll, "dump-all", false, "Dump all interesting tables")
	flag.StringVar(&opts.SQLQuery, "sql-query", "", "Run a scalar SQL query")
	flag.IntVar(&opts.Rows, "rows", 50, "Maximum rows to dump")
	flag.IntVar(&opts.Limit, "limit", 50, "Maximum rows per table")
	flag.IntVar(&opts.Offset, "offset", 0, "Row offset")
	flag.StringVar(&opts.Where, "where", "", "WHERE clause for dump")
	flag.StringVar(&opts.ColumnsCSV, "columns-csv", "", "Columns to dump, comma separated")
	flag.IntVar(&opts.MaxLength, "max-length", 512, "Maximum blind extraction length")
	flag.IntVar(&opts.TimeSecs, "time-secs", 3, "Time-based delay in seconds")

	// Metadata shortcuts.
	flag.BoolVar(&opts.CurrentDB, "current-db", false, "Show current database")
	flag.BoolVar(&opts.CurrentUser, "current-user", false, "Show current user")
	flag.BoolVar(&opts.Hostname, "hostname", false, "Show database hostname")
	flag.BoolVar(&opts.Banner, "banner", false, "Show DBMS banner")
	flag.BoolVar(&opts.Privileges, "privileges", false, "Show privileges")
	flag.BoolVar(&opts.IsDBA, "is-dba", false, "Check DBA privileges")
	flag.BoolVar(&opts.Users, "users", false, "List database users")
	flag.BoolVar(&opts.Passwords, "passwords", false, "List password hashes")
	flag.BoolVar(&opts.Roles, "roles", false, "List roles")

	// Exploitation options.
	flag.BoolVar(&opts.PrivEsc, "priv-esc", false, "Privilege escalation")
	flag.BoolVar(&opts.OSAccess, "os-access", false, "OS access")
	flag.BoolVar(&opts.ExfilDNS, "exfil-dns", false, "DNS exfiltration")
	flag.BoolVar(&opts.ExfilHTTP, "exfil-http", false, "HTTP exfiltration")

	// Crawl options.
	flag.StringVar(&opts.CrawlMode, "crawl", "", "Crawl mode: full, schema, sensitive, system")
	flag.IntVar(&opts.CrawlDepth, "crawl-depth", 5, "Crawl depth")
	flag.IntVar(&opts.CrawlThreads, "crawl-threads", 10, "Crawl workers")
	flag.BoolVar(&opts.CrawlExtract, "crawl-extract", true, "Extract data while crawling")
	flag.BoolVar(&opts.CrawlSensitive, "crawl-sensitive", true, "Scan sensitive data")
	flag.BoolVar(&opts.CrawlProcs, "crawl-procs", true, "Extract procedures")
	flag.BoolVar(&opts.CrawlViews, "crawl-views", true, "Extract views")
	flag.BoolVar(&opts.CrawlIndexes, "crawl-indexes", true, "Extract indexes")
	flag.BoolVar(&opts.CrawlSystem, "crawl-system", true, "Extract system information")
	flag.StringVar(&opts.CrawlOutput, "crawl-output", "crawl_output", "Output directory")
	flag.StringVar(&opts.CrawlReport, "crawl-report", "json", "Report format")

	// Extraction options.
	flag.StringVar(&opts.ExtractTechnique, "extract-technique", "auto", "Extraction technique")
	flag.StringVar(&opts.ExtractCharset, "extract-charset", "common", "Blind extraction charset")
	flag.IntVar(&opts.ExtractWorkers, "extract-workers", 5, "Extraction workers")
	flag.IntVar(&opts.ExtractBatchSize, "extract-batch", 100, "Extraction batch size")

	// Network options.
	flag.BoolVar(&opts.NetworkScan, "network-scan", false, "Network scan")
	flag.StringVar(&opts.ScanTarget, "scan-target", "", "Network scan target")
	flag.StringVar(&opts.ScanPorts, "scan-ports", "", "Ports to scan")

	// Authentication options.
	flag.BoolVar(&opts.AuthBypass, "auth-bypass", false, "Authentication bypass")
	flag.StringVar(&opts.AuthUser, "auth-user", "admin", "Authentication username")
	flag.StringVar(&opts.AuthPass, "auth-pass", "password", "Authentication password")

	// File operation options.
	flag.StringVar(&opts.FileRead, "file-read", "", "Read a file from the database server")
	flag.StringVar(&opts.FileWrite, "file-write", "", "Write a file on the database server")
	flag.StringVar(&opts.FileExec, "file-exec", "", "Execute an OS command through the database")

	// Out-of-band options.
	flag.StringVar(&opts.OOBChannel, "oob-channel", "dns", "OOB channel: dns, http, smb")
	flag.StringVar(&opts.OOBDomain, "oob-domain", "", "OOB domain")

	// Misc options.
	flag.BoolVar(&opts.NoColor, "no-color", false, "Disable colored output")
	flag.IntVar(&opts.Verbose, "verbose", 1, "Verbose level")
	flag.IntVar(&opts.Verbose, "v", 1, "Verbose shorthand")
	flag.IntVar(&opts.Retry, "retry", 2, "Retry count")
	flag.StringVar(&outputFormat, "output-format", "json", "Output format: json or ndjson")

	flag.Parse()

	if opts.URL == "" && !opts.NetworkScan {
		fmt.Println(`{"error": "URL is required (use -u)"}`)
		os.Exit(1)
	}

	if headerList != "" {
		for _, h := range strings.Split(headerList, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				opts.Header = append(opts.Header, h)
			}
		}
	}
	if tamperList != "" {
		for _, t := range strings.Split(tamperList, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				opts.Tamper = append(opts.Tamper, t)
			}
		}
	}

	engine := core.NewEngine(opts)

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

		param := opts.Param
		if param == "" {
			if points, err := core.DiscoverInjectionPoints(opts); err == nil && len(points) > 0 {
				param = points[0].Name
			}
		}
		if param == "" {
			param = "id"
		}
		dbms := opts.DBMS
		if dbms == "" {
			dbms = "MySQL"
		}
		master := crawl.NewCrawlMaster(engine, cfg)
		results, err := master.Run(param, dbms, nil)
		if err != nil {
			fmt.Printf(`{"error": "%v"}`, err)
			os.Exit(1)
		}
		report := crawl.NewCrawlReport(results, engine.GetLogger(), nil)
		report.PrintToConsole()
		out, _ := json.Marshal(results)
		fmt.Println(string(out))
		return
	}

	results := engine.StartV2()
	if outputFormat == "ndjson" {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range results {
			_ = enc.Encode(r)
		}
		return
	}
	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}
