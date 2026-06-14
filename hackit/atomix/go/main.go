package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type flagSet struct {
	*flag.FlagSet
	cfg     *ScanConfig
	rawArgs []string
}

func main() {
	cfg := &ScanConfig{}

	// Section 1: Target & Scope
	flag.StringVar(&cfg.URL, "u", "", "Target URL to scan")
	flag.StringVar(&cfg.URL, "target", "", "Target URL to scan (alias)")
	flag.StringVar(&cfg.TargetFile, "target-file", "", "File containing target URLs (one per line)")
	flag.StringVar(&cfg.ResumeFile, "resume", "", "Resume scan from a previous resume file")
	flag.StringVar(&cfg.ExcludeFile, "exclude-file", "", "File containing URLs/hosts to exclude")
	flag.StringVar(&cfg.ScopeFile, "scope-file", "", "File containing allowed scope patterns")
	flag.StringVar(&cfg.ExcludePat, "ep", "", "Exclude URLs matching regex patterns")
	flag.StringVar(&cfg.ExcludeTags, "etag", "", "Exclude templates with given tags")
	flag.StringVar(&cfg.ExcludeTags, "es", "", "Exclude templates with given severity (alias)")
	flag.StringVar(&cfg.ExcludeTags, "esev", "", "Exclude templates with given severity")

	// Section 2: Template Management
	flag.StringVar(&cfg.TemplateDir, "t", "../template", "Template directory path")
	flag.StringVar(&cfg.TemplateDir, "templates", "../template", "Template directory path (alias)")
	flag.StringVar(&cfg.ID, "id", "", "Run a specific template by ID")
	flag.StringVar(&cfg.Tags, "tags", "", "Filter by tags (comma-separated)")
	flag.StringVar(&cfg.Severity, "severity", "", "Filter by severity (info,low,medium,high,critical)")
	flag.StringVar(&cfg.Severity, "s", "", "Filter by severity (shorthand)")
	flag.StringVar(&cfg.Author, "author", "", "Filter by template author")
	flag.StringVar(&cfg.Type, "type", "", "Filter by template type")
	flag.Bool("l", false, "List all available templates")
	flag.Bool("list", false, "List all available templates (alias)")
	flag.Bool("validate", false, "Validate all templates")
	flag.BoolVar(&cfg.UpdateTemplates, "update", false, "Update templates from Nuclei template hub")
	flag.Bool("validate-deep", false, "Deep validation with schema checking")
	flag.StringVar(&cfg.ConfigFile, "config", "", "Atomix config file path")
	flag.StringVar(&cfg.CustomTemplateDir, "custom-templates", "", "Custom template directory path")
	flag.StringVar(&cfg.CustomTemplateDir, "custom-dir", "", "Custom template directory (alias)")
	flag.Bool("no-cache", false, "Disable template compilation caching")
	flag.BoolVar(&cfg.Priority, "priority", false, "Priority scheduling (critical/high first)")
	flag.StringVar(&cfg.LoadFiles, "load", "", "Load specific template file, directory, or URL (comma-separated)")
	flag.StringVar(&cfg.LoadFiles, "template-file", "", "Load specific template file (alias)")
	flag.StringVar(&cfg.FromGit, "from-git", "", "Load templates from a git repository URL")
	flag.Bool("list-sources", false, "List all custom template sources")
	flag.Bool("custom-guide", false, "Show custom template usage guide")

	// Section 3: Performance
	flag.IntVar(&cfg.Threads, "c", 20, "Concurrency (number of parallel templates)")
	flag.IntVar(&cfg.Threads, "concurrency", 20, "Concurrency (alias)")
	flag.IntVar(&cfg.Concurrency, "threads", 25, "Threads per template")
	flag.IntVar(&cfg.Timeout, "timeout", 60, "Request timeout in seconds")
	flag.IntVar(&cfg.Retries, "retries", 0, "Max retries per request")
	flag.IntVar(&cfg.MaxHostError, "max-host-error", 30, "Max errors per host before skip")
	// Rate limit / bulk
	flag.IntVar(&cfg.RateLimit, "rate-limit", 0, "Rate limit (requests per second)")
	flag.IntVar(&cfg.BulkSize, "bulk-size", 0, "Bulk size for batch processing")
	flag.Bool("stream", false, "Stream mode (output findings in real-time)")
	flag.BoolVar(&cfg.AdaptiveRate, "adaptive-rate", false, "Adaptive rate limiting based on success rate")

	// Section 4: Network
	flag.StringVar(&cfg.Resolver, "r", "", "Custom DNS resolver (host:port)")
	flag.StringVar(&cfg.Resolver, "resolvers", "", "Custom resolvers (comma-separated)")
	flag.StringVar(&cfg.Resolver, "resolver", "", "Custom resolver (alias)")
	flag.BoolVar(&cfg.ScanAllIps, "scan-all-ips", false, "Scan all resolved IPs")
	flag.StringVar(&cfg.IP, "ip-version", "", "IP version to use (4 or 6)")
	flag.StringVar(&cfg.Port, "exclude-ports", "", "Ports to exclude from scan")
	flag.StringVar(&cfg.Path, "path", "", "Custom request path to use")
	flag.StringVar(&cfg.Method, "m", "", "HTTP method override (GET,POST,PUT,DELETE,etc.)")
	flag.StringVar(&cfg.Method, "method", "", "HTTP method override (alias)")
	flag.Bool("pn", false, "Pipeline mode (continuous scanning)")
	flag.Bool("pipeline", false, "Pipeline mode (alias)")
	flag.StringVar(&cfg.Payloads, "payloads", "", "Custom payloads file path")
	flag.StringVar(&cfg.Fuzz, "fuzz", "", "Fuzz mode (parameter/path/header)")
	flag.IntVar(&cfg.FuzzThread, "fuzz-thread", 10, "Fuzzer thread count")
	flag.BoolVar(&cfg.FuzzRecurse, "fuzz-recursive", false, "Recursive fuzzing on found paths")

	// Section 5: Output
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file path")
	flag.StringVar(&cfg.OutputFile, "output", "", "Output file path (alias)")
	flag.BoolVar(&cfg.JSON, "json", false, "Output results in JSON format")
	flag.BoolVar(&cfg.JSONL, "jsonl", false, "Output results in JSONL format")
	flag.BoolVar(&cfg.CSV, "csv", false, "Output results in CSV format")
	flag.BoolVar(&cfg.HTML, "html", false, "Output results in HTML format")
	flag.StringVar(&cfg.Markdown, "md", "", "Output results in Markdown format (file path)")
	flag.StringVar(&cfg.Markdown, "markdown", "", "Output results in Markdown format (alias)")
	flag.BoolVar(&cfg.SARIF, "sarif", false, "Output results in SARIF format")
	flag.BoolVar(&cfg.Silent, "silent", false, "Silent mode (no output except results)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output (alias)")
	flag.BoolVar(&cfg.Debug, "d", false, "Enable debug output")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug output (alias)")
	flag.BoolVar(&cfg.NoColor, "nc", false, "Disable colored output")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored output (alias)")
	flag.BoolVar(&cfg.Stats, "stats", false, "Show detailed statistics after scan")
	flag.BoolVar(&cfg.Metrics, "metrics", false, "Show metrics after scan")
	flag.BoolVar(&cfg.Analytics, "analytics", false, "Show template analytics (match rates, effectiveness)")
	flag.BoolVar(&cfg.MultiTarget, "multi", false, "Multi-target coordinated scanning")
	flag.StringVar(&cfg.TraceLog, "trace", "", "Enable trace logging to file")
	flag.StringVar(&cfg.TraceLog, "trace-log", "", "Trace log path (alias)")
	flag.StringVar(&cfg.ResumeCfg, "no-meta", "", "Disable metadata output")
	flag.StringVar(&cfg.ResumeCfg, "resume-cfg", "", "Resume configuration file")

	// Section 6: Network Config
	flag.StringVar(&cfg.Proxy, "p", "", "HTTP proxy URL (http://host:port)")
	flag.StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy URL (alias)")
	flag.StringVar(&cfg.ProxyAuth, "proxy-auth", "", "Proxy authentication (user:pass)")
	flag.IntVar(&cfg.MaxRedirects, "max-redirects", 5, "Maximum redirects to follow")
	flag.BoolVar(&cfg.FollowRedirects, "follow-redirects", false, "Follow HTTP redirects")
	flag.StringVar(&cfg.SNI, "sni", "", "Custom SNI name for TLS")

	// Section 7: HTTP Config
	flag.BoolVar(&cfg.RandomAgent, "rand-agent", false, "Use random User-Agent header")
	flag.StringVar(&cfg.CustomAgent, "custom-agent", "", "Custom User-Agent header value")
	flag.BoolVar(&cfg.HTTP2, "http2", false, "Enable HTTP/2 support")
	flag.BoolVar(&cfg.DisableHTTP2, "http2-downgrade", false, "Disable HTTP/2")
	flag.BoolVar(&cfg.KeepAlive, "keep-alive", false, "Enable HTTP keep-alive")
	flag.StringVar(&cfg.HeaderStr, "H", "", "Custom header (Name: Value) - can be repeated")
	flag.StringVar(&cfg.HeaderStr, "header", "", "Custom header (alias)")
	flag.StringVar(&cfg.Cookie, "cookie", "", "Set Cookie header")
	flag.StringVar(&cfg.CookieJar, "cookie-jar", "", "Cookie jar file path")

	// Section 8: Auth
	flag.StringVar(&cfg.BasicAuth, "auth", "", "Basic authentication (user:pass)")
	flag.StringVar(&cfg.BasicAuth, "auth-type", "", "Auth type (basic/bearer/api-key/oauth2)")
	flag.StringVar(&cfg.Bearer, "auth-token", "", "Bearer token authentication")
	flag.StringVar(&cfg.APIKey, "api-key", "", "API key for authentication")
	flag.StringVar(&cfg.AuthURL, "auth-url", "", "OAuth2 token URL")
	flag.StringVar(&cfg.AuthData, "auth-data", "", "OAuth2 request data")
	flag.StringVar(&cfg.ClientCert, "client-cert", "", "TLS client certificate file")
	flag.StringVar(&cfg.ClientKey, "client-key", "", "TLS client key file")
	flag.StringVar(&cfg.ClientCA, "client-ca", "", "TLS client CA file")

	// Section 9: Advanced
	flag.BoolVar(&cfg.WafSkip, "waf-skip", false, "Skip hosts protected by WAF")
	flag.BoolVar(&cfg.WafBypass, "waf-bypass", false, "Attempt WAF bypass techniques")
	flag.BoolVar(&cfg.DetectTech, "tech-detect", false, "Detect technologies used by target")
	flag.StringVar(&cfg.TechDB, "tech-db", "", "Custom technology signatures database")
	flag.BoolVar(&cfg.APIDiscovery, "api-discovery", false, "Discover API endpoints from responses")
	flag.BoolVar(&cfg.Interactsh, "interactsh", false, "Enable Interactsh OOB support")
	flag.StringVar(&cfg.InteractshServer, "oob-server", "", "Custom Interactsh server URL")
	flag.StringVar(&cfg.InteractshToken, "oob-token", "", "Interactsh authentication token")
	flag.StringVar(&cfg.OOBType, "oob-type", "", "OOB type (dns/http/ldap/rmi)")

	// Section 10: Chaining & Misc
	flag.StringVar(&cfg.Chain, "w", "", "Workflow file to execute")
	flag.StringVar(&cfg.Chain, "workflow", "", "Workflow file (alias)")
	flag.StringVar(&cfg.ChainVars, "chain-vars", "", "Chain variables (key=val,key=val)")
	flag.BoolVar(&cfg.SmartScan, "smart", false, "Smart scan (auto-select templates)")
	flag.BoolVar(&cfg.SmartScan, "smart-scan", false, "Smart scan (alias)")
	flag.StringVar(&cfg.Replay, "replay", "", "Replay a finding from JSON file")
	flag.StringVar(&cfg.Diff, "diff", "", "Diff two result JSON files (old:new)")
	flag.StringVar(&cfg.Monitor, "monitor", "", "Monitor mode: target:interval (seconds)")
	flag.BoolVar(&cfg.Web, "dashboard", false, "Enable web dashboard")
	flag.IntVar(&cfg.WebPort, "dashboard-port", 8484, "Dashboard port number")
	flag.StringVar(&cfg.WebPath, "dashboard-path", "/dashboard", "Dashboard URL path")
	flag.StringVar(&cfg.WebAuth, "dashboard-auth", "", "Dashboard auth (user:pass)")
	flag.StringVar(&cfg.Push, "push", "", "Push results to webhook URL")
	flag.StringVar(&cfg.PushFormat, "push-format", "json", "Push format (json/slack/telegram)")
	flag.StringVar(&cfg.TelegramBot, "telegram", "", "Telegram bot token for notifications")
	flag.StringVar(&cfg.TelegramChat, "telegram-chat", "", "Telegram chat ID for notifications")
	flag.StringVar(&cfg.SlackWebhook, "slack", "", "Slack webhook URL for notifications")
	flag.Bool("no-banner", false, "Skip banner display")
	flag.BoolVar(&cfg.Health, "health", false, "Run health check")
	flag.StringVar(&cfg.Completion, "completion", "", "Generate shell completion (bash/zsh/fish)")
	flag.Bool("version", false, "Show version information")
	flag.Bool("license", false, "Show license information")
	flag.BoolVar(&cfg.Examples, "examples", false, "Show usage examples")
	flag.Bool("probe", false, "Probe target and detect technologies")

	// Section 11: Headless Browser
	flag.BoolVar(&cfg.Headless, "headless", false, "Enable headless browser scanning")
	flag.StringVar(&cfg.HeadlessOpts, "headless-opt", "", "Chrome/Chromium options")
	flag.BoolVar(&cfg.NoSandbox, "no-sandbox", false, "Chrome no-sandbox mode")
	flag.BoolVar(&cfg.ShowBrowser, "show-browser", false, "Show browser window (debug)")
	flag.BoolVar(&cfg.SystemChrome, "system-chrome", false, "Use system Chrome instead of bundled")
	flag.StringVar(&cfg.UseChrome, "use-chrome", "", "Path to Chrome/Chromium executable")
	flag.IntVar(&cfg.PageTimeout, "headless-page-timeout", 10000, "Headless page load timeout (ms)")
	flag.IntVar(&cfg.ActionTimeout, "headless-action-timeout", 5000, "Headless action timeout (ms)")

	// Section 12: Project
	flag.StringVar(&cfg.Project, "project", "", "Project name for organized scanning")
	flag.StringVar(&cfg.ProjectPath, "project-path", "", "Project directory path")
	flag.BoolVar(&cfg.AllowLocalAccess, "allow-local-access", false, "Allow local file access in templates")

	// Section 13: Protocol Scanning
	flag.StringVar(&cfg.Protocol, "proto", "", "Protocol scanning mode (dns/tcp/tls/all)")
	flag.StringVar(&cfg.DnsResolvers, "dns-resolver", "", "Custom DNS resolver(s) for protocol scan")
	flag.BoolVar(&cfg.TlsImpersonate, "tls-impersonate", false, "TLS fingerprint impersonation")

	// Section 14: Uncover / Target Discovery
	flag.BoolVar(&cfg.Uncover, "uncover", false, "Enable target discovery via Shodan/Censys/etc")
	flag.StringVar(&cfg.UncoverEngine, "uncover-engine", "shodan", "Uncover engine (shodan/censys/fofa)")
	flag.StringVar(&cfg.UncoverQuery, "uncover-query", "", "Uncover search query")
	flag.IntVar(&cfg.UncoverLimit, "uncover-limit", 100, "Max uncover results")
	flag.StringVar(&cfg.UncoverField, "uncover-field", "ip:port", "Uncover output field (ip/host/ip:port)")

	// Section 15: Template Signing
	flag.StringVar(&cfg.Sign, "sign", "", "Sign a template file")
	flag.StringVar(&cfg.Verify, "verify", "", "Verify a template signature")
	flag.StringVar(&cfg.SignKey, "sign-key", "", "Private key file for signing")
	flag.StringVar(&cfg.SignPass, "sign-pass", "", "Signing key passphrase")
	flag.StringVar(&cfg.VerifyKey, "verify-key", "", "Public key file for verification")

	flag.Parse()

	// Handle --no-color early
	if hasFlag("nc") || hasFlag("no-color") {
		SetNoColor(true)
	}

	// Handle --completion early
	if comp := cfg.Completion; comp != "" {
		HandleCompletion(comp)
		return
	}

	// Handle --version
	if hasFlag("version") {
		fmt.Printf("Atomix v2.1.0 - Nuclei-Style YAML Template Scanner\n")
		fmt.Printf("Part of HackIT V2.1 - By: AniipID\n")
		return
	}

	// Handle --license
	if hasFlag("license") {
		fmt.Printf("Atomix - HackIT V2.1\n")
		fmt.Printf("Copyright (c) 2024 AniipID\n")
		fmt.Printf("MIT License\n")
		return
	}

	// Handle --sign
	if cfg.Sign != "" {
		HandleSignTemplate(cfg)
		return
	}

	// Handle --verify
	if cfg.Verify != "" {
		HandleVerifyTemplate(cfg)
		return
	}

	// Handle --examples
	if cfg.Examples {
		fmt.Println("\nAtomix Usage Examples:")
		fmt.Println("  atomix -u https://example.com                     # Basic scan")
		fmt.Println("  atomix -u https://example.com -severity high      # High severity only")
		fmt.Println("  atomix -u https://example.com -tags rce,oob       # RCE + OOB templates")
		fmt.Println("  atomix -u https://example.com -id log4j           # Specific template")
		fmt.Println("  atomix -u https://example.com -json -o result.json # JSON output")
		fmt.Println("  atomix -u https://example.com -c 50               # Higher concurrency")
		fmt.Println("  atomix -l                                         # List templates")
		fmt.Println("  atomix --validate                                 # Validate templates")
		fmt.Println("  atomix --update                                   # Update templates")
		fmt.Println("  atomix --health                                   # Health check")
		fmt.Println("  atomix --smart -u https://example.com             # Smart scan")
		fmt.Println("  atomix -u https://example.com -fuzz parameter     # Fuzz parameters")
		fmt.Println("  atomix -u https://example.com -tech-detect        # Tech detection")
		fmt.Println("  atomix -u https://example.com -w workflow.yaml    # Workflow")
		fmt.Println("  atomix --completion bash                          # Shell completion")
		fmt.Println()
		return
	}

	// Load config file if specified
	if cfg.ConfigFile != "" {
		fileCfg, err := LoadConfigFile(cfg.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Config error: %v\n", SColor(ColorRed, "[!]"), err)
			os.Exit(1)
		}
		MergeConfig(cfg, fileCfg)
	} else {
		// Try loading default config
		defaultCfg := LoadDefaultConfig()
		if defaultCfg != nil {
			MergeConfig(cfg, defaultCfg)
		}
	}

	listFlag := hasFlag("l") || hasFlag("list")
	listSourcesFlag := hasFlag("list-sources")
	customGuideFlag := hasFlag("custom-guide")
	validateFlag := hasFlag("validate") || hasFlag("validate-deep")
	validateDeep := hasFlag("validate-deep")
	updateFlag := cfg.UpdateTemplates
	healthFlag := cfg.Health
	probeFlag := hasFlag("probe")

	// Handle --update
	if updateFlag {
		err := UpdateTemplates(cfg.TemplateDir, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Update failed: %v\n", SColor(ColorRed, "[!]"), err)
			os.Exit(1)
		}
		return
	}

	// Validate templates
	if validateFlag {
		ValidateAll(cfg.TemplateDir)
		return
	}

	// List templates
	if listFlag {
		templates, err := LoadTemplates(cfg.TemplateDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error loading templates: %v\n", SColor(ColorRed, "[!]"), err)
			os.Exit(1)
		}
		PrintTemplateList(templates)
		return
	}

	// List custom template sources
	if listSourcesFlag {
		ListCustomTemplateDirs()
		return
	}

	// Show custom template guide
	if customGuideFlag {
		PrintCustomTemplateGuide()
		return
	}

	// Health check
	if healthFlag {
		report := RunHealthCheck(cfg)
		PrintHealthReport(report)
		return
	}

	// Need URL for most operations
	if cfg.URL == "" && cfg.TargetFile == "" {
		if probeFlag {
			fmt.Fprintf(os.Stderr, "%s Need a target URL: atomix --probe -u <url>\n", SColor(ColorRed, "[!]"))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Usage: atomix -u <target> [options]\n")
		fmt.Fprintf(os.Stderr, "       atomix -l              (list templates)\n")
		fmt.Fprintf(os.Stderr, "       atomix --validate      (validate templates)\n")
		fmt.Fprintf(os.Stderr, "       atomix --health        (health check)\n")
		fmt.Fprintf(os.Stderr, "       atomix --update        (update templates)\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Ensure no-banner flag is respected (for JSON output)
	noBanner := hasFlag("no-banner")

	// Protocol scan mode (doesn't need templates)
	if cfg.Protocol != "" {
		if !noBanner { PrintBanner() }
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Protocol scan: %s mode\n",
				SColor(ColorBCyan, "►"), strings.ToUpper(cfg.Protocol))
		}
		HandleProtocolScan(cfg)
		return
	}

	// Headless scan mode
	if cfg.Headless {
		if !noBanner { PrintBanner() }
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Headless browser scan: %s\n",
				SColor(ColorBCyan, "►"), cfg.URL)
		}
		HandleHeadlessMode(cfg, []string{cfg.URL})
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Headless scan complete\n",
				SColor(ColorGreen, "[+]"))
		}
		return
	}

	// Uncover target discovery
	if cfg.Uncover && cfg.UncoverQuery != "" {
		if !noBanner { PrintBanner() }
		discoveredTargets := HandleUncoverMode(cfg)
		if len(discoveredTargets) > 0 {
			cfg.Targets = append(cfg.Targets, discoveredTargets...)
		}
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Uncover complete: %d targets\n",
				SColor(ColorGreen, "[+]"), len(discoveredTargets))
		}
		// Continue to normal scan with discovered targets
	}

	// Load templates (with custom dir support)
	templateDirs := ResolveTemplateDirs(cfg)
	templates, err := LoadTemplatesFromDirs(templateDirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error loading templates: %v\n", SColor(ColorRed, "[!]"), err)
		os.Exit(1)
	}

	// Load individual template files from --load / --template-file
	if cfg.LoadFiles != "" {
		paths := strings.Split(cfg.LoadFiles, ",")
		for i := range paths {
			paths[i] = strings.TrimSpace(paths[i])
		}
		loaded, err := LoadTemplateFiles(paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error loading files: %v\n", SColor(ColorRed, "[!]"), err)
		}
		templates = append(templates, loaded...)
	}

	// Load from git repository
	if cfg.FromGit != "" {
		loaded, err := LoadTemplatesFromGit(cfg.FromGit, cfg.TemplateDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error loading from git: %v\n", SColor(ColorRed, "[!]"), err)
		}
		templates = append(templates, loaded...)
	}

	// Load from stdin pipe
	stdinTemplates, err := LoadTemplatesFromStdin()
	if err == nil && len(stdinTemplates) > 0 {
		templates = append(templates, stdinTemplates...)
	}

	if len(templates) == 0 {
		fmt.Fprintf(os.Stderr, "%s No templates found in %s\n", SColor(ColorYellow, "[!]"), cfg.TemplateDir)
		if !cfg.JSON && !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Use --update to download templates\n", SColor(ColorCyan, "[*]"))
		}
		os.Exit(1)
	}

	// Pre-compile templates into cache (skip if --no-cache)
	if !cfg.NoCache {
		cache := NewTemplateCache()
		compiled := cache.PrecompileAll(templates)
		if cfg.Verbose && !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Pre-compiled %d templates\n",
				SColor(ColorGreen, "[+]"), compiled)
		}
	}

	// Deep validation
	if validateDeep {
		ValidateTmux(templates)
		return
	}

	// Probe mode: detect tech only
	if probeFlag {
		client := NewHTTPClient(cfg.Timeout)
		PrintBanner()
		fmt.Fprintf(os.Stderr, "%s Probing: %s\n", SColor(ColorBCyan, "►"), cfg.URL)
		techs := DetectTechnologies(cfg.URL, client, cfg.TechDB)
		PrintTechDetections(techs)
		waf := DetectWAF(cfg.URL, client)
		if waf != nil {
			fmt.Fprintf(os.Stderr, "%s WAF Detected: %s\n", SColor(ColorYellow, "[!]"), waf.Product)
		} else {
			fmt.Fprintf(os.Stderr, "%s No WAF detected\n", SColor(ColorGreen, "[+]"))
		}
		return
	}

	// Resolve targets
	allTargets, err := LoadTargets(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error loading targets: %v\n", SColor(ColorRed, "[!]"), err)
		os.Exit(1)
	}

	// Filter templates
	parsedTags := parseTags(cfg.Tags)
	excludeTags := parseTags(cfg.ExcludeTags)
	filterOpts := FilterOptions{
		ID:          cfg.ID,
		Severity:    cfg.Severity,
		Tags:        parsedTags,
		ExcludeTags: excludeTags,
		Author:      cfg.Author,
	}
	filtered := FilterTemplates(templates, filterOpts)

	if len(filtered) == 0 {
		fmt.Fprintf(os.Stderr, "%s No templates match filters\n", SColor(ColorYellow, "[!]"))
		os.Exit(1)
	}

	// Smart scan reduces template set
	if cfg.SmartScan {
		before := len(filtered)
		filtered = SmartSelectTemplates(filtered, cfg.URL)
		PrintSmartInfo(before, len(filtered))
	}

	// Print banner
	if !cfg.JSON && !cfg.Silent && !noBanner {
		PrintBanner()
	}

	if !cfg.Silent {
		PrintLoadingInfo(len(filtered), filterOpts)
	}

	// WAF detection
	if !cfg.WafSkip {
		client := NewHTTPClient(cfg.Timeout)
		waf := DetectWAF(cfg.URL, client)
		if waf != nil && waf.Detected && !cfg.Silent {
			blockStr := ""
			if waf.BlockedCode > 0 { blockStr = fmt.Sprintf("blocked %d", waf.BlockedCode) }
			fmt.Fprintf(os.Stderr, "%s WAF Detected: %s %s\n",
				SColor(ColorYellow, "[!]"), waf.Product, blockStr)
		}
	}

	// Tech detection
	if cfg.DetectTech && !cfg.Silent {
		client := NewHTTPClient(cfg.Timeout)
		techs := DetectTechnologies(cfg.URL, client, cfg.TechDB)
		PrintTechDetections(techs)
	}

	// Priority scheduling
	if cfg.Priority {
		before := len(filtered)
		filtered = PrioritizeTemplates(filtered)
		if cfg.Verbose && !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Prioritized %d templates\n",
				SColor(ColorGreen, "[+]"), before)
		}
	}

	// Setup scanner
	scanner := NewScanner(cfg.Timeout, cfg.Threads)
	scanner.Templates = filtered
	scanner.Config = cfg
	scanner.Verbose = cfg.Verbose || cfg.Debug
	scanner.Deduplicator = NewDeduplicator()
	scanner.Stats = &ScanStats{
		TemplatesTotal: int32(len(filtered)),
		StartedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	// Stats collector
	if cfg.Analytics || cfg.Stats {
		scanner.StatsCollector = NewStatsCollector()
	}

	// Debugger / trace
	if cfg.Debug || cfg.TraceLog != "" {
		traceFile := cfg.TraceLog
		if traceFile == "" {
			traceFile = fmt.Sprintf("atomix-trace-%d.log", time.Now().Unix())
		}
		debugger := NewDebugger(cfg.Debug)
		debugger.StartSession("scan", traceFile)
		scanner.Debugger = debugger
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Trace logging to %s\n",
				SColor(ColorCyan, "[*]"), traceFile)
		}
	}

	// Adaptive rate limiter
	if cfg.AdaptiveRate || cfg.RateLimit > 0 {
		baseRate := cfg.RateLimit
		if baseRate == 0 { baseRate = 100 }
		arl := NewAdaptiveRateLimiter(baseRate, baseRate*2)
		_ = arl
		if cfg.Verbose && !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Rate limiting enabled (%d req/s)\n",
				SColor(ColorCyan, "[*]"), baseRate)
		}
	}

	// Handle monitor mode
	if cfg.Monitor != "" {
		mt := ParseMonitorConfig(cfg.Monitor)
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Monitor mode enabled\n", SColor(ColorBCyan, "►"))
		}
		go RunMonitor(mt, scanner)
		select {}
	}

	// Handle workflow mode
	if cfg.Chain != "" {
		results := LoadAndRunWorkflow(cfg.Chain, cfg.URL, scanner)
		duration := time.Since(scanner.StartTime).Round(time.Second)
		scanner.Stats.Duration = duration.String()
		if !cfg.Silent {
			scanner.Progress.Stop()
			scanner.Progress.Summary()
		}
		handleResults(results, cfg, scanner)
		return
	}

	// Multi-target coordinated scan
	var allResults []Result

	if cfg.MultiTarget && len(allTargets) > 1 {
		coordinator := NewMultiTargetCoordinator(allTargets, cfg)
		coordinator.ScannerConfig = cfg
		coordinator.Run()
		coordinator.mu.RLock()
		for _, results := range coordinator.Results {
			allResults = append(allResults, results...)
		}
		coordinator.mu.RUnlock()
		goto afterScan
	}

	// Scan each target
	for _, target := range allTargets {
		if !cfg.Silent && len(allTargets) > 1 {
			fmt.Fprintf(os.Stderr, "\n%s Target [%d/%d]: %s\n",
				SColor(ColorBCyan, "►"),
				len(allResults)+1, len(allTargets), target)
		}

		results := scanner.Scan(target)
		allResults = append(allResults, results...)

		// Fuzzing mode
		if cfg.Fuzz != "" {
			fuzzMode := FuzzMode(cfg.Fuzz)
			client := NewHTTPClient(cfg.Timeout)
			fuzzResults := FuzzTarget(target, fuzzMode, cfg.FuzzThread, cfg.FuzzRecurse, client)
			if !cfg.Silent {
				PrintFuzzResults(fuzzResults)
			}
		}
	}

afterScan:
	duration := time.Since(scanner.StartTime).Round(time.Second)
	scanner.Stats.Duration = duration.String()
	scanner.Stats.TargetsScanned = int32(len(allTargets))

	// API Discovery from response bodies
	if cfg.APIDiscovery && cfg.URL != "" {
		client := NewHTTPClient(cfg.Timeout)
		resp, err := SendRequest(client, cfg.URL, "GET", "", nil)
		if err == nil && resp != nil {
			discovered := DiscoverAPIs(resp.Body, cfg.URL)
			probed := ProbeCommonAPIs(cfg.URL, client)
			allEndpoints := append(discovered, probed...)
			if len(allEndpoints) > 0 {
				report := AnalyzeAPIEndpoints(allEndpoints)
				PrintAPIReport(report)
				ScanDiscoveredAPIs(cfg.URL, allEndpoints, scanner)
			}
		}
	}

	// Handle results
	if !cfg.Silent {
		scanner.Progress.Stop()
		scanner.Progress.Summary()
	}

	// Template analytics
	if cfg.Analytics && scanner.StatsCollector != nil {
		PrintTemplateAnalytics(scanner)
	}

	// If diff mode, compare with previous results
	if cfg.Diff != "" {
		parts := strings.SplitN(cfg.Diff, ":", 2)
		if len(parts) == 2 {
			entries, err := DiffResults(parts[0], parts[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s Diff error: %v\n", SColor(ColorRed, "[!]"), err)
			} else {
				PrintDiff(entries)
			}
		}
	}

	// Replay mode
	if cfg.Replay != "" {
		results, err := loadResultsFile(cfg.Replay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Replay error: %v\n", SColor(ColorRed, "[!]"), err)
		} else {
			replayRunner := NewReplayRunner(scanner)
			for _, r := range results {
				replayRunner.ReplayFinding(r)
			}
		}
	}

	handleResults(allResults, cfg, scanner)

	// Project mode: save results to project DB
	if cfg.Project != "" {
		HandleProjectMode(cfg, allResults, duration, scanner.Stats)
	}

	// Start dashboard if enabled
	if cfg.Web {
		ds := &DashboardServer{
			Port: cfg.WebPort,
			Path: cfg.WebPath,
			Auth: cfg.WebAuth,
		}
		ds.Start()
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Dashboard: http://localhost:%d%s\n",
				SColor(ColorGreen, "[+]"), cfg.WebPort, cfg.WebPath)
			select {}
		}
	}

	// Send notifications
	if cfg.Push != "" || cfg.SlackWebhook != "" || (cfg.TelegramBot != "" && cfg.TelegramChat != "") {
		notifier := NewNotifier(cfg)
		notifier.Send(allResults)
	}
}

func handleResults(results []Result, cfg *ScanConfig, scanner *Scanner) {
	// Write output file
	if cfg.OutputFile != "" {
		format := detectFormat(cfg.OutputFile)
		err := WriteReport(results, scanner.Stats, format, cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error writing report: %v\n", SColor(ColorRed, "[!]"), err)
		} else if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "%s Report written to %s\n", SColor(ColorGreen, "[+]"), cfg.OutputFile)
		}
	}

	// Format-specific output
	if cfg.JSON {
		fmt.Println(FormatResultsJSON(results))
		return
	}
	if cfg.JSONL {
		fmt.Println(FormatResultsJSONL(results))
		return
	}
	if cfg.CSV {
		fmt.Println(FormatResultsCSV(results))
		return
	}
	if cfg.SARIF {
		fmt.Println(FormatResultsSarif(results))
		return
	}
	if cfg.Markdown != "" {
		err := WriteReport(results, scanner.Stats, "markdown", cfg.Markdown)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error: %v\n", SColor(ColorRed, "[!]"), err)
		}
		return
	}
	if cfg.HTML {
		fn := cfg.OutputFile
		if fn == "" { fn = "report.html" }
		err := WriteReport(results, scanner.Stats, "html", fn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error: %v\n", SColor(ColorRed, "[!]"), err)
		}
		return
	}

	// Default: print finding table
	if len(results) > 0 {
		PrintFindingsTable(results)
	} else if !cfg.Silent {
		fmt.Printf("\n%s No vulnerabilities found.\n", SColor(ColorGreen, "[+]"))
	}

	// Stats
	if cfg.Stats || cfg.Metrics {
		PrintStats(scanner.Stats)
	}
}

func detectFormat(path string) string {
	if strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".markdown") {
		return "markdown"
	}
	if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm") {
		return "html"
	}
	if strings.HasSuffix(path, ".csv") {
		return "csv"
	}
	if strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".ndjson") {
		return "jsonl"
	}
	if strings.HasSuffix(path, ".sarif") {
		return "sarif"
	}
	return "json"
}

func hasFlag(name string) bool {
	for _, arg := range os.Args[1:] {
		if arg == "-"+name || arg == "--"+name {
			return true
		}
	}
	return false
}

func parseTags(raw string) []string {
	if raw == "" {
		return nil
	}
	var tags []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}
