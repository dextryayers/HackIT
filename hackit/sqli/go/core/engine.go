package core

import (
	"crypto/tls"
	"hackit/sqli/go/utils"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Engine Options - Complete configuration
type Options struct {
	URL            string   `json:"url"`
	Data           string   `json:"data,omitempty"`
	Cookie         string   `json:"cookie,omitempty"`
	Header         []string `json:"header,omitempty"`
	Agent          string   `json:"agent,omitempty"`
	Referer        string   `json:"referer,omitempty"`
	Method         string   `json:"method,omitempty"`
	Timeout        int      `json:"timeout,omitempty"`
	Proxy          string   `json:"proxy,omitempty"`
	FollowRedirect bool     `json:"follow_redirect,omitempty"`

	Mode       string   `json:"mode,omitempty"`
	RiskLevel  int      `json:"risk_level,omitempty"`
	Depth      int      `json:"depth,omitempty"`
	Threads    int      `json:"threads,omitempty"`
	Delay      int      `json:"delay,omitempty"`
	RandomCase bool     `json:"random_case,omitempty"`
	Tamper     []string `json:"tamper,omitempty"`
	Encode     string   `json:"encode,omitempty"`
	BypassWAF  bool     `json:"bypass_waf,omitempty"`
	Stealth    bool     `json:"stealth,omitempty"`

	Fingerprint bool `json:"fingerprint,omitempty"`
	BannerGrab  bool `json:"banner_grab,omitempty"`
	OSDetect    bool `json:"os_detect,omitempty"`
	WAFDetect   bool `json:"waf_detect,omitempty"`
	SmartDiff   bool `json:"smart_diff,omitempty"`
	Baseline    bool `json:"baseline,omitempty"`
	TechDetect  bool `json:"tech_detect,omitempty"`

	ListDBs     bool   `json:"list_dbs,omitempty"`
	ListTables  bool   `json:"list_tables,omitempty"`
	ListColumns bool   `json:"list_columns,omitempty"`
	Database    string `json:"database,omitempty"`
	Table       string `json:"table,omitempty"`
	Column      string `json:"column,omitempty"`
	Schema      bool   `json:"schema,omitempty"`
	CountRows   bool   `json:"count_rows,omitempty"`
	Search      string `json:"search,omitempty"`

	DumpTable string `json:"dump_table,omitempty"`
	DumpAll   bool   `json:"dump_all,omitempty"`

	PrivEsc  bool `json:"priv_esc,omitempty"`
	OSAccess bool `json:"os_access,omitempty"`
	ExfilDNS  bool `json:"exfil_dns,omitempty"`
	ExfilHTTP bool `json:"exfil_http,omitempty"`
	NoColor   bool `json:"no_color,omitempty"`

	Verbose int `json:"verbose,omitempty"`
	Retry   int `json:"retry,omitempty"`

	// === CRAWL EXTENSION ===
	CrawlMode      string `json:"crawl_mode,omitempty"`      // full, schema, sensitive, system
	CrawlDepth     int    `json:"crawl_depth,omitempty"`     // 1-5
	CrawlThreads   int    `json:"crawl_threads,omitempty"`   // parallel workers
	CrawlExtract   bool   `json:"crawl_extract,omitempty"`   // extract data
	CrawlSensitive bool   `json:"crawl_sensitive,omitempty"` // scan sensitive
	CrawlProcs     bool   `json:"crawl_procs,omitempty"`     // extract procs
	CrawlViews     bool   `json:"crawl_views,omitempty"`     // extract views
	CrawlIndexes   bool   `json:"crawl_indexes,omitempty"`   // extract indexes
	CrawlSystem    bool   `json:"crawl_system,omitempty"`    // extract system info
	CrawlOutput    string `json:"crawl_output,omitempty"`    // output dir
	CrawlReport    string `json:"crawl_report,omitempty"`    // report format

	// === ADVANCED EXTRACTION ===
	ExtractTechnique string `json:"extract_technique,omitempty"` // auto, union, error, blind, time
	ExtractCharset   string `json:"extract_charset,omitempty"`   // charset for blind
	ExtractWorkers   int    `json:"extract_workers,omitempty"`   // parallel extraction
	ExtractBatchSize int    `json:"extract_batch_size,omitempty"`

	// === NETWORK SCAN ===
	NetworkScan bool   `json:"network_scan,omitempty"`
	ScanTarget  string `json:"scan_target,omitempty"`
	ScanPorts   string `json:"scan_ports,omitempty"` // comma separated

	// === AUTH BYPASS ===
	AuthBypass bool   `json:"auth_bypass,omitempty"`
	AuthUser   string `json:"auth_user,omitempty"`
	AuthPass   string `json:"auth_pass,omitempty"`

	// === FILE OPERATIONS ===
	FileRead  string `json:"file_read,omitempty"`
	FileWrite string `json:"file_write,omitempty"`
	FileExec  string `json:"file_exec,omitempty"`

	// === OOB ===
	OOBChannel string `json:"oob_channel,omitempty"` // dns, http, smb
	OOBDomain  string `json:"oob_domain,omitempty"`
}

type Engine struct {
	Opts                 *Options
	Client               *http.Client
	Log                  *utils.Logger
	Perf                 *utils.PerformanceManager
	LastResponseHeaders  http.Header
	LastResponseBody     string
	LastResponseTime     time.Duration

	rateLimiter      *RateLimiter
}

type RateLimiter struct {
	mu              sync.Mutex
	responseTimes   []time.Duration
	minDelay        time.Duration
	maxDelay        time.Duration
	currentDelay    time.Duration
	consecutiveFast int
	consecutiveSlow int
	slowThreshold   time.Duration
	fastThreshold   time.Duration
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		minDelay:        0,
		maxDelay:        5 * time.Second,
		currentDelay:    0,
		slowThreshold:   3 * time.Second,
		fastThreshold:   500 * time.Millisecond,
	}
}

func (rl *RateLimiter) RecordResponseTime(d time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.responseTimes = append(rl.responseTimes, d)
	if len(rl.responseTimes) > 20 {
		rl.responseTimes = rl.responseTimes[len(rl.responseTimes)-20:]
	}

	if d > rl.slowThreshold {
		rl.consecutiveSlow++
		rl.consecutiveFast = 0
		if rl.consecutiveSlow >= 3 {
			rl.currentDelay += 500 * time.Millisecond
			if rl.currentDelay > rl.maxDelay {
				rl.currentDelay = rl.maxDelay
			}
		}
	} else if d < rl.fastThreshold {
		rl.consecutiveFast++
		rl.consecutiveSlow = 0
		if rl.consecutiveFast >= 10 {
			rl.currentDelay -= 200 * time.Millisecond
			if rl.currentDelay < rl.minDelay {
				rl.currentDelay = rl.minDelay
			}
		}
	} else {
		rl.consecutiveFast = 0
		rl.consecutiveSlow = 0
	}
}

func (rl *RateLimiter) GetDelay() time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.currentDelay
}

func (rl *RateLimiter) GetAverageResponseTime() time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.responseTimes) == 0 {
		return 0
	}
	var total time.Duration
	for _, t := range rl.responseTimes {
		total += t
	}
	return total / time.Duration(len(rl.responseTimes))
}

func NewEngine(opts *Options) *Engine {
	// Setup Transport with better tuning
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if opts.Proxy != "" {
		proxyURL, _ := url.Parse(opts.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Adaptive timeout for Stealth mode
	timeout := time.Duration(opts.Timeout) * time.Second
	if opts.Stealth {
		timeout = time.Duration(opts.Timeout*2) * time.Second
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if !opts.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	e := &Engine{
		Opts:        opts,
		Client:      client,
		Log:         utils.NewLogger(opts.Verbose, opts.NoColor),
		Perf:        utils.NewPerformanceManager(opts.Retry, time.Duration(opts.Delay)*time.Millisecond),
		rateLimiter: NewRateLimiter(),
	}

	if opts.BypassWAF {
		e.Log.Info("WAF bypass mode engaged — using maximum evasion techniques")
	}

	return e
}

func (e *Engine) GetLogger() *utils.Logger {
	return e.Log
}
