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

// Engine Options
type Options struct {
	URL            string
	Data           string
	Cookie         string
	Header         []string
	Agent          string
	Referer        string
	Method         string
	Timeout        int
	Proxy          string
	FollowRedirect bool

	Mode       string
	RiskLevel  int
	Depth      int
	Threads    int
	Delay      int
	RandomCase bool
	Tamper     []string
	Encode     string
	BypassWAF  bool
	Stealth    bool

	Fingerprint bool
	BannerGrab  bool
	OSDetect    bool
	WAFDetect   bool
	SmartDiff   bool
	Baseline    bool
	TechDetect  bool

	ListDBs     bool
	ListTables  bool
	ListColumns bool
	Database    string
	Table       string
	Column      string
	Schema      bool
	CountRows   bool
	Search      string

	DumpTable string
	DumpAll   bool

	PrivEsc  bool
	OSAccess bool
	ExfilDNS  bool
	ExfilHTTP bool
	NoColor   bool

	Verbose int
	Retry   int
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
