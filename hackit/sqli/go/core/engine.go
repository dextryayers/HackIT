package core

import (
	"crypto/tls"
	"hackit/sqli/go/utils"
	"net"
	"net/http"
	"net/url"
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
	Schema      bool
	CountRows   bool
	Search      string

	DumpTable string
	DumpAll   bool

	Verbose int
	NoColor bool
	Retry   int
}

type Engine struct {
	Opts   *Options
	Client *http.Client
	Log    *utils.Logger
	Perf   *utils.PerformanceManager
}

func NewEngine(opts *Options) *Engine {
	// Setup Transport with better tuning
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
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

	client := &http.Client{
		Timeout:   time.Duration(opts.Timeout) * time.Second,
		Transport: transport,
	}

	if !opts.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Engine{
		Opts:   opts,
		Client: client,
		Log:    utils.NewLogger(opts.Verbose, opts.NoColor),
		Perf:   utils.NewPerformanceManager(opts.Retry, time.Duration(opts.Delay)*time.Millisecond),
	}
}

func (e *Engine) GetLogger() *utils.Logger {
	return e.Log
}
