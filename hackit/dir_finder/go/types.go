package main

type DirResult struct {
	Path        string  `json:"path"`
	Status      int     `json:"status"`
	Size        uint64  `json:"size"`
	ContentType string  `json:"content_type"`
	Redirect    string  `json:"redirect,omitempty"`
	Title       string  `json:"title,omitempty"`
}

type ScanConfig struct {
	// TARGET OPTIONS
	Target    string            `json:"target"`
	Paths     []string          `json:"paths"`
	Method    string            `json:"method"`
	Data      *string           `json:"data,omitempty"`
	Headers   map[string]string `json:"headers"`
	Cookie    *string           `json:"cookie,omitempty"`
	Auth      *string           `json:"auth,omitempty"`
	Proxy     *string           `json:"proxy,omitempty"`
	UserAgent *string           `json:"user_agent,omitempty"`

	// PERFORMANCE OPTIONS
	Threads         int    `json:"threads"`
	TimeoutMS       uint64 `json:"timeout_ms"`
	DelayMS         uint64 `json:"delay_ms"`
	Retries         int    `json:"retries"`
	RandomAgent     bool   `json:"random_agent"`
	HTTP2           bool   `json:"http2"`
	FollowRedirects bool   `json:"follow_redirects"`
	MaxRedirects    int    `json:"max_redirects"`

	// SCANNING OPTIONS
	Extensions    []string `json:"extensions"`
	Recursive     bool     `json:"recursive"`
	Depth         int      `json:"depth"`
	ExcludeStatus []int    `json:"exclude_status"`
	IncludeStatus []int    `json:"include_status"`
	ExcludeLength []uint64 `json:"exclude_length"`
	IncludeLength []uint64 `json:"include_length"`

	// DETECTION OPTIONS
	DetectWAF    bool `json:"detect_waf"`
	DetectTech   bool `json:"detect_tech"`
	DetectCMS    bool `json:"detect_cms"`
	DetectBackup bool `json:"detect_backup"`
	SmartFilter  bool `json:"smart_filter"`

	// ADVANCED OPTIONS
	FuzzParam *string `json:"fuzz_param,omitempty"`
	APIMode   bool    `json:"api_mode"`
	JSONBody  bool    `json:"json_body"`
	GraphQL   bool    `json:"graphql"`
	RateLimit *float64 `json:"rate_limit,omitempty"`

	// OSINT / SMART MODE
	AutoWordlist bool `json:"auto_wordlist"`
	Crawl        bool `json:"crawl"`
	ExtractJS    bool `json:"extract_js"`
}

type ScanOutput struct {
	Target      string      `json:"target"`
	Results     []DirResult `json:"results"`
	Error       string      `json:"error,omitempty"`
	TechStack   []string    `json:"tech_stack,omitempty"`
	WAFDetected string      `json:"waf_detected,omitempty"`
}
