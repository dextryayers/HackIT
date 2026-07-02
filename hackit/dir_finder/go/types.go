package main

import (
	"regexp"
	"time"
)

type DirResult struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
	Redirect    string `json:"redirect,omitempty"`
	Title       string `json:"title,omitempty"`
	BodyHash    string `json:"body_hash,omitempty"`
	Words       int    `json:"words,omitempty"`
	Lines       int    `json:"lines,omitempty"`
	TimeMs      int64  `json:"time_ms,omitempty"`
	Depth       int    `json:"depth,omitempty"`
}

type SizeRange struct {
	Min uint64
	Max uint64
}

type RawRequest struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    string
	Target  string
}

type ScanConfig struct {
	Target    string
	URLsFile  string
	RawFile   string
	Stdin     bool

	Wordlists          []string
	WordlistCategories []string
	Extensions         []string
	ForceExtensions    bool
	OverwriteExtensions bool
	ExcludeExtensions  []string
	Prefixes           []string
	Suffixes           []string
	Uppercase          bool
	Lowercase          bool
	Capital            bool

	Threads        int
	Recursive      bool
	DeepRecursive  bool
	ForceRecursive bool
	MaxDepth       int
	RecursionStatus []int
	Subdirs        []string
	ExcludeSubdirs []string
	IncludeStatus  []int
	ExcludeStatus  []int
	ExcludeSizes   []string
	ExcludeText    []string
	ExcludeRegex   string
	ExcludeRedirect string
	ExcludeResponse string
	SkipOnStatus   []int
	MinResponseSize int64
	MaxResponseSize int64
	MaxTime        int
	ExitOnError    bool

	AutoCalibration  bool
	MatchStatus      []int
	FilterStatus     []int
	MatchSize        []SizeRange
	FilterSize       []SizeRange
	MatchWords       []SizeRange
	FilterWords      []SizeRange
	MatchLines       []SizeRange
	FilterLines      []SizeRange
	MatchRegex       string
	FilterRegex      string
	MatchHeader      []string
	FilterHeader     []string

	Method         string
	Data           string
	DataFile       string
	Headers        map[string]string
	HeadersFile    string
	FollowRedirect bool
	RandomAgent    bool
	Auth           string
	AuthType       string
	UserAgent      string
	Cookie         string

	Timeout       int
	Delay         int
	Proxy         string
	ProxiesFile   string
	ProxyAuth     string
	ReplayProxy   string
	Tor           bool
	Scheme        string
	MaxRate       float64
	Retries       int
	IP            string
	Interface     string

	Crawl bool

	FullURL  bool
	NoColor  bool
	Quiet    bool
	Verbose  bool

	OutputFormats []string
	OutputFile    string
	LogFile       string

	ExcludeRegexCompiled    *regexp.Regexp
	MatchRegexCompiled      *regexp.Regexp
	ExcludeRedirectCompiled *regexp.Regexp

	DetectWAF    bool
	DetectTech   bool
	DetectCMS    bool
	DetectBackup bool
	SmartFilter  bool
	ExtractJS    bool
	AutoWordlist bool

	SaveSession bool
	HTTP2       bool
	JSONBody    bool
	GraphQL     bool
	APIMode     bool

	Paths             []string
	SessionFile    string
	SessionID      int
	RestoredPaths  []string
	RestoredResults []DirResult

	Blacklists        map[int][]string
	WildcardStatus    int
	WildcardSize      int64
	DetectedWAF       string
	DetectedTech      []string
	ReferenceResponse *DirResult
	Scheduler         *Scheduler
	Fingerprint       FingerprintResult
}

type ScanStats struct {
	TotalRequests int
	Found         int
	Filtered      int
	Errors        int
	StartTime     time.Time
	EndTime       time.Time
}

type SessionData struct {
	Target    string
	Remaining []string
	Found     []DirResult
	Stats     ScanStats
	Timestamp time.Time
}
