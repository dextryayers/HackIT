package main

import (
	"sync/atomic"
	"time"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var SeverityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

var SeverityFromStr = map[string]Severity{
	"info":     SeverityInfo,
	"low":      SeverityLow,
	"medium":   SeverityMedium,
	"high":     SeverityHigh,
	"critical": SeverityCritical,
}

type TemplateInfo struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Tags        string `yaml:"tags"`
}

type Request struct {
	Method   string              `yaml:"method"`
	Path     []string            `yaml:"path"`
	Headers  map[string]string   `yaml:"headers,omitempty"`
	Body     string              `yaml:"body,omitempty"`
	Matchers []MatcherCondition  `yaml:"matchers,omitempty"`
	Payloads []string            `yaml:"payloads,omitempty"`
}

type MatcherCondition struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Part      string   `yaml:"part,omitempty"`
	Name      string   `yaml:"name,omitempty"`
}

type Extractor struct {
	Type  string   `yaml:"type"`
	Name  string   `yaml:"name"`
	Regex []string `yaml:"regex"`
}

type Template struct {
	ID        string              `yaml:"id"`
	Info      TemplateInfo        `yaml:"info"`
	Requests  []Request           `yaml:"requests"`
	Matchers  []MatcherCondition  `yaml:"matchers,omitempty"`
	Extractor *Extractor          `yaml:"extractor,omitempty"`
	FilePath  string              `yaml:"-"`
}

type ResponseInfo struct {
	StatusCode  int
	Headers     string
	Body        string
	BodyLen     int
	Duration    time.Duration
	ContentType string
}

type Result struct {
	TemplateID   string `json:"template_id"`
	TemplateName string `json:"template_name"`
	Severity     string `json:"severity"`
	Type         string `json:"type"`
	MatcherName  string `json:"matcher_name"`
	URL          string `json:"url"`
	Matched      string `json:"matched"`
	Extracted    string `json:"extracted,omitempty"`
	Description  string `json:"description"`
	Tags         string `json:"tags"`
	Timestamp    string `json:"timestamp"`
	Request      string `json:"request,omitempty"`
	ResponseLen  int    `json:"response_length"`
	ResponseTime string `json:"response_time"`
	Host         string `json:"host,omitempty"`
	Port         string `json:"port,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	CVE          string `json:"cve,omitempty"`
	CWE          string `json:"cwe,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
}

type MatchResult struct {
	Matched     bool
	Extracted   string
	MatcherName string
}

type FilterOptions struct {
	ID          string
	Severity    string
	Tags        []string
	ExcludeTags []string
	Author      string
	Types       []string
}

type ScanStats struct {
	TemplatesTotal   int32  `json:"templates_total"`
	TemplatesTested  int32  `json:"templates_tested"`
	RequestsSent     int32  `json:"requests_sent"`
	Findings         int32  `json:"findings"`
	Errors           int32  `json:"errors"`
	StartedAt        string `json:"started_at"`
	Duration         string `json:"duration"`
	TargetsScanned   int32  `json:"targets_scanned"`
	Retries          int32  `json:"retries"`
}

func (s *ScanStats) IncTested()    { atomic.AddInt32(&s.TemplatesTested, 1) }
func (s *ScanStats) IncRequests()  { atomic.AddInt32(&s.RequestsSent, 1) }
func (s *ScanStats) IncFindings()  { atomic.AddInt32(&s.Findings, 1) }
func (s *ScanStats) IncErrors()    { atomic.AddInt32(&s.Errors, 1) }
func (s *ScanStats) IncRetries()   { atomic.AddInt32(&s.Retries, 1) }

type ScanConfig struct {
	// Section 1: Target & Scope
	URL         string
	TargetFile  string
	ResumeFile  string
	ExcludeFile string
	ScopeFile   string
	Targets     []string
	ExcludePat  string
	ScopePat    []string

	// Section 2: Template Management
	Template        string
	TemplateDir     string
	Tags            string
	ExcludeTags     string
	Severity        string
	Author          string
	ID              string
	Type            string
	TemplateVersion string
	UpdateTemplates bool
	Validate            bool
	CustomTemplateDir    string
	ValidateDeep        bool
	NoCache             bool
	Priority            bool
	AdaptiveRate        bool
	LoadFiles           string
	FromGit             string

	// Section 3: Performance
	Threads      int
	Concurrency  int
	Timeout      int
	Retries      int
	MaxHostError int
	Delay        int
	BulkSize     int

	// Section 4: Network
	ScanAllIps   bool
	IP           string
	Port         string
	Path         string
	Method       string
	Payloads     string
	Fuzz         string
	FuzzThread   int
	FuzzRecurse  bool

	// Section 5: Output
	OutputFile string
	JSON       bool
	JSONL      bool
	CSV        bool
	HTML       bool
	Markdown   string
	SARIF      bool
	Silent     bool
	NoColor    bool
	Verbose    bool
	Debug      bool
	Progress   bool
	Stats      bool
	Metrics    bool
	Analytics  bool
	TraceLog   string
	ResumeCfg  string

	// Section 6: Network Config
	Resolver        string
	ResolversFile   string
	Proxy           string
	ProxyAuth       string
	TimeoutGlobal   string
	RateLimit       int
	RateLimitMinute int
	MaxRedirects    int
	FollowRedirects bool
	SNI             string

	// Section 7: HTTP Config
	RandomAgent  bool
	CustomAgent  string
	NoFallback   bool
	HTTP2        bool
	DisableHTTP2 bool
	KeepAlive    bool
	Header       []string
	HeaderStr    string
	HeadersFile  string
	Cookie       string
	CookieJar    string

	// Section 8: Auth
	BasicAuth  string
	Bearer     string
	APIKey     string
	AuthURL    string
	AuthData   string
	ClientCert string
	ClientKey  string
	ClientCA   string

	// Section 9: Advanced
	WafSkip          bool
	WafBypass        bool
	DetectTech       bool
	TechDB           string
	Interactsh       bool
	InteractshServer string
	InteractshToken  string
	Ceye             bool
	CeyeDomain       string
	CeyeToken        string
	OOBType          string

	// Section 10: Chaining & Misc
	Chain        string
	ChainVars    string
	NucleiCompat bool
	SmartScan    bool
	MultiTarget  bool
	APIDiscovery bool
	Replay       string
	Diff         string
	Monitor      string
	Web          bool
	WebPort      int
	WebPath      string
	WebAuth      string
	Push         string
	PushFormat   string
	TelegramBot  string
	TelegramChat string
	SlackWebhook string
	NoBanner     bool
	ConfigFile   string
	Examples     bool
	Health       bool
	Completion   string
	License      bool

	// Section 11: Headless Browser
	Headless          bool
	HeadlessOpts      string
	NoSandbox         bool
	ShowBrowser       bool
	SystemChrome      bool
	UseChrome         string
	PageTimeout       int
	ActionTimeout     int

	// Section 12: Project Database
	Project         string
	ProjectPath     string
	AllowLocalAccess bool

	// Section 13: Protocol Scanning
	Protocol       string
	DnsResolvers   string
	TlsImpersonate bool

	// Section 14: Uncover / Target Discovery
	Uncover       bool
	UncoverEngine string
	UncoverQuery  string
	UncoverLimit  int
	UncoverField  string

	// Section 15: Template Signing
	Sign     string
	Verify   string
	SignKey  string
	SignPass string
	VerifyKey string
}

type FindingCallback func(result Result)
type ProgressCallback func(current, total int, tplID string)
