package main

type Options struct {
	Target      string
	Host        string
	MaxDepth    int
	ShowCode    bool
	Concurrency int
	Timeout     int
	Delay       int
	Proxy       string
	Crawl       bool
	JS          bool
	Secrets     bool
	Subdomains  bool
	Archive     bool
	Brute       bool
	Sourcemap   bool
	Tech        bool
	Endpoints   bool
	Network     bool
	JSON        bool
	RateLimit   int
}

type urlQueue struct {
	url    string
	source string
	depth  int
}

type CrawlResult struct {
	URL         string `json:"url"`
	SourceURL   string `json:"source_url"`
	Type        string `json:"type"`
	Extension   string `json:"extension"`
	StatusCode  int    `json:"status_code,omitempty"`
	Depth       int    `json:"depth"`
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

type ExtractedString struct {
	Value   string `json:"value"`
	Context string `json:"context"`
	IsURL   bool   `json:"is_url"`
	IsPath  bool   `json:"is_path"`
}

type EndpointResult struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type SensitiveFinding struct {
	Name  string `json:"name"`
	Match string `json:"match"`
	Line  int    `json:"line,omitempty"`
}

type CommentFinding struct {
	Comment string `json:"comment"`
	Type    string `json:"type"`
	Source  string `json:"source_url"`
}

type JSAnalysisResult struct {
	Strings        []ExtractedString
	ModuleURLs     []ExtractedString
	TemplateParts  []ExtractedString
	CSSRefs        []ExtractedString
	EnvURLs        []ExtractedString
	Concatenations []ExtractedString
	ConfigObjects  []ExtractedString
	SvelteKitURLs  []ExtractedString
	Endpoints      []EndpointResult
	Secrets        []SensitiveFinding
}

type TechDetect struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
	Source  string `json:"source"`
}
