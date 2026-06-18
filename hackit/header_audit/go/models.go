package main

type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
	SeverityInfo     Severity = "Info"
)

type HeaderInfo struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Category    string `json:"category"`
	IsSecurity  bool   `json:"is_security"`
}

type Finding struct {
	Header         string   `json:"header"`
	Value          string   `json:"value,omitempty"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category,omitempty"`
	Path           string   `json:"path,omitempty"`
	Method         string   `json:"method,omitempty"`
}

type CookieFinding struct {
	Name     string   `json:"name"`
	Value    string   `json:"value,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Issues   []string `json:"issues"`
	Severity Severity `json:"severity"`
}

type TLSInfo struct {
	Version            string `json:"version"`
	CipherSuite        string `json:"cipher_suite"`
	CertificateSubject string `json:"cert_subject"`
	CertificateIssuer  string `json:"cert_issuer"`
	CertificateExpiry  string `json:"cert_expiry"`
	CertificateDaysLeft int   `json:"cert_days_left"`
	SelfSigned         bool   `json:"self_signed"`
	WildcardCert       bool   `json:"wildcard_cert"`
}

type CacheDirective struct {
	Directive string `json:"directive"`
	Value     string `json:"value,omitempty"`
	Safe      bool   `json:"safe"`
}

type CacheAudit struct {
	Present        bool             `json:"present"`
	Directives     []CacheDirective `json:"directives"`
	NoStorePresent bool             `json:"no_store_present"`
	PublicPresent  bool             `json:"public_present"`
	MaxAgeSet      bool             `json:"max_age_set"`
	MaxAge         int              `json:"max_age_seconds"`
	HasExpires     bool             `json:"has_expires"`
	HasPragmaNoCache bool           `json:"has_pragma_no_cache"`
	Findings       []Finding        `json:"findings"`
}

type TechFingerprint struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Certainty string `json:"certainty"` // High, Medium, Low
	Source   string `json:"source"`
}

type MethodCheck struct {
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	Allowed     bool   `json:"allowed"`
}

type ScanPath struct {
	Path          string                  `json:"path"`
	GETHeaders    []HeaderInfo            `json:"get_headers,omitempty"`
	HEADHeaders   []HeaderInfo            `json:"head_headers,omitempty"`
	OPTIONSResult *MethodCheck            `json:"options_result,omitempty"`
	StatusCode    int                     `json:"status_code"`
	Missing       []Finding               `json:"missing,omitempty"`
	Dangerous     []Finding               `json:"dangerous,omitempty"`
	CacheAudit    *CacheAudit             `json:"cache_audit,omitempty"`
}

type RedirectStep struct {
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Headers []HeaderInfo `json:"headers,omitempty"`
}

type Config struct {
	MaxDepth      int
	Timeout       int
	FollowRedirect bool
	Paths         []string
	Subdomains    []string
	Methods       []string
	Threads       int
}

var DefaultConfig = Config{
	MaxDepth:       1,
	Timeout:        15,
	FollowRedirect: true,
	Paths:          []string{"/", "/api", "/admin", "/graphql", "/robots.txt", "/.env", "/.well-known/security.txt"},
	Subdomains:     []string{"www", "api", "admin", "mail", "cdn", "app", "dev", "blog", "static", "docs"},
	Methods:        []string{"GET", "HEAD", "OPTIONS"},
	Threads:        5,
}

type Result struct {
	Target         string           `json:"target"`
	ResolvedIP     string           `json:"resolved_ip"`
	Grade          string           `json:"grade"`
	Score          int              `json:"score"`
	ScoreBreakdown map[string]int   `json:"score_breakdown"`
	ResponseTimeMs int64            `json:"response_time_ms"`
	AllHeaders     []HeaderInfo     `json:"all_headers"`
	Missing        []Finding        `json:"missing"`
	Dangerous      []Finding        `json:"dangerous"`
	CookieAudit    []CookieFinding  `json:"cookie_audit"`
	CorsAudit      []Finding        `json:"cors_audit"`
	CacheAudit     *CacheAudit      `json:"cache_audit,omitempty"`
	ServerInfo     string           `json:"server_info"`
	PoweredBy      string           `json:"powered_by"`
	XFrameOptions  string           `json:"x_frame_options,omitempty"`
	CSP            string           `json:"csp,omitempty"`
	HSTS           string           `json:"hsts,omitempty"`
	TLSInfo        *TLSInfo         `json:"tls_info,omitempty"`
	Technologies   []TechFingerprint `json:"technologies,omitempty"`
	RedirectChain  []RedirectStep   `json:"redirect_chain,omitempty"`
	ScanPaths      []ScanPath       `json:"scan_paths,omitempty"`
	MethodsAllowed []string         `json:"methods_allowed,omitempty"`
	SubdomainResults []SubdomainResult `json:"subdomain_results,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type SubdomainResult struct {
	Subdomain string `json:"subdomain"`
	Status    int    `json:"status"`
	Grade     string `json:"grade"`
	Score     int    `json:"score"`
	Server    string `json:"server"`
	Findings  int    `json:"findings"`
}
