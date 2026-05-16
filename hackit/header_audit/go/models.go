package main

type HeaderInfo struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Category    string `json:"category"`
	IsSecurity  bool   `json:"is_security"`
}

type Finding struct {
	Header         string `json:"header"`
	Value          string `json:"value,omitempty"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Severity       string `json:"severity"` // Low, Medium, High, Critical
}

type Result struct {
	Target       string          `json:"target"`
	Grade        string          `json:"grade"`
	Score        int             `json:"score"`
	AllHeaders   []HeaderInfo    `json:"all_headers"`
	Missing      []Finding       `json:"missing"`
	Dangerous    []Finding       `json:"dangerous"`
	CookieAudit  []CookieFinding `json:"cookie_audit"`
	CORSAudit    []Finding       `json:"cors_audit"`
	ServerInfo   string          `json:"server_info"`
	PoweredBy    string          `json:"powered_by"`
	ResponseTime int64           `json:"response_time_ms"`
	Error        string          `json:"error,omitempty"`
}
