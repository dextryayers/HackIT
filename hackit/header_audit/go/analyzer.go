package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Analyzer struct {
	Client *http.Client
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Client: CreateEliteClient(),
	}
}

func (a *Analyzer) Analyze(targetURL string) Result {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	start := time.Now()
	req, _ := http.NewRequest("GET", targetURL, nil)
	SetStealthHeaders(req)

	resp, err := a.Client.Do(req)
	if err != nil {
		// Fallback to HTTP if HTTPS fails
		if strings.HasPrefix(targetURL, "https://") {
			targetURL = strings.Replace(targetURL, "https://", "http://", 1)
			req, _ = http.NewRequest("GET", targetURL, nil)
			SetStealthHeaders(req)
			resp, err = a.Client.Do(req)
		}
		
		if err != nil {
			return Result{Error: fmt.Sprintf("Connection failed: %v", err)}
		}
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()

	var allHeaders []HeaderInfo
	for k, v := range resp.Header {
		val := strings.Join(v, ", ")
		desc, cat := GetHeaderMetadata(k)
		allHeaders = append(allHeaders, HeaderInfo{
			Key:         k,
			Value:       val,
			Description: desc,
			Category:    cat,
			IsSecurity:  cat == "Security",
		})
	}

	// Run specialized audits
	missing, missingPenalty := AuditSecurityHeaders(resp.Header)
	dangerous, dangerousPenalty := AuditDangerousHeaders(resp.Header)
	cookieFindings := AuditCookies(resp.Header)
	corsFindings := AuditCORS(resp.Header)

	// Additional penalty for cookie issues
	cookiePenalty := len(cookieFindings) * 5
	corsPenalty := len(corsFindings) * 10

	score := 100 - missingPenalty - dangerousPenalty - cookiePenalty - corsPenalty
	if score < 0 { score = 0 }

	return Result{
		Target:       targetURL,
		Grade:        CalculateGrade(score),
		Score:        score,
		AllHeaders:   allHeaders,
		Missing:      missing,
		Dangerous:    dangerous,
		CookieAudit:  cookieFindings,
		CORSAudit:    corsFindings,
		ServerInfo:   resp.Header.Get("Server"),
		PoweredBy:    resp.Header.Get("X-Powered-By"),
		ResponseTime: elapsed,
	}
}

func getHeaderMetadata(key string) (string, string) {
	k := strings.ToLower(key)
	// Known Headers Dictionary
	dict := map[string][2]string{
		"server":               {"Identifies the server software", "Information"},
		"content-type":         {"Media type of the resource", "Content"},
		"content-length":       {"Size of the response body in bytes", "Content"},
		"date":                 {"The date and time the message was sent", "Network"},
		"connection":           {"Controls whether the network connection stays open", "Network"},
		"strict-transport-security": {"Enforces HTTPS connections", "Security"},
		"content-security-policy":   {"Prevents XSS and other injection attacks", "Security"},
		"x-frame-options":           {"Prevents Clickjacking", "Security"},
		"x-content-type-options":    {"Prevents MIME-sniffing", "Security"},
		"referrer-policy":           {"Controls Referrer information", "Security"},
		"x-xss-protection":          {"Legacy XSS protection", "Security"},
		"cache-control":             {"Directives for caching mechanisms", "Caching"},
		"expires":                   {"The date/time after which the response is considered stale", "Caching"},
		"vary":                      {"Tells caches how to match future request headers", "Caching"},
		"x-powered-by":              {"Underlying technology (Risk of leak)", "Information"},
		"set-cookie":                {"Sends cookies from the server to the user agent", "Security/Session"},
		"access-control-allow-origin": {"Indicates whether the response can be shared (CORS)", "Security"},
		"alt-svc":                   {"Alternative services available", "Network"},
		"transfer-encoding":         {"The form of encoding used to transfer the entity", "Network"},
		"cf-ray":                    {"Cloudflare internal tracking ID", "Network"},
	}

	if val, ok := dict[k]; ok {
		return val[0], val[1]
	}
	return "General response header", "General"
}
