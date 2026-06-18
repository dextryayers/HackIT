package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Analyzer struct {
	Client         *http.Client
	NoRedirectClient *http.Client
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Client:            CreateClient(),
		NoRedirectClient:  CreateNoRedirectClient(),
	}
}

func (a *Analyzer) Analyze(targetURL string) Result {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	start := time.Now()

	u, err := url.Parse(targetURL)
	if err != nil {
		return Result{Error: fmt.Sprintf("Invalid URL: %v", err)}
	}
	hostname := u.Hostname()
	resolvedIP := ResolveIP(hostname)

	var (
		allHeaders      []HeaderInfo
		missing         []Finding
		dangerous       []Finding
		cookieFindings  []CookieFinding
		corsFindings    []Finding
		tlsInfo         *TLSInfo
		tlsFindings     []Finding
		technologies    []TechFingerprint
		redirectChain   []RedirectStep
		scanPaths       []ScanPath
		methodsAllowed  []string
		cacheAudit      *CacheAudit
		subdomainResults []SubdomainResult
	)

	resp, err := a.fetchWithFallback(targetURL)
	if err != nil {
		return Result{
			Target:     targetURL,
			ResolvedIP: resolvedIP,
			Error:      fmt.Sprintf("Connection failed: %v", err),
		}
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()
	allHeaders = ExtractHeaderList(resp.Header)

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	missing, _ = AuditSecurityHeaders(resp.Header)
	dangerous, _ = AuditDangerousHeaders(resp.Header)
	cookieFindings = AuditCookies(resp.Header)
	corsFindings = AuditCORS(resp.Header)

	corsFindings = append(corsFindings, a.auditDeepCORS(targetURL)...)

	tlsInfo = AuditTLS(targetURL)
	tlsFindings = AuditTLSSecurity(tlsInfo)

	cacheAudit = AuditCachePolicy(resp.Header)

	technologies = FingerprintTechnologies(resp.Header)

	redirectChain = TraceRedirectChain(targetURL)

	scanPaths = a.scanMultiplePaths(targetURL)

	methodsAllowed = CheckAllowedMethods(targetURL)

	subdomainResults = a.scanSubdomains(u.Hostname(), targetURL)

	score, breakdown := CalculateScore(missing, dangerous, cookieFindings, corsFindings, cacheAudit, tlsFindings)

	return Result{
		Target:          targetURL,
		ResolvedIP:     resolvedIP,
		Grade:           CalculateGrade(score),
		Score:           score,
		ScoreBreakdown:  breakdown,
		ResponseTimeMs:  elapsed,
		AllHeaders:      allHeaders,
		Missing:         missing,
		Dangerous:       dangerous,
		CookieAudit:     cookieFindings,
		CorsAudit:       corsFindings,
		CacheAudit:      cacheAudit,
		ServerInfo:      server,
		PoweredBy:       poweredBy,
		TLSInfo:         tlsInfo,
		Technologies:    technologies,
		RedirectChain:   redirectChain,
		ScanPaths:       scanPaths,
		MethodsAllowed:  methodsAllowed,
		SubdomainResults: subdomainResults,
	}
}

func (a *Analyzer) fetchWithFallback(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	SetHeaders(req)

	resp, err := a.Client.Do(req)
	if err == nil {
		return resp, nil
	}

	if strings.HasPrefix(targetURL, "https://") {
		httpURL := strings.Replace(targetURL, "https://", "http://", 1)
		req, err = http.NewRequest("GET", httpURL, nil)
		if err != nil {
			return nil, err
		}
		SetHeaders(req)
		return a.Client.Do(req)
	}

	return nil, err
}

func (a *Analyzer) auditDeepCORS(targetURL string) []Finding {
	var findings []Finding
	seenPreflight := false

	testOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		SetHeaders(req)
		req.Header.Set("Origin", origin)

		resp, err := a.NoRedirectClient.Do(req)
		if err != nil {
			continue
		}

		reflectFinding := AuditCORSOriginReflection(resp.Header, origin)
		if reflectFinding != nil {
			findings = append(findings, *reflectFinding)
		}
		resp.Body.Close()
	}

	for _, origin := range testOrigins {
		resp := PerformCORSPreflight(targetURL, origin)
		if resp != nil {
			if !seenPreflight {
				preflightFindings := AuditCORSPreflight(resp, origin)
				findings = append(findings, preflightFindings...)
				seenPreflight = true
			}
			resp.Body.Close()
		}
	}

	return findings
}

func (a *Analyzer) scanMultiplePaths(baseURL string) []ScanPath {
	var paths []ScanPath

	checkPaths := []string{"/", "/api", "/admin", "/graphql", "/robots.txt", "/.env", "/.well-known/security.txt"}

	for _, p := range checkPaths {
		fullURL := strings.TrimRight(baseURL, "/") + p
		pathResult := ScanPath{Path: p}

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		SetHeaders(req)
		resp, err := a.Client.Do(req)
		if err != nil {
			continue
		}

		pathResult.StatusCode = resp.StatusCode
		pathResult.GETHeaders = ExtractHeaderList(resp.Header)

		missing, _ := AuditSecurityHeaders(resp.Header)
		pathResult.Missing = missing
		dangerous, _ := AuditDangerousHeaders(resp.Header)
		pathResult.Dangerous = dangerous
		pathResult.CacheAudit = AuditCachePolicy(resp.Header)
		resp.Body.Close()

		optResp := PerformOPTIONS(fullURL)
		if optResp != nil {
			allowed := optResp.StatusCode < 400
			pathResult.OPTIONSResult = &MethodCheck{
				Method: "OPTIONS", StatusCode: optResp.StatusCode, Allowed: allowed,
			}
			allowHeader := strings.Join(optResp.Header["Allow"], ", ")
			if allowHeader != "" && allowed {
				pathResult.OPTIONSResult = &MethodCheck{
					Method: "OPTIONS", StatusCode: optResp.StatusCode, Allowed: true,
				}
			}
			optResp.Body.Close()
		}

		paths = append(paths, pathResult)
	}

	return paths
}

func (a *Analyzer) scanSubdomains(hostname, baseURL string) []SubdomainResult {
	var results []SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return results
	}
	baseDomain := strings.Join(parts[len(parts)-2:], ".")

	// Only scan subdomains if we're not already on a subdomain
	if len(parts) > 2 {
		return results
	}

	subs := []string{"www", "api", "admin", "mail", "cdn", "app", "dev", "blog", "static", "docs", "m", "test", "staging"}

	sem := make(chan struct{}, 5)

	for _, sub := range subs {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subURL := fmt.Sprintf("https://%s.%s", sub, baseDomain)

			req, err := http.NewRequest("GET", subURL, nil)
			if err != nil {
				return
			}
			SetHeaders(req)

			client := &http.Client{Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			server := resp.Header.Get("Server")
			missing, _ := AuditSecurityHeaders(resp.Header)
			dangerous, _ := AuditDangerousHeaders(resp.Header)
			score, _ := CalculateScore(missing, dangerous, nil, nil, nil, nil)

			mu.Lock()
			results = append(results, SubdomainResult{
				Subdomain: subURL,
				Status:    resp.StatusCode,
				Grade:     CalculateGrade(score),
				Score:     score,
				Server:    server,
				Findings:  len(missing) + len(dangerous),
			})
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	return results
}
