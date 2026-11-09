package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Scanner struct {
	Interactive     bool
	Client          *http.Client
	Templates       []*Template
	URL             string
	Threads         int
	Timeout         int
	Results         []Result
	Config          *ScanConfig
	Verbose         bool
	Deduplicator    *Deduplicator
	Stats           *ScanStats
	Progress        *ProgressDisplay
	StatsCollector  *StatsCollector
	Debugger        *Debugger
	StartTime       time.Time
	vars            *TemplateVars
	throttler       *Throttler
	bulkSize        int
	resume          *ResumeTracker
	hostErr         sync.Map // host -> *int32 consecutive failures
	customHeaders   []CustomHeader
	customHeadersOK bool
	baselineCache   sync.Map // baseline URL -> *ResponseInfo
	mu              sync.Mutex
	findingsCh      chan Result
	doneCh          chan struct{}
}

// baselineURLFor rewrites every query value to "1" — the benign
// counterpart of an injected payload URL, used for differential
// (time-based) detection.
func baselineURLFor(rawURL string) string {
	i := strings.Index(rawURL, "?")
	if i < 0 {
		return rawURL
	}
	path, query := rawURL[:i], rawURL[i+1:]
	pairs := strings.Split(query, "&")
	for j, p := range pairs {
		if eq := strings.Index(p, "="); eq >= 0 {
			pairs[j] = p[:eq+1] + "1"
		}
	}
	return sanitizeRequestURL(path + "?" + strings.Join(pairs, "&"))
}

// baselineFor fetches (once per scan, cached) the benign counterpart of
// the payload URL. GET only; other methods return nil. Stored response
// powers baseline_* DSL variables.
func (s *Scanner) baselineFor(targetURL, method string, headers map[string]string, hostOverride string) *ResponseInfo {
	if method != "" && method != "GET" {
		return nil
	}
	bu := baselineURLFor(targetURL)
	if bu == targetURL {
		return nil // no query string → same URL, differential is meaningless
	}
	if cached, ok := s.baselineCache.Load(bu); ok {
		b, _ := cached.(*ResponseInfo)
		return b
	}
	start := time.Now()
	resp, err := SendRequest(s.Client, bu, "GET", "", headers, hostOverride)
	duration := time.Since(start)
	if err != nil {
		s.baselineCache.Store(bu, &ResponseInfo{})
		return &ResponseInfo{}
	}
	resp.Duration = duration
	s.baselineCache.Store(bu, resp)
	return resp
}

func NewScanner(timeout, threads int) *Scanner {
	if threads <= 0 {
		threads = 20
	}
	client := NewHTTPClient(timeout)
	client.Timeout = time.Duration(timeout) * time.Second
	s := &Scanner{
		Interactive: true,
		Client:      client,
		Threads:     threads,
		Timeout:     timeout,
		Progress:    NewProgressDisplay(),
		throttler:   NewThrottlerFromRPS(0), // disabled unless -rate-limit set
		StartTime:   time.Now(),
		findingsCh:  make(chan Result, 1000),
		doneCh:      make(chan struct{}),
	}
	return s
}

func (s *Scanner) InitScanner(cfg *ScanConfig) {
	if cfg == nil {
		return
	}
	s.Config = cfg
	s.Client = NewConfiguredClient(cfg)
	// Rate-limit minute is expressed per-minute; derive requests/second.
	if cfg.RateLimitMinute > 0 && cfg.RateLimit == 0 {
		cfg.RateLimit = cfg.RateLimitMinute / 60
		if cfg.RateLimit < 1 {
			cfg.RateLimit = 1
		}
	}
	// RateLimit is requests-per-second with exact global pacing.
	// Adaptive mode starts fast and backs off on error storms.
	switch {
	case cfg.AdaptiveRate:
		s.throttler = NewAdaptiveThrottler(cfg.RateLimit)
	case cfg.RateLimit > 0:
		s.throttler = NewThrottlerFromRPS(cfg.RateLimit)
	case cfg.Delay > 0:
		s.throttler = NewThrottler(cfg.Delay)
	default:
		s.throttler = NewThrottlerFromRPS(0)
	}
	if cfg.BulkSize > 0 {
		s.bulkSize = cfg.BulkSize
	}
	if cfg.Threads > 0 {
		s.Threads = cfg.Threads
	}
	// Parse -H headers once instead of per request.
	s.customHeaders = ParseCustomHeaders(cfg)
	s.customHeadersOK = true
}

// hostOverrideFor returns the original hostname when the target URL was
// rewritten to a literal IP by -scan-all-ips.
func hostOverrideFor(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	origin := u.Scheme + "://" + u.Host
	if h, ok := HostOverrides.Load(origin); ok {
		return h.(string)
	}
	return ""
}

// joinRequestURL maps a template path onto the scan target. Paths that
// already carry a scheme are used verbatim; absolute paths are joined
// onto the origin; everything else is resolved relative to the base.
// Illegal raw characters are percent-encoded so the request line is valid.
func joinRequestURL(baseURL, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return sanitizeRequestURL(baseURL)
	}
	if strings.Contains(path, "://") {
		return sanitizeRequestURL(path)
	}
	trimmedBase := strings.TrimRight(baseURL, "/")
	if strings.HasPrefix(path, "/") {
		return sanitizeRequestURL(trimmedBase + path)
	}
	return sanitizeRequestURL(trimmedBase + "/" + path)
}

// hostErrorThreshold: <=0 means the circuit breaker is disabled.
func (s *Scanner) hostErrorThreshold() int {
	if s.Config == nil {
		return 30
	}
	if s.Config.MaxHostError <= 0 {
		return 0
	}
	return s.Config.MaxHostError
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func (s *Scanner) hostFailures(host string) *int32 {
	v, _ := s.hostErr.LoadOrStore(host, new(int32))
	return v.(*int32)
}

func (s *Scanner) noteHostError(host string) {
	atomic.AddInt32(s.hostFailures(host), 1)
}

func (s *Scanner) noteHostSuccess(host string) {
	atomic.StoreInt32(s.hostFailures(host), 0)
}

func (s *Scanner) hostCircuitOpen(host string) bool {
	th := s.hostErrorThreshold()
	if th <= 0 {
		return false
	}
	return atomic.LoadInt32(s.hostFailures(host)) >= int32(th)
}

// requestHeaders merges template headers with global CLI overrides.
func (s *Scanner) requestHeaders(req Request) map[string]string {
	headers := map[string]string{}
	for k, v := range req.Headers {
		headers[k] = v
		if s.vars != nil {
			headers[k] = s.vars.Resolve(headers[k])
		}
	}
	var cfg *ScanConfig
	if s != nil {
		cfg = s.Config
	}
	if cfg == nil {
		return headers
	}
	if cfg.CustomAgent != "" {
		headers["User-Agent"] = cfg.CustomAgent
	} else if cfg.RandomAgent {
		headers["User-Agent"] = RandomUserAgent()
	}
	if cfg.Cookie != "" {
		if prev, ok := headers["Cookie"]; ok && prev != "" {
			headers["Cookie"] = prev + "; " + cfg.Cookie
		} else {
			headers["Cookie"] = cfg.Cookie
		}
	}
	customHeaders := s.customHeaders
	if !s.customHeadersOK && cfg != nil {
		customHeaders = ParseCustomHeaders(cfg)
	}
	for _, h := range customHeaders {
		if h.Name != "" {
			headers[h.Name] = h.Value
		}
	}
	ApplyAuthHeaders(headers, cfg)
	return headers
}

func effectiveMethod(reqMethod string, cfg *ScanConfig) string {
	if reqMethod != "" {
		return reqMethod
	}
	if cfg != nil && cfg.Method != "" {
		return cfg.Method
	}
	return "GET"
}

func effectiveRetries(cfg *ScanConfig) int {
	if cfg == nil {
		return 0
	}
	return cfg.Retries
}

func (s *Scanner) perTemplateParallelism() int {
	n := 10
	if s.bulkSize > 0 {
		n = s.bulkSize
	} else if s.Config != nil && s.Config.Threads > 0 {
		n = s.Config.Threads
	}
	if n < 1 {
		n = 1
	}
	if n > 32 {
		n = 32
	}
	return n
}

func (s *Scanner) TestTemplate(baseURL string, t *Template, reqIdx int, req Request) bool {
	payloads := req.Payloads
	if len(payloads) == 0 {
		payloads = []string{""}
	}

	headers := s.requestHeaders(req)
	body := t.ResolveRequestPart(req.Body, s.vars)
	method := effectiveMethod(req.Method, s.Config)
	retries := effectiveRetries(s.Config)
	adaptive := s.Config != nil && s.Config.AdaptiveRate

	// Fan out independent path x payload probes; requests within one
	// Request block stay exact (stop-at-first-match is handled by the
	// caller across Request blocks, which remain sequential).
	var matched atomic.Int32 // 0/1
	sem := make(chan struct{}, s.perTemplateParallelism())
	var wg sync.WaitGroup

	for _, pathTmpl := range req.Path {
		for _, pay := range payloads {
			resolvedPath := ResolvePayload(t.ResolveRequestPart(pathTmpl, s.vars), pay, s.vars)
			targetURL := joinRequestURL(s.vars.BaseURL, resolvedPath)
			host := hostOf(targetURL)
			if s.hostCircuitOpen(host) {
				// Host has exceeded its consecutive-error budget; skip.
				continue
			}
			hostOverride := hostOverrideFor(targetURL)
			var baseline *ResponseInfo
			if req.Baseline {
				baseline = s.baselineFor(targetURL, method, headers, hostOverride)
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(targetURL, host, hostOverride string, baseline *ResponseInfo) {
				defer wg.Done()
				defer func() { <-sem }()
				if s.hostCircuitOpen(host) {
					return
				}
				if s.Stats != nil {
					atomic.AddInt32(&s.Stats.RequestsSent, 1)
				}
				atomic.AddInt32(&s.Progress.Requests, 1)
				if s.throttler != nil {
					s.throttler.Wait()
				}

				startTime := time.Now()
				resp, err := SendRequestWithRetry(s.Client, targetURL, method, body, headers, retries, hostOverride)
				duration := time.Since(startTime)

				if s.throttler != nil && adaptive {
					s.throttler.Adapt(err == nil)
				}
				if err != nil {
					s.noteHostError(host)
					if s.Stats != nil {
						s.Stats.IncErrors()
					}
					atomic.AddInt32(&s.Progress.Errors, 1)
					if s.Verbose {
						PrintError(targetURL, err)
					}
					return
				}
				s.noteHostSuccess(host)

				resp.Duration = duration

				match := MatchTemplate(resp, t, reqIdx, baseline)
				if match == nil || !match.Matched {
					return
				}
				if match.Reflection && s.Config != nil && s.Config.SuppressReflectionMatch {
					if s.Verbose {
						fmt.Fprintf(os.Stderr, "  %s Suppressed (payload reflection): %s %s\n",
							SColor(ColorDim, "•"), t.ID, targetURL)
					}
					return
				}
				if s.Deduplicator.IsDuplicate(t.ID, targetURL, match.MatcherName) {
					return
				}
				s.Deduplicator.MarkSeen(t.ID, targetURL, match.MatcherName)

				r := Result{
					TemplateID:   t.ID,
					TemplateName: t.Info.Name,
					Severity:     t.Info.Severity,
					Type:         "vulnerability",
					MatcherName:  match.MatcherName,
					URL:          targetURL,
					Matched:      match.Extracted,
					Extracted:    match.Extracted,
					Confidence:   match.Confidence,
					Description:  t.Info.Description,
					Tags:         t.Info.Tags.String(),
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Request:      method + " " + targetURL,
					ResponseLen:  resp.BodyLen,
					ResponseTime: duration.Round(time.Millisecond).String(),
				}
				if c := t.Info.Classification; c != nil {
					r.CVE = strings.Join([]string(c.CVEID), ",")
					r.CWE = strings.Join([]string(c.CWEID), ",")
					if len(t.Info.Reference) > 0 {
						r.Remediation = strings.Join([]string(t.Info.Reference), ",")
					}
				}
				matched.Store(1)

				s.mu.Lock()
				s.Results = append(s.Results, r)
				s.mu.Unlock()

				s.Stats.IncFindings()
				atomic.AddInt32(&s.Progress.Findings, 1)

				quiet := s.Config != nil && (s.Config.Silent || s.Config.JSON || s.Config.JSONL || s.Config.CSV || s.Config.SARIF)
				if !quiet {
					PrintResultRealTime(r)
				}
			}(targetURL, host, hostOverride, baseline)
		}
	}
	wg.Wait()
	return matched.Load() == 1
}

func (s *Scanner) ProcessTemplate(baseURL string, t *Template) {
	if len(t.Requests) == 0 {
		return
	}
	for ri, req := range t.Requests {
		if s.TestTemplate(baseURL, t, ri, req) && req.StopAtFirstMatch {
			break
		}
	}
}

func (s *Scanner) progressRoutine() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Progress.Render()
		case <-s.doneCh:
			return
		}
	}
}

func (s *Scanner) Scan(baseURL string) []Result {
	s.Results = make([]Result, 0)
	if s.Stats == nil {
		s.Stats = &ScanStats{
			TemplatesTotal: int32(len(s.Templates)),
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
		}
	} else {
		s.Stats.TemplatesTotal = int32(len(s.Templates))
	}
	if s.Deduplicator == nil {
		s.Deduplicator = NewDeduplicator()
	}
	s.vars = NewTemplateVars(baseURL)
	s.StartTime = time.Now()

	// Resume support: replay checkpoint, skip completed (target, template) pairs.
	if s.Config != nil && s.Config.ResumeFile != "" {
		tracker, err := NewResumeTracker(s.Config.ResumeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] resume: %v\n", err)
		} else {
			s.resume = tracker
			defer tracker.Close()
		}
	}

	// Fresh progress + completion channel per Scan (multi-target safe).
	if s.Progress == nil {
		s.Progress = NewProgressDisplay()
	}
	atomic.StoreInt32(&s.Progress.Current, 0)
	atomic.StoreInt32(&s.Progress.Findings, 0)
	atomic.StoreInt32(&s.Progress.Requests, 0)
	atomic.StoreInt32(&s.Progress.Errors, 0)
	s.Progress.Total = int32(len(s.Templates))
	s.Progress.StartTime = time.Now()
	if s.Interactive {
		s.Progress.Start()
	}

	// Recreate doneCh every scan to avoid "close of closed channel".
	s.doneCh = make(chan struct{})

	threads := s.Threads
	if threads <= 0 {
		threads = 20
	}

	if s.Interactive {
		PrintScanStart(baseURL, threads, s.Timeout, len(s.Templates))
	}

	if !s.Verbose && s.Interactive {
		go s.progressRoutine()
	}

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, t := range s.Templates {
		wg.Add(1)
		sem <- struct{}{}
		go func(tmpl *Template) {
			defer wg.Done()
			defer func() {
				<-sem
				if s.Stats != nil {
					s.Stats.IncTested()
				}
				atomic.AddInt32(&s.Progress.Current, 1)
			}()
			if s.resume != nil && s.resume.Done(baseURL, tmpl.ID) {
				if s.Verbose {
					fmt.Fprintf(os.Stderr, "  %s Skipping (resumed): %s\n",
						SColor(ColorDim, "•"), tmpl.ID)
				}
				return
			}
			if s.Verbose {
				fmt.Fprintf(os.Stderr, "  %s Testing: %s\n",
					SColor(ColorDim, "•"), tmpl.ID)
			}
			s.ProcessTemplate(baseURL, tmpl)
			if s.resume != nil {
				s.resume.Mark(baseURL, tmpl.ID)
			}
		}(t)
	}
	wg.Wait()

	select {
	case <-s.doneCh:
	default:
		close(s.doneCh)
	}
	time.Sleep(50 * time.Millisecond)
	if s.Interactive {
		s.Progress.Render()
	}

	return s.Results
}
