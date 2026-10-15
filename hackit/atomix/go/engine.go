package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Scanner struct {
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
	mu              sync.Mutex
	findingsCh      chan Result
	doneCh          chan struct{}
}

func NewScanner(timeout, threads int) *Scanner {
	if threads <= 0 {
		threads = 20
	}
	client := NewHTTPClient(timeout)
	client.Timeout = time.Duration(timeout) * time.Second
	s := &Scanner{
		Client:     client,
		Threads:    threads,
		Timeout:    timeout,
		Progress:   NewProgressDisplay(),
		throttler:  NewThrottlerFromRPS(0), // disabled unless -rate-limit set
		StartTime:  time.Now(),
		findingsCh: make(chan Result, 1000),
		doneCh:     make(chan struct{}),
	}
	return s
}

func (s *Scanner) InitScanner(cfg *ScanConfig) {
	if cfg == nil {
		return
	}
	s.Config = cfg
	s.Client = NewConfiguredClient(cfg)
	// RateLimit is requests-per-second.
	s.throttler = NewThrottlerFromRPS(cfg.RateLimit)
	if cfg.Threads > 0 {
		s.Threads = cfg.Threads
	} else if cfg.Concurrency > 0 {
		s.Threads = cfg.Concurrency
	}
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
	for _, h := range ParseCustomHeaders(cfg) {
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

func (s *Scanner) TestTemplate(baseURL string, t *Template, reqIdx int, req Request) bool {
	matched := false
	payloads := req.Payloads
	if len(payloads) == 0 {
		payloads = []string{""}
	}

	headers := s.requestHeaders(req)
	body := t.ResolveRequestPart(req.Body, s.vars)
	method := effectiveMethod(req.Method, s.Config)
	retries := effectiveRetries(s.Config)

	for _, pathTmpl := range req.Path {
		for _, pay := range payloads {
			resolvedPath := ResolvePayload(t.ResolveRequestPart(pathTmpl, s.vars), pay, s.vars)
			targetURL := s.vars.Resolve(resolvedPath)
			if s.Stats != nil {
				atomic.AddInt32(&s.Stats.RequestsSent, 1)
			}
			atomic.AddInt32(&s.Progress.Requests, 1)
			if s.throttler != nil {
				s.throttler.Wait()
			}

			startTime := time.Now()
			resp, err := SendRequestWithRetry(s.Client, targetURL, method, body, headers, retries)
			duration := time.Since(startTime)

			if err != nil {
				if s.Stats != nil {
					s.Stats.IncErrors()
				}
				atomic.AddInt32(&s.Progress.Errors, 1)
				if s.Verbose {
					PrintError(targetURL, err)
				}
				continue
			}

			resp.Duration = duration

			match := MatchTemplate(resp, t, reqIdx)
			if match != nil && match.Matched {
				if s.Deduplicator.IsDuplicate(t.ID, targetURL, match.MatcherName) {
					continue
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
					Request:      req.Method + " " + targetURL,
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
				matched = true

				s.mu.Lock()
				s.Results = append(s.Results, r)
				s.mu.Unlock()

				s.Stats.IncFindings()
				atomic.AddInt32(&s.Progress.Findings, 1)

				PrintResultRealTime(r)
			}
		}
	}
	return matched
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
	s.Progress.Start()

	// Recreate doneCh every scan to avoid "close of closed channel".
	s.doneCh = make(chan struct{})

	threads := s.Threads
	if threads <= 0 {
		threads = 20
	}

	PrintScanStart(baseURL, threads, s.Timeout, len(s.Templates))

	if !s.Verbose {
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
			if s.Verbose {
				fmt.Fprintf(os.Stderr, "  %s Testing: %s\n",
					SColor(ColorDim, "•"), tmpl.ID)
			}
			s.ProcessTemplate(baseURL, tmpl)
		}(t)
	}
	wg.Wait()

	select {
	case <-s.doneCh:
	default:
		close(s.doneCh)
	}
	time.Sleep(50 * time.Millisecond)
	s.Progress.Render()

	return s.Results
}
