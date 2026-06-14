package main

import (
	"fmt"
	"net/http"
	"os"
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
	client := NewHTTPClient(timeout)
	client.Timeout = time.Duration(timeout) * time.Second
	s := &Scanner{
		Client:     client,
		Threads:    threads,
		Timeout:    timeout,
		Progress:   NewProgressDisplay(),
		throttler:  NewThrottler(100),
		StartTime:  time.Now(),
		findingsCh: make(chan Result, 1000),
		doneCh:     make(chan struct{}),
	}
	return s
}

func (s *Scanner) InitScanner(cfg *ScanConfig) {
	if cfg != nil {
		s.Client = NewConfiguredClient(cfg)
		if cfg.RateLimit > 0 {
			s.throttler = NewThrottler(cfg.RateLimit)
		}
	}
}

func (s *Scanner) TestTemplate(baseURL string, t *Template, reqIdx int, req Request) {
	payloads := req.Payloads
	if len(payloads) == 0 {
		payloads = []string{""}
	}

	for _, pathTmpl := range req.Path {
		for _, pay := range payloads {
			resolvedPath := ResolvePayload(pathTmpl, pay, s.vars)
			targetURL := s.vars.Resolve(resolvedPath)
			atomic.AddInt32(&s.Stats.RequestsSent, 1)
			s.throttler.Wait()

			startTime := time.Now()
			resp, err := SendRequest(s.Client, targetURL, req.Method, req.Body, req.Headers)
			duration := time.Since(startTime)

			if err != nil {
				s.Stats.IncErrors()
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
					Description:  t.Info.Description,
					Tags:         t.Info.Tags,
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Request:      req.Method + " " + targetURL,
					ResponseLen:  resp.BodyLen,
					ResponseTime: duration.Round(time.Millisecond).String(),
				}

				s.mu.Lock()
				s.Results = append(s.Results, r)
				s.mu.Unlock()

				s.Stats.IncFindings()
				atomic.AddInt32(&s.Progress.Findings, 1)

				PrintResultRealTime(r)
			}
		}
	}
}

func (s *Scanner) ProcessTemplate(baseURL string, t *Template) {
	if len(t.Requests) == 0 {
		return
	}
	for ri, req := range t.Requests {
		s.TestTemplate(baseURL, t, ri, req)
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
	}
	if s.Deduplicator == nil {
		s.Deduplicator = NewDeduplicator()
	}
	s.vars = NewTemplateVars(baseURL)
	s.StartTime = time.Now()

	s.Progress.Total = int32(len(s.Templates))
	s.Progress.Start()

	PrintScanStart(baseURL, s.Threads, s.Timeout, len(s.Templates))

	if !s.Verbose {
		go s.progressRoutine()
	}

	sem := make(chan struct{}, s.Threads)
	var wg sync.WaitGroup

	for _, t := range s.Templates {
		wg.Add(1)
		sem <- struct{}{}
		go func(tmpl *Template) {
			defer wg.Done()
			defer func() {
				<-sem
				s.Stats.IncTested()
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

	close(s.doneCh)
	time.Sleep(50 * time.Millisecond)
	s.Progress.Render()

	return s.Results
}
