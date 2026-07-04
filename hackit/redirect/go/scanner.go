package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Engine     string `json:"engine"`
	Location   string `json:"location"`
	HTTPStatus int    `json:"http_status"`
	Confidence string `json:"confidence"`
	BodyCheck  string `json:"body_check,omitempty"`
}

type Scanner struct {
	Client       *http.Client
	Timeout      int
	Deadline     time.Time
	Results      []Result
	RequestCount int
	mu           sync.Mutex
}

func NewScanner(timeout int) *Scanner {
	sc := &Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    100,
				MaxConnsPerHost: 50,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 5 * time.Second,
		},
		Timeout:  timeout,
		Deadline: time.Now().Add(time.Duration(timeout) * time.Second),
		Results:  make([]Result, 0),
	}
	return sc
}

func (s *Scanner) isDeadlinePassed() bool {
	return time.Now().After(s.Deadline)
}

func (s *Scanner) Scan(targetURL string) []Result {
	s.Results = make([]Result, 0)
	s.RequestCount = 0

	u, err := url.Parse(targetURL)
	if err != nil {
		return s.Results
	}

	var wg sync.WaitGroup
	resultsChan := make(chan []Result, 10)

	engines := []func(string, *url.URL) []Result{
		s.scanQueryParams,
		s.scanBody,
		s.scanHeaders,
		s.scanPath,
		s.scanDOMPayloads,
		s.scanBypass,
		s.scanBlindRedirect,
		s.scanDeepPayload,
		s.scanCookieRedirect,
		s.scanEncodingMatrix,
	}

	for _, engine := range engines {
		wg.Add(1)
		go func(fn func(string, *url.URL) []Result) {
			defer wg.Done()
			resultsChan <- fn(targetURL, u)
		}(engine)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for batch := range resultsChan {
		s.mu.Lock()
		s.Results = append(s.Results, batch...)
		s.mu.Unlock()
	}

	return s.Results
}

func (s *Scanner) makeRequest(attackURL string) (*http.Response, string, string, error) {
	s.mu.Lock()
	s.RequestCount++
	s.mu.Unlock()

	req, err := http.NewRequest("GET", attackURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	loc := resp.Header.Get("Location")
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	resp.Body.Close()
	return resp, loc, bodyStr, nil
}

func (s *Scanner) makeRequestWithHeader(attackURL string, headers map[string]string) (*http.Response, string, string, error) {
	s.mu.Lock()
	s.RequestCount++
	s.mu.Unlock()

	req, err := http.NewRequest("GET", attackURL, nil)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	loc := resp.Header.Get("Location")
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	resp.Body.Close()
	return resp, loc, bodyStr, nil
}

func (s *Scanner) checkRedirect(targetURL, attackURL, param, payload, engine, loc, body string, status int) {
	if loc != "" {
		parsed, err := url.Parse(loc)
		if err == nil && parsed.Host != "" && !strings.HasPrefix(loc, "/") {
			originalHost, _ := extractHost(targetURL)
			if parsed.Host != originalHost && !strings.HasSuffix(parsed.Host, "."+originalHost) {
				s.mu.Lock()
				s.Results = append(s.Results, Result{
					URL:        attackURL,
					Parameter:  param,
					Payload:    payload,
					Engine:     engine,
					Location:   loc,
					HTTPStatus: status,
					Confidence: "HIGH",
				})
				s.mu.Unlock()
				return
			}
		}
	}

	if body != "" {
		jsLoc := extractJSRedirect(body)
		if jsLoc != "" {
			parsed, err := url.Parse(jsLoc)
			if err == nil && parsed.Host != "" {
				originalHost, _ := extractHost(targetURL)
				if parsed.Host != originalHost && !strings.HasSuffix(parsed.Host, "."+originalHost) {
					s.mu.Lock()
					s.Results = append(s.Results, Result{
						URL:        attackURL,
						Parameter:  param,
						Payload:    payload,
						Engine:     engine + " (JS)",
						Location:   jsLoc,
						HTTPStatus: status,
						Confidence: "MEDIUM",
						BodyCheck:  "js_redirect",
					})
					s.mu.Unlock()
					return
				}
			}
		}

		metaLoc := extractMetaRefresh(body)
		if metaLoc != "" {
			parsed, err := url.Parse(metaLoc)
			if err == nil && parsed.Host != "" {
				originalHost, _ := extractHost(targetURL)
				if parsed.Host != originalHost && !strings.HasSuffix(parsed.Host, "."+originalHost) {
					s.mu.Lock()
					s.Results = append(s.Results, Result{
						URL:        attackURL,
						Parameter:  param,
						Payload:    payload,
						Engine:     engine + " (Meta)",
						Location:   metaLoc,
						HTTPStatus: status,
						Confidence: "MEDIUM",
						BodyCheck:  "meta_refresh",
					})
					s.mu.Unlock()
					return
				}
			}
		}

		if strings.Contains(body, payload) && (strings.HasPrefix(payload, "http://") || strings.HasPrefix(payload, "https://") || strings.HasPrefix(payload, "//")) {
			originalHost, _ := extractHost(targetURL)
			parsedPayload, err := url.Parse(payload)
			if err == nil && parsedPayload.Host != "" && parsedPayload.Host != originalHost && !strings.HasSuffix(parsedPayload.Host, "."+originalHost) {
				s.mu.Lock()
				s.Results = append(s.Results, Result{
					URL:        attackURL,
					Parameter:  param,
					Payload:    payload,
					Engine:     engine + " (Reflected)",
					Location:   payload,
					HTTPStatus: status,
					Confidence: "LOW",
					BodyCheck:  "reflected_payload",
				})
				s.mu.Unlock()
			}
		}
	}
}

var (
	jsRedirectRe1 = regexp.MustCompile(`(?:window|document|top|parent|self|this|opener)\.(?:location|location\.href|location\.replace|location\.assign|navigate|open)\s*[=:]\s*['"]([^'"]+)['"]`)
	jsRedirectRe2 = regexp.MustCompile(`(?:location|document\.url|document\.location|document\.location\.href)\s*[=:]\s*['"]([^'"]+)['"]`)
	jsRedirectRe3 = regexp.MustCompile(`location\.(?:href|replace|assign)\s*\(\s*['"]([^'"]+)['"]`)
	jsRedirectRe4 = regexp.MustCompile(`window\.open\s*\(\s*['"]([^'"]+)['"]`)
	jsRedirectRe5 = regexp.MustCompile(`\$\s*\.\s*redirect\s*\(\s*['"]([^'"]+)['"]`)
	jsRedirectRe6 = regexp.MustCompile(`window\.navigate\s*\(\s*['"]([^'"]+)['"]`)
	metaRefreshRe = regexp.MustCompile(`<meta[^>]*http-equiv\s*=\s*["']?\s*refresh\s*["']?[^>]*content\s*=\s*["']?\d+;\s*url\s*=\s*([^'"\s>]+)`)
)

func extractJSRedirect(body string) string {
	if body == "" {
		return ""
	}
	for _, re := range []*regexp.Regexp{jsRedirectRe1, jsRedirectRe2, jsRedirectRe3, jsRedirectRe4, jsRedirectRe5, jsRedirectRe6} {
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 && matches[1] != "" {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func extractMetaRefresh(body string) string {
	if body == "" {
		return ""
	}
	matches := metaRefreshRe.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func extractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	clone := new(url.URL)
	*clone = *u
	if u.User != nil {
		clone.User = &url.Userinfo{}
		*clone.User = *u.User
	}
	return clone
}
