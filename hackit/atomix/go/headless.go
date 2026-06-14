package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type HeadlessResult struct {
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status"`
	Body     string `json:"body,omitempty"`
	Headers  string `json:"headers,omitempty"`
	Duration string `json:"duration"`
	ScreenshotPath string `json:"screenshot,omitempty"`
	ConsoleErrors  []string `json:"console_errors,omitempty"`
	NetworkRequests []string `json:"network_requests,omitempty"`
	Cookies        []string `json:"cookies,omitempty"`
	LocalStorage   map[string]string `json:"local_storage,omitempty"`
	JSVariables    map[string]string `json:"js_variables,omitempty"`
}

type HeadlessScanner struct {
	Config     *ScanConfig
	Client     *http.Client
	Timeout    time.Duration
	PageLoadTimeout time.Duration
	ActionTimeout   time.Duration
}

func NewHeadlessScanner(cfg *ScanConfig) *HeadlessScanner {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout < 10*time.Second { timeout = 30 * time.Second }
	pageTimeout := time.Duration(cfg.PageTimeout) * time.Millisecond
	if pageTimeout < 1 { pageTimeout = 10 * time.Second }
	actionTimeout := time.Duration(cfg.ActionTimeout) * time.Millisecond
	if actionTimeout < 1 { actionTimeout = 5 * time.Second }
	return &HeadlessScanner{
		Config:          cfg,
		Client:          NewHTTPClient(cfg.Timeout),
		Timeout:         timeout,
		PageLoadTimeout: pageTimeout,
		ActionTimeout:   actionTimeout,
	}
}

func (h *HeadlessScanner) ScanURL(url string) *HeadlessResult {
	start := time.Now()
	res := &HeadlessResult{URL: url, Duration: "0s"}

	client := h.Client
	if h.Config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 { return http.ErrUseLastResponse }
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		res.Status = 0
		return res
	}
	req.Header.Set("User-Agent", RandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		res.Status = 0
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	var headerStr strings.Builder
	resp.Header.Write(&headerStr)
	res.Headers = headerStr.String()

	res.Duration = time.Since(start).Round(time.Millisecond).String()

	return res
}

func (h *HeadlessScanner) ExtractTitle(body string) string {
	idx := strings.Index(strings.ToLower(body), "<title")
	if idx == -1 { return "" }
	end := strings.Index(body[idx:], "</title>")
	if end == -1 { return "" }
	startContent := strings.Index(body[idx:], ">")
	if startContent == -1 { return "" }
	title := body[idx+startContent+1 : idx+end]
	title = strings.TrimSpace(title)
	title = strings.ReplaceAll(title, "\n", " ")
	return title
}

func (h *HeadlessScanner) RunAll(urls []string) []HeadlessResult {
	var results []HeadlessResult
	for _, u := range urls {
		r := h.ScanURL(u)
		if r.Body != "" {
			r.Title = h.ExtractTitle(r.Body)
		}
		results = append(results, *r)
	}
	return results
}

func PrintHeadlessResults(results []HeadlessResult) {
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "%s No headless results\n", SColor(ColorYellow, "[!]"))
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s Headless Scan Results:\n", SColor(ColorBCyan, "►"))
	for _, r := range results {
		statusColor := ColorGreen
		if r.Status >= 400 { statusColor = ColorRed
		} else if r.Status >= 300 { statusColor = ColorYellow }
		title := r.Title
		if title != "" { title = " - " + title }
		fmt.Fprintf(os.Stderr, "  %s %s%s\n",
			SColor(statusColor, fmt.Sprintf("[%d]", r.Status)),
			r.URL, title)
		if r.Duration != "0s" {
			fmt.Fprintf(os.Stderr, "     Duration: %s\n", r.Duration)
		}
		if len(r.ConsoleErrors) > 0 {
			fmt.Fprintf(os.Stderr, "     Console: %d errors\n", len(r.ConsoleErrors))
		}
	}
}

func HandleHeadlessMode(cfg *ScanConfig, urls []string) {
	scanner := NewHeadlessScanner(cfg)
	results := scanner.RunAll(urls)
	PrintHeadlessResults(results)
}
