package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type CommonOptions struct {
	URL       string
	Data      string
	Method    string
	Param     string
	Timeout   int
	Threads   int
	Proxy     string
	Cookie    string
	UserAgent string
	Blind     bool
	All       bool
	OOB       string
	Verbose   bool
	Tech      string
	Delay     int
	Retries   int
}

type Detector struct {
	CommonOptions
	Client     *http.Client
	Params     []string
	Techniques []string
}

func NewDetector(opts CommonOptions) *Detector {
	d := &Detector{CommonOptions: opts}
	transport := &http.Transport{
		MaxIdleConns:       200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:    30 * time.Second,
		DisableKeepAlives:  false,
	}
	if opts.Proxy != "" {
		proxyURL, _ := url.Parse(opts.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	d.Client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout+10) * time.Second,
	}
	d.Params = d.extractParams()
	d.Techniques = d.selectTechniques()
	return d
}

func (d *Detector) buildRequest(param, payload string) (*http.Request, error) {
	baseURL := d.URL
	method := d.Method

	parsed, err := url.Parse(baseURL)
	if err != nil {
		parsed, _ = url.Parse("http://" + baseURL)
	}

	query := parsed.Query()
	query.Set(param, payload)
	parsed.RawQuery = query.Encode()

	var body io.Reader
	method = "GET"
	if d.Data != "" || strings.ToUpper(d.Method) == "POST" {
		method = "POST"
		formData := d.Data
		if formData == "" {
			formData = url.Values{param: {payload}}.Encode()
		} else {
			vals, _ := url.ParseQuery(formData)
			vals.Set(param, payload)
			formData = vals.Encode()
		}
		body = strings.NewReader(formData)
	}

	req, err := http.NewRequest(method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", d.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	if d.Cookie != "" {
		req.Header.Set("Cookie", d.Cookie)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req, nil
}

func (d *Detector) sendPayload(param, payload string) (string, time.Duration, int, error) {
	req, err := d.buildRequest(param, payload)
	if err != nil {
		return "", 0, 0, err
	}
	start := time.Now()
	resp, err := d.Client.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, 0, err
	}
	return string(body), elapsed, resp.StatusCode, nil
}

func (d *Detector) testBaseline(param string) (string, time.Duration, int) {
	body, elapsed, code, err := d.sendPayload(param, "HACKIT_BASELINE_1749")
	if err != nil {
		return "", 0, 0
	}
	return body, elapsed, code
}

func (d *Detector) testTimePayload(param string, p RCEPayload) (bool, float64) {
	payload := fmt.Sprintf(p.Payload, p.SleepTime)
	for r := 0; r < d.Retries; r++ {
		_, elapsed, _, err := d.sendPayload(param, payload)
		if err == nil {
			minDur := time.Duration(p.SleepTime) * time.Second
			if elapsed >= minDur && p.SleepTime > 0 {
				return true, 0.85
			}
		}
		if d.Delay > 0 {
			time.Sleep(time.Duration(d.Delay) * time.Millisecond)
		}
	}
	return false, 0
}

func (d *Detector) testOutputPayload(param string, p RCEPayload) (bool, float64) {
	payload := fmt.Sprintf(p.Payload, ECHO_MARKER)
	for r := 0; r < d.Retries; r++ {
		body, _, _, err := d.sendPayload(param, payload)
		if err != nil {
			if d.Delay > 0 {
				time.Sleep(time.Duration(d.Delay) * time.Millisecond)
			}
			continue
		}
		baseline, _, _ := d.testBaseline(param)

		if strings.Contains(body, p.EchoStr) {
			isInBaseline := strings.Contains(baseline, p.EchoStr)
			conf := 0.90
			if !isInBaseline {
				conf = 0.97
			}
			return true, conf
		}
		if d.Delay > 0 {
			time.Sleep(time.Duration(d.Delay) * time.Millisecond)
		}
	}
	return false, 0
}

func (d *Detector) testErrorPayload(param string, p RCEPayload) (bool, float64) {
	payload := p.Payload
	baseline, _, _ := d.testBaseline(param)

	body, _, _, err := d.sendPayload(param, payload)
	if err != nil || body == baseline {
		return false, 0
	}

	bodyLower := strings.ToLower(body)
	indicators := []string{
		"warning", "error", "unexpected", "not found", "command not found",
		"stack trace", "fatal error", "exception", "traceback", "parse error",
		"syntax error", "undefined", "permission denied", "cannot execute",
		"500", "internal server error",
	}

	hits := 0
	for _, ind := range indicators {
		if strings.Contains(bodyLower, ind) {
			hits++
		}
	}
	if hits > 0 {
		conf := 0.60 + float64(hits)*0.05
		if conf > 0.90 {
			conf = 0.90
		}
		return true, conf
	}
	return false, 0
}

func (d *Detector) testBlindPayload(param string, p RCEPayload) (bool, float64) {
	for r := 0; r < d.Retries; r++ {
		payload := fmt.Sprintf(p.Payload, ECHO_MARKER, ECHO_MARKER)
		baseline, _, _ := d.testBaseline(param)
		body, _, _, err := d.sendPayload(param, payload)
		if err != nil {
			continue
		}
		if strings.Contains(body, p.EchoStr) && !strings.Contains(baseline, p.EchoStr) {
			return true, 0.90
		}
		if d.Delay > 0 {
			time.Sleep(time.Duration(d.Delay) * time.Millisecond)
		}
	}
	return false, 0
}

func (d *Detector) testOOBPayload(param string, payload string) {
	parsedPayload := fmt.Sprintf(payload, d.OOB)
	d.sendPayload(param, parsedPayload)
	d.sendPayload(param, strings.ReplaceAll(parsedPayload, ";", "|"))
}

func (d *Detector) detectParam(param string) *Result {
	allPayloads := getAllPayloads("all")

	for _, p := range allPayloads {
		var vuln bool
		var conf float64

		switch p.Technique {
		case "time", "time-waf":
			vuln, conf = d.testTimePayload(param, p)
			if vuln {
				return &Result{
					Vulnerable: true, URL: d.URL, Parameter: param,
					Method: d.Method, Technique: "time-based",
					Confidence: conf, Engine: "go",
					Output: fmt.Sprintf("Time delay: %ds", p.SleepTime),
				}
			}
		case "output", "output-waf", "output-perl", "output-python3", "output-python",
			"output-ruby", "output-php", "output-node", "output-lua", "output-awk",
			"output-bash", "output-sh":
			vuln, conf = d.testOutputPayload(param, p)
			if vuln {
				return &Result{
					Vulnerable: true, URL: d.URL, Parameter: param,
					Method: d.Method, Technique: p.Technique,
					Confidence: conf, Engine: "go",
					Output: fmt.Sprintf("Output-based RCE (%s)", p.Category),
				}
			}
		case "error":
			vuln, conf = d.testErrorPayload(param, p)
			if vuln {
				return &Result{
					Vulnerable: true, URL: d.URL, Parameter: param,
					Method: d.Method, Technique: "error-based",
					Confidence: conf, Engine: "go",
					Output: "Error-based RCE detected",
				}
			}
		case "blind":
			if d.Blind {
				vuln, conf = d.testBlindPayload(param, p)
				if vuln {
					return &Result{
						Vulnerable: true, URL: d.URL, Parameter: param,
						Method: d.Method, Technique: "blind-boolean",
						Confidence: conf, Engine: "go",
						Output: "Blind boolean RCE",
					}
				}
			}
		case "oob-http", "oob-dns":
			if d.OOB != "" {
				d.testOOBPayload(param, p.Payload)
			}
		}
	}
	return nil
}

func (d *Detector) extractParams() []string {
	if d.Param != "" {
		return []string{d.Param}
	}
	parsed, err := url.Parse(d.URL)
	if err != nil {
		parsed, _ = url.Parse("http://" + d.URL)
	}
	paramSet := make(map[string]bool)
	for k := range parsed.Query() {
		paramSet[k] = true
	}

	if d.Data != "" {
		vals, _ := url.ParseQuery(d.Data)
		for k := range vals {
			paramSet[k] = true
		}
	}

	if len(paramSet) == 0 || d.All {
		defaults := []string{
			"q", "id", "cmd", "exec", "command", "url", "host", "file", "input",
			"search", "c", "code", "lang", "debug", "action", "process", "run",
			"system", "shell", "page", "dir", "folder", "path", "cat", "read",
			"include", "require", "open", "doc", "document", "template", "view",
			"load", "import", "config", "setting", "option", "opt", "key", "token",
			"pass", "password", "user", "username", "email",
		}
		if len(paramSet) == 0 {
			return defaults
		}
		if d.All {
			for _, k := range defaults {
				paramSet[k] = true
			}
		}
	}

	params := make([]string, 0, len(paramSet))
	for k := range paramSet {
		params = append(params, k)
	}
	return params
}

func (d *Detector) selectTechniques() []string {
	if d.Blind {
		return []string{"blind", "time", "output"}
	}
	return []string{"output", "output-waf", "time", "error", "blind", "oob"}
}

func (d *Detector) Scan() []Result {
	var mu sync.Mutex
	results := []Result{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.Threads)

	for _, param := range d.Params {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			if d.Verbose {
				fmt.Fprintf(os.Stderr, "[*] Testing parameter: %s\n", p)
			}
			result := d.detectParam(p)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(param)
	}
	wg.Wait()

	if len(results) == 0 {
		results = append(results, Result{
			Vulnerable: false, URL: d.URL, Method: d.Method,
			Engine: "go", Confidence: 0,
		})
	}
	return results
}
