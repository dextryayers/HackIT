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
	Client            *http.Client
	Params            []string
	BaselineBody      string
	BaselineTime      time.Duration
	BaselineCode      int
	baselineObtained  bool
	baselineMu        sync.Mutex
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
		Timeout:   time.Duration(opts.Timeout+20) * time.Second,
	}
	d.Params = d.extractParams()
	return d
}

func (d *Detector) buildRequest(param, payload string) (*http.Request, error) {
	baseURL := d.URL
	parsed, err := url.Parse(baseURL)
	if err != nil {
		parsed, _ = url.Parse("http://" + baseURL)
	}
	query := parsed.Query()
	query.Set(param, payload)
	parsed.RawQuery = query.Encode()

	var body io.Reader
	method := "GET"
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

func (d *Detector) ensureBaseline(param string) {
	d.baselineMu.Lock()
	defer d.baselineMu.Unlock()
	if d.baselineObtained {
		return
	}
	body, elapsed, code, err := d.sendPayload(param, "HACKIT_BASELINE_1749")
	if err != nil {
		return
	}
	d.BaselineBody = body
	d.BaselineTime = elapsed
	d.BaselineCode = code
	d.baselineObtained = true
	if d.Verbose {
		fmt.Fprintf(os.Stderr, "[baseline] time=%v size=%d code=%d\n", elapsed, len(body), code)
	}
}

func (d *Detector) testTimePayload(param string, p RCEPayload, baselineTime time.Duration) (bool, float64) {
	payload := fmt.Sprintf(p.Payload, p.SleepTime)
	for r := 0; r < d.Retries; r++ {
		_, elapsed, _, err := d.sendPayload(param, payload)
		if err == nil && p.SleepTime > 0 {
			minDur := time.Duration(p.SleepTime) * time.Second
			ratio := float64(elapsed) / float64(minDur)
			baselineRatio := float64(elapsed) / float64(baselineTime+time.Millisecond)
			if elapsed >= minDur && ratio >= 0.8 {
				conf := 0.85
				if baselineRatio > 3 {
					conf = 0.95
				}
				if elapsed >= minDur*2 {
					conf = 0.98
				}
				return true, conf
			}
			if elapsed >= minDur/2 && baselineRatio > 5 {
				return true, 0.75
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
	baseline := d.BaselineBody

	for r := 0; r < d.Retries; r++ {
		body, _, _, err := d.sendPayload(param, payload)
		if err != nil {
			if d.Delay > 0 {
				time.Sleep(time.Duration(d.Delay) * time.Millisecond)
			}
			continue
		}
		if strings.Contains(body, p.EchoStr) {
			inBaseline := strings.Contains(baseline, p.EchoStr)
			conf := 0.90
			if !inBaseline {
				conf = 0.97
			}
			if p.EchoStr == ECHO_MARKER {
				conf = 0.99
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
	baseline := d.BaselineBody

	body, _, _, err := d.sendPayload(param, payload)
	if err != nil || body == baseline {
		return false, 0
	}

	bodyLower := strings.ToLower(body)
	indicators := []string{
		"warning", "error", "unexpected", "not found", "command not found",
		"stack trace", "fatal error", "exception", "traceback", "parse error",
		"syntax error", "undefined", "permission denied", "cannot execute",
		"500", "internal server error", "division by zero", "index out of",
		"nil pointer", "invalid memory", "segmentation fault",
	}

	hits := 0
	for _, ind := range indicators {
		if strings.Contains(bodyLower, ind) {
			hits++
		}
	}
	if hits > 0 {
		conf := 0.60 + float64(hits)*0.06
		if conf > 0.92 {
			conf = 0.92
		}
		return true, conf
	}
	return false, 0
}

func (d *Detector) testBlindPayload(param string, p RCEPayload) (bool, float64) {
	baseline := d.BaselineBody
	for r := 0; r < d.Retries; r++ {
		payload := fmt.Sprintf(p.Payload, ECHO_MARKER, ECHO_MARKER)
		body, _, _, err := d.sendPayload(param, payload)
		if err != nil {
			continue
		}
		if strings.Contains(body, p.EchoStr) && !strings.Contains(baseline, p.EchoStr) {
			return true, 0.92
		}
		if d.Delay > 0 {
			time.Sleep(time.Duration(d.Delay) * time.Millisecond)
		}
	}
	return false, 0
}

func (d *Detector) testOOBPayload(param string, payload string) {
	if d.OOB == "" {
		return
	}
	parsedPayload := fmt.Sprintf(payload, d.OOB)
	d.sendPayload(param, parsedPayload)
	d.sendPayload(param, strings.ReplaceAll(parsedPayload, ";", "|"))
}

func (d *Detector) detectParam(param string) *Result {
	d.ensureBaseline(param)
	timeMultiplier := 1.0
	if d.BaselineTime > 0 {
		timeMultiplier = float64(d.BaselineTime) / float64(time.Second)
		if timeMultiplier < 0.1 {
			timeMultiplier = 1.0
		}
	}

	maxConf := 0.0
	var bestResult *Result

	allPayloads := getAllPayloads("all")
	for _, p := range allPayloads {
		var vuln bool
		var conf float64

		switch {
		case strings.HasPrefix(p.Technique, "time"):
			vuln, conf = d.testTimePayload(param, p, d.BaselineTime)
		case strings.HasPrefix(p.Technique, "output") || strings.HasPrefix(p.Technique, "output-"):
			vuln, conf = d.testOutputPayload(param, p)
		case p.Technique == "error":
			vuln, conf = d.testErrorPayload(param, p)
		case p.Technique == "blind":
			vuln, conf = d.testBlindPayload(param, p)
		case strings.HasPrefix(p.Technique, "oob"):
			d.testOOBPayload(param, p.Payload)
			continue
		}

		if vuln && conf > maxConf {
			maxConf = conf
			payloadStr := strings.Split(p.Payload, ECHO_MARKER)[0]
			if len(payloadStr) > 60 {
				payloadStr = payloadStr[:60]
			}
			bestResult = &Result{
				Vulnerable: true,
				URL:        d.URL,
				Parameter:  param,
				Method:     d.Method,
				Payload:    payloadStr,
				Confidence: conf,
				Engine:     "go",
				Technique:  p.Technique,
				Output:     fmt.Sprintf("%s RCE via %s", p.Category, p.Technique),
			}
		}
	}

	if bestResult != nil {
		bestResult.Confidence = maxConf
		return bestResult
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
