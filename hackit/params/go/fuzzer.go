package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Fuzzer struct {
	Client  *http.Client
	Timeout int
}

func NewFuzzer(timeout int) *Fuzzer {
	return &Fuzzer{
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Timeout: timeout,
	}
}

var sqlErrors = []string{
	"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite/JDBCDriver",
	"System.Data.SQLClient", "Unclosed quotation mark", "Microsoft OLE DB",
	"mysql_error", "Warning: mysql", "supplied argument is not a valid",
	"SQLite3::", "SQLSTATE[", "MariaDB", "DB2 SQL error", "Driver may not be capable",
	"Error Executing Database Query", "Syntax error in query",
	"Invalid query:", "Unknown column", "Table", "doesn't exist",
	"Column not found", "Data too long for column",
}

var xssReflections = []string{
	"<script>", "alert(", "onerror=", "onload=", "onclick=",
	"javascript:", "onfocus=", "onmouseover=", "onchange=",
}

var sstiPatterns = []string{
	"{{", "}}", "${", "{{7*7}}", "{{7*'7'}}",
}

func (f *Fuzzer) Fuzz(target, param, payload, method string) FuzzResult {
	start := time.Now()
	result := FuzzResult{
		Param:   param,
		Payload: payload,
		Method:  method,
	}

	u, err := url.Parse(target)
	if err != nil {
		return result
	}

	var req *http.Request
	if method == "POST" {
		formData := url.Values{}
		formData.Set(param, payload)
		req, err = http.NewRequest("POST", target, strings.NewReader(formData.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		q := u.Query()
		q.Set(param, payload)
		u.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", u.String(), nil)
	}

	if err != nil {
		return result
	}

	req.Header.Set("User-Agent", "HackIt-ParamScanner/2.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := f.Client.Do(req)
	result.RTT_MS = time.Since(start).Milliseconds()
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	result.Status = resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}
	body := string(bodyBytes)

	// Reflection check
	if strings.Contains(body, payload) {
		result.Reflected = true
		idx := strings.Index(body, payload)
		start := idx - 30
		if start < 0 {
			start = 0
		}
		end := idx + len(payload) + 30
		if end > len(body) {
			end = len(body)
		}
		result.Context = body[start:end]
	}

	// Error detection
	for _, sqlErr := range sqlErrors {
		if strings.Contains(body, sqlErr) {
			result.Error = "SQL Error: " + sqlErr
			break
		}
	}

	// XSS reflection context detection
	if result.Reflected {
		for _, xss := range xssReflections {
			if strings.Contains(body, xss) {
				if result.Error == "" {
					result.Error = "XSS reflection context detected"
				}
				break
			}
		}
	}

	return result
}

func (f *Fuzzer) FuzzDiscovered(results []DiscoResult, payloads []string, method string, threads int) []FuzzResult {
	var fuzzResults []FuzzResult
	var muFuzz sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	// Collect unique param+URL combos
	type fuzzTarget struct {
		URL   string
		Param string
	}
	var targets []fuzzTarget
	seen := make(map[string]bool)
	for _, r := range results {
		for _, p := range r.ParamNames {
			key := r.URL + ":" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, fuzzTarget{URL: r.URL, Param: p})
		}
	}

	for _, target := range targets {
		for _, payload := range payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(t fuzzTarget, pay string) {
				defer wg.Done()
				defer func() { <-sem }()
				res := f.Fuzz(t.URL, t.Param, pay, method)
				if res.Reflected || res.Error != "" {
					muFuzz.Lock()
					fuzzResults = append(fuzzResults, res)
					muFuzz.Unlock()
				}
			}(target, payload)
		}
	}
	wg.Wait()

	return fuzzResults
}
