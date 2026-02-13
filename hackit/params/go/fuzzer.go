package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Result struct {
	Param     string `json:"param"`
	Payload   string `json:"payload"`
	Reflected bool   `json:"reflected"`
	Error     string `json:"error,omitempty"`
	Context   string `json:"context,omitempty"`
}

type Fuzzer struct {
	Client *http.Client
}

func NewFuzzer(timeout int) *Fuzzer {
	return &Fuzzer{
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (f *Fuzzer) Fuzz(target, param, payload, method string) Result {
	u, err := url.Parse(target)
	if err != nil {
		return Result{}
	}

	q := u.Query()
	q.Set(param, payload)
	
	u.RawQuery = q.Encode()
	reqURL := u.String()

	var req *http.Request
	if method == "POST" {
		formData := url.Values{}
		formData.Set(param, payload)
		req, err = http.NewRequest("POST", target, strings.NewReader(formData.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequest("GET", reqURL, nil)
	}

	if err != nil {
		return Result{}
	}

	req.Header.Set("User-Agent", "HackIt-Fuzzer/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		return Result{}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}
	}
	body := string(bodyBytes)

	res := Result{
		Param:   param,
		Payload: payload,
	}

	// Check Reflection
	if strings.Contains(body, payload) {
		res.Reflected = true
		// Grab context (some chars around the payload)
		idx := strings.Index(body, payload)
		start := idx - 20
		if start < 0 {
			start = 0
		}
		end := idx + len(payload) + 20
		if end > len(body) {
			end = len(body)
		}
		res.Context = body[start:end]
	}

	// Check Errors (Simple SQLi detection patterns)
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-",
		"PostgreSQL",
		"SQLite/JDBCDriver",
		"System.Data.SQLClient",
	}

	for _, sqlErr := range sqlErrors {
		if strings.Contains(body, sqlErr) {
			res.Error = "SQL Error Detected: " + sqlErr
			break
		}
	}

	return res
}
