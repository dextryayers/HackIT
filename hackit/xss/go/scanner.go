package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Type       string `json:"type"` 
	Details    string `json:"details"`
	Confidence string `json:"confidence"`
	Severity   string `json:"severity"`
	Impact     string `json:"impact"`
}

type Scanner struct {
	Client   *http.Client
	Payloads []string
}

func NewScanner(timeout int) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(timeout) * time.Second,
		},
		Payloads: Payloads, // Default to hardcoded
	}
}

func (s *Scanner) LoadPayloads(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	s.Payloads = make([]string, 0)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			s.Payloads = append(s.Payloads, trimmed)
		}
	}
	return nil
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

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Limit concurrency to avoid overwhelming the server
	sem := make(chan struct{}, 10) 

	for param := range params {
		for _, payload := range s.Payloads {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				// Construct URL
				newParams := make(url.Values)
				for k, v := range params {
					if k == p {
						newParams.Set(k, pay)
					} else {
						newParams[k] = v
					}
				}
				u.RawQuery = newParams.Encode()
				attackURL := u.String()

				req, err := http.NewRequest("GET", attackURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "HackIt-XSS/1.0")

				resp, err := s.Client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				// PRECISION CHECK: Reflection is not enough. Check if it's encoded or filtered.
				if strings.Contains(bodyStr, pay) {
					// Detection Logic: 
					// 1. Is it reflected exactly? (Yes, strings.Contains already checked)
					// 2. Is it in an executable context?
					
					confidence := "Medium"
					details := "Reflected in HTML body"
					severity := "Low"
					impact := "Content Spoofing"

					// Context-Aware Precision Analysis & Risk Scoring
					if strings.Contains(bodyStr, "<script>"+pay) || strings.Contains(bodyStr, pay+"</script>") {
						details = "CRITICAL: Executable Script Context"
						confidence = "High"
						severity = "High"
						impact = "Full Account Takeover (Session Theft)"
					} else if strings.Contains(bodyStr, "=\""+pay) || strings.Contains(bodyStr, "='"+pay) {
						details = "HIGH: Attribute Breakout Context"
						confidence = "High"
						severity = "Medium"
						impact = "Phishing / Forced Redirection"
					} else if strings.Contains(bodyStr, "href=\"javascript:"+pay) {
						details = "CRITICAL: URI Handler Context"
						confidence = "High"
						severity = "Critical"
						impact = "Direct Code Execution"
					}

					// Check for sensitive cookie access in payload
					if strings.Contains(pay, "cookie") || strings.Contains(pay, "fetch") {
						severity = "Critical"
						impact = "Data Exfiltration (Sensitive Information)"
					}

					// Verify if it's NOT encoded (Precision check)
					if strings.Contains(pay, "<") && strings.Contains(bodyStr, "&lt;") && !strings.Contains(bodyStr, "<") {
						return
					}
					if strings.Contains(pay, "\"") && strings.Contains(bodyStr, "&quot;") && !strings.Contains(bodyStr, "\"") {
						return
					}

					mutex.Lock()
					results = append(results, Result{
						URL:        attackURL,
						Parameter:  p,
						Payload:    pay,
						Type:       "Reflected XSS",
						Details:    details,
						Confidence: confidence,
						Severity:   severity,
						Impact:     impact,
					})
					mutex.Unlock()
				}
			}(param, payload)
		}
	}
	wg.Wait()
	return results
}
