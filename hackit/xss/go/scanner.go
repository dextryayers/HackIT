package main

import (
	"crypto/tls"
	"fmt"
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
	Method     string `json:"method"`
}

type Scanner struct {
	Client   *http.Client
	Payloads []string
	Method   string
	Data     string
}

func NewScanner(timeout int) *Scanner {
	return &Scanner{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(timeout) * time.Second,
		},
		Payloads: Payloads,
		Method:   "GET",
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

func (s *Scanner) detectContext(bodyStr, pay string) (string, string, string, string) {
	bodyLower := strings.ToLower(bodyStr)
	payLower := strings.ToLower(pay)
	hasScriptOpen := strings.Contains(bodyLower, "<script>"+payLower) || strings.Contains(bodyLower, payLower+"</script>")
	hasAttrBreakout := strings.Contains(bodyLower, "=\""+payLower) || strings.Contains(bodyLower, "='"+payLower)
	hasHrefJS := strings.Contains(bodyLower, "href=\"javascript:") || strings.Contains(bodyLower, "src=javascript:")
	hasEventHandler := strings.Contains(bodyLower, "onerror="+payLower) || strings.Contains(bodyLower, "onload="+payLower) ||
		strings.Contains(bodyLower, "onclick="+payLower) || strings.Contains(bodyLower, "onfocus="+payLower) ||
		strings.Contains(bodyLower, "onmouseover="+payLower) || strings.Contains(bodyLower, "ontoggle="+payLower) ||
		strings.Contains(bodyLower, "onstart="+payLower)
	hasInScript := strings.Contains(bodyLower, "<script") && strings.Contains(bodyLower, payLower) && strings.Contains(bodyLower, "</script>")
	hasInEvent := strings.Contains(bodyLower, "on"+payLower)

	if hasHrefJS {
		return "CRITICAL: URI Handler Context (javascript:)", "High", "Critical", "Direct Code Execution"
	}
	if hasScriptOpen {
		return "CRITICAL: Executable Script Context", "High", "High", "Full Account Takeover (Session Theft)"
	}
	if hasEventHandler || hasInEvent {
		return "HIGH: Event Handler Context (executable)", "High", "High", "Sensitive Data Access / Redirection"
	}
	if hasInScript {
		return "HIGH: Inside Script Block", "High", "Medium", "Phishing / Content Injection"
	}
	if hasAttrBreakout {
		return "HIGH: Attribute Breakout Context", "High", "Medium", "Phishing / Forced Redirection"
	}
	if strings.Contains(pay, "{{") || strings.Contains(pay, "${") || strings.Contains(pay, "<%=") {
		return "MEDIUM: Template Injection Detected", "Medium", "Medium", "Server-Side Template Injection"
	}
	if strings.Contains(pay, "base64") || strings.Contains(pay, "data:") {
		return "MEDIUM: Data URI Injection", "Medium", "Medium", "Content Injection via Data URI"
	}
	if strings.Contains(pay, "constructor") || strings.Contains(pay, "__proto__") {
		return "MEDIUM: Prototype Pollution / Sandbox Escape", "Medium", "High", "Code Execution via Prototype Pollution"
	}
	return "LOW: Payload Reflected in Response", "Low", "Low", "Content Spoofing"
}

func (s *Scanner) isFalsePositive(bodyStr, pay string) bool {
	specificChars := []string{"<", ">", "\"", "'", "&"}
	for _, c := range specificChars {
		if strings.Contains(pay, c) {
			var encoded string
			switch c {
			case "<":
				encoded = "&lt;"
			case ">":
				encoded = "&gt;"
			case "\"":
				encoded = "&quot;"
			case "'":
				encoded = "&#39;"
			case "&":
				encoded = "&amp;"
			}
			if strings.Contains(bodyStr, encoded) && !strings.Contains(bodyStr, c) {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) scanParam(urlStr string, param string, pay string, wg *sync.WaitGroup, sem chan struct{}, results *[]Result, mutex *sync.Mutex) {
	defer wg.Done()
	defer func() { <-sem }()

	u, err := url.Parse(urlStr)
	if err != nil {
		return
	}
	params := u.Query()
	newParams := make(url.Values)
	for k, v := range params {
		if k == param {
			newParams.Set(k, pay)
		} else {
			newParams[k] = v
		}
	}
	u.RawQuery = newParams.Encode()
	attackURL := u.String()

	req, err := http.NewRequest(s.Method, attackURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "HackIt-XSS/2.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := s.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, pay) {
		return
	}
	if s.isFalsePositive(bodyStr, pay) {
		return
	}

	details, confidence, severity, impact := s.detectContext(bodyStr, pay)

	if strings.Contains(pay, "cookie") || strings.Contains(pay, "fetch") || strings.Contains(pay, "xss.report") {
		severity = "Critical"
		impact = "Data Exfiltration (Sensitive Information)"
	}

	mutex.Lock()
	*results = append(*results, Result{
		URL:        attackURL,
		Parameter:  param,
		Payload:    pay,
		Type:       "Reflected XSS",
		Details:    details,
		Confidence: confidence,
		Severity:   severity,
		Impact:     impact,
		Method:     s.Method,
	})
	mutex.Unlock()
}

func (s *Scanner) Scan(targetURL string) []Result {
	results := make([]Result, 0)
	u, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	params := u.Query()
	if len(params) == 0 {
		fmt.Fprintf(os.Stderr, "[!] No query parameters in URL: %s\n", targetURL)
		return results
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	sem := make(chan struct{}, 15)

	for param := range params {
		for _, payload := range s.Payloads {
			wg.Add(1)
			sem <- struct{}{}
			go s.scanParam(targetURL, param, payload, &wg, sem, &results, &mutex)
		}
	}
	wg.Wait()
	return results
}
