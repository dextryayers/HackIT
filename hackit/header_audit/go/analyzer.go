package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Grade     string              `json:"grade"`
	Score     int                 `json:"score"`
	Missing   []map[string]string `json:"missing"`
	Present   []map[string]string `json:"present"`
	Warnings  []string            `json:"warnings"`
	Dangerous []map[string]string `json:"dangerous"`
	Error     string              `json:"error,omitempty"`
}

type Analyzer struct {
	Client *http.Client
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (a *Analyzer) Analyze(url string) Result {
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	resp, err := a.Client.Get(url)
	if err != nil {
		// Try http if https failed
		if strings.HasPrefix(url, "https") {
			url = strings.Replace(url, "https", "http", 1)
			resp, err = a.Client.Get(url)
		}
		if err != nil {
			return Result{Error: fmt.Sprintf("%v", err)}
		}
	}
	defer resp.Body.Close()

	var missing []map[string]string
	var present []map[string]string
	var warnings []string
	var dangerous []map[string]string
	score := 100

	// Check Security Headers
	for _, h := range SecurityHeaders {
		val := resp.Header.Get(h.Name)
		if val == "" {
			score -= 10
			missing = append(missing, map[string]string{
				"header":         h.Name,
				"description":    h.Description,
				"recommendation": h.Recommendation,
			})
		} else {
			present = append(present, map[string]string{
				"header": h.Name,
				"value":  val,
			})
			// Check specific values
			if h.SafeValue != "" && !strings.Contains(strings.ToLower(val), strings.ToLower(h.SafeValue)) {
				score -= 5
				warnings = append(warnings, fmt.Sprintf("%s value is weak: '%s' (Recommended: '%s')", h.Name, val, h.Recommendation))
			}
			if h.Name == "X-Frame-Options" && strings.ToUpper(val) != "DENY" && strings.ToUpper(val) != "SAMEORIGIN" {
				score -= 5
				warnings = append(warnings, fmt.Sprintf("X-Frame-Options value might be weak: %s", val))
			}
		}
	}

	// Check Dangerous Headers
	for _, h := range DangerousHeaders {
		val := resp.Header.Get(h.Name)
		if val != "" {
			score -= 5
			dangerous = append(dangerous, map[string]string{
				"header":      h.Name,
				"value":       val,
				"description": h.Description,
			})
		}
	}

	if score < 0 {
		score = 0
	}

	grade := "F"
	if score >= 90 {
		grade = "A"
	} else if score >= 80 {
		grade = "B"
	} else if score >= 60 {
		grade = "C"
	} else if score >= 40 {
		grade = "D"
	}

	return Result{
		Grade:     grade,
		Score:     score,
		Missing:   missing,
		Present:   present,
		Warnings:  warnings,
		Dangerous: dangerous,
	}
}
