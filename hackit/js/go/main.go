package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

type Result struct {
	URL     string `json:"url"`
	Type    string `json:"type"` // Secret, Endpoint
	Content string `json:"content"`
}

func main() {
	urlFlag := flag.String("url", "", "Target JS URL")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Println(`{"error": "URL required"}`)
		return
	}

	results := scan(*urlFlag)
	jsonOut, _ := json.Marshal(results)
	fmt.Println(string(jsonOut))
}

func scan(targetURL string) []Result {
	results := make([]Result, 0)
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// Regex for secrets (simplified)
	secretRegex := regexp.MustCompile(`(?i)(api_key|access_token|secret|password|auth)`)
	endpointRegex := regexp.MustCompile(`(https?://[^\s"']+)`)

	// Find secrets
	secrets := secretRegex.FindAllString(body, -1)
	for _, s := range secrets {
		results = append(results, Result{
			URL:     targetURL,
			Type:    "Possible Secret",
			Content: s,
		})
	}

	// Find endpoints
	endpoints := endpointRegex.FindAllString(body, -1)
	for _, e := range endpoints {
		results = append(results, Result{
			URL:     targetURL,
			Type:    "Endpoint",
			Content: e,
		})
	}

	return results
}
