package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WaybackResult struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Status    int    `json:"status"`
}

func (c *Crawler) queryWayback(targetURL string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	domain := u.Host

	// CDX API: get all known URLs for this domain, filter by JS/map/json
	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,timestamp,statuscode&filter=!statuscode:404&limit=5000&collapse=urlkey",
		domain,
	)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return
	}

	seen := make(map[string]bool)
	count := 0
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 3 {
			continue
		}
		rawURL := row[0]
		ts := row[1]
		// statusStr := row[2]

		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true

		if !isRelevantURL(rawURL) {
			continue
		}
		if !strings.HasPrefix(rawURL, "http") {
			continue
		}
		if c.Filters.Seen(rawURL) {
			continue
		}

		fmt.Printf(`{"type":"wayback","url":%q,"timestamp":%q,"source":%q}`+"\n", rawURL, ts, domain)

		if strings.HasSuffix(rawURL, ".js") || strings.HasSuffix(rawURL, ".json") || strings.HasSuffix(rawURL, ".map") {
			c.addQueueItem(urlQueue{url: rawURL, source: "archive.org", depth: 1, phase: 1})
		}

		count++
		if count >= 200 {
			break
		}
	}
}

func isRelevantURL(rawURL string) bool {
	extensions := []string{
		".js", ".json", ".map", ".ts", ".mjs", ".cjs",
		".env", ".yaml", ".yml", ".xml", ".conf",
		".php", ".asp", ".aspx", ".jsp",
	}
	for _, ext := range extensions {
		if strings.HasSuffix(rawURL, ext) {
			return true
		}
	}

	keywords := []string{
		"/api/", "/graphql", "/swagger",
		"/config", "/secret", "/backup", "/dump",
		"/.git", "/.env", "/admin", "/login",
		"/package.json", "/webpack", "/build",
	}
	rawLower := strings.ToLower(rawURL)
	for _, kw := range keywords {
		if strings.Contains(rawLower, kw) {
			return true
		}
	}

	return false
}
