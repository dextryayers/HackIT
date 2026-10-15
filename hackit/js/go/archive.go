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

func (c *Crawler) queryWayback(targetURL string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	domain := u.Host

	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,timestamp,statuscode&filter=!statuscode:404&limit=10000&collapse=urlkey",
		domain,
	)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
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
	if json.Unmarshal(body, &rows) != nil {
		return
	}
	seen := make(map[string]bool)
	count := 0
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 3 || seen[row[0]] || !strings.HasPrefix(row[0], "http") {
			continue
		}
		seen[row[0]] = true
		if !isRelevantURL(row[0]) {
			continue
		}
		if c.Filters.HasSeen(row[0]) {
			continue
		}
		writeOutput(`{"type":"wayback","url":%q,"timestamp":%q,"source":%q}`+"\n", row[0], row[1], domain)
		if isArchiveAsset(row[0]) {
			c.addQueueItem(urlQueue{url: row[0], source: "archive.org", depth: 1})
		}
		count++
		if count >= 500 {
			break
		}
	}
}

func latestCommonCrawlIndex() string {
	type collInfo struct {
		ID string `json:"id"`
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://index.commoncrawl.org/collinfo.json", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	resp, err := client.Do(req)
	if err != nil {
		return "CC-MAIN-2025-30"
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "CC-MAIN-2025-30"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var colls []collInfo
	if json.Unmarshal(body, &colls) != nil || len(colls) == 0 || colls[0].ID == "" {
		return "CC-MAIN-2025-30"
	}
	return colls[0].ID
}

func (c *Crawler) queryCommonCrawl(targetURL string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	domain := u.Host

	// CommonCrawl index API (latest crawl, auto-resolved)
	apiURL := fmt.Sprintf(
		"https://index.commoncrawl.org/%s-index?url=%s/*&output=json&limit=500",
		latestCommonCrawlIndex(), domain,
	)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	lines := strings.Split(string(bodyBytes), "\n")
	seen := make(map[string]bool)
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || entry.URL == "" || seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true
		if !isRelevantURL(entry.URL) || c.Filters.HasSeen(entry.URL) {
			continue
		}
		writeOutput(`{"type":"commoncrawl","url":%q,"source":%q}`+"\n", entry.URL, domain)
		if isArchiveAsset(entry.URL) {
			c.addQueueItem(urlQueue{url: entry.URL, source: "commoncrawl.org", depth: 1})
		}
		count++
		if count >= 200 {
			break
		}
	}
}

func isArchiveAsset(rawURL string) bool {
	low := strings.ToLower(rawURL)
	for _, ext := range []string{".js", ".mjs", ".cjs", ".json", ".map", ".css", ".scss", ".less", ".ts", ".tsx", ".xml", ".txt", ".env", ".yaml", ".yml", ".php", ".asp", ".aspx", ".jsp"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

func isRelevantURL(rawURL string) bool {
	if strings.Contains(rawURL, "void(") || strings.Contains(rawURL, "javascript:") || strings.Contains(rawURL, "removed") || strings.HasPrefix(rawURL, "javascript:") {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return false
	}
	extensions := []string{".js", ".json", ".map", ".ts", ".mjs", ".cjs", ".env", ".yaml", ".yml", ".xml", ".conf", ".php", ".asp", ".aspx", ".jsp"}
	for _, ext := range extensions {
		if strings.HasSuffix(rawURL, ext) {
			return true
		}
	}
	keywords := []string{"/api/", "/graphql", "/swagger", "/config", "/secret", "/backup", "/dump", "/.git", "/.env", "/admin", "/login", "/package.json", "/webpack", "/build"}
	rawLower := strings.ToLower(rawURL)
	for _, kw := range keywords {
		if strings.Contains(rawLower, kw) {
			return true
		}
	}
	return false
}
