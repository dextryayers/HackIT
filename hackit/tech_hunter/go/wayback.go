package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type WaybackResult struct {
	URLs           []string `json:"urls"`
	Snapshots      int      `json:"snapshots"`
	OldestSnapshot string   `json:"oldest_snapshot"`
	NewestSnapshot string   `json:"newest_snapshot"`
	ForgottenPaths []string `json:"forgotten_paths"`
}

func fetchWaybackData(domain string) *WaybackResult {
	res := &WaybackResult{}

	// Fetch CDX data from Wayback Machine with timestamps
	urls, oldest, newest := fetchWaybackCDX(domain)
	if len(urls) > 0 {
		res.URLs = urls
		res.Snapshots = len(urls)
	}
	if oldest != "" {
		res.OldestSnapshot = oldest
	}
	if newest != "" {
		res.NewestSnapshot = newest
	}

	// Find forgotten endpoints (paths that existed historically but not now)
	res.ForgottenPaths = findForgottenPaths(domain, urls)

	// Also fetch from CommonCrawl for additional coverage
	cc := fetchCommonCrawl(domain)
	if len(cc) > 0 {
		seen := make(map[string]bool)
		for _, u := range urls {
			seen[u] = true
		}
		for _, u := range cc {
			if !seen[u] {
				res.URLs = append(res.URLs, u)
				res.Snapshots++
				seen[u] = true
			}
		}
	}

	return res
}

func fetchWaybackCDX(domain string) (urls []string, oldest, newest string) {
	client := &http.Client{Timeout: 5 * time.Second}
	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original,timestamp&limit=200&collapse=urlkey", domain)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) < 2 {
		return nil, "", ""
	}
	urls = []string{}
	seen := make(map[string]bool)
	var oldestTs, newestTs string
	for _, entry := range raw[1:] {
		if len(entry) >= 2 {
			u := entry[0]
			ts := entry[1]
			if !seen[u] && u != "" {
				urls = append(urls, u)
				seen[u] = true
			}
			// Track oldest/newest timestamps
			if ts != "" {
				if oldestTs == "" || ts < oldestTs {
					oldestTs = ts
				}
				if newestTs == "" || ts > newestTs {
					newestTs = ts
				}
			}
		}
	}
	// Format timestamps as human-readable dates
	if oldestTs != "" {
		oldest = fmt.Sprintf("%s-%s-%s %s:%s:%s",
			oldestTs[:4], oldestTs[4:6], oldestTs[6:8],
			oldestTs[8:10], oldestTs[10:12], oldestTs[12:14])
	}
	if newestTs != "" {
		newest = fmt.Sprintf("%s-%s-%s %s:%s:%s",
			newestTs[:4], newestTs[4:6], newestTs[6:8],
			newestTs[8:10], newestTs[10:12], newestTs[12:14])
	}
	return urls, oldest, newest
}

func findForgottenPaths(domain string, knownURLs []string) []string {
	if len(knownURLs) == 0 {
		return nil
	}
	var paths []string
	seen := make(map[string]bool)
	for _, u := range knownURLs {
		// Extract path from URL
		if idx := strings.Index(u, "://"); idx != -1 {
			afterProto := u[idx+3:]
			if slashIdx := strings.Index(afterProto, "/"); slashIdx != -1 {
				path := afterProto[slashIdx:]
				if !seen[path] && path != "/" && path != "" && len(path) < 200 {
					paths = append(paths, path)
					seen[path] = true
				}
			}
		}
	}
	return paths
}

func fetchCommonCrawl(domain string) []string {
	client := &http.Client{Timeout: 4 * time.Second}
	apiURL := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2025-50-index?url=*.%s&output=json&limit=30", domain)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var urls []string
	seen := make(map[string]bool)
	for _, line := range lines {
		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.URL != "" && !seen[entry.URL] {
			urls = append(urls, entry.URL)
			seen[entry.URL] = true
		}
	}
	return urls
}
