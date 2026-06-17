package main

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type Filters struct {
	visited map[string]bool
	mu      sync.Mutex
}

func NewFilters() *Filters {
	return &Filters{visited: make(map[string]bool)}
}

func (f *Filters) Seen(rawURL string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := normalizeKey(rawURL)
	if f.visited[key] {
		return true
	}
	f.visited[key] = true
	return false
}

func normalizeKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	u.RawQuery = sortQuery(u.RawQuery)
	return strings.TrimSuffix(u.String(), "/")
}

func sortQuery(q string) string {
	if q == "" {
		return ""
	}
	params := strings.Split(q, "&")
	sort.Strings(params)
	return strings.Join(params, "&")
}

var mimeExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true,
	".ts": true, ".tsx": true, ".json": true, ".html": true,
	".htm": true, ".xml": true, ".yaml": true, ".yml": true,
	".conf": true, ".env": true, ".txt": true, ".php": true,
	".asp": true, ".aspx": true, ".jsp": true, ".py": true,
	".go": true, ".rb": true, ".java": true, ".vue": true,
	".svelte": true, ".map": true, ".wasm": true,
}

func isCrawable(rawURL string) bool {
	ext := strings.ToLower(path.Ext(strings.Split(rawURL, "?")[0]))
	if ext == "" {
		return true
	}
	return mimeExts[ext]
}

var sensitiveFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.env$`),
	regexp.MustCompile(`(?i)\.git/config$`),
	regexp.MustCompile(`(?i)\.htaccess$`),
	regexp.MustCompile(`(?i)config\.(json|yaml|yml|php|js|py)$`),
	regexp.MustCompile(`(?i)secret`),
	regexp.MustCompile(`(?i)credential`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)password`),
	regexp.MustCompile(`(?i)api[_-]?key`),
	regexp.MustCompile(`(?i)auth\.(json|yaml|yml|php|js|py)$`),
	regexp.MustCompile(`(?i)(dump|backup|sql|db|database)`),
	regexp.MustCompile(`(?i)cloudinary`),
	regexp.MustCompile(`(?i)firebase`),
	regexp.MustCompile(`(?i)s3\.amazonaws`),
}

func isSensitiveFile(rawURL string) bool {
	for _, re := range sensitiveFilePatterns {
		if re.MatchString(rawURL) {
			return true
		}
	}
	return false
}
