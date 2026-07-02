package main

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	hrefRe      = regexp.MustCompile(`(?i)(?:href|src|action|data-url|data-href)\s*=\s*["']([^"']+)["']`)
	formRe      = regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']([^"']+)["']`)
	scriptRe    = regexp.MustCompile(`(?i)<script[^>]*src\s*=\s*["']([^"']+)["']`)
	linkRe      = regexp.MustCompile(`(?i)<link[^>]*href\s*=\s*["']([^"']+)["']`)
	commentRe   = regexp.MustCompile(`(?i)<!--([^-]*)-->`)
	jsEndpointRe = regexp.MustCompile(`(?i)(?:["'](/[a-z0-9_\-./]+)["']|\b(fetch|axios|ajax|getJSON|post|put|delete)\s*\(\s*["']([^"']+)["'])`)
	sitemapRe   = regexp.MustCompile(`(?i)<loc>\s*([^<]+)\s*</loc>`)
	robotsPathRe = regexp.MustCompile(`(?i)(?:Disallow|Allow)\s*:\s*(/\S*)`)
)

func ParseHTMLLinks(body, baseURL string) []string {
	seen := make(map[string]bool)
	var paths []string

	matches := hrefRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if p := normalizeLink(m[1], baseURL); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	comments := commentRe.FindAllStringSubmatch(body, -1)
	for _, m := range comments {
		cm := strings.TrimSpace(m[1])
		linkMatches := hrefRe.FindAllStringSubmatch(cm, -1)
		for _, lm := range linkMatches {
			if p := normalizeLink(lm[1], baseURL); p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}

	return paths
}

func ParseJSEndpoints(body string) []string {
	seen := make(map[string]bool)
	var paths []string

	matches := jsEndpointRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		var raw string
		if m[1] != "" {
			raw = m[1]
		} else if m[3] != "" {
			raw = m[3]
		} else {
			continue
		}
		raw = strings.Trim(raw, "'\"")
		if !strings.HasPrefix(raw, "/") {
			continue
		}
		raw = CleanURLPath(raw)
		if raw != "" && !seen[raw] && !strings.HasPrefix(raw, "//") {
			seen[raw] = true
			paths = append(paths, raw)
		}
	}

	apiRe := regexp.MustCompile(`(?i)(?:api|v[0-9]+|endpoint|route|\/api\/)[a-z0-9_\-/.]+`)
	apiMatches := apiRe.FindAllString(body, -1)
	for _, m := range apiMatches {
		m = "/" + strings.TrimLeft(m, "/")
		m = CleanURLPath(m)
		if !seen[m] {
			seen[m] = true
			paths = append(paths, m)
		}
	}

	return paths
}

func ParseRobots(target string, client *http.Client) []string {
	robotsURL := strings.TrimRight(target, "/") + "/robots.txt"
	resp, err := client.Get(robotsURL)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return extractPathsFromRobots(string(body))
}

func extractPathsFromRobots(body string) []string {
	seen := make(map[string]bool)
	var paths []string
	matches := robotsPathRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		p := strings.TrimSpace(m[1])
		if p == "/" || p == "" {
			continue
		}
		p = CleanURLPath(p)
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

func ParseSitemap(target string, client *http.Client) []string {
	sitemapURL := strings.TrimRight(target, "/") + "/sitemap.xml"
	resp, err := client.Get(sitemapURL)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return extractPathsFromSitemap(string(body))
}

func extractPathsFromSitemap(body string) []string {
	seen := make(map[string]bool)
	var paths []string
	matches := sitemapRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		u := strings.TrimSpace(m[1])
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		p := CleanURLPath(parsed.Path)
		if p != "" && p != "/" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

func ExtractFormActions(body, baseURL string) []string {
	seen := make(map[string]bool)
	var paths []string
	matches := formRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if p := normalizeLink(m[1], baseURL); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

func ExtractScriptSrc(body, baseURL string) []string {
	seen := make(map[string]bool)
	var paths []string
	matches := scriptRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if p := normalizeLink(m[1], baseURL); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	matches = linkRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if p := normalizeLink(m[1], baseURL); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

func normalizeLink(raw, baseURL string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" || strings.HasPrefix(raw, "#") {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return CleanURLPath(parsed.Path)
	}
	if strings.HasPrefix(raw, "//") {
		return ""
	}
	if strings.HasPrefix(raw, "?") {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		return ""
	}
	return CleanURLPath(raw)
}

func ExtractAllPaths(body, baseURL string) []string {
	seen := make(map[string]bool)
	var paths []string

	all := append([]string{}, ParseHTMLLinks(body, baseURL)...)
	all = append(all, ParseJSEndpoints(body)...)
	all = append(all, ExtractFormActions(body, baseURL)...)
	all = append(all, ExtractScriptSrc(body, baseURL)...)

	re := regexp.MustCompile(`(?i)(?:["'`+"`"+`])(/[a-z0-9_\-./]+(?:\.[a-z]+)?)(?:["'`+"`"+`])`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		p := CleanURLPath(m[1])
		if !seen[p] && p != "" && p != "/" && !strings.HasPrefix(p, "//") {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	var filtered []string
	for _, p := range paths {
		if len(p) > 2 && len(p) < 500 && !strings.HasPrefix(p, "/.") {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
