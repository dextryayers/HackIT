package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *Crawler) performPassiveChecks() {
	checks := []struct {
		path string
		name string
	}{
		{"/robots.txt", "Robots.txt"},
		{"/sitemap.xml", "Sitemap.xml"},
		{"/sitemap_index.xml", "Sitemap Index"},
		{"/.well-known/security.txt", "Security.txt"},
		{"/humans.txt", "Humans.txt"},
		{"/crossdomain.xml", "Crossdomain.xml"},
		{"/clientaccesspolicy.xml", "Client Access Policy"},
		{"/.well-known/assetlinks.json", "Asset Links"},
		{"/.well-known/change-password", "Change Password"},
		{"/.well-known/dnt-policy.txt", "DNT Policy"},
		{"/.well-known/gpc.json", "GPC JSON"},
	}

	for _, check := range checks {
		fullURL := fmt.Sprintf("%s%s", strings.TrimSuffix(c.BaseURL, "/"), check.path)
		if c.Filters.Seen(fullURL) {
			continue
		}
		req, _ := http.NewRequest("GET", fullURL, nil)
		c.setHeaders(req)
		req.Header.Set("Accept", "*/*")
		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			fmt.Printf(`{"type":"discovered","url":%q,"source":%q,"method":"passive","status":200}`+"\n", fullURL, c.BaseURL)

			if strings.Contains(fullURL, "robots.txt") {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				body := string(bodyBytes)
				lines := strings.Split(body, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
						part := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
						if part != "" {
							absURL := resolveURL(part, c.BaseURL)
							if absURL != "" && c.Scope.IsInScope(absURL, 1) {
								fmt.Printf(`{"type":"robots_entry","url":%q,"source":%q,"rule":%q}`+"\n", absURL, fullURL, line)
								if strings.HasSuffix(absURL, ".js") || strings.HasSuffix(absURL, ".json") || isSensitiveFile(absURL) {
									c.addQueueItem(urlQueue{url: absURL, source: fullURL, depth: 1, phase: 1})
								}
							}
						}
					}
				}
			}

			if strings.Contains(fullURL, "sitemap") {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
				body := string(bodyBytes)
				sitemapURLs := extractSitemapURLs(body)
				for _, su := range sitemapURLs {
					if c.Scope.IsInScope(su, 1) {
						fmt.Printf(`{"type":"sitemap_entry","url":%q,"source":%q}`+"\n", su, fullURL)
						c.addQueueItem(urlQueue{url: su, source: fullURL, depth: 1, phase: 1})
					}
				}
			}
		}
		resp.Body.Close()
	}
}

func extractSitemapURLs(body string) []string {
	var urls []string
	seen := make(map[string]bool)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "<loc>") {
			start := strings.Index(line, "<loc>") + 5
			end := strings.Index(line, "</loc>")
			if start > 4 && end > start {
				u := line[start:end]
				if !seen[u] {
					seen[u] = true
					urls = append(urls, u)
				}
			}
		}
	}
	return urls
}
