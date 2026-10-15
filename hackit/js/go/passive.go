package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

func (c *Crawler) performPassiveChecks() {
	checks := []struct {
		path string
		name string
	}{
		{"/robots.txt", "Robots.txt"},
		{"/sitemap.xml", "Sitemap.xml"},
		{"/sitemap.xml.gz", "Sitemap.xml.gz"},
		{"/sitemap_index.xml", "Sitemap Index"},
		{"/.well-known/security.txt", "Security.txt"},
		{"/security.txt", "Security.txt (root)"},
		{"/.well-known/openid-configuration", "OIDC Discovery"},
		{"/.well-known/oauth-authorization-server", "OAuth Metadata"},
		{"/.well-known/jwks.json", "JWK Set"},
		{"/.well-known/did.json", "DID Document"},
		{"/.well-known/microsoft-identity-association.json", "MS Identity"},
		{"/.well-known/nodeinfo", "NodeInfo"},
		{"/.well-known/webfinger", "WebFinger"},
		{"/.well-known/matrix/client", "Matrix Client"},
		{"/.well-known/matrix/server", "Matrix Server"},
		{"/.well-known/apple-app-site-association", "Apple App Site Assoc"},
		{"/.well-known/assetlinks.json", "Asset Links"},
		{"/.well-known/change-password", "Change Password"},
		{"/.well-known/dnt-policy.txt", "DNT Policy"},
		{"/.well-known/gpc.json", "GPC JSON"},
		{"/.well-known/traffic-advice", "Traffic Advice"},
		{"/.well-known/private-tab", "Private Tab"},
		{"/.well-known/autoconfig/mail", "Mail Autoconfig"},
		{"/.well-known/caldav", "CalDAV"},
		{"/.well-known/carddav", "CardDAV"},
		{"/humans.txt", "Humans.txt"},
		{"/crossdomain.xml", "Crossdomain.xml"},
		{"/clientaccesspolicy.xml", "Client Access Policy"},
		{"/ads.txt", "Ads.txt"},
		{"/app-ads.txt", "App Ads.txt"},
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, 10)
	for _, check := range checks {
		check := check
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()
			c.passiveCheckOne(check.path)
		}()
	}
	wg.Wait()
}

func (c *Crawler) recordFetchedFile(pageURL, sourceURL, kind, ext, ct string, length int) {
	writeOutput(`{"type":"filemap","url":%q,"source":%q,"kind":%q,"ext":%q,"content_type":%q,"length":%d,"depth":0}`+"\n",
		pageURL, sourceURL, kind, ext, ct, length)
	c.mu.Lock()
	c.allCrawled = append(c.allCrawled, CrawlResult{
		URL: pageURL, SourceURL: sourceURL, Type: kind,
		Extension: ext, StatusCode: 200, Depth: 0, ContentType: ct,
	})
	c.mu.Unlock()
}

func (c *Crawler) passiveCheckOne(path string) {
	fullURL := fmt.Sprintf("%s%s", strings.TrimSuffix(c.BaseURL, "/"), path)
	if c.Filters.Seen(fullURL) {
		return
	}
	req, _ := http.NewRequest("GET", fullURL, nil)
	c.setHeaders(req)
	req.Header.Set("Accept", "*/*")
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		ct := resp.Header.Get("Content-Type")
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		body := string(bodyBytes)
		writeOutput(`{"type":"discovered","url":%q,"source":%q,"method":"passive","status":200}`+"\n", fullURL, c.BaseURL)
		c.recordFetchedFile(fullURL, c.BaseURL, "Meta", getExtension(fullURL), ct, len(bodyBytes))
		if strings.Contains(fullURL, "robots.txt") {
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
					part := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					if part != "" {
						absURL := resolveURL(part, c.BaseURL)
						if absURL != "" && c.Scope.IsInScope(absURL, 1) {
							writeOutput(`{"type":"robots_entry","url":%q,"source":%q,"rule":%q}`+"\n", absURL, fullURL, line)
							if strings.HasSuffix(absURL, ".js") || strings.HasSuffix(absURL, ".json") || isSensitiveFile(absURL) {
								c.addQueueItem(urlQueue{url: absURL, source: fullURL, depth: 1})
							}
						}
					}
				}
				if strings.HasPrefix(line, "Sitemap:") {
					part := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					if part != "" {
						writeOutput(`{"type":"sitemap_entry","url":%q,"source":%q}`+"\n", part, fullURL)
						c.addQueueItem(urlQueue{url: part, source: fullURL, depth: 1})
					}
				}
			}
		}
		if strings.Contains(fullURL, "sitemap") {
			c.parseSitemapBody(body, fullURL, 0)
		}
	}
}

// parseSitemapBody handles sitemap indexes recursively (capped) plus urlsets.
func (c *Crawler) parseSitemapBody(body, fullURL string, level int) {
	urls := extractSitemapURLs(body)
	isIndex := strings.Contains(body, "<sitemapindex")
	queued := 0
	for _, su := range urls {
		if !c.Scope.IsInScope(su, 1) {
			continue
		}
		writeOutput(`{"type":"sitemap_entry","url":%q,"source":%q}`+"\n", su, fullURL)
		if isIndex && level < 1 && (strings.HasSuffix(su, ".xml") || strings.HasSuffix(su, ".xml.gz")) {
			if c.Filters.Seen(su) {
				continue
			}
			req, _ := http.NewRequest("GET", su, nil)
			c.setHeaders(req)
			resp, err := c.Client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 {
				child, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
				resp.Body.Close()
				c.parseSitemapBody(string(child), su, level+1)
			} else {
				resp.Body.Close()
			}
			continue
		}
		if queued >= 2000 {
			writeOutput(`{"type":"limit","reason":"sitemap-cap","source":%q,"max":2000}`+"\n", fullURL)
			break
		}
		queued++
		c.addQueueItem(urlQueue{url: su, source: fullURL, depth: 1})
	}
}

func extractSitemapURLs(body string) []string {
	var urls []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
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
		if strings.Contains(line, "<loc><![CDATA[") {
			start := strings.Index(line, "<loc><![CDATA[") + 14
			end := strings.Index(line, "]]></loc>")
			if start > 13 && end > start {
				u := line[start:end]
				if !seen[u] {
					seen[u] = true
					urls = append(urls, u)
				}
			}
		}
	}
	if len(urls) == 0 {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				if !seen[line] {
					seen[line] = true
					urls = append(urls, line)
				}
			}
		}
	}
	return urls
}
