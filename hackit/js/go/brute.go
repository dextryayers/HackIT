package main

import (
	"fmt"
	"net/http"
	"strings"
)

// performActiveBrute attempts to guess common JS file paths
func (c *Crawler) performActiveBrute() {
	commonPaths := []string{
		"/app.js",
		"/main.js",
		"/index.js",
		"/bundle.js",
		"/vendor.js",
		"/static/js/main.js",
		"/static/js/bundle.js",
		"/dist/main.js",
		"/dist/bundle.js",
		"/assets/js/main.js",
		"/assets/js/app.js",
		"/manifest.json",
		"/service-worker.js",
		"/sw.js",
	}

	for _, path := range commonPaths {
		c.WG.Add(1)
		go func(p string) {
			defer c.WG.Done()
			fullURL := fmt.Sprintf("%s%s", strings.TrimSuffix(c.BaseURL, "/"), p)
			
			req, _ := http.NewRequest("HEAD", fullURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
			
			resp, err := c.Client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				c.addResult(fullURL, c.BaseURL, "Active Brute")
				
				// If found, deep scan it
				c.WG.Add(1)
				go c.deepScanJS(fullURL)
			}
		}(path)
	}
}
