package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// performPassiveChecks runs non-invasive checks to find hidden JS assets
func (c *Crawler) performPassiveChecks() {
	// 1. Check common sensitive files
	c.checkRobots()
	
	// 2. Check sitemap.xml for JS links
	c.checkSitemap()
	
	// 3. Check for security.txt
	c.checkSecurityTxt()
}

func (c *Crawler) checkSitemap() {
	sitemapURL := fmt.Sprintf("%s/sitemap.xml", strings.TrimSuffix(c.BaseURL, "/"))
	req, _ := http.NewRequest("GET", sitemapURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		c.addResult(sitemapURL, c.BaseURL, "Sitemap.xml")
	}
}

func (c *Crawler) checkSecurityTxt() {
	securityURL := fmt.Sprintf("%s/.well-known/security.txt", strings.TrimSuffix(c.BaseURL, "/"))
	req, _ := http.NewRequest("GET", securityURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		c.addResult(securityURL, c.BaseURL, "Security.txt")
	}
}

// simulateHumanBehavior adds random delays to avoid simple WAF rate limits
func (c *Crawler) simulateHumanBehavior() {
	time.Sleep(time.Duration(100+ (time.Now().UnixNano() % 400)) * time.Millisecond)
}
