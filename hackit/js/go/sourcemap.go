package main

import (
	"fmt"
	"net/http"
	"strings"
)

func (c *Crawler) checkSourceMap(jsURL string) {
	mapURL := jsURL + ".map"
	
	req, _ := http.NewRequest("HEAD", mapURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("Referer", jsURL)

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		c.addResult(mapURL, jsURL, TypeMap)
	}
}

func (c *Crawler) checkRobots() {
	robotsURL := fmt.Sprintf("%s/robots.txt", strings.TrimSuffix(c.BaseURL, "/"))
	req, _ := http.NewRequest("GET", robotsURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		c.addResult(robotsURL, c.BaseURL, TypeRobots)
	}
}
