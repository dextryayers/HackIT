package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	subdomainInJS  = regexp.MustCompile(`["'=](https?://([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?)/?["' ]`)
	subdomainVar   = regexp.MustCompile(`(?:api|cdn|static|assets|img|media|uploads?|files?|s3|bucket|store|admin|dev|test|staging|app|web|www|mail|smtp|pop|imap|ns[0-9]|mx)[.\-_]`)
	jsVarHostname  = regexp.MustCompile(`["']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,})["']`)
	fetchHost      = regexp.MustCompile(`(?:url|host|hostname|domain|server|apiUrl|baseUrl|endpoint|proxy|target)\s*[:=]\s*"(https?://([^"/\s]+))"`)
)

func (c *Crawler) addSubdomain(subdomain, fullURL string) {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	if c.Subdomains[subdomain] {
		return
	}
	c.Subdomains[subdomain] = true
	c.subdomainURLs[subdomain] = fullURL
}

func (c *Crawler) extractSubdomainFromURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	host := hostWithoutPort(u.Host)
	if host == "" {
		return
	}
	if !strings.HasSuffix(host, "."+c.BaseDomain) && host != c.BaseDomain {
		return
	}
	if host == c.BaseHost || host == c.BaseDomain {
		return
	}

	// New subdomain discovered
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	c.addSubdomain(host, scheme+"://"+host)
}

func (c *Crawler) extractSubdomainsFromBody(body string, sourceURL string) {
	// Extract URLs with different subdomains
	matches := subdomainInJS.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			c.extractSubdomainFromURL(m[1])
		}
	}

	// Extract subdomain hints from JS variable patterns
	varMatches := subdomainVar.FindAllString(body, -1)
	for _, vm := range varMatches {
		// Try to construct potential subdomain URLs
		vm = strings.Trim(vm, ".")
		potential := vm + "." + c.BaseDomain
		if !c.Subdomains[potential] {
			fmt.Printf(`{"type":"subdomain_hint","host":%q,"source":%q,"method":"variable_pattern"}`+"\n",
				potential, sourceURL)
		}
	}

	// Extract hostname variables (apiUrl, baseUrl, etc)
	hostMatches := fetchHost.FindAllStringSubmatch(body, -1)
	for _, m := range hostMatches {
		if len(m) >= 2 {
			c.extractSubdomainFromURL(m[1])
		}
	}

	// Extract bare hostnames from JS strings
	bareMatches := jsVarHostname.FindAllStringSubmatch(body, -1)
	for _, m := range bareMatches {
		if len(m) >= 2 {
			h := m[1]
			if strings.HasSuffix(h, "."+c.BaseDomain) && h != c.BaseHost && !c.Subdomains[h] {
				c.extractSubdomainFromURL("https://" + h)
			}
		}
	}
}

func (c *Crawler) discoverSubdomainsFromJS() {
	c.mu.Lock()
	// Scan all crawled JS content for subdomains
	// We need to extract this from the allCrawled results
	// Since we don't store body, we scan inline during parsing
	// This function is called AFTER phase 1, so any subdomains
	// discovered during parsing are already in c.Subdomains
	c.mu.Unlock()
}

func (c *Crawler) discoverCTLogs() {
	// Query Certificate Transparency logs via crt.sh
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&limit=100", c.BaseDomain)

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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		// crt.sh sometimes returns non-standard JSON, try line-by-line
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var entry struct {
				NameValue string `json:"name_value"`
			}
			if json.Unmarshal([]byte(line), &entry) == nil && entry.NameValue != "" {
				name := strings.TrimSpace(entry.NameValue)
				if strings.HasSuffix(name, "."+c.BaseDomain) && name != c.BaseHost {
					scheme := "https"
					c.addSubdomain(name, scheme+"://"+name)
					fmt.Printf(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"ct_log"}`+"\n",
						scheme+"://"+name, name)
				}
			}
		}
		return
	}

	for _, entry := range entries {
		name := strings.TrimSpace(entry.NameValue)
		if strings.HasSuffix(name, "."+c.BaseDomain) && name != c.BaseHost {
			scheme := "https"
			c.addSubdomain(name, scheme+"://"+name)
			fmt.Printf(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"ct_log"}`+"\n",
				scheme+"://"+name, name)
		}
	}
}

func (c *Crawler) discoverAlienVault() {
	apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", c.BaseDomain)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	for _, entry := range result.PassiveDNS {
		name := strings.TrimSpace(entry.Hostname)
		if name == "" {
			continue
		}
		if !strings.HasSuffix(name, "."+c.BaseDomain) && name != c.BaseDomain {
			continue
		}
		if name == c.BaseHost {
			continue
		}
		scheme := "https"
		c.addSubdomain(name, scheme+"://"+name)
		fmt.Printf(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"alienvault"}`+"\n",
			scheme+"://"+name, name)
	}
}

func (c *Crawler) discoverGoogleCT() {
	apiURL := fmt.Sprintf("https://certificate.transparency.google.com/api/v1/ctlog/v1/get-entries?start=0&end=10")

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func (c *Crawler) discoverDNSBrute() {
	common := []string{
		"www", "mail", "ftp", "admin", "blog", "cdn", "api", "dev",
		"test", "staging", "app", "web", "static", "assets", "img",
		"media", "upload", "download", "files", "docs", "help",
		"support", "status", "monitor", "git", "svn", "jenkins",
		"jenkis", "ci", "teamcity", "jira", "confluence", "wiki",
		"phpmyadmin", "phpMyAdmin", "pma", "mysql", "db", "database",
		"backup", "backups", "old", "new", "beta", "alpha", "demo",
		"stage", "prod", "production", "live", "preprod", "sandbox",
		"ns1", "ns2", "ns3", "mx", "mail2", "smtp", "pop", "imap",
		"cpanel", "whm", "webmail", "webdisk", "dns", "direct",
		"server", "vpn", "remote", "ssh", "proxy", "gateway",
		"firewall", "router", "switch", "mon", "nagios", "zabbix",
		"grafana", "prometheus", "kibana", "elastic", "logstash",
		"k8s", "kubernetes", "docker", "registry", "nexus",
		"artifactory", "maven", "npm", "pypi", "rubygems",
		"chat", "slack", "discord", "teams", "rocket",
		"calendar", "drive", "cloud", "storage", "sync",
		"portal", "dashboard", "console", "manager",
		"auth", "login", "sso", "saml", "oauth", "oidc",
		"s3", "bucket", "storage", "object",
		"analytics", "tracking", "metrics", "stats",
		"redis", "memcached", "mq", "queue", "rabbit",
		"solr", "lucene", "search", "api", "rest", "soap",
		"graphql", "gql", "hasura", "prisma",
		"ws", "wss", "websocket", "socket",
		"stream", "video", "tv", "radio",
		"shop", "store", "cart", "checkout", "payment",
		"secure", "ssl", "tls", "cert", "crt",
		"news", "press", "info", "about", "contact",
		"forum", "community", "users", "members",
		"mobile", "m", "touch", "tablet",
		"amp", "accelerator", "cdn", "static",
		"reseller", "partner", "affiliate", "wholesale",
	}

	for _, sub := range common {
		name := sub + "." + c.BaseDomain
		if c.Subdomains[name] {
			continue
		}

		// Try DNS resolution
		addrs, err := net.LookupHost(name)
		if err != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}

		scheme := "https"
		c.addSubdomain(name, scheme+"://"+name)
		fmt.Printf(`{"type":"subdomain","url":%q,"subdomain":%q,"method":"dns_brute","ips":%q}`+"\n",
			scheme+"://"+name, name, strings.Join(addrs, ","))
	}
}

func getBrutePaths() []string {
	return []string{
		"/app.js", "/main.js", "/index.js", "/bundle.js", "/vendor.js",
		"/common.js", "/utils.js", "/core.js", "/app.min.js", "/main.min.js",
		"/script.js", "/scripts.js", "/application.js", "/global.js",
		"/site.js", "/theme.js", "/custom.js", "/init.js", "/config.js",
		"/conf.js", "/runtime.js", "/polyfills.js", "/styles.js",
		"/api", "/api/", "/graphql", "/swagger.json",
		"/robots.txt", "/sitemap.xml", "/security.txt",
		"/.env", "/config.json", "/package.json",
		"/static/js/main.js", "/static/js/bundle.js",
		"/dist/main.js", "/dist/bundle.js",
		"/js/app.js", "/js/main.js", "/js/bundle.js",
	}
}
