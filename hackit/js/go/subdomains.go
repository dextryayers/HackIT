package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	subdomainInJS = regexp.MustCompile(`["'=](https?://([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?)/?["' ]`)
	subdomainVar  = regexp.MustCompile(`((?:api|cdn|static|assets|img|media|uploads?|files?|s3|bucket|store|admin|dev|test|staging|app|web|www|mail|smtp|pop|imap|ns[0-9]|mx))[.\-_]`)
	jsVarHostname = regexp.MustCompile(`["']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,})["']`)
	fetchHost     = regexp.MustCompile(`(?:url|host|hostname|domain|server|apiUrl|baseUrl|endpoint|proxy|target)\s*[:=]\s*"(https?://([^"/\s]+))"`)
)

func (c *Crawler) discoverAllSubdomains() {
	var wg sync.WaitGroup
	wg.Add(8)
	go func() { defer wg.Done(); c.discoverCTLogs() }()
	go func() { defer wg.Done(); c.discoverAlienVault() }()
	go func() { defer wg.Done(); c.discoverGoogleCT() }()
	go func() { defer wg.Done(); c.discoverDNSBrute() }()
	go func() { defer wg.Done(); c.discoverSecurityTrails() }()
	go func() { defer wg.Done(); c.discoverVirusTotal() }()
	go func() { defer wg.Done(); c.discoverCensys() }()
	go func() { defer wg.Done(); c.discoverShodan() }()
	wg.Wait()
}

func (c *Crawler) extractSubdomainFromURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	host := hostWithoutPort(u.Host)
	if host == "" || !strings.HasSuffix(host, "."+c.BaseDomain) && host != c.BaseDomain {
		return
	}
	if host == c.BaseHost || host == c.BaseDomain {
		return
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	c.addSubdomain(host, scheme+"://"+host)
}

func (c *Crawler) extractSubdomainsFromBody(body string, sourceURL string) {
	for _, m := range subdomainInJS.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 {
			c.extractSubdomainFromURL(m[1])
		}
	}
	for _, vm := range subdomainVar.FindAllStringSubmatch(body, -1) {
		if len(vm) >= 2 {
			vmName := strings.TrimSpace(vm[1])
			potential := vmName + "." + c.BaseDomain
			if !c.Subdomains[potential] {
				if c.hintsShown[potential] {
					continue
				}
				c.hintsShown[potential] = true
				writeOutput(`{"type":"subdomain_hint","host":%q,"source":%q,"method":"variable_pattern"}`+"\n", potential, sourceURL)
			}
		}
	}
	for _, m := range fetchHost.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 {
			c.extractSubdomainFromURL(m[1])
		}
	}
	for _, m := range jsVarHostname.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 {
			h := m[1]
			if strings.HasSuffix(h, "."+c.BaseDomain) && h != c.BaseHost && !c.Subdomains[h] {
				c.extractSubdomainFromURL("https://" + h)
			}
		}
	}
}

func (c *Crawler) discoverCTLogs() {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&limit=500", c.BaseDomain)
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
	processCTName := func(name string) {
		for _, n := range strings.Split(name, "\n") {
			n = strings.TrimSpace(n)
			if n == "" || !strings.HasSuffix(n, "."+c.BaseDomain) && n != c.BaseDomain || n == c.BaseHost {
				continue
			}
			if c.addSubdomain(n, "https://"+n) {
				writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"ct_log"}`+"\n", "https://"+n, n)
			}
		}
	}
	if strings.HasPrefix(string(body), "[") {
		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal(body, &entries) == nil {
			for _, entry := range entries {
				processCTName(entry.NameValue)
			}
			return
		}
	}
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
			processCTName(entry.NameValue)
		}
	}
	apiURL2 := fmt.Sprintf("https://crt.sh/?dNSName=%s&output=json&limit=500", c.BaseDomain)
	req2, _ := http.NewRequest("GET", apiURL2, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	resp2, err := client.Do(req2)
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == 200 {
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 5*1024*1024))
			if strings.HasPrefix(string(body2), "[") {
				var entries2 []struct {
					NameValue string `json:"name_value"`
				}
				if json.Unmarshal(body2, &entries2) == nil {
					for _, entry := range entries2 {
						processCTName(entry.NameValue)
					}
				}
			}
		}
	}
}

func (c *Crawler) discoverAlienVault() {
	apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", c.BaseDomain)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	client := &http.Client{Timeout: 10 * time.Second}
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
	if json.Unmarshal(body, &result) != nil {
		return
	}
	for _, entry := range result.PassiveDNS {
		name := strings.TrimSpace(entry.Hostname)
		if name == "" || !strings.HasSuffix(name, "."+c.BaseDomain) && name != c.BaseDomain || name == c.BaseHost {
			continue
		}
		if c.addSubdomain(name, "https://"+name) {
			writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"alienvault"}`+"\n", "https://"+name, name)
		}
	}
}

func (c *Crawler) discoverGoogleCT() {
	apiURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=", c.BaseDomain)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
			var entries []struct {
				DNSNames []string `json:"dns_names"`
			}
			if json.Unmarshal(body, &entries) == nil {
				for _, entry := range entries {
					for _, name := range entry.DNSNames {
						name = strings.TrimSpace(name)
						if name == "" || !strings.HasSuffix(name, "."+c.BaseDomain) || name == c.BaseHost {
							continue
						}
						if c.addSubdomain(name, "https://"+name) {
							writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"certspotter"}`+"\n", "https://"+name, name)
						}
					}
				}
			}
		}
	}
}

func (c *Crawler) discoverSecurityTrails() {
	nameservers := []string{"8.8.8.8", "1.1.1.1", "8.8.4.4"}
	common := []string{"www", "mail", "api", "admin", "blog", "cdn", "dev", "app", "web", "static", "assets", "docs", "help", "support", "status", "wiki", "forum", "community", "shop", "store", "portal", "dashboard", "console", "auth", "login", "sso", "saml", "oauth", "ws", "wss", "socket", "stream", "video", "media", "upload", "download", "files", "backup", "old", "new", "beta", "alpha", "demo", "stage", "prod", "live", "test", "staging", "sandbox", "ns1", "ns2", "ns3", "mx", "mail2", "smtp", "pop", "imap", "cpanel", "whm", "webmail", "webdisk", "dns", "server", "vpn", "remote", "ssh", "proxy", "gateway", "firewall", "router", "switch", "mon", "nagios", "zabbix", "grafana", "prometheus", "kibana", "elastic", "k8s", "kubernetes", "docker", "registry", "nexus", "artifactory", "chat", "slack", "discord", "teams", "calendar", "drive", "cloud", "storage", "sync", "s3", "bucket", "analytics", "tracking", "metrics", "stats", "redis", "memcached", "mq", "queue", "rabbit", "solr", "lucene", "search", "rest", "soap", "graphql", "gql", "hasura", "prisma", "ws", "wss", "websocket", "socket", "secure", "ssl", "tls", "cert", "news", "press", "info", "about", "contact", "mobile", "m", "touch", "amp", "reseller", "partner", "affiliate", "wholesale", "git", "svn", "jenkins", "ci", "teamcity", "jira", "confluence", "phpmyadmin", "pma", "mysql", "db", "database", "backup", "backups"}
	for _, name := range common {
		fqdn := name + "." + c.BaseDomain
		if c.Subdomains[fqdn] {
			continue
		}
		for _, ns := range nameservers {
			resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "tcp", ns+":53")
			}}
			addrs, err := resolver.LookupHost(context.Background(), fqdn)
			if err == nil && len(addrs) > 0 {
				if c.addSubdomain(fqdn, "https://"+fqdn) {
					writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"dns_resolve","ips":%q}`+"\n", "https://"+fqdn, fqdn, strings.Join(addrs, ","))
				}
				break
			}
		}
	}
}

func (c *Crawler) discoverVirusTotal() {
	apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", c.BaseDomain)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil {
		return
	}
	for _, entry := range result.Data {
		name := strings.TrimSpace(entry.ID)
		if name == "" || !strings.HasSuffix(name, "."+c.BaseDomain) || name == c.BaseHost {
			continue
		}
		if c.addSubdomain(name, "https://"+name) {
			writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"virustotal"}`+"\n", "https://"+name, name)
		}
	}
}

func (c *Crawler) discoverCensys() {
	apiURL := fmt.Sprintf("https://search.censys.io/api/v2/certificates?q=parsed.names:%s&per_page=100", c.BaseDomain)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	client := &http.Client{Timeout: 10 * time.Second}
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
		Result struct {
			Hits []struct {
				Parsed struct {
					Names []string `json:"names"`
				} `json:"parsed"`
			} `json:"hits"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &result) != nil {
		return
	}
	for _, hit := range result.Result.Hits {
		for _, name := range hit.Parsed.Names {
			name = strings.TrimSpace(name)
			if name == "" || !strings.HasSuffix(name, "."+c.BaseDomain) || name == c.BaseHost {
				continue
			}
			if c.addSubdomain(name, "https://"+name) {
				writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"censys"}`+"\n", "https://"+name, name)
			}
		}
	}
}

func (c *Crawler) discoverShodan() {
	apiURL := fmt.Sprintf("https://www.shodan.io/search?query=hostname:%s", c.BaseDomain)
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/2.1)")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func (c *Crawler) discoverDNSBrute() {
	common := []string{"www", "mail", "ftp", "admin", "blog", "cdn", "api", "dev", "test", "staging", "app", "web", "static", "assets", "img", "media", "upload", "download", "files", "docs", "help", "support", "status", "monitor", "git", "svn", "jenkins", "ci", "teamcity", "jira", "confluence", "wiki", "phpmyadmin", "pma", "mysql", "db", "database", "backup", "backups", "old", "new", "beta", "alpha", "demo", "stage", "prod", "production", "live", "preprod", "sandbox", "ns1", "ns2", "ns3", "mx", "mail2", "smtp", "pop", "imap", "cpanel", "whm", "webmail", "webdisk", "dns", "server", "vpn", "remote", "ssh", "proxy", "gateway", "firewall", "router", "switch", "mon", "nagios", "zabbix", "grafana", "prometheus", "kibana", "elastic", "logstash", "k8s", "kubernetes", "docker", "registry", "nexus", "artifactory", "maven", "npm", "pypi", "rubygems", "chat", "slack", "discord", "teams", "rocket", "calendar", "drive", "cloud", "storage", "sync", "portal", "dashboard", "console", "manager", "auth", "login", "sso", "saml", "oauth", "oidc", "s3", "bucket", "analytics", "tracking", "metrics", "stats", "redis", "memcached", "mq", "queue", "rabbit", "solr", "lucene", "search", "rest", "soap", "graphql", "gql", "hasura", "prisma", "ws", "wss", "websocket", "socket", "stream", "video", "tv", "radio", "shop", "store", "cart", "checkout", "payment", "secure", "ssl", "tls", "cert", "news", "press", "info", "about", "contact", "forum", "community", "users", "members", "mobile", "m", "touch", "tablet", "amp", "accelerator", "reseller", "partner", "affiliate", "wholesale"}
	for _, sub := range common {
		name := sub + "." + c.BaseDomain
		if c.Subdomains[name] {
			continue
		}
		addrs, err := net.LookupHost(name)
		if err != nil || len(addrs) == 0 {
			continue
		}
		if c.addSubdomain(name, "https://"+name) {
			writeOutput(`{"type":"subdomain_found","url":%q,"subdomain":%q,"method":"dns_brute","ips":%q}`+"\n", "https://"+name, name, strings.Join(addrs, ","))
		}
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
