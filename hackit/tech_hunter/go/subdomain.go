package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"`
}

var (
	commonSubdomains = []string{
		"www", "mail", "ftp", "ssh", "admin", "dashboard", "api", "dev",
		"staging", "test", "vpn", "blog", "shop", "cdn", "m", "mobile",
		"app", "webmail", "portal", "login", "auth", "sso", "git",
		"jenkins", "jira", "confluence", "wiki", "docs", "support",
		"help", "status", "monitor", "grafana", "prometheus", "kibana",
		"splunk", "nexus", "artifactory", "docker", "k8s", "kubernetes",
		"prod", "production", "devops", "ci", "cd", "backup", "db",
		"database", "redis", "mysql", "postgres", "mongo", "elasticsearch",
		"mq", "rabbitmq", "kafka", "zookeeper", "consul", "vault",
		"proxy", "gateway", "router", "firewall", "waf", "lb",
		"loadbalancer", "ha", "cluster", "node", "worker", "master",
		"smtp", "imap", "pop3",
		"static", "assets", "img", "images", "css", "js", "fonts",
		"analytics", "metrics", "report", "billing", "payment",
		"checkout", "cart", "order", "tracking", "invoice",
		"partner", "vendor", "recruit", "career", "job",
		"learn", "training", "demo", "preview", "beta",
		"private", "internal", "archive",
		"nyc", "london", "tokyo", "sgp", "fra", "iad", "ams",
	}

	fastResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}
)

func PerformSubdomainRecon(domain string) []SubdomainResult {
	results := []SubdomainResult{}
	found := make(map[string]bool)

	htSubs := fetchHackerTarget(domain)
	for _, s := range htSubs {
		if !found[s] {
			results = append(results, SubdomainResult{Subdomain: s, Source: "HackerTarget"})
			found[s] = true
		}
	}

	crtSubs := fetchCrtsh(domain)
	for _, s := range crtSubs {
		if !found[s] {
			results = append(results, SubdomainResult{Subdomain: s, Source: "Crt.sh"})
			found[s] = true
		}
	}

	alienSubs := fetchAlienVault(domain)
	for _, s := range alienSubs {
		if !found[s] {
			results = append(results, SubdomainResult{Subdomain: s, Source: "AlienVault OTX"})
			found[s] = true
		}
	}

	bruteSubs := bruteCommonSubdomains(domain)
	for _, s := range bruteSubs {
		if !found[s.Subdomain] {
			results = append(results, s)
			found[s.Subdomain] = true
		}
	}

	return results
}

func fetchHackerTarget(domain string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	subs := []string{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			sub := strings.TrimSpace(parts[0])
			if strings.HasSuffix(sub, "."+domain) || sub == domain {
				subs = append(subs, sub)
			}
		}
	}
	return subs
}

func fetchCrtsh(domain string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	found := make(map[string]bool)
	subs := []string{}
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			if strings.HasSuffix(name, "."+domain) && !found[name] {
				subs = append(subs, name)
				found[name] = true
			}
		}
	}
	return subs
}

func fetchAlienVault(domain string) []string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	found := make(map[string]bool)
	subs := []string{}
	for _, pdns := range result.PassiveDNS {
		h := strings.TrimSpace(pdns.Hostname)
		if h != "" && strings.HasSuffix(h, "."+domain) && !found[h] {
			subs = append(subs, h)
			found[h] = true
		}
	}
	return subs
}

func bruteCommonSubdomains(domain string) []SubdomainResult {
	results := []SubdomainResult{}
	for _, sub := range commonSubdomains {
		target := fmt.Sprintf("%s.%s", sub, domain)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := fastResolver.LookupHost(ctx, target)
		cancel()
		if err == nil && len(ips) > 0 {
			results = append(results, SubdomainResult{
				Subdomain: target,
				IPs:       ips,
				Source:    "Brute",
			})
		}
	}
	return results
}

func CollectOSINT(domain string) *OSINTResult {
	res := &OSINTResult{}
	res.CrtshSubdomains = fetchCrtsh(domain)
	res.HackerTargetIPs = fetchHackerTarget(domain)
	return res
}

type OSINTResult struct {
	CrtshSubdomains []string `json:"crtsh_subdomains"`
	HackerTargetIPs []string `json:"hackertarget_ips"`
}

func (res *Result) AddSubdomains(domain string) {
	subs := PerformSubdomainRecon(domain)
	for _, s := range subs {
		res.Technologies[s.Subdomain] = TechInfo{
			Name:       "Subdomain",
			Category:   "Infrastructure",
			Confidence: 100,
			Version:    s.Source,
		}
	}
}
