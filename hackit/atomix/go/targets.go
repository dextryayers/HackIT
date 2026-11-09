package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

type Target struct {
	Raw    string
	URL    string
	Scheme string
	Host   string
	Port   string
	Path   string
}

// HostOverrides maps target origins (scheme://ip:port) back to the
// original hostname so the engine can set the Host header — required for
// virtual hosting when -scan-all-ips rewrites the URL host to a literal IP.
var HostOverrides sync.Map

func LoadTargets(config *ScanConfig) ([]string, error) {
	targets := make(map[string]bool)
	if config.URL != "" {
		targets[EnsureScheme(config.URL)] = true
	}
	if config.TargetFile != "" {
		f, err := os.Open(config.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("target file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets[EnsureScheme(line)] = true
			}
		}
	}
	if len(config.Targets) > 0 {
		for _, t := range config.Targets {
			if t != "" {
				targets[EnsureScheme(t)] = true
			}
		}
	}
	excludes := LoadExcludes(config.ExcludeFile)
	scope := LoadScope(config.ScopeFile)
	result := make([]string, 0, len(targets))
	for t := range targets {
		if isExcluded(t, excludes) {
			continue
		}
		if len(scope) > 0 && !inScope(t, scope) {
			continue
		}
		result = append(result, t)
	}
	if config.ScanAllIps {
		result = expandAllIPs(result)
	}
	return result, nil
}

// expandAllIPs replaces each hostname target with one target per resolved
// A/AAAA address. The literal-IP URL carries a HostOverride so the engine
// sends the original hostname in the Host header.
func expandAllIPs(targets []string) []string {
	var out []string
	for _, t := range targets {
		u, err := url.Parse(t)
		if err != nil {
			out = append(out, t)
			continue
		}
		host := u.Hostname()
		if net.ParseIP(host) != nil {
			out = append(out, t) // already a literal IP
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			fmt.Fprintf(os.Stderr, "[!] scan-all-ips: lookup %s failed (%v); keeping hostname\n", host, err)
			out = append(out, t)
			continue
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		for _, ip := range ips {
			u2 := *u
			u2.Host = net.JoinHostPort(ip.String(), port)
			// Key by origin only — template paths resolve against it.
			HostOverrides.Store(u2.Scheme+"://"+u2.Host, host)
			out = append(out, u2.String())
		}
	}
	return out
}

func LoadExcludes(path string) []*regexp.Regexp {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var patterns []*regexp.Regexp
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if re, err := regexp.Compile(line); err == nil {
				patterns = append(patterns, re)
			}
		}
	}
	return patterns
}

func LoadScope(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}

func isExcluded(target string, excludes []*regexp.Regexp) bool {
	for _, re := range excludes {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

func inScope(target string, scope []string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, s := range scope {
		if strings.Contains(host, s) {
			return true
		}
	}
	return false
}

func ParseTarget(raw string) *Target {
	u, err := url.Parse(raw)
	if err != nil {
		u = &url.URL{Scheme: "https", Host: raw}
	}
	t := &Target{
		Raw:    raw,
		URL:    u.String(),
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Path:   u.Path,
	}
	t.Port = u.Port()
	if t.Port == "" {
		if t.Scheme == "https" {
			t.Port = "443"
		} else {
			t.Port = "80"
		}
	}
	return t
}
