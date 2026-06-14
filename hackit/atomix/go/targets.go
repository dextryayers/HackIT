package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Target struct {
	Raw    string
	URL    string
	Scheme string
	Host   string
	Port   string
	Path   string
}

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
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets[EnsureScheme(line)] = true
			}
		}
	}
	excludes := LoadExcludes(config.ExcludeFile)
	scope := LoadScope(config.ScopeFile)
	result := make([]string, 0, len(targets))
	for t := range targets {
		if isExcluded(t, excludes) { continue }
		if len(scope) > 0 && !inScope(t, scope) { continue }
		result = append(result, t)
	}
	return result, nil
}

func LoadExcludes(path string) []*regexp.Regexp {
	if path == "" { return nil }
	f, err := os.Open(path)
	if err != nil { return nil }
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
	if path == "" { return nil }
	f, err := os.Open(path)
	if err != nil { return nil }
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
		if re.MatchString(target) { return true }
	}
	return false
}

func inScope(target string, scope []string) bool {
	u, err := url.Parse(target)
	if err != nil { return false }
	host := u.Hostname()
	for _, s := range scope {
		if strings.Contains(host, s) { return true }
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
		if t.Scheme == "https" { t.Port = "443" } else { t.Port = "80" }
	}
	return t
}
