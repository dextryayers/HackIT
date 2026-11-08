package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type probeSignature struct {
	header   string // header name, empty for body/cookie match
	pattern  *regexp.Regexp
	software string
	version  string // empty = discovered from pattern capture group 1
	source   string
}

var probeSignatures []probeSignature

func init() {
	probeSignatures = []probeSignature{
		{header: "server", pattern: regexp.MustCompile(`(?i)(nginx)[/ ]([0-9.]+)`), software: "nginx", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(apache)[/ ]([0-9.]+)`), software: "apache", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(openssh)[/_]([0-9.]+)`), software: "openssh", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(microsoft-iis)[/ ]([0-9.]+)`), software: "iis", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(cloudflare)`), software: "cloudflare", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(lite\-?speed)[/ ]([0-9.]+)`), software: "litespeed", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(tomcat)[/ ]([0-9.]+)`), software: "tomcat", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(jetty)[/ ]([0-9.]+)`), software: "jetty", source: "server header"},
		{header: "server", pattern: regexp.MustCompile(`(?i)(caddy)[/ ]([0-9.]+)`), software: "caddy", source: "server header"},

		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(php)[/ ]([0-9.]+)`), software: "php", source: "x-powered-by"},
		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(express)[/ ]([0-9.]+)`), software: "express", source: "x-powered-by"},
		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(asp\.net)`), software: "asp.net", source: "x-powered-by"},
		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(next\.js)[/ ]([0-9.]+)`), software: "nextjs", source: "x-powered-by"},
		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(django)`), software: "django", source: "x-powered-by"},
		{header: "x-powered-by", pattern: regexp.MustCompile(`(?i)(laravel)`), software: "laravel", source: "x-powered-by"},

		{header: "x-generator", pattern: regexp.MustCompile(`(?i)(wordpress)[ ]?([0-9.]+)?`), software: "wordpress", source: "x-generator"},
		{header: "x-generator", pattern: regexp.MustCompile(`(?i)(drupal)[ ]?([0-9.]+)?`), software: "drupal", source: "x-generator"},
		{header: "x-generator", pattern: regexp.MustCompile(`(?i)(joomla)[ ]?([0-9.]+)?`), software: "joomla", source: "x-generator"},

		{header: "x-aspnet-version", pattern: regexp.MustCompile(`([0-9.]+)`), software: "asp.net", source: "x-aspnet-version"},
		{header: "x-aspnetmvc-version", pattern: regexp.MustCompile(`([0-9.]+)`), software: "asp.net-mvc", source: "x-aspnetmvc-version"},

		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)(PHPSESSID)=`), software: "php", source: "cookie"},
		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)wp-settings-`), software: "wordpress", source: "cookie"},
		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)(JSESSIONID|tomcat)=`), software: "tomcat", source: "cookie"},
		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)(laravel_session|laravel-session)`), software: "laravel", source: "cookie"},
		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)(connect\.sid|express)`), software: "express", source: "cookie"},
		{header: "set-cookie", pattern: regexp.MustCompile(`(?i)(nuxt|nuxt-session)`), software: "nuxt.js", source: "cookie"},

		// Body markers
		{header: "", pattern: regexp.MustCompile(`(?i)generator["']?\s*[:=]\s*["']wordpress\s*([0-9.]+)?`), software: "wordpress", source: "html generator"},
		{header: "", pattern: regexp.MustCompile(`(?i)generator["']?\s*[:=]\s*["']drupal\s*([0-9.]+)?`), software: "drupal", source: "html generator"},
		{header: "", pattern: regexp.MustCompile(`(?i)generator["']?\s*[:=]\s*["']joomla[!]?\s*([0-9.]+)?`), software: "joomla", source: "html generator"},
		{header: "", pattern: regexp.MustCompile(`(?i)wp-content/(themes|plugins)`), software: "wordpress", source: "html path"},
		{header: "", pattern: regexp.MustCompile(`(?i)/(sites|core)/(default|modules)/`), software: "drupal", source: "html path"},
		{header: "", pattern: regexp.MustCompile(`(?i)next/static/`), software: "nextjs", source: "html path"},
		{header: "", pattern: regexp.MustCompile(`(?i)/content/`), software: "adobe-aem", source: "html path"},
		{header: "", pattern: regexp.MustCompile(`(?i)<title>Administration [-–]`), software: "apache-tomcat", source: "html title"},
		{header: "", pattern: regexp.MustCompile(`(?i)Moodle\s*([0-9.]+)?`), software: "moodle", source: "html generator"},
		{header: "", pattern: regexp.MustCompile(`(?i)prestashop`), software: "prestashop", source: "html generator"},
	}
}

// ProbeTarget fetches a host, reads headers and HTML body, and returns the
// technologies it can prove. Returns an empty slice on any failure.
func ProbeTarget(target string) []DetectedTech {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// Normalise to root; keep path if supplied.
	var parsed *url.URL
	var err error
	if parsed, err = url.Parse(target); err != nil {
		return nil
	}

	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "HackIt-CVE/2.0 (+authorised assessment)")
	// Cap body read to 256 KB.
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	body := string(bodyBytes)

	var techs []DetectedTech
	seen := map[string]bool{}

	add := func(name, version, source string) {
		if name == "" {
			return
		}
		if version == "" {
			version = "unknown"
		}
		key := strings.ToLower(name) + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		techs = append(techs, DetectedTech{Software: strings.ToLower(name), Version: version})
	}

	// Header matchers.
	lowHeaders := map[string]string{}
	for k, vals := range resp.Header {
		lowHeaders[strings.ToLower(k)] = strings.Join(vals, ", ")
	}

	for _, sig := range probeSignatures {
		if sig.header == "" {
			continue
		}
		value, ok := lowHeaders[sig.header]
		if !ok {
			continue
		}
		matches := sig.pattern.FindStringSubmatch(value)
		if len(matches) >= 3 {
			add(sig.software, matches[2], sig.source)
		} else if len(matches) >= 2 {
			add(sig.software, matches[1], sig.source)
		}
	}

	// Body matchers.
	for _, sig := range probeSignatures {
		if sig.header != "" {
			continue
		}
		matches := sig.pattern.FindStringSubmatch(body)
		switch len(matches) {
		case 0:
			continue
		case 1:
			add(sig.software, "unknown", sig.source)
		case 2:
			if matches[1] != "" {
				add(sig.software, matches[1], sig.source)
			} else {
				add(sig.software, "unknown", sig.source)
			}
		default:
			if matches[1] != "" {
				add(sig.software, matches[1], sig.source)
			} else {
				add(sig.software, "unknown", sig.source)
			}
		}
	}

	_ = parsed
	return techs
}

// FilterSubdomains removes duplicates and anything that resolved locally
// without a public TXT/A answer.
func FilterSubdomains(baseHost string, subs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, label := range subs {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		fqdn := label + "." + baseHost
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true
		out = append(out, fqdn)
	}
	return out
}

// findRepoRoot walks upward looking for the hackit root directory.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		if info, err := os.Stat(filepath.Join(dir, "hackit")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func locateSubdomainWorker() string {
	hints := []string{}
	if root := findRepoRoot(); root != "" {
		hints = append(hints, filepath.Join(root, "hackit", "subdomain", "go", "subdomain_worker"))
	}
	if exe, err := os.Executable(); err == nil {
		hints = append(hints, filepath.Join(filepath.Dir(exe), "..", "..", "subdomain", "go", "subdomain_worker"))
	}
	for _, hint := range hints {
		if abs, err := filepath.Abs(hint); err == nil {
			if info, err := os.Stat(abs); err == nil && !info.IsDir() {
				return abs
			}
		}
	}
	return ""
}

// enumeratePassiveSubdomains invokes the dedicated subdomain engine (crt.sh,
// hackertarget.com, waybackmachine, rapiddns, commoncrawl, ...) so the CVE
// worker sees every publicly-announced subdomain, not a static wordlist.
// Duplicates are suppressed.
func enumeratePassiveSubdomains(host string, timeout time.Duration) []string {
	worker := locateSubdomainWorker()
	if worker == "" {
		fmt.Fprintf(os.Stderr, "[probes] subdomain_worker not found; passive subdomain enumeration skipped\n")
		return nil
	}

	// Capture stdout directly — the worker prints "[sub] <fqdn>" lines.
	cmd := exec.Command(worker,
		"-d", host,
		"-passive-only",
		"-fast",
		"-resolve=false",
	)
	done := make(chan []byte, 1)
	go func() {
		data, _ := cmd.Output()
		done <- data
	}()
	out := []byte{}
	select {
	case out = <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case out = <-done:
		default:
		}
	}

	seen := map[string]bool{}
	results := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "[sub]") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		fqdn := strings.TrimPrefix(fields[len(fields)-1], "[sub]")
		fqdn = strings.TrimSpace(strings.TrimPrefix(fqdn, "["))
		fqdn = strings.TrimSuffix(fqdn, "]")
		fqdn = strings.TrimSuffix(fqdn, ".")
		fqdn = strings.ToLower(fqdn)
		if fqdn == "" || fqdn == host {
			continue
		}
		if !strings.HasSuffix(fqdn, "."+host) {
			continue
		}
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true
		results = append(results, fqdn)
	}
	return results
}

// LoadSubdomainFile reads hosts from a file, one per line, supports # comments.
func LoadSubdomainFile(path string) []string {
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()

	subs := []string{}
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subs = append(subs, line)
	}
	return subs
}

// HostReachable reports true when an HTTP/HTTPS probe completes.
func HostReachable(host string) bool {
	for _, scheme := range []string{"https://", "http://"} {
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Head(scheme + host)
		if err == nil {
			resp.Body.Close()
			return true
		}
		// Fall back to GET for servers that reject HEAD.
		resp, err = client.Get(scheme + host)
		if err == nil {
			resp.Body.Close()
			return true
		}
	}
	return false
}
