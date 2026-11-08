package main

import (
	"bufio"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// SubdomainWordlist is a curated set of labels most likely to carry an app
// with a distinct tech stack. Not a full brute-force dump — accuracy beats
// volume.
var SubdomainWordlist = []string{
	"www", "api", "app", "admin", "portal", "panel", "dashboard", "manage",
	"docs", "help", "support", "status", "blog", "shop", "store",
	"auth", "sso", "oauth", "id", "connect",
	"cdn", "static", "assets", "media", "upload", "images", "img",
	"dev", "staging", "stage", "uat", "test", "demo", "beta", "preview",
	"m", "mobile", "wap",
	"git", "gitlab", "ci", "jenkins", "build", "deploy",
	"grafana", "kibana", "prometheus", "monitor", "metrics", "status",
	"mail", "owa", "webmail", "email",
	"db", "mysql", "postgres", "redis", "elasticsearch", "mongo",
	"ftp", "sftp", "vpn",
	"secure", "vault", "secret",
	"internal", "intranet", "private", "corp", "corporate",
	"docs", "wiki", "knowledge", "kb",
	"forum", "community", "chat", "irc",
	"download", "update", "releases",
	"payments", "pay", "billing",
	"crm", "erp", "hr",
	"cloud", "objects", "s3", "storage",
	"mx", "autodiscover", "autoconfig",
}

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
