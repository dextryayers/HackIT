package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type HttpResponse struct {
	StatusCode      int               `json:"status_code"`
	StatusText      string            `json:"status_text"`
	Server          string            `json:"server"`
	PoweredBy       string            `json:"powered_by"`
	ContentType     string            `json:"content_type"`
	Title           string            `json:"title"`
	Headers         map[string]string `json:"headers"`
	BodyPreview     string            `json:"body_preview"`
	TechnologyStack []string          `json:"technology_stack"`
}

var titleRegex = regexp.MustCompile(`(?i)<title\b[^>]*>([^<]+)</title>`)

func ProbeHTTP(host string, port int, timeout time.Duration) (*HttpResponse, error) {
	ip := ResolveHost(host)
	if len(ip) == 0 {
		return nil, fmt.Errorf("could not resolve host: %s", host)
	}

	addr := net.JoinHostPort(ip[0], fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/", addr), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/3.0; +https://hackit.local)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     dialer.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &HttpResponse{
		StatusCode:  resp.StatusCode,
		StatusText:  resp.Status,
		Headers:     make(map[string]string),
	}
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")
	result.ContentType = resp.Header.Get("Content-Type")

	for k, v := range resp.Header {
		result.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return result, nil
	}

	bodyStr := string(body)
	if len(bodyStr) > 512 {
		result.BodyPreview = bodyStr[:512]
	} else {
		result.BodyPreview = bodyStr
	}

	result.Title = ExtractTitle(bodyStr)
	result.TechnologyStack = DetectTechnology(result)

	return result, nil
}

func ProbeHTTPS(host string, port int, timeout time.Duration) (*HttpResponse, error) {
	ip := ResolveHost(host)
	if len(ip) == 0 {
		return nil, fmt.Errorf("could not resolve host: %s", host)
	}

	addr := net.JoinHostPort(ip[0], fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/", addr), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HackIT/3.0; +https://hackit.local)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &HttpResponse{
		StatusCode:  resp.StatusCode,
		StatusText:  resp.Status,
		Headers:     make(map[string]string),
	}
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")
	result.ContentType = resp.Header.Get("Content-Type")

	for k, v := range resp.Header {
		result.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return result, nil
	}

	bodyStr := string(body)
	if len(bodyStr) > 512 {
		result.BodyPreview = bodyStr[:512]
	} else {
		result.BodyPreview = bodyStr
	}

	result.Title = ExtractTitle(bodyStr)
	result.TechnologyStack = DetectTechnology(result)

	return result, nil
}

func ExtractTitle(html string) string {
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Fallback: look for <title> without attributes
	idx := strings.Index(strings.ToLower(html), "<title>")
	if idx >= 0 {
		start := idx + 7
		end := strings.Index(html[start:], "</title>")
		if end >= 0 {
			return strings.TrimSpace(html[start : start+end])
		}
	}

	return ""
}

func DetectTechnology(response *HttpResponse) []string {
	var tech []string
	server := strings.ToLower(response.Server)
	powered := strings.ToLower(response.PoweredBy)
	ct := strings.ToLower(response.ContentType)
	title := strings.ToLower(response.Title)

	if strings.Contains(server, "nginx") {
		tech = append(tech, "Nginx")
		tech = append(tech, detectVersion(response.Server, "nginx/"))
	}
	if strings.Contains(server, "apache") {
		tech = append(tech, "Apache HTTP Server")
		tech = append(tech, detectVersion(response.Server, "apache/"))
	}
	if strings.Contains(server, "iis") || strings.Contains(server, "microsoft-iis") {
		tech = append(tech, "IIS")
		tech = append(tech, detectVersion(response.Server, "iis/"))
	}
	if strings.Contains(server, "cloudflare") {
		tech = append(tech, "Cloudflare")
	}
	if strings.Contains(server, "openresty") {
		tech = append(tech, "OpenResty")
	}
	if strings.Contains(server, "caddy") {
		tech = append(tech, "Caddy")
	}
	if strings.Contains(server, "lighttpd") {
		tech = append(tech, "Lighttpd")
	}

	if strings.Contains(powered, "php") {
		tech = append(tech, "PHP")
	}
	if strings.Contains(powered, "asp.net") || strings.Contains(powered, "aspnet") {
		tech = append(tech, "ASP.NET")
	}
	if strings.Contains(powered, "java") || strings.Contains(powered, "servlet") {
		tech = append(tech, "Java")
	}
	if strings.Contains(powered, "express") {
		tech = append(tech, "Express.js")
	}
	if strings.Contains(powered, "django") {
		tech = append(tech, "Django")
	}
	if strings.Contains(powered, "flask") {
		tech = append(tech, "Flask")
	}
	if strings.Contains(powered, "rails") || strings.Contains(powered, "ruby on rails") {
		tech = append(tech, "Ruby on Rails")
	}
	if strings.Contains(powered, "laravel") {
		tech = append(tech, "Laravel")
	}
	if strings.Contains(powered, "symfony") {
		tech = append(tech, "Symfony")
	}
	if strings.Contains(powered, "wordpress") {
		tech = append(tech, "WordPress")
	}
	if strings.Contains(powered, "drupal") {
		tech = append(tech, "Drupal")
	}
	if strings.Contains(powered, "joomla") {
		tech = append(tech, "Joomla")
	}
	if strings.Contains(powered, "magento") {
		tech = append(tech, "Magento")
	}
	if strings.Contains(powered, "shopify") {
		tech = append(tech, "Shopify")
	}
	if strings.Contains(powered, "wix") {
		tech = append(tech, "Wix")
	}
	if strings.Contains(powered, "next.js") || strings.Contains(powered, "nextjs") {
		tech = append(tech, "Next.js")
	}
	if strings.Contains(powered, "nuxt") {
		tech = append(tech, "Nuxt.js")
	}
	if strings.Contains(powered, "gatsby") {
		tech = append(tech, "Gatsby")
	}
	if strings.Contains(powered, "vue") {
		tech = append(tech, "Vue.js")
	}
	if strings.Contains(powered, "react") {
		tech = append(tech, "React")
	}
	if strings.Contains(powered, "angular") {
		tech = append(tech, "Angular")
	}
	if strings.Contains(powered, "svelte") {
		tech = append(tech, "Svelte")
	}

	if strings.Contains(ct, "application/json") || strings.Contains(ct, "application/xml") {
		tech = append(tech, "API")
	}

	if strings.Contains(ct, "text/html") {
		tech = append(tech, "Web Application")
	}

	if strings.Contains(title, "wordpress") {
		tech = append(tech, "WordPress")
	}
	if strings.Contains(title, "drupal") {
		tech = append(tech, "Drupal")
	}
	if strings.Contains(title, "joomla") {
		tech = append(tech, "Joomla")
	}
	if strings.Contains(title, "phpmyadmin") {
		tech = append(tech, "phpMyAdmin")
	}
	if strings.Contains(title, "phpinfo") {
		tech = append(tech, "PHPInfo (information disclosure)")
	}

	// Header-based detection
	h := response.Headers
	if v, ok := h["x-generator"]; ok {
		gen := strings.ToLower(v)
		if strings.Contains(gen, "drupal") {
			tech = append(tech, "Drupal")
		}
		if strings.Contains(gen, "wordpress") {
			tech = append(tech, "WordPress")
		}
	}
	if _, ok := h["x-aspnet-version"]; ok {
		tech = append(tech, "ASP.NET")
	}
	if _, ok := h["x-drupal-cache"]; ok {
		tech = append(tech, "Drupal")
	}
	if _, ok := h["x-drupal-dynamic-cache"]; ok {
		tech = append(tech, "Drupal")
	}
	if _, ok := h["x-pingback"]; ok {
		tech = append(tech, "WordPress (XML-RPC)")
	}
	if _, ok := h["x-nginx-proxy"]; ok {
		tech = append(tech, "Nginx Proxy")
	}
	if _, ok := h["x-varnish"]; ok {
		tech = append(tech, "Varnish Cache")
	}
	if _, ok := h["x-cache"]; ok {
		tech = append(tech, "Reverse Proxy Cache")
	}
	if _, ok := h["x-frame-options"]; ok {
		tech = append(tech, "X-Frame-Options (clickjacking protection)")
	}

	// Deduplicate
	seen := make(map[string]bool, len(tech))
	dedup := make([]string, 0, len(tech))
	for _, t := range tech {
		if t != "" && !seen[t] {
			seen[t] = true
			dedup = append(dedup, t)
		}
	}
	return dedup
}

func detectVersion(header, prefix string) string {
	lower := strings.ToLower(header)
	idx := strings.Index(lower, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	rest := header[start:]
	parts := strings.Fields(rest)
	if len(parts) > 0 {
		v := strings.TrimRight(parts[0], ",; \t\r\n")
		if v != "" {
			return v
		}
	}
	return ""
}

func CheckHTTPVulnerabilities(response *HttpResponse) []string {
	var vulns []string
	h := response.Headers

	missingHeaders := map[string]struct {
		name        string
		description string
	}{
		"strict-transport-security":          {"Strict-Transport-Security", "Missing HSTS header — allows MITM downgrade attacks"},
		"content-security-policy":            {"Content-Security-Policy", "Missing CSP header — vulnerable to XSS and data injection"},
		"x-content-type-options":             {"X-Content-Type-Options", "Missing nosniff header — MIME-type sniffing possible"},
		"x-frame-options":                    {"X-Frame-Options", "Missing clickjacking protection"},
		"x-xss-protection":                   {"X-XSS-Protection", "Missing XSS filter header"},
		"referrer-policy":                    {"Referrer-Policy", "Missing referrer policy — information leakage possible"},
		"permissions-policy":                 {"Permissions-Policy", "Missing permissions policy"},
		"access-control-allow-origin":        {"Access-Control-Allow-Origin", "CORS header missing — may allow cross-origin access"},
	}

	for header, info := range missingHeaders {
		if _, ok := h[header]; !ok {
			vulns = append(vulns, fmt.Sprintf("%s: %s", info.name, info.description))
		}
	}

	if hsts, ok := h["strict-transport-security"]; ok {
		if !strings.Contains(strings.ToLower(hsts), "max-age=") {
			vulns = append(vulns, "HSTS: max-age directive missing — ineffective")
		}
	}

	if server, ok := h["server"]; ok {
		svc := strings.ToLower(server)
		if strings.Contains(svc, "apache/2.2") {
			vulns = append(vulns, "Apache 2.2: End-of-life, multiple known CVEs")
		}
		if strings.Contains(svc, "apache/2.4.49") {
			vulns = append(vulns, "CVE-2021-41773: Apache 2.4.49 path traversal + RCE")
		}
		if strings.Contains(svc, "apache/2.4.50") {
			vulns = append(vulns, "CVE-2021-42013: Apache 2.4.50 path traversal bypass")
		}
		if strings.Contains(svc, "iis/6.0") {
			vulns = append(vulns, "CVE-2017-7269: IIS 6.0 buffer overflow RCE")
		}
		if strings.Contains(svc, "iis/7.5") {
			vulns = append(vulns, "CVE-2010-1256: IIS 7.5 information disclosure")
		}
		if strings.Contains(svc, "nginx/1.") {
			vulns = append(vulns, "Nginx 1.x: End-of-life, upgrade recommended")
		}
	}

	if pw, ok := h["x-powered-by"]; ok {
		p := strings.ToLower(pw)
		if strings.Contains(p, "php/5") {
			vulns = append(vulns, "PHP 5.x: End-of-life, multiple known vulnerabilities")
		}
		if strings.Contains(p, "php/7.0") || strings.Contains(p, "php/7.1") {
			vulns = append(vulns, fmt.Sprintf("PHP 7.x: %s is end-of-life", pw))
		}
	}

	if ct, ok := h["content-type"]; ok {
		ctLow := strings.ToLower(ct)
		if strings.Contains(ctLow, "text/html") {
			if _, ok := h["x-content-type-options"]; !ok {
				vulns = append(vulns, "HTML content without X-Content-Type-Options: nosniff")
			}
		}
	}

	if _, ok := h["www-authenticate"]; ok {
		vulns = append(vulns, "Basic/Digest authentication detected — credentials transmitted unless over HTTPS")
	}

	return vulns
}
