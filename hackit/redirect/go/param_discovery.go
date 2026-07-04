package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ParameterInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Values int    `json:"values"`
}

var commonParamNames = []string{
	"url", "redirect", "return", "next", "goto", "target", "view",
	"file", "load", "page", "r", "u", "link", "href", "ref", "out",
	"dest", "destination", "continue", "redir", "redirect_uri",
	"redirect_url", "callback", "return_url", "return_to",
	"return_path", "forward", "forward_url", "path", "go",
	"site", "html", "image", "img", "to", "domain", "host",
	"external", "external_url", "source", "src", "url1", "url2",
	"url3", "uri", "urli", "ru", "su", "sp", "cu", "cu1", "cu2",
	"req", "action", "done", "continue_url", "cont", "ret",
	"ret_url", "retpath", "rurl", "rd", "redirect_to", "goto_url",
}

func (s *Scanner) scanQueryParams(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	params := parsedURL.Query()
	fuzzedParams := false

	if len(params) == 0 {
		params = make(url.Values)
		for _, name := range commonParamNames[:30] {
			params.Set(name, "test")
		}
		fuzzedParams = true
	}

	discovered := make([]ParameterInfo, 0)
	for k, v := range params {
		discovered = append(discovered, ParameterInfo{
			Name:   k,
			Source: "query",
			Values: len(v),
		})
	}

	allPayloads := append(DomainPayloads, EncodedPayloads...)
	allPayloads = append(allPayloads, BypassPayloads...)
	allPayloads = append(allPayloads, DataPayloads[:10]...)

	if fuzzedParams {
		allPayloads = allPayloads[:15]
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 15)

	for _, param := range discovered {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range allPayloads {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				clone := cloneURL(parsedURL)
				newParams := make(url.Values)
				for k, v := range params {
					if k == p {
						newParams.Set(k, pay)
					} else {
						newParams[k] = v
					}
				}
				clone.RawQuery = newParams.Encode()
				attackURL := clone.String()

				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, p, pay, "Query Param", loc, body, resp.StatusCode)
				mu.Unlock()
			}(param.Name, pay)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanBody(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)

	payloads := make([]string, 0)
	payloads = append(payloads, DomainPayloads[:10]...)
	payloads = append(payloads, EncodedPayloads[:10]...)
	payloads = append(payloads, BypassPayloads[:10]...)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, param := range commonParamNames[:20] {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range payloads {
			if s.isDeadlinePassed() {
				break
			}
			formData := url.Values{}
			formData.Set(param, pay)
			encoded := formData.Encode()

			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay, body string) {
				defer wg.Done()
				defer func() { <-sem }()

				req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := s.Client.Do(req)
				if err != nil {
					return
				}
				loc := resp.Header.Get("Location")

				s.mu.Lock()
				s.RequestCount++
				s.mu.Unlock()

				bodyBytes := make([]byte, 65536)
				n, _ := resp.Body.Read(bodyBytes)
				resp.Body.Close()
				bodyStr := string(bodyBytes[:n])

				mu.Lock()
				s.checkRedirect(targetURL, targetURL, p, pay, "Body POST", loc, bodyStr, resp.StatusCode)
				mu.Unlock()
			}(param, pay, encoded)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanHeaders(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	headers := []string{
		"Referer", "Origin", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Host", "X-Real-IP", "Forwarded", "X-Original-URL",
		"X-Rewrite-URL", "X-Forwarded-For", "X-Proxy-Host",
		"X-Custom-IP-Authorization", "X-Forwarded-Server",
		"X-Forwarded-Scheme", "X-Url-Scheme", "X-HTTP-Host-Override",
		"CF-Connecting-IP", "True-Client-IP", "X-Client-IP",
		"Client-IP", "X-Cluster-Client-IP", "X-Remote-IP",
		"X-Remote-Addr", "X-Originating-IP", "X-Real-IP-Override",
		"Destination", "Host", "X-Forwarded",
	}

	payloads := make([]string, 0)
	payloads = append(payloads, HeaderPayloads...)
	payloads = append(payloads, BypassPayloads[:10]...)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 15)

	for _, header := range headers {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range payloads {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(h, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					return
				}
				req.Header.Set(h, p)
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := s.Client.Do(req)
				if err != nil {
					return
				}
				loc := resp.Header.Get("Location")
				bodyBytes := make([]byte, 65536)
				n, _ := resp.Body.Read(bodyBytes)
				resp.Body.Close()
				bodyStr := string(bodyBytes[:n])

				mu.Lock()
				s.checkRedirect(targetURL, targetURL, h, p, "Header Inject", loc, bodyStr, resp.StatusCode)
				mu.Unlock()
			}(header, pay)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanPath(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	pathPrefixes := []string{
		"/redirect?url=", "/redirect?next=", "/redirect?to=",
		"/go?url=", "/go?next=", "/out?url=",
		"/link?url=", "/?url=", "/?next=", "/?goto=",
		"/redirect?redirect_uri=", "/redirect?return_url=",
		"/redirect?callback=", "/redirect?page=",
		"/go?redirect=", "/out?redirect=",
		"/link?redirect=", "/?redirect=",
		"/redirect?r=", "/redirect?u=",
		"/api/redirect?url=", "/api/v1/redirect?url=",
		"/auth/redirect?url=", "/login?redirect=",
		"/login?next=", "/login?return=",
		"/auth/login?redirect=", "/sso?redirect=",
		"/saml?redirect=", "/oauth?redirect=",
		"/callback?url=", "/callback?redirect=",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, prefix := range pathPrefixes {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range PathPayloads {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(prefix, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				baseURL := strings.SplitN(targetURL, "?", 2)[0]
				baseURL = strings.SplitN(baseURL, "#", 2)[0]
				baseURL = strings.TrimRight(baseURL, "/")

				attackURL := baseURL + prefix + url.QueryEscape(pay)
				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, "path", pay, "Path Inject", loc, body, resp.StatusCode)
				mu.Unlock()
			}(prefix, pay)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanDOMPayloads(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	domParams := []string{
		"next", "url", "redirect", "return", "goto", "to", "link",
		"page", "view", "r", "u", "href", "ref", "out", "path",
		"redirect_uri", "redirect_url", "callback", "return_url",
		"return_to", "forward", "forward_url", "site", "html",
		"external", "source", "src", "uri", "action", "done",
	}

	payloads := make([]string, 0)
	payloads = append(payloads, DataPayloads...)
	payloads = append(payloads, DomainPayloads[:10]...)
	payloads = append(payloads, BypassPayloads[:10]...)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, param := range domParams {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range payloads {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(param, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				clone := cloneURL(parsedURL)
				q := clone.Query()
				q.Set(param, pay)
				clone.RawQuery = q.Encode()
				attackURL := clone.String()

				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, param, pay, "DOM/Client", loc, body, resp.StatusCode)
				mu.Unlock()
			}(param, pay)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanBypass(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	params := parsedURL.Query()

	if len(params) == 0 {
		params = make(url.Values)
		params.Set("url", "test")
	}

	bypassTests := []struct {
		payload string
		desc    string
	}{
		{"http://evil.com@", "At-sign bypass"},
		{"http://evil.com%00", "Null byte"},
		{"http://evil.com%23", "Hash fragment"},
		{"http://127.0.0.1", "IP bypass"},
		{"http://0x7f000001", "Hex IP"},
		{"http://2130706433", "Decimal IP"},
		{"http://0x0.0x0.0x0.0x1", "Hex octets"},
		{"http://[::1]", "IPv6 loopback"},
		{"http://localhost", "Localhost"},
		{"http://evil.com:80", "Port bypass"},
		{"http://evil.com%2e", "Encoded dot"},
		{"http://%65vil.com", "Hex encoding"},
		{"///evil.com", "Triple slash"},
		{"////evil.com", "Quad slash"},
		{"hTTP://evil.com", "Case bypass"},
		{"HTTP://evil.com", "Uppercase"},
		{"http://evil.com/..", "Path traversal"},
		{"http://evil.com/../", "Path traversal 2"},
		{"http://evil.com%2f..", "Encoded traversal"},
		{"//evil.com", "Protocol relative"},
		{"\\\\evil.com", "Backslash"},
		{"\\/evil.com", "Backslash 2"},
		{"http://evil.com@127.0.0.1", "Credentials bypass"},
		{"http://evil.com%00@127.0.0.1", "Null creds bypass"},
		{"http://evil.com.good.com", "Subdomain confusion"},
		{"http://evil.com%2e.good.com", "Encoded subdomain"},
		{"http://evil.com/..;/", "Path truncation"},
		{"http://evil.com;/", "Semicolon truncation"},
		{"http://0", "Zero IP"},
		{"http://127.1", "Short IP"},
		{"http://0177.0.0.1", "Octal IP"},
		{"http://[::ffff:127.0.0.1]", "IPv4-mapped IPv6"},
		{"http://evil.com?@", "Questionmark bypass"},
		{"http://evil.com#@", "Hash bypass"},
		{"http://evil.com%3f@", "Encoded question"},
		{"http://evil.com%3f", "Encoded question 2"},
		{"http://evil.com%23@", "Encoded hash"},
		{"http://evil.com..", "Double dot"},
		{"http://evil.com.%00", "Null dot"},
		{"http://evil.com%5c", "Encoded backslash"},
		{"//127.0.0.1", "IP protocol relative"},
		{"///127.0.0.1", "Triple slash IP"},
		{"//localhost", "Localhost protocol relative"},
		{"/\\127.0.0.1", "Forward-backslash IP"},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 12)

	for paramName := range params {
		if s.isDeadlinePassed() {
			break
		}
		for _, bt := range bypassTests {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay, desc string) {
				defer wg.Done()
				defer func() { <-sem }()

				clone := cloneURL(parsedURL)
				q := clone.Query()
				q.Set(p, pay)
				clone.RawQuery = q.Encode()
				attackURL := clone.String()

				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, p, pay, "Bypass ("+desc+")", loc, body, resp.StatusCode)
				mu.Unlock()
			}(paramName, bt.payload, bt.desc)
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanBlindRedirect(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)

	blindTargets := []string{
		targetURL,
	}
	params := parsedURL.Query()

	if len(params) == 0 {
		params = make(url.Values)
		for _, name := range commonParamNames[:20] {
			params.Set(name, "test")
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 15)

	for _, paramName := range commonParamNames[:15] {
		if s.isDeadlinePassed() {
			break
		}
		for _, targetURL := range blindTargets {
			if s.isDeadlinePassed() {
				break
			}
			for _, pay := range BlindPayloads {
				if s.isDeadlinePassed() {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(tgt, p, pay string) {
					defer wg.Done()
					defer func() { <-sem }()

					clone := cloneURL(parsedURL)
					q := clone.Query()
					q.Set(p, pay)
					clone.RawQuery = q.Encode()
					attackURL := clone.String()

					resp, loc, body, err := s.makeRequest(attackURL)
					if err != nil {
						return
					}

					mu.Lock()
					blindEngine := "Blind Redirect"
					if loc != "" {
						s.checkRedirect(tgt, attackURL, p, pay, blindEngine, loc, body, resp.StatusCode)
					} else if strings.Contains(body, pay) {
						s.checkRedirect(tgt, attackURL, p, pay, blindEngine+" (Reflected)", "", body, resp.StatusCode)
					}
					mu.Unlock()
				}(targetURL, paramName, pay)
			}
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanDeepPayload(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)

	allPayloads := GenerateMassivePayloads()
	params := parsedURL.Query()

	if len(params) == 0 {
		params = make(url.Values)
		for _, name := range commonParamNames[:10] {
			params.Set(name, "test")
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 12)

	deadlineCheck := s.Deadline.Add(-2 * time.Second)

	for paramName := range params {
		if time.Now().After(deadlineCheck) || s.isDeadlinePassed() {
			break
		}
		batchSize := len(allPayloads) / 5
		if batchSize < 50 {
			batchSize = 50
		}
		maxPayloads := 100
		if s.isDeadlinePassed() {
			break
		}
		count := 0
		for _, pay := range allPayloads {
			if s.isDeadlinePassed() || count >= maxPayloads {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				clone := cloneURL(parsedURL)
				q := clone.Query()
				q.Set(p, pay)
				clone.RawQuery = q.Encode()
				attackURL := clone.String()

				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, p, pay, "Deep Payload", loc, body, resp.StatusCode)
				mu.Unlock()
			}(paramName, pay)
			count++
		}
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanCookieRedirect(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)

	cookieParams := []string{
		"redirect", "next", "url", "return", "goto", "target",
		"page", "dest", "destination", "continue", "redirect_uri",
		"redirect_url", "callback", "return_url", "return_to",
		"forward", "forward_url", "path", "site", "redir",
		"locale", "lang", "referer", "source", "from", "ru",
	}

	cookiePayloads := DomainPayloads
	if len(cookiePayloads) > 15 {
		cookiePayloads = cookiePayloads[:15]
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 15)

	for _, param := range cookieParams {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range cookiePayloads {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				headers := map[string]string{
					"Cookie": p + "=" + url.QueryEscape(pay),
				}
				resp, loc, body, err := s.makeRequestWithHeader(targetURL, headers)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, targetURL, "Cookie:"+p, pay, "Cookie Redirect", loc, body, resp.StatusCode)
				mu.Unlock()
			}(param, pay)
		}
	}

	for _, param := range cookieParams[:10] {
		if s.isDeadlinePassed() {
			break
		}
		for _, pay := range BypassPayloads[:10] {
			if s.isDeadlinePassed() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				headers := map[string]string{
					"Set-Cookie":       p + "=" + url.QueryEscape(pay),
					"X-Forwarded-Host": pay,
				}
				resp, loc, body, err := s.makeRequestWithHeader(targetURL, headers)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, targetURL, "Set-Cookie:"+p, pay, "Cookie Redirect", loc, body, resp.StatusCode)
				mu.Unlock()
			}(param, pay)
		}
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanEncodingMatrix(targetURL string, parsedURL *url.URL) []Result {
	results := make([]Result, 0)
	params := parsedURL.Query()

	if len(params) == 0 {
		params = make(url.Values)
		for _, name := range commonParamNames[:20] {
			params.Set(name, "test")
		}
	}

	baseHosts := []string{"evil.com", "evil.net", "attacker.io", "127.0.0.1", "localhost"}
	matrix := make([]string, 0)

	for _, h := range baseHosts {
		matrix = append(matrix, "http://"+h)
		matrix = append(matrix, "https://"+h)
		matrix = append(matrix, "//"+h)

		matrix = append(matrix, "http%3a%2f%2f"+h)
		matrix = append(matrix, "https%3a%2f%2f"+h)
		matrix = append(matrix, "%2f%2f"+h)

		matrix = append(matrix, "http%253a%252f%252f"+h)
		matrix = append(matrix, "https%253a%252f%252f"+h)
		matrix = append(matrix, "%252f%252f"+h)

		matrix = append(matrix, "http%25253a%25252f%25252f"+h)
		matrix = append(matrix, "%25252f%25252f"+h)

		hexEncoded := ""
		for _, c := range "http://" + h {
			hexEncoded += fmt.Sprintf("%%%02x", c)
		}
		if len(hexEncoded) < 200 {
			matrix = append(matrix, hexEncoded)
		}

		hexUpper := ""
		for _, c := range "http://" + h {
			hexUpper += fmt.Sprintf("%%%02X", c)
		}
		if len(hexUpper) < 200 {
			matrix = append(matrix, hexUpper)
		}

		matrix = append(matrix, "hTTP%3a%2f%2f"+h)
		matrix = append(matrix, "HTTP%3a%2f%2f"+h)
		matrix = append(matrix, "Http%3a%2f%2f"+h)

		matrix = append(matrix, "http://"+h+"%09")
		matrix = append(matrix, "http://"+h+"%09test")
		matrix = append(matrix, "http://"+h+"%0a")
		matrix = append(matrix, "http://"+h+"%0d%0a")
		matrix = append(matrix, "http://"+h+"%00")
		matrix = append(matrix, "http://"+h+"%00test")
		matrix = append(matrix, "http://"+h+"%23test")
		matrix = append(matrix, "http://"+h+"%3ftest")
		matrix = append(matrix, "http://"+h+"%2f..")
		matrix = append(matrix, "http://"+h+"%2f../")
		matrix = append(matrix, "http://"+h+"/%2e%2e")
		matrix = append(matrix, "http://"+h+"/%2e%2e/")
		matrix = append(matrix, "http://"+h+"%5c..")
		matrix = append(matrix, "http://"+h+"/..%5c")
		matrix = append(matrix, "http://"+h+"%c0%ae%c0%ae/")
		matrix = append(matrix, "http://"+h+"/%c0%ae%c0%ae/")
		matrix = append(matrix, "http://"+h+"%c0%2e%c0%2e/")
		matrix = append(matrix, "http://"+h+"%252e%252e/")
		matrix = append(matrix, "http://"+h+"%252f..")
		matrix = append(matrix, "http://"+h+"..%5c")
		matrix = append(matrix, "http://"+h+"..%c0%af")
		matrix = append(matrix, "http://"+h+"%c0%af..")
	}

	tabHex := []string{
		"%09", "%0a", "%0d", "%0c", "%0b", "%a0",
	}
	for _, h := range baseHosts[:3] {
		for _, t := range tabHex {
			matrix = append(matrix, "http://"+h+t)
			matrix = append(matrix, "http://"+h+"/"+t)
			matrix = append(matrix, "http://"+h+"%00"+t)
			matrix = append(matrix, "//"+h+t)
		}
	}

	for _, h := range baseHosts[:2] {
		for i := 1; i <= 5; i++ {
			matrix = append(matrix, fmt.Sprintf("http://%s/%s..", h, strings.Repeat("%252f", i)))
			matrix = append(matrix, fmt.Sprintf("http://%s/%s..\\", h, strings.Repeat("%252f", i)))
		}
	}

	matrix = uniqueStrings(matrix)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 15)

	for paramName := range params {
		if s.isDeadlinePassed() {
			break
		}
		maxTests := 120
		tested := 0
		for _, pay := range matrix {
			if s.isDeadlinePassed() || tested >= maxTests {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				clone := cloneURL(parsedURL)
				q := clone.Query()
				q.Set(p, pay)
				clone.RawQuery = q.Encode()
				attackURL := clone.String()

				resp, loc, body, err := s.makeRequest(attackURL)
				if err != nil {
					return
				}

				mu.Lock()
				s.checkRedirect(targetURL, attackURL, p, pay, "Encoding Matrix", loc, body, resp.StatusCode)
				mu.Unlock()
			}(paramName, pay)
			tested++
		}
	}
	wg.Wait()
	return results
}
