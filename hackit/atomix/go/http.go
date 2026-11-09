package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.91",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile",
	"curl/8.4.0",
	"Wget/1.21.4",
	"Go-http-client/2.0",
}

func newTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		MaxIdleConns:        500,
		MaxConnsPerHost:     200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		// Go skips ALPN h2 when TLSClientConfig is set on the Transport
		// unless ForceAttemptHTTP2 is explicit. Default ON: multiplexed
		// streams are a meaningful win on h2 targets.
		ForceAttemptHTTP2: true,
	}
}

func NewHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Transport: newTransport(),
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func NewConfiguredClient(config *ScanConfig) *http.Client {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	transport := newTransport()
	if config.SNI != "" {
		transport.TLSClientConfig.ServerName = config.SNI
	}

	// Custom DNS resolver (comma-separated, first wins) dialed over UDP/TCP.
	if raw := strings.Split(config.Resolver, ","); len(raw) > 0 {
		if dns := strings.TrimSpace(raw[0]); dns != "" {
			dnsAddr := dns
			if !strings.Contains(dnsAddr, ":") {
				dnsAddr = net.JoinHostPort(dnsAddr, "53")
			}
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, "udp", dnsAddr)
				},
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
		}
	}

	if config.DisableHTTP2 {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	if !config.KeepAlive {
		transport.DisableKeepAlives = true
	}
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			if config.ProxyAuth != "" {
				parts := strings.SplitN(config.ProxyAuth, ":", 2)
				if len(parts) == 2 {
					proxyURL.User = url.UserPassword(parts[0], parts[1])
					transport.Proxy = http.ProxyURL(proxyURL)
				}
			}
		}
	}

	maxRedir := config.MaxRedirects
	if maxRedir <= 0 {
		maxRedir = 10
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	// Cookie jar: load Netscape or JSON cookie files.
	if config.CookieJar != "" {
		if jar, err := cookiejar.New(&cookiejar.Options{}); err == nil {
			if err := LoadCookieJar(config.CookieJar, jar); err == nil {
				client.Jar = jar
			} else {
				fmt.Fprintf(os.Stderr, "[!] cookie-jar: %v\n", err)
			}
		}
	}

	if config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedir {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// LoadCookieJar reads a cookie file in either JSON (array of
// {name,value,domain,path,secure}) or Netscape (domain\tflag\tpath\tsecure\t
// expires\tname\tvalue) format and populates jar.
func LoadCookieJar(path string, jar http.CookieJar) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var entries []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
			Path   string `json:"path"`
			Secure bool   `json:"secure"`
		}
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return fmt.Errorf("cookie-jar JSON: %w", err)
		}
		for _, e := range entries {
			setJarCookie(jar, e.Domain, e.Path, e.Secure, e.Name, e.Value)
		}
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		domain, path, secure := fields[0], fields[2], strings.EqualFold(fields[3], "TRUE")
		name, value := fields[5], fields[6]
		setJarCookie(jar, domain, path, secure, name, value)
	}
	return nil
}

func setJarCookie(jar http.CookieJar, domain, path string, secure bool, name, value string) {
	if domain == "" {
		return
	}
	if path == "" {
		path = "/"
	}
	host := strings.TrimPrefix(domain, ".")
	u, err := url.Parse("https://" + host + path)
	if err != nil {
		return
	}
	jar.SetCookies(u, []*http.Cookie{{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: false,
	}})
}

func RandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

const maxBodyBytes = 5 << 20 // 5 MiB cap on response bodies

// urlPathQueryChar reports whether b is legal raw in the path component
// or the query component. Go's transport writes RequestURI verbatim, so
// raw spaces (or quotes/brackets from payloads) produce malformed request
// lines and 400s from strict servers.
func urlPathQueryChar(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '-', '.', '_', '~', // unreserved
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
		':', '/', '?', '@': // allowed in query/path (pchar, path also '/')
		return true
	}
	return false
}

// sanitizeRequestURL percent-encodes characters that are illegal raw in
// the path and query components while preserving:
//   - already-valid percent-triplets (payloads like %27 pass through),
//   - structural query characters (&, =, ?) and sub-delims (raw ' stays).
//
// Applied at the HTTP boundary; idempotent.
func sanitizeRequestURL(raw string) string {
	i := strings.Index(raw, "?")
	if i < 0 {
		return sanitizeSegment(raw, false)
	}
	return sanitizeSegment(raw[:i], false) + "?" + sanitizeSegment(raw[i+1:], true)
}

func sanitizeSegment(s string, isQuery bool) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	hex := "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			b.WriteByte(s[i+2])
			i += 2
			continue
		}
		if urlPathQueryChar(c) {
			if !isQuery && c == '?' {
				// path segment may not carry '?' raw
				b.WriteString("%3F")
				continue
			}
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// bodyBufPool recycles read buffers across responses to reduce
// allocation churn on large template fan-outs. Buffers larger than
// poolBufMax are dropped instead of returned.
var bodyBufPool = sync.Pool{New: func() interface{} {
	b := &bytes.Buffer{}
	b.Grow(128 * 1024)
	return b
}}

const poolBufMax = 2 << 20

// readBodyPooled reads a bounded body using a recycled buffer. The
// returned string is a fresh copy safe for the caller to retain.
func readBodyPooled(r io.Reader, limit int64) string {
	buf := bodyBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, _ = buf.ReadFrom(io.LimitReader(r, limit))
	s := buf.String()
	if buf.Cap() <= poolBufMax {
		buf.Reset()
		bodyBufPool.Put(buf)
	}
	return s
}

func ResolveURL(baseURL string, pathTmpl string, payload string) string {
	result := strings.ReplaceAll(pathTmpl, "{{BaseURL}}", strings.TrimRight(baseURL, "/"))
	result = strings.ReplaceAll(result, "{{URL}}", baseURL)
	if payload != "" {
		result = strings.ReplaceAll(result, "{{payload}}", url.QueryEscape(payload))
	}
	return result
}

// SendRequest issues one request. If hostOverride is set, it replaces the
// Host header (used by -scan-all-ips, where the URL points at a literal IP
// but virtual hosting needs the original hostname).
func SendRequest(client *http.Client, reqURL, method, body string, headers map[string]string, hostOverride ...string) (*ResponseInfo, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, sanitizeRequestURL(reqURL), reqBody)
	if err != nil {
		return nil, err
	}
	if len(hostOverride) > 0 && hostOverride[0] != "" {
		req.Host = hostOverride[0]
	}

	// Default UA only when caller did not supply one (custom-agent /
	// rand-agent handled by engine via headers map).
	hasUA := false
	for k := range headers {
		if strings.EqualFold(k, "User-Agent") {
			hasUA = true
			break
		}
	}
	if !hasUA {
		req.Header.Set("User-Agent", RandomUserAgent())
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// Do NOT set Accept-Encoding manually: Go auto-decompresses gzip
	// only when the header is absent. Setting it manually previously
	// delivered gzip bytes to matchers.
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody := readBodyPooled(resp.Body, maxBodyBytes)
	var headerStr strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			headerStr.WriteString(k)
			headerStr.WriteString(": ")
			headerStr.WriteString(v)
			headerStr.WriteString("\n")
		}
	}

	contentType := resp.Header.Get("Content-Type")

	return &ResponseInfo{
		StatusCode:  resp.StatusCode,
		Headers:     headerStr.String(),
		Body:        respBody,
		BodyLen:     len(respBody),
		Duration:    duration,
		ContentType: contentType,
	}, nil
}

func SendRequestWithRetry(client *http.Client, reqURL, method, body string, headers map[string]string, maxRetries int, hostOverride ...string) (*ResponseInfo, error) {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > 5 {
		maxRetries = 5
	}
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			backoff := time.Duration(i*300) * time.Millisecond
			time.Sleep(backoff)
		}
		resp, err := SendRequest(client, reqURL, method, body, headers, hostOverride...)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
