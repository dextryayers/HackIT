package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Fallback browser-like UA pool used when db/user-agents.txt is unavailable.
var fallbackUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}

var acceptLangs = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.8",
	"id-ID,id;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,id;q=0.7",
	"en;q=0.9,de;q=0.8",
}

var acceptTypes = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json, text/plain, */*",
}

var forwardIPHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
	"X-Remote-Addr", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP",
}

// Header sets applied only when a path was blocked. Each set is one attempt.
var bypassHeaderSets = []map[string]string{
	{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
	{"X-Original-URL": "/", "X-Rewrite-URL": "/"},
	{"X-Forwarded-Host": "localhost", "X-Host": "localhost"},
	{"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
	{"X-Forwarded-For": "10.0.0.1", "Client-IP": "10.0.0.1"},
}

// applyStealth fills in browser-like headers and, in stealth mode, a random
// forwarding IP. Explicit values from -H/--user-agent/--cookie always win.
func applyStealth(req *http.Request, config *ScanConfig, uaList []string) {
	if req.Header.Get("User-Agent") == "" && config.UserAgent == "" {
		req.Header.Set("User-Agent", pickUA(uaList))
	}
	if req.Header.Get("Accept") == "" && !config.APIMode {
		req.Header.Set("Accept", acceptTypes[rand.Intn(len(acceptTypes))])
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", acceptLangs[rand.Intn(len(acceptLangs))])
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}
	if req.Header.Get("Upgrade-Insecure-Requests") == "" && !config.APIMode {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	if config.Stealth {
		h := forwardIPHeaders[rand.Intn(len(forwardIPHeaders))]
		if req.Header.Get(h) == "" {
			req.Header.Set(h, randomIP())
		}
		if req.Header.Get("Cache-Control") == "" {
			req.Header.Set("Cache-Control", "no-cache")
		}
	}
}

func pickUA(uaList []string) string {
	pool := uaList
	if len(pool) == 0 {
		pool = fallbackUAs
	}
	return strings.TrimSpace(pool[rand.Intn(len(pool))])
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1)
}

func applyBypassHeaders(req *http.Request, setIndex int) {
	set := bypassHeaderSets[setIndex%len(bypassHeaderSets)]
	for k, v := range set {
		req.Header.Set(k, v)
	}
}

// pathMutations returns ffuf-style encoded variants used to dodge naive WAF
// and 403 rules. The original path is never included; callers keep it.
func pathMutations(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	base := "/" + p
	raw := []string{
		base + "/",
		base + "/.",
		base + "//",
		base + "%20",
		base + "%09",
		base + "%2e",
		"/%2e/" + p,
		"//" + p,
		"/." + base,
		base + ";",
		base + "..;/",
		base + "%3f",
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v == base || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func isBlockStatus(code int) bool {
	switch code {
	case 403, 406, 429, 501, 503:
		return true
	}
	return false
}

func looksLikeChallenge(body string) bool {
	l := strings.ToLower(body)
	for _, s := range []string{
		"just a moment", "cf-chl", "attention required", "checking your browser",
		"ddos protection by", "request blocked", "web application firewall",
		"access denied", "you have been blocked", "captcha",
	} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// Global adaptive backoff: a 429/503/403 anywhere slows every worker so the
// scanner backs off as a whole instead of hammering the WAF into a hard ban.
var (
	backoffUntilNano int64
	blockCount       int32
)

func noteBlockStatus(code int) {
	base := int64(300 * time.Millisecond)
	switch code {
	case 429:
		base = int64(2 * time.Second)
	case 503:
		base = int64(time.Second)
	case 403, 406:
		base = int64(400 * time.Millisecond)
	}
	n := atomic.AddInt32(&blockCount, 1)
	if n > 4 {
		n = 4
	}
	d := time.Duration(base * int64(1<<uint(n)))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	until := time.Now().Add(d).UnixNano()
	for {
		old := atomic.LoadInt64(&backoffUntilNano)
		if until <= old {
			break
		}
		if atomic.CompareAndSwapInt64(&backoffUntilNano, old, until) {
			break
		}
	}
}

func waitBackoff() {
	for {
		until := atomic.LoadInt64(&backoffUntilNano)
		if until == 0 {
			return
		}
		d := time.Until(time.Unix(0, until))
		if d <= 0 {
			return
		}
		if d > 250*time.Millisecond {
			d = 250 * time.Millisecond
		}
		time.Sleep(d)
	}
}

func resetBackoff() {
	atomic.StoreInt64(&backoffUntilNano, 0)
	atomic.StoreInt32(&blockCount, 0)
}
