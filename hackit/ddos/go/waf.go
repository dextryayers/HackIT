package main

// Per-request evasion profile for the Go engine. Mirrors c/waf.h: header-name
// case, forwarding-header IPs, path mutation, cache buster, UA draw. Every
// request gets a distinct client identity.

import (
	"math/rand"
	"strings"
)

var wafUA = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
}

var wafAccept = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"application/json, text/plain, */*",
	"*/*",
}

var wafLang = []string{
	"en-US,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8", "en-GB,en;q=0.9", "en-US,en;q=0.5",
}

var wafRef = []string{
	"https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
	"https://t.co/", "https://www.facebook.com/", "https://www.reddit.com/",
}

var wafFwd = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP",
	"True-Client-IP", "X-Originating-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP",
}

const wafAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

var wafFirstOctet = []int{1, 5, 23, 31, 37, 45, 62, 77, 82, 91, 103, 113, 124, 151, 176, 185, 193, 202, 212, 223}

type wafProfile struct {
	rng *rand.Rand
}

func newWAF(seed int64) *wafProfile {
	return &wafProfile{rng: rand.New(rand.NewSource(seed))}
}

func (w *wafProfile) randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = wafAlnum[w.rng.Intn(len(wafAlnum))]
	}
	return string(b)
}

func (w *wafProfile) randIP() string {
	return itoa(wafFirstOctet[w.rng.Intn(len(wafFirstOctet))]) + "." +
		itoa(w.rng.Intn(256)) + "." + itoa(w.rng.Intn(256)) + "." +
		itoa(1+w.rng.Intn(254))
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func (w *wafProfile) mangleCase(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' && w.rng.Intn(2) == 0 {
			b[i] = c + 32
		} else if c >= 'a' && c <= 'z' && w.rng.Intn(2) == 0 {
			b[i] = c - 32
		}
	}
	return string(b)
}

// buildPath returns a mutated path so no two requests share a cache key.
func (w *wafProfile) buildPath(base string) string {
	var sb strings.Builder
	nseg := 1 + w.rng.Intn(3)
	sb.WriteByte('/')
	for i := 0; i < nseg; i++ {
		if i > 0 {
			sb.WriteByte('/')
		}
		sb.WriteString(w.randStr(3 + w.rng.Intn(7)))
	}
	switch w.rng.Intn(4) {
	case 0:
		sb.WriteString(".html")
	case 1:
		sb.WriteString("/%2e%2e/" + w.randStr(4))
	case 2:
		sb.WriteString(";jsessionid=" + w.randStr(12))
	default:
		s := w.randStr(4)
		sb.WriteString("/" + s + "%20" + s)
	}
	sb.WriteString("?_=" + w.randStr(8) + w.randStr(8))
	_ = base
	return sb.String()
}

// apply fills the request headers with a fresh identity.
func (w *wafProfile) apply(h map[string]string, keepalive bool) {
	h["User-Agent"] = wafUA[w.rng.Intn(len(wafUA))]
	h["Accept"] = wafAccept[w.rng.Intn(len(wafAccept))]
	h["Accept-Language"] = wafLang[w.rng.Intn(len(wafLang))]
	h["Accept-Encoding"] = "gzip, deflate, br"
	h["Referer"] = wafRef[w.rng.Intn(len(wafRef))]
	h["Cache-Control"] = []string{"no-cache", "max-age=0"}[w.rng.Intn(2)]
	h["Pragma"] = "no-cache"
	h["Upgrade-Insecure-Requests"] = "1"
	h["DNT"] = "1"
	if keepalive {
		h["Connection"] = "keep-alive"
	} else {
		h["Connection"] = "close"
	}
	for i := 0; i < 3; i++ {
		h[w.mangleCase(wafFwd[w.rng.Intn(len(wafFwd))])] = w.randIP()
	}
	h["Forwarded"] = "for=" + w.randIP() + ";proto=https"
	h[w.mangleCase("X-Custom-"+w.randStr(5))] = w.randStr(16)
}