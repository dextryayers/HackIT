package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// lookupHostTimeout resolves a host with a hard deadline so a stalled
// system resolver can never block a probe worker.
func lookupHostTimeout(host string, timeout time.Duration) ([]string, error) {
	type res struct {
		ips []string
		err error
	}
	done := make(chan res, 1)
	go func() {
		ips, err := net.LookupHost(host)
		done <- res{ips: ips, err: err}
	}()
	select {
	case r := <-done:
		return r.ips, r.err
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
var langRegex = regexp.MustCompile(`(?i)(?:<html[^>]*\s(?:lang)=["']([a-zA-Z-]+)["']|content="text/html;\s*charset=([^"]+)")`)

func runProbe(results []*Result, config Config) {
	actualConcurrency := config.Concurrency
	if len(results) > 500 {
		actualConcurrency = config.Concurrency * 2
		if actualConcurrency > 1000 {
			actualConcurrency = 1000
		}
	}

	sem := make(chan bool, actualConcurrency)
	var wg sync.WaitGroup

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, r := range results {
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			var pWg sync.WaitGroup
			schemes := []string{"https", "http"}

			for _, scheme := range schemes {
				pWg.Add(1)
				go func(s string) {
					defer pWg.Done()
					probeURL(client, res, s, config)
				}(scheme)
			}
			pWg.Wait()
			// Stream each result the moment its probes finish, exactly once.
			res.mu.Lock()
			needsDetail := res.Status > 0 || len(res.Title) > 0 || len(res.Tech) > 0
			alreadyPrinted := res.printed
			if needsDetail && !alreadyPrinted {
				res.printed = true
			}
			res.mu.Unlock()
			if needsDetail && !alreadyPrinted {
				printMu.Lock()
				printResultDetail(res, config)
				printMu.Unlock()
			}
		}(r)
	}
	wg.Wait()
}

func probeURL(client *http.Client, res *Result, scheme string, config Config) {
	if res.Status == 200 && scheme == "http" {
		return
	}

	url := fmt.Sprintf("%s://%s", scheme, res.Subdomain)
	method := "HEAD"
	if config.ShowTitle || config.TechDetect {
		method = "GET"
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")

	var resp *http.Response
	maxRetries := 2
	if config.Stealth {
		maxRetries = 1
	}

	for i := 0; i < maxRetries; i++ {
		startTime := time.Now()
		resp, err = client.Do(req)
		if err == nil {
			elapsed := time.Since(startTime)
			elapsedMs := float64(elapsed.Microseconds()) / 1000.0
			res.mu.Lock()
			res.ResponseTime = fmt.Sprintf("%.3fs", elapsedMs/1000.0)
			res.mu.Unlock()
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
		}
	}

	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	isSuccessful := resp.StatusCode >= 200 && resp.StatusCode < 400
	res.mu.Lock()
	if res.Status == 0 || (isSuccessful && res.Status >= 400) {
		res.Status = resp.StatusCode
		res.Server = resp.Header.Get("Server")
		if res.Server == "" {
			res.Server = resp.Header.Get("X-Powered-By")
		}
		// A completed HTTP exchange proves the name resolves even when
		// the earlier DNS pass came back empty: backfill the IP so the
		// finding line is complete.
		if len(res.IPs) == 0 {
			if u, err := neturl.Parse(url); err == nil && u.Hostname() != "" {
				if ips, err := lookupHostTimeout(u.Hostname(), 5*time.Second); err == nil && len(ips) > 0 {
					res.IPs = ips
				}
			}
		}
	}

	// CDN Detection from headers
	res.CDN = detectCDN(resp.Header, scheme, res.Subdomain)
	res.mu.Unlock()

	if (config.ShowTitle || config.TechDetect) && method == "GET" {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err == nil {
			body := string(bodyBytes)

			res.mu.Lock()
			res.ContentLength = len(body)

			if config.ShowTitle {
				title := getPageTitle(url, body)
				if title != "" {
					res.Title = title
				}
			}

			if config.TechDetect {
				res.Tech = detectTech(resp.Header, body)
				var cleanedTech []string
				for _, t := range res.Tech {
					if strings.HasPrefix(t, "WAF:") {
						res.WAF = strings.TrimPrefix(t, "WAF:")
					} else if !strings.HasPrefix(t, "CDN:") {
						cleanedTech = append(cleanedTech, t)
					}
				}
				res.Tech = cleanedTech
			}
			res.mu.Unlock()
		}
	}

	// CNAME via Linux Rust bridge or Windows FFI
	if runtime.GOOS == "linux" {
		cname := linuxRustGetCname(res.Subdomain)
		if cname != "" {
			res.mu.Lock()
			res.CNAME = cname
			res.mu.Unlock()
		}
	} else if rustGetCname != nil && rustGetCname.Find() == nil {
		cDomain := []byte(res.Subdomain + "\x00")
		ptr, _, _ := rustGetCname.Call(uintptr(unsafe.Pointer(&cDomain[0])))
		if ptr != 0 {
			cnameStr := strings.TrimSpace(CStrToGo(ptr))
			if cnameStr != "" {
				res.mu.Lock()
				res.CNAME = cnameStr
				res.mu.Unlock()
			}
		}
	}
}

func detectCDN(headers http.Header, scheme, subdomain string) string {
	via := headers.Get("Via")
	server := headers.Get("Server")
	serverLower := strings.ToLower(server)
	cfRay := headers.Get("cf-ray")
	cfCache := headers.Get("cf-cache-status")
	akamai := headers.Get("X-Akamai-Transformed")
	akamaiGhost := headers.Get("X-Akamai-Ghost")
	azure := headers.Get("X-Azure-Ref")
	sucuri := headers.Get("X-Sucuri-ID")
	incapsula := headers.Get("X-CDN")

	if cfRay != "" || cfCache != "" || strings.Contains(serverLower, "cloudflare") {
		return "Cloudflare"
	}
	if akamai != "" || akamaiGhost != "" || strings.Contains(serverLower, "akamai") || strings.Contains(serverLower, "akamaighost") || strings.Contains(serverLower, "akamaistorage") || strings.Contains(serverLower, "akamaized") {
		return "Akamai"
	}
	if azure != "" {
		return "Azure CDN"
	}
	if sucuri != "" {
		return "Sucuri"
	}
	if incapsula != "" {
		return "Incapsula"
	}
	if strings.Contains(strings.ToLower(via), "google") || strings.Contains(serverLower, "gfe") {
		return "Google Cloud CDN"
	}
	if strings.Contains(serverLower, "amazons3") || strings.Contains(serverLower, "amazonaws") {
		return "AWS S3"
	}
	if strings.Contains(serverLower, "cloudfront") {
		return "AWS CloudFront"
	}
	if strings.Contains(serverLower, "fastly") {
		return "Fastly"
	}
	if strings.Contains(serverLower, "keycdn") {
		return "KeyCDN"
	}
	if strings.Contains(serverLower, "stackpath") {
		return "StackPath"
	}
	if strings.Contains(serverLower, "cdn") {
		return "Generic CDN"
	}
	return "-"
}

func getPageTitle(url string, body string) string {
	m := titleRegex.FindStringSubmatch(body)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func printResultDetail(res *Result, config Config) {
	ipStr := "-"
	if len(res.IPs) > 0 {
		ipStr = res.IPs[0]
	}

	scStr := "-"
	if res.Status > 0 {
		scStr = fmt.Sprintf("\x1b[%dm%d\x1b[0m", statusColorCode(res.Status), res.Status)
	}

	titleStr := "-"
	if res.Title != "" {
		titleStr = res.Title
	}

	asnStr := "-"
	if res.ASN != "" {
		asnStr = res.ASN
	}

	lenStr := "-"
	if res.ContentLength > 0 {
		lenStr = fmt.Sprintf("%d", res.ContentLength)
	}

	svrStr := "-"
	if res.Server != "" {
		svrStr = res.Server
	}

	timeStr := "-"
	if res.ResponseTime != "" {
		timeStr = res.ResponseTime
	}

	cdnStr := "-"
	if res.CDN != "" && res.CDN != "-" {
		cdnStr = res.CDN
	}

	techStr := "-"
	if len(res.Tech) > 0 {
		techStr = strings.Join(res.Tech, ",")
	}

	fmt.Printf("\x1b[1;32m[+]\x1b[0m \x1b[1;36m[sub]\x1b[0m %s \x1b[1;36m[ip]\x1b[0m %s \x1b[1;33m[title]\x1b[0m %s \x1b[1;35m[asn]\x1b[0m %s \x1b[1;33m[sc]\x1b[0m %s \x1b[1;34m[len]\x1b[0m %s \x1b[1;36m[server]\x1b[0m %s \x1b[1;32m[time]\x1b[0m %s \x1b[1;31m[cdn]\x1b[0m %s \x1b[1;35m[tech]\x1b[0m %s\n",
		res.Subdomain, ipStr, titleStr, asnStr, scStr, lenStr, svrStr, timeStr, cdnStr, techStr)
}

func statusColorCode(code int) int {
	switch {
	case code >= 200 && code < 300:
		return 32
	case code >= 300 && code < 400:
		return 33
	case code >= 400 && code < 500:
		return 31
	case code >= 500:
		return 35
	default:
		return 37
	}
}
