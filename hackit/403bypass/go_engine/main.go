// 403bypass engine — industrial-grade 403 / WAF bypass fuzzer.
//
// Protocol: one JSON object on stdout.
//
//	{"target":..., "waf":..., "baseline":{...}, "requested_status":...,
//	 "results":[...], "clusters":[...], "duration_ms":..., "version":...}
//
// Flags: -url -threads -timeout -insecure
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const engineVersion = "2.0.0"

const maxBodyBytes = 4 * 1024 * 1024 // hard cap per response to avoid memory blowup

// ---------- result types ----------

type Result struct {
	Payload    string  `json:"payload"`
	Type       string  `json:"type"`
	Method     string  `json:"method"`
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Length     int     `json:"length"`
	BodyHash   string  `json:"body_hash"`
	Title      string  `json:"title"`
	Location   string  `json:"location"`
	Server     string  `json:"server"`
	Duration   float64 `json:"duration_ms"`
	Error      string  `json:"error,omitempty"`
	SameAsBase bool    `json:"same_as_baseline"`
	Verdict    string  `json:"verdict"`
}

type Baseline struct {
	URL      string  `json:"url"`
	Status   int     `json:"status_code"`
	Length   int     `json:"length"`
	BodyHash string  `json:"body_hash"`
	Title    string  `json:"title"`
	Server   string  `json:"server"`
	FinalURL string  `json:"final_url"`
	Duration float64 `json:"duration_ms"`
	Error    string  `json:"error,omitempty"`
}

type Output struct {
	Target    string   `json:"target"`
	WAF       string   `json:"waf"`
	Baseline  Baseline `json:"baseline"`
	Requested string   `json:"requested_status"`
	Results   []Result `json:"results"`
	Clusters  []string `json:"clusters"`
	Duration  float64  `json:"duration_ms"`
	Version   string   `json:"version"`
}

// ---------- main ----------

func main() {
	targetURL := flag.String("url", "", "Target URL")
	threads := flag.Int("threads", 60, "Concurrent workers")
	timeout := flag.Int("timeout", 12, "Per-request timeout seconds")
	insecure := flag.Bool("insecure", true, "Accept invalid TLS")
	flag.Parse()

	if *targetURL == "" {
		emitError("Target URL required")
		return
	}
	u, err := url.Parse(*targetURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		emitError(fmt.Sprintf("Invalid URL: %v", err))
		return
	}

	client := buildClient(*insecure, *timeout)
	start := time.Now()

	base := fetchBaseline(client, *targetURL, *timeout)
	waf := detectWAF(base.Server)
	payloads := generatePayloads(u.Host, u.Path)
	results := runBypasses(client, *targetURL, payloads, *threads, *timeout)

	classify(results, base)
	sortResults(results)

	out := Output{
		Target:    *targetURL,
		WAF:       waf,
		Baseline:  base,
		Requested: statusClass(base.Status),
		Results:   results,
		Clusters:  clusterSignatures(results),
		Duration:  float64(time.Since(start).Microseconds()) / 1000.0,
		Version:   engineVersion,
	}
	j, _ := json.Marshal(out)
	fmt.Println(string(j))
}

func emitError(msg string) {
	j, _ := json.Marshal(map[string]string{"error": msg})
	fmt.Println(string(j))
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code == 401:
		return "401"
	case code == 403:
		return "403"
	case code == 404:
		return "404"
	case code >= 500:
		return "5xx"
	case code == 0:
		return "0"
	default:
		return fmt.Sprintf("%d", code)
	}
}

// ---------- http client ----------

func buildClient(insecure bool, timeoutSec int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // assessment tool
		MaxIdleConns:          400,
		MaxIdleConnsPerHost:   400,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(timeoutSec) * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ---------- single fetch ----------

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type fetchOut struct {
	status   int
	length   int
	hash     string
	title    string
	location string
	server   string
	finalURL string
	dur      float64
	err      string
}

func doFetch(client *http.Client, req *http.Request, timeoutSec int) fetchOut {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return fetchOut{err: err.Error(), dur: ms(started)}
	}
	defer resp.Body.Close()

	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if rerr != nil && len(body) == 0 {
		return fetchOut{status: resp.StatusCode, err: rerr.Error(), dur: ms(started)}
	}

	sum := sha256.Sum256(body)
	fo := fetchOut{
		status:   resp.StatusCode,
		length:   len(body),
		hash:     hex.EncodeToString(sum[:]),
		location: resp.Header.Get("Location"),
		server:   resp.Header.Get("Server"),
		dur:      ms(started),
	}
	if m := titleRe.FindSubmatch(body); len(m) == 2 {
		fo.title = strings.TrimSpace(strings.Join(strings.Fields(string(m[1])), " "))
		if len(fo.title) > 120 {
			fo.title = fo.title[:120]
		}
	}
	if resp.Request != nil && resp.Request.URL != nil {
		fo.finalURL = resp.Request.URL.String()
	}
	return fo
}

func ms(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

// ---------- baseline ----------

func fetchBaseline(client *http.Client, target string, timeoutSec int) Baseline {
	probe := target
	if u, err := url.Parse(target); err == nil {
		u.Path = "/" + randomSlug(10)
		u.RawQuery = ""
		u.Fragment = ""
		probe = u.String()
	}

	req, err := http.NewRequest("GET", probe, nil)
	if err != nil {
		return Baseline{URL: probe, Error: err.Error()}
	}
	req.Header.Set("User-Agent", browserUA())

	fo := doFetch(client, req, timeoutSec)
	return Baseline{
		URL:      probe,
		Status:   fo.status,
		Length:   fo.length,
		BodyHash: fo.hash,
		Title:    fo.title,
		Server:   fo.server,
		FinalURL: fo.finalURL,
		Duration: fo.dur,
		Error:    fo.err,
	}
}

// ---------- WAF fingerprint ----------

func detectWAF(server string) string {
	s := strings.ToLower(server)
	cases := []struct{ needle, name string }{
		{"cloudflare", "Cloudflare"},
		{"akamai", "Akamai"},
		{"awselb", "AWS ELB"},
		{"amazon", "AWS"},
		{"sucuri", "Sucuri"},
		{"incapsula", "Imperva Incapsula"},
		{"imperva", "Imperva"},
		{"big-ip", "F5 BIG-IP"},
		{"bigip", "F5 BIG-IP"},
		{"barracuda", "Barracuda"},
		{"fortiweb", "FortiWeb"},
		{"netscaler", "Citrix NetScaler"},
		{"citrix", "Citrix NetScaler"},
	}
	for _, c := range cases {
		if strings.Contains(s, c.needle) {
			return c.name
		}
	}
	if s == "" {
		return "Unknown"
	}
	return server
}

// ---------- helpers ----------

func randomSlug(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func browserUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

// ---------- request execution ----------

func runBypasses(client *http.Client, target string, payloads []Payload, threads, timeoutSec int) []Result {
	var (
		results []Result
		mu      sync.Mutex
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, threads)

	for _, pl := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			reqURL, method, headers, err := buildRequest(target, pl)
			if err != nil {
				mu.Lock()
				results = append(results, Result{
					Payload: headerDesc(pl), Type: pl.Type,
					Method: pl.Method, URL: target, Error: err.Error(), Verdict: "error",
				})
				mu.Unlock()
				return
			}

			var body io.Reader
			if pl.Body != "" {
				body = strings.NewReader(pl.Body)
			}
			req, err := http.NewRequest(method, reqURL, body)
			if err != nil {
				mu.Lock()
				results = append(results, Result{
					Payload: headerDesc(pl), Type: pl.Type,
					Method: method, URL: reqURL, Error: err.Error(), Verdict: "error",
				})
				mu.Unlock()
				return
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", browserUA())
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if pl.ContentType != "" {
				req.Header.Set("Content-Type", pl.ContentType)
			}

			fo := doFetch(client, req, timeoutSec)

			mu.Lock()
			results = append(results, Result{
				Payload:    headerDesc(pl),
				Type:       pl.Type,
				Method:     method,
				URL:        reqURL,
				StatusCode: fo.status,
				Length:     fo.length,
				BodyHash:   fo.hash,
				Title:      fo.title,
				Location:   fo.location,
				Server:     fo.server,
				Duration:   fo.dur,
				Error:      fo.err,
			})
			mu.Unlock()
		}(pl)
	}
	wg.Wait()
	return results
}

// buildRequest computes the final URL and method for a payload.
func buildRequest(target string, pl Payload) (reqURL, method string, headers map[string]string, err error) {
	method = pl.Method
	if method == "" {
		method = "GET"
	}
	headers = pl.Header

	u, perr := url.Parse(target)
	if perr != nil {
		return "", method, headers, perr
	}

	switch {
	case pl.PathOverride != "":
		// Rebuild the URL against host so Go doesn't re-encode the payload path.
		reqURL = u.Scheme + "://" + u.Host + pl.PathOverride
	case pl.Suffix != "":
		raw := strings.TrimSuffix(target, "/")
		if u.RawQuery != "" {
			raw = u.Scheme + "://" + u.Host + u.EscapedPath()
		}
		reqURL = raw + pl.Suffix
	default:
		reqURL = target
	}
	return reqURL, method, headers, nil
}

func headerDesc(pl Payload) string {
	parts := []string{}
	for k, v := range pl.Header {
		parts = append(parts, k+": "+v)
	}
	desc := pl.Type
	if len(parts) > 0 {
		desc += " [" + strings.Join(parts, "; ") + "]"
	}
	if pl.PathOverride != "" {
		desc += " [path: " + pl.PathOverride + "]"
	} else if pl.Suffix != "" {
		desc += " [suffix: " + pl.Suffix + "]"
	}
	return desc
}

// ---------- classification ----------

func classify(results []Result, base Baseline) {
	for i := range results {
		r := &results[i]
		switch {
		case r.Error != "":
			r.Verdict = "error"
		case r.StatusCode == 0:
			r.Verdict = "error"
		case base.BodyHash != "" && r.BodyHash == base.BodyHash:
			r.SameAsBase = true
			if r.StatusCode >= 200 && r.StatusCode < 300 {
				r.Verdict = "soft-200" // 200 with baseline body → custom error page
			} else {
				r.Verdict = "blocked"
			}
		case r.StatusCode >= 200 && r.StatusCode < 300:
			r.Verdict = "bypass"
		case r.StatusCode >= 300 && r.StatusCode < 400:
			r.Verdict = "redirect"
		case r.StatusCode == 401:
			r.Verdict = "auth-required"
		case r.StatusCode == 403:
			r.Verdict = "blocked"
		case r.StatusCode >= 500:
			r.Verdict = "error5xx"
		default:
			r.Verdict = "neutral"
		}
	}
}

// clusterSignatures groups results by status + body hash so noisy duplicates
// collapse into a single line in the report.
func clusterSignatures(results []Result) []string {
	seen := map[string]struct{}{}
	var clusters []string
	for _, r := range results {
		key := fmt.Sprintf("%d|%s", r.StatusCode, r.BodyHash)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		short := r.BodyHash
		if len(short) >= 8 {
			short = short[:8]
		}
		if short == "" {
			short = "nohash"
		}
		label := fmt.Sprintf("%d %s len=%d", r.StatusCode, short, r.Length)
		if r.Title != "" {
			label += " title=" + r.Title
		}
		clusters = append(clusters, label)
	}
	return clusters
}

func sortResults(results []Result) {
	rank := map[string]int{
		"bypass":        0,
		"redirect":      1,
		"neutral":       2,
		"soft-200":      3,
		"auth-required": 4,
		"blocked":       5,
		"error5xx":      6,
		"error":         7,
	}
	// Insertion sort is fine here (1200+ items × tiny constant).
	for i := 1; i < len(results); i++ {
		cur := results[i]
		j := i - 1
		for j >= 0 && rank[results[j].Verdict] > rank[cur.Verdict] {
			results[j+1] = results[j]
			j--
		}
		results[j+1] = cur
	}
}
