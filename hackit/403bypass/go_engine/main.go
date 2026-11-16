// 403bypass engine — industrial-grade 403 / WAF authorization bypass fuzzer.
//
// Protocol: one JSON object on stdout.
//
//	{"target":..., "waf":..., "baselines":[...], "requested_status":...,
//	 "results":[...], "clusters":[...], "confirmed":[...], "duration_ms":...,
//	 "version":...}
//
// Flags: -url -threads -timeout -insecure -verify
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
	"sort"
	"strings"
	"sync"
	"time"
)

const engineVersion = "3.0.0"

const maxBodyBytes = 4 * 1024 * 1024

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
	Similarity float64 `json:"baseline_similarity"`
	Verdict    string  `json:"verdict"`
	Verified   bool    `json:"verified,omitempty"`

	shingles map[uint64]struct{} `json:"-"`
}

type Baseline struct {
	URL      string              `json:"url"`
	Status   int                 `json:"status_code"`
	Length   int                 `json:"length"`
	BodyHash string              `json:"body_hash"`
	Title    string              `json:"title"`
	Server   string              `json:"server"`
	FinalURL string              `json:"final_url"`
	Duration float64             `json:"duration_ms"`
	Error    string              `json:"error,omitempty"`
	Shingles map[uint64]struct{} `json:"-"`
}

type Confirmed struct {
	Method     string  `json:"method"`
	Payload    string  `json:"payload"`
	Type       string  `json:"type"`
	Status     int     `json:"status_code"`
	Length     int     `json:"length"`
	Title      string  `json:"title"`
	Similarity float64 `json:"baseline_similarity"`
}

type Output struct {
	Target    string      `json:"target"`
	WAF       string      `json:"waf"`
	Baselines []Baseline  `json:"baselines"`
	Requested string      `json:"requested_status"`
	Results   []Result    `json:"results"`
	Clusters  []string    `json:"clusters"`
	Confirmed []Confirmed `json:"confirmed"`
	Duration  float64     `json:"duration_ms"`
	Version   string      `json:"version"`
}

// ---------- main ----------

func main() {
	targetURL := flag.String("url", "", "Target URL")
	threads := flag.Int("threads", 60, "Concurrent workers")
	timeout := flag.Int("timeout", 12, "Per-request timeout seconds")
	insecure := flag.Bool("insecure", true, "Accept invalid TLS")
	verify := flag.Bool("verify", true, "Re-issue each 2xx candidate to confirm stability")
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

	baselines := fetchBaselines(client, *targetURL, *timeout)
	waf := detectWAF(firstServer(baselines))
	payloads := generatePayloads(u.Host, u.Path)
	results := runBypasses(client, *targetURL, payloads, *threads, *timeout)

	classifyAll(results, baselines)

	if *verify {
		verifyCandidates(client, results, baselines, *timeout)
	}

	sortResults(results)
	confirmed := collectConfirmed(results)

	out := Output{
		Target:    *targetURL,
		WAF:       waf,
		Baselines: baselines,
		Requested: statusClass(pickBaselineStatus(baselines)),
		Results:   results,
		Clusters:  clusterSignatures(results),
		Confirmed: confirmed,
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

func firstServer(bs []Baseline) string {
	for _, b := range bs {
		if b.Server != "" {
			return b.Server
		}
	}
	return ""
}

func pickBaselineStatus(bs []Baseline) int {
	for _, b := range bs {
		if b.URL == "original" {
			return b.Status
		}
	}
	if len(bs) > 0 {
		return bs[0].Status
	}
	return 0
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
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
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
	shingles map[uint64]struct{}
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
		shingles: shingle(body),
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

// ---------- body similarity ----------

// shingle converts the body into a set of trigram hashes after whitespace
// collapsing. Two responses with volatile tokens still produce the same set if
// the surrounding markup is identical.
func shingle(body []byte) map[uint64]struct{} {
	if len(body) == 0 {
		return nil
	}
	norm := normalizeBody(body)
	set := make(map[uint64]struct{}, len(norm)/4+1)
	for i := 0; i+3 <= len(norm); i++ {
		var h uint64 = 1469598103934665603
		for j := 0; j < 3; j++ {
			h ^= uint64(norm[i+j])
			h *= 1099511628211
		}
		set[h] = struct{}{}
	}
	return set
}

var wsRun = regexp.MustCompile(`\s+`)

func normalizeBody(body []byte) []byte {
	b := wsRun.ReplaceAll(body, []byte(" "))
	if len(b) > 200000 {
		b = b[:200000]
	}
	return b
}

func jaccard(a, b map[uint64]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		if len(a) == 0 && len(b) == 0 {
			return 1
		}
		return 0
	}
	inter := 0
	small, large := a, b
	if len(a) > len(b) {
		small, large = b, a
	}
	for k := range small {
		if _, ok := large[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// maxSimilarity returns how close a response is to any captured deny page.
func maxSimilarity(sh map[uint64]struct{}, bs []Baseline) float64 {
	best := 0.0
	for _, b := range bs {
		if b.Shingles == nil {
			continue
		}
		if s := jaccard(sh, b.Shingles); s > best {
			best = s
		}
	}
	return best
}

// ---------- baselines ----------

func fetchBaselines(client *http.Client, target string, timeoutSec int) []Baseline {
	out := []Baseline{}
	seen := map[string]struct{}{}

	capture := func(label, probe string) {
		if _, ok := seen[label]; ok {
			return
		}
		seen[label] = struct{}{}
		req, err := http.NewRequest("GET", probe, nil)
		if err != nil {
			out = append(out, Baseline{URL: label, Error: err.Error()})
			return
		}
		req.Header.Set("User-Agent", browserUA())
		fo := doFetch(client, req, timeoutSec)
		out = append(out, Baseline{
			URL: label, Status: fo.status, Length: fo.length, BodyHash: fo.hash,
			Title: fo.title, Server: fo.server, FinalURL: fo.finalURL,
			Duration: fo.dur, Error: fo.err, Shingles: fo.shingles,
		})
	}

	capture("original", target)

	if u, err := url.Parse(target); err == nil {
		for i := 0; i < 3; i++ {
			probe := *u
			probe.Path = "/" + randomSlug(10+i)
			probe.RawQuery = ""
			probe.Fragment = ""
			capture(fmt.Sprintf("random%d", i+1), probe.String())
		}
		// 404 fingerprint: a deep nested random path that almost certainly does
		// not exist.
		deep := *u
		deep.Path = "/" + randomSlug(6) + "/" + randomSlug(6) + "/" + randomSlug(6)
		deep.RawQuery = ""
		capture("deep404", deep.String())
	}
	return out
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
		{"azure", "Azure Front Door"},
		{"cloudfront", "AWS CloudFront"},
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
				shingles:   fo.shingles,
			})
			mu.Unlock()
		}(pl)
	}
	wg.Wait()
	return results
}

func buildRequest(target string, pl Payload) (reqURL, method string, headers map[string]string, err error) {
	method = pl.Method
	if method == "" {
		method = "GET"
	}
	headers = pl.Header
	if headers != nil {
		if at, ok := headers["__req_target"]; ok {
			delete(headers, "__req_target")
			return at, method, headers, nil
		}
	}

	u, perr := url.Parse(target)
	if perr != nil {
		return "", method, headers, perr
	}

	switch {
	case pl.PathOverride != "":
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
	keys := make([]string, 0, len(pl.Header))
	for k := range pl.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+": "+pl.Header[k])
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

const similarityThreshold = 0.85

func classifyAll(results []Result, bs []Baseline) {
	denyHashes := map[string]bool{}
	for _, b := range bs {
		if b.Status >= 400 && b.BodyHash != "" {
			denyHashes[b.BodyHash] = true
		}
	}

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != "":
			r.Verdict = "error"
			continue
		case r.StatusCode == 0:
			r.Verdict = "error"
			continue
		}

		sim := maxSimilarity(r.shingles, bs)
		r.Similarity = sim

		if denyHashes[r.BodyHash] {
			r.SameAsBase = true
			if r.StatusCode >= 200 && r.StatusCode < 300 {
				r.Verdict = "soft-200"
			} else {
				r.Verdict = "blocked"
			}
			continue
		}

		if r.StatusCode >= 200 && r.StatusCode < 300 {
			if sim >= similarityThreshold {
				// 2xx body nearly identical to the deny page → custom error.
				r.SameAsBase = true
				r.Verdict = "soft-200"
			} else if r.Length == 0 && r.Location == "" {
				r.Verdict = "neutral"
			} else {
				r.Verdict = "bypass"
			}
			continue
		}

		if r.StatusCode >= 300 && r.StatusCode < 400 {
			r.Verdict = "redirect"
			continue
		}
		if r.StatusCode == 401 {
			r.Verdict = "auth-required"
			continue
		}
		if r.StatusCode == 403 {
			r.Verdict = "blocked"
			if sim >= similarityThreshold {
				r.SameAsBase = true
			}
			continue
		}
		if r.StatusCode >= 500 {
			r.Verdict = "error5xx"
			continue
		}
		r.Verdict = "neutral"
	}
}

// verifyCandidates re-issues every 2xx/3xx bypass or redirect once so flapping
// servers don't inflate the result set.
func verifyCandidates(client *http.Client, results []Result, bs []Baseline, timeoutSec int) {
	var denySets []map[uint64]struct{}
	for _, b := range bs {
		if b.Shingles != nil && b.Status >= 400 {
			denySets = append(denySets, b.Shingles)
		}
	}

	for i := range results {
		r := &results[i]
		if r.Verdict != "bypass" && r.Verdict != "redirect" && r.Verdict != "soft-200" {
			continue
		}
		req, err := http.NewRequest(r.Method, r.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", browserUA())
		fo := doFetch(client, req, timeoutSec)
		if fo.err != "" {
			continue
		}
		// Treat as verified when the second attempt reaches the application
		// layer again (2xx/3xx) and the body is not the deny page.
		sim := 0.0
		for _, d := range denySets {
			if s := jaccard(fo.shingles, d); s > sim {
				sim = s
			}
		}
		if (fo.status >= 200 && fo.status < 400) && sim < similarityThreshold {
			r.Verified = true
		}
	}
}

// ---------- aggregation ----------

func collectConfirmed(results []Result) []Confirmed {
	out := []Confirmed{}
	for _, r := range results {
		if r.Verdict != "bypass" && r.Verdict != "redirect" {
			continue
		}
		if r.Verified || r.Verdict == "bypass" {
			out = append(out, Confirmed{
				Method:     r.Method,
				Payload:    r.Payload,
				Type:       r.Type,
				Status:     r.StatusCode,
				Length:     r.Length,
				Title:      r.Title,
				Similarity: r.Similarity,
			})
		}
	}
	return out
}

func clusterSignatures(results []Result) []string {
	type cluster struct {
		status int
		hash   string
		length int
		title  string
		count  int
	}
	index := map[string]*cluster{}
	var order []string
	for _, r := range results {
		if r.BodyHash == "" {
			continue
		}
		key := fmt.Sprintf("%d|%s", r.StatusCode, r.BodyHash)
		c, ok := index[key]
		if !ok {
			c = &cluster{status: r.StatusCode, hash: r.BodyHash, length: r.Length, title: r.Title}
			index[key] = c
			order = append(order, key)
		}
		c.count++
	}

	out := make([]string, 0, len(order))
	for _, key := range order {
		c := index[key]
		short := c.hash
		if len(short) >= 8 {
			short = short[:8]
		}
		label := fmt.Sprintf("%d %s len=%d x%d", c.status, short, c.length, c.count)
		if c.title != "" {
			label += " title=" + c.title
		}
		out = append(out, label)
	}
	return out
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
