// stresslab-go — scoped HTTP(S) load generator for authorized resilience testing.
// Standard library only. No spoofing, no amplification, no evasion: it is a
// measurement tool, not an attack kit. The caller (hackit ddos) enforces
// authorization and caps before this binary ever runs.
//
// Wire protocol on stdout: progress lines {"type":"progress",...} every
// -progress-ms milliseconds, then one final {"type":"result",...} object.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	hardMaxRPS      = 10000
	hardMaxWorkers  = 256
	hardMaxDuration = 600 * time.Second
	sampleCap       = 100000
)

var mixedMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

type sampler struct {
	mu      sync.Mutex
	n       int64
	samples []float64
	cap     int
	rng     *rand.Rand
}

func newSampler(cap int) *sampler {
	return &sampler{samples: make([]float64, 0, cap), cap: cap, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (s *sampler) add(v float64) {
	s.mu.Lock()
	s.n++
	if len(s.samples) < s.cap {
		s.samples = append(s.samples, v)
	} else {
		i := s.rng.Int63n(s.n)
		if i < int64(s.cap) {
			s.samples[i] = v
		}
	}
	s.mu.Unlock()
}

func (s *sampler) percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p / 100 * float64(len(sorted)-1)
	lo := int(idx)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func (s *sampler) snapshot() []float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]float64, len(s.samples))
	copy(out, s.samples)
	return out
}

type progress struct {
	Type      string  `json:"type"`
	ElapsedS  float64 `json:"elapsed_s"`
	Requests  int64   `json:"requests"`
	OK        int64   `json:"ok"`
	Errors    int64   `json:"errors"`
	AchievedRPS float64 `json:"achieved_rps"`
}

type report struct {
	Type        string  `json:"type"`
	Engine      string  `json:"engine"`
	Mode        string  `json:"mode"`
	Target      string  `json:"target"`
	Method      string  `json:"method,omitempty"`
	DurationS   float64 `json:"duration_s"`
	Requests    int64   `json:"requests"`
	OK          int64   `json:"ok"`
	Errors      int64   `json:"errors"`
	AchievedRPS float64 `json:"achieved_rps"`
	ErrorRate   float64 `json:"error_rate"`
	LatencyMS   struct {
		P50 float64 `json:"p50"`
		P90 float64 `json:"p90"`
		P99 float64 `json:"p99"`
		Max float64 `json:"max"`
	} `json:"latency_ms"`
}

type netModeConfig struct {
	url, dnsServer, dnsName, dnsType string
	udpPayload                       string
	udpEcho                          bool
	duration, workers, rps, ramp     int
	progressMS                       int
	start                            time.Time
	hardMaxDuration                  time.Duration
}

func newTokenSource(rps, ramp int, start time.Time, ctx context.Context) <-chan struct{} {
	tokens := make(chan struct{}, max64(1, int64(rps)/10))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rate := float64(rps)
			if ramp > 0 {
				el := time.Since(start).Seconds()
				if el < float64(ramp) {
					rate = rate * el / float64(ramp)
					if rate < 1 {
						rate = 1
					}
				}
			}
			interval := time.Duration(float64(time.Second) / rate)
			if interval < time.Microsecond {
				interval = time.Microsecond
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				select {
				case tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return tokens
}

func startProgress(progressMS int, ctx context.Context, start time.Time,
	okCount, errCount, reqCount *int64) {
	if progressMS <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Duration(progressMS) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(start).Seconds()
				if elapsed <= 0 {
					continue
				}
				req := atomic.LoadInt64(reqCount)
				p := progress{Type: "progress", ElapsedS: elapsed, Requests: req,
					OK: atomic.LoadInt64(okCount), Errors: atomic.LoadInt64(errCount),
					AchievedRPS: float64(req) / elapsed}
				_ = json.NewEncoder(os.Stdout).Encode(p)
			}
		}
	}()
}

func finishReport(engine, mode, target, method string, start time.Time,
	lat *sampler, okCount, errCount *int64) {
	elapsed := time.Since(start).Seconds()
	total := atomic.LoadInt64(okCount) + atomic.LoadInt64(errCount)
	out := report{
		Type: "result", Engine: engine, Mode: mode, Target: target, Method: method,
		DurationS: elapsed, Requests: total,
		OK: atomic.LoadInt64(okCount), Errors: atomic.LoadInt64(errCount),
		AchievedRPS: float64(total) / elapsed,
	}
	if total > 0 {
		out.ErrorRate = float64(atomic.LoadInt64(errCount)) / float64(total)
	}
	samples := lat.snapshot()
	sort.Float64s(samples)
	out.LatencyMS.P50 = lat.percentile(samples, 50)
	out.LatencyMS.P90 = lat.percentile(samples, 90)
	out.LatencyMS.P99 = lat.percentile(samples, 99)
	if len(samples) > 0 {
		out.LatencyMS.Max = samples[len(samples)-1]
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func runNetMode(mode string, cfg netModeConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.duration)*time.Second)
	defer cancel()
	start := time.Now()
	var okCount, errCount, reqCount int64
	lat := newSampler(sampleCap)

	tokens := newTokenSource(cfg.rps, cfg.ramp, start, ctx)
	startProgress(cfg.progressMS, ctx, start, &okCount, &errCount, &reqCount)

	var dial func() (time.Duration, error)
	switch mode {
	case "dns":
		dial = func() (time.Duration, error) {
			resolver := &net.Resolver{PreferGo: true}
			if cfg.dnsServer != "" {
				server := cfg.dnsServer
				if !strings.Contains(server, ":") {
					server += ":53"
				}
				resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, network, server)
				}
			}
			lookupCtx, cancel2 := context.WithTimeout(ctx, 2*time.Second)
			defer cancel2()
			t0 := time.Now()
			var err error
			switch cfg.dnsType {
			case "AAAA":
				_, err = resolver.LookupIP(lookupCtx, "ip6", cfg.dnsName)
			case "MX":
				_, err = resolver.LookupMX(lookupCtx, cfg.dnsName)
			case "TXT":
				_, err = resolver.LookupTXT(lookupCtx, cfg.dnsName)
			case "NS":
				_, err = resolver.LookupNS(lookupCtx, cfg.dnsName)
			default:
				_, err = resolver.LookupIP(lookupCtx, "ip4", cfg.dnsName)
			}
			return time.Since(t0), err
		}
	case "udp":
		raddr, err := net.ResolveUDPAddr("udp", cfg.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stresslab-go: bad udp target %q: %v\n", cfg.url, err)
			os.Exit(2)
		}
		payload := []byte(cfg.udpPayload)
		dial = func() (time.Duration, error) {
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				return 0, err
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			t0 := time.Now()
			if _, werr := conn.Write(payload); werr != nil {
				return time.Since(t0), werr
			}
			if cfg.udpEcho {
				buf := make([]byte, len(payload))
				if _, rerr := conn.Read(buf); rerr != nil {
					return time.Since(t0), rerr
				}
			}
			return time.Since(t0), nil
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tokens:
				}
				rtt, err := dial()
				atomic.AddInt64(&reqCount, 1)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				lat.add(float64(rtt.Microseconds()) / 1000.0)
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	methodLabel := cfg.dnsType
	if mode == "udp" {
		methodLabel = "ECHO"
		if !cfg.udpEcho {
			methodLabel = "SEND"
		}
	}
	finishReport("go", mode, cfg.url, methodLabel, start, lat, &okCount, &errCount)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func main() {
	url := flag.String("url", "", "target URL, http(s)://host[:port]/path")
	duration := flag.Int("duration", 10, "test duration in seconds")
	workers := flag.Int("workers", 10, "concurrent workers")
	rps := flag.Int("rps", 50, "global request rate cap (requests/second)")
	method := flag.String("method", "GET", "HTTP method, or MIXED for a rotating set")
	timeoutMS := flag.Int("timeout-ms", 5000, "per-request timeout in milliseconds")
	body := flag.String("body", "", "request body for POST/PUT/PATCH (default empty)")
	ramp := flag.Int("ramp", 0, "seconds to linearly ramp 0 -> rps (0 = steady rate)")
	forceClose := flag.Bool("close", false, "send Connection: close instead of keep-alive")
	progressMS := flag.Int("progress-ms", 500, "progress line interval in milliseconds (0 = silent)")
	mode := flag.String("mode", "http", "engine mode: http | dns | udp")
	dnsServer := flag.String("dns-server", "", "DNS server host[:port] (default: system resolver)")
	dnsName := flag.String("dns-name", "", "name to resolve (dns mode)")
	dnsType := flag.String("dns-type", "A", "record type: A | AAAA | MX | TXT | NS")
	udpPayload := flag.String("udp-payload", "hackit-ddos-probe", "UDP payload bytes")
	udpEcho := flag.Bool("udp-echo", true, "wait for an echo reply (udp mode); false = fire-and-forget send rate")
	flag.Parse()

	if *mode == "dns" {
		if *dnsName == "" {
			fmt.Fprintln(os.Stderr, "stresslab-go: -dns-name is required in dns mode")
			os.Exit(2)
		}
		*url = "dns://" + *dnsName
	} else if *mode == "udp" {
		if *url == "" {
			fmt.Fprintln(os.Stderr, "stresslab-go: -url host:port is required in udp mode")
			os.Exit(2)
		}
	} else if *url == "" {
		fmt.Fprintln(os.Stderr, "stresslab-go: -url is required")
		os.Exit(2)
	}
	if *duration < 1 {
		*duration = 1
	}
	if time.Duration(*duration)*time.Second > hardMaxDuration {
		*duration = int(hardMaxDuration / time.Second)
	}
	if *workers < 1 {
		*workers = 1
	}
	if *workers > hardMaxWorkers {
		*workers = hardMaxWorkers
	}
	if *rps < 1 {
		*rps = 1
	}
	if *rps > hardMaxRPS {
		*rps = hardMaxRPS
	}
	*method = strings.ToUpper(strings.TrimSpace(*method))
	if *method != "MIXED" && *method == "" {
		*method = "GET"
	}

	if *mode == "dns" || *mode == "udp" {
		runNetMode(*mode, netModeConfig{
			url: *url, dnsServer: *dnsServer, dnsName: *dnsName, dnsType: strings.ToUpper(*dnsType),
			udpPayload: *udpPayload, udpEcho: *udpEcho,
			duration: *duration, workers: *workers, rps: *rps,
			ramp: *ramp, progressMS: *progressMS,
			start: time.Now(), hardMaxDuration: hardMaxDuration,
		})
		return
	}

	client := &http.Client{
		Timeout: time.Duration(*timeoutMS) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        *workers * 2,
			MaxIdleConnsPerHost: *workers * 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	defer client.CloseIdleConnections()

	var okCount, errCount, reqCount int64
	lat := newSampler(sampleCap)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*duration)*time.Second)
	defer cancel()

	start := time.Now()

	// Rate source: one token per slot. With -ramp the effective rate climbs
	// linearly from ~1 rps to the cap over the ramp window.
	tokens := make(chan struct{}, max64(1, int64(*rps)/10))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rate := float64(*rps)
			if *ramp > 0 {
				el := time.Since(start).Seconds()
				if el < float64(*ramp) {
					rate = rate * el / float64(*ramp)
					if rate < 1 {
						rate = 1
					}
				}
			}
			interval := time.Duration(float64(time.Second) / rate)
			if interval < time.Microsecond {
				interval = time.Microsecond
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				select {
				case tokens <- struct{}{}:
				default: // bucket full; drop the token rather than burst
				}
			}
		}
	}()

	// Progress monitor: periodic JSON lines on stdout.
	if *progressMS > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(*progressMS) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					elapsed := time.Since(start).Seconds()
					if elapsed <= 0 {
						continue
					}
					req := atomic.LoadInt64(&reqCount)
					p := progress{
						Type:        "progress",
						ElapsedS:    elapsed,
						Requests:    req,
						OK:          atomic.LoadInt64(&okCount),
						Errors:      atomic.LoadInt64(&errCount),
						AchievedRPS: float64(req) / elapsed,
					}
					_ = json.NewEncoder(os.Stdout).Encode(p)
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID+1)*7919))
			for {
				select {
				case <-ctx.Done():
					return
				case <-tokens:
				}

				m := *method
				if m == "MIXED" {
					m = mixedMethods[rng.Intn(len(mixedMethods))]
				}

				var bodyReader io.Reader
				if *body != "" && (m == "POST" || m == "PUT" || m == "PATCH") {
					bodyReader = strings.NewReader(*body)
				}
				req, err := http.NewRequestWithContext(ctx, m, *url, bodyReader)
				if err != nil {
					atomic.AddInt64(&reqCount, 1)
					atomic.AddInt64(&errCount, 1)
					continue
				}
				req.Header.Set("User-Agent", "hackit-ddos/1.0 (+authorized resilience testing)")
				if *forceClose {
					req.Header.Set("Connection", "close")
				} else {
					req.Header.Set("Connection", "keep-alive")
				}
				if bodyReader != nil {
					if strings.HasPrefix(strings.TrimSpace(*body), "{") || strings.HasPrefix(strings.TrimSpace(*body), "[") {
						req.Header.Set("Content-Type", "application/json")
					} else {
						req.Header.Set("Content-Type", "text/plain; charset=utf-8")
					}
				}

				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					atomic.AddInt64(&reqCount, 1)
					atomic.AddInt64(&errCount, 1)
					continue
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()

				elapsed := float64(time.Since(t0).Microseconds()) / 1000.0
				lat.add(elapsed)
				atomic.AddInt64(&reqCount, 1)
				if resp.StatusCode < 500 {
					atomic.AddInt64(&okCount, 1)
				} else {
					atomic.AddInt64(&errCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	total := atomic.LoadInt64(&okCount) + atomic.LoadInt64(&errCount)
	out := report{
		Type:        "result",
		Engine:      "go",
		Mode:        "http",
		Target:      *url,
		Method:      *method,
		DurationS:   elapsed,
		Requests:    total,
		OK:          atomic.LoadInt64(&okCount),
		Errors:      atomic.LoadInt64(&errCount),
		AchievedRPS: float64(total) / elapsed,
	}
	if total > 0 {
		out.ErrorRate = float64(atomic.LoadInt64(&errCount)) / float64(total)
	}

	samples := lat.snapshot()
	sort.Float64s(samples)
	out.LatencyMS.P50 = lat.percentile(samples, 50)
	out.LatencyMS.P90 = lat.percentile(samples, 90)
	out.LatencyMS.P99 = lat.percentile(samples, 99)
	if len(samples) > 0 {
		out.LatencyMS.Max = samples[len(samples)-1]
	}

	_ = json.NewEncoder(os.Stdout).Encode(out)
}
