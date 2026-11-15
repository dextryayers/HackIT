// stresslab — scoped HTTP(S)/DNS/UDP load generator.
//
// Complements the C engines: HTTP/2 via net/http, verified TLS by default,
// persistent resolver and per-worker UDP sockets so the measured RTT is the
// network's and not a socket-pair syscall.
//
// -waf regenerates request identity per request (see waf.go).
// stdout: progress JSON lines, then one result JSON line.
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
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	hardMaxRPS      = 20000
	hardMaxWorkers  = 512
	hardMaxDuration = 1200 * time.Second
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

func newSampler(c int) *sampler {
	return &sampler{samples: make([]float64, 0, c), cap: c,
		rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (s *sampler) add(v float64) {
	s.mu.Lock()
	s.n++
	if len(s.samples) < s.cap {
		s.samples = append(s.samples, v)
	} else if i := s.rng.Int63n(s.n); i < int64(s.cap) {
		s.samples[i] = v
	}
	s.mu.Unlock()
}

func (s *sampler) snapshot() []float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]float64, len(s.samples))
	copy(out, s.samples)
	return out
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p / 100 * float64(len(sorted)-1)
	lo := int(idx)
	if lo+1 >= len(sorted) {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[lo+1]*frac
}

type progress struct {
	Type        string  `json:"type"`
	ElapsedS    float64 `json:"elapsed_s"`
	Requests    int64   `json:"requests"`
	OK          int64   `json:"ok"`
	Errors      int64   `json:"errors"`
	AchievedRPS float64 `json:"achieved_rps"`
}

type latency struct {
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

type report struct {
	Type        string  `json:"type"`
	Engine      string  `json:"engine"`
	Mode        string  `json:"mode"`
	Target      string  `json:"target"`
	Method      string  `json:"method,omitempty"`
	H2          int64   `json:"h2_responses,omitempty"`
	WAF         bool    `json:"waf,omitempty"`
	DurationS   float64 `json:"duration_s"`
	Requests    int64   `json:"requests"`
	OK          int64   `json:"ok"`
	Errors      int64   `json:"errors"`
	AchievedRPS float64 `json:"achieved_rps"`
	ErrorRate   float64 `json:"error_rate"`
	LatencyMS   latency `json:"latency_ms"`
}

func tokenSource(rps, ramp int, start time.Time, ctx context.Context) <-chan struct{} {
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
				if el := time.Since(start).Seconds(); el < float64(ramp) {
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

func startProgress(ms int, ctx context.Context, start time.Time, ok, er, req *int64) {
	if ms <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(time.Duration(ms) * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				el := time.Since(start).Seconds()
				if el <= 0 {
					continue
				}
				r := atomic.LoadInt64(req)
				_ = json.NewEncoder(os.Stdout).Encode(progress{
					Type: "progress", ElapsedS: el, Requests: r,
					OK: atomic.LoadInt64(ok), Errors: atomic.LoadInt64(er),
					AchievedRPS: float64(r) / el,
				})
			}
		}
	}()
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func finish(engine, mode, target, method string, waf bool, start time.Time,
	lat *sampler, ok, er *int64) {
	el := time.Since(start).Seconds()
	if el <= 0 {
		el = 1e-6
	}
	total := atomic.LoadInt64(ok) + atomic.LoadInt64(er)
	out := report{
		Type: "result", Engine: engine, Mode: mode, Target: target, Method: method,
		WAF: waf, DurationS: el, Requests: total,
		OK: atomic.LoadInt64(ok), Errors: atomic.LoadInt64(er),
		AchievedRPS: float64(total) / el,
	}
	if total > 0 {
		out.ErrorRate = float64(atomic.LoadInt64(er)) / float64(total)
	}
	s := lat.snapshot()
	sort.Float64s(s)
	out.LatencyMS = latency{
		P50: percentile(s, 50), P90: percentile(s, 90),
		P99: percentile(s, 99),
	}
	if len(s) > 0 {
		out.LatencyMS.Max = s[len(s)-1]
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

type netCfg struct {
	url, dnsServer, dnsName, dnsType, udpPayload string
	udpEcho                                      bool
	duration, workers, rps, ramp, progressMS     int
	waf                                          bool
}

func runNet(mode string, cfg netCfg) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.duration)*time.Second)
	defer cancel()
	start := time.Now()
	var ok, er, req int64
	lat := newSampler(sampleCap)
	tokens := tokenSource(cfg.rps, cfg.ramp, start, ctx)
	startProgress(cfg.progressMS, ctx, start, &ok, &er, &req)

	var probe func() (time.Duration, error)

	switch mode {
	case "dns":
		resolver := &net.Resolver{PreferGo: true}
		if cfg.dnsServer != "" {
			srv := cfg.dnsServer
			if !strings.Contains(srv, ":") {
				srv += ":53"
			}
			resolver.Dial = func(c context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(c, network, srv)
			}
		}
		probe = func() (time.Duration, error) {
			lc, c2 := context.WithTimeout(ctx, 2*time.Second)
			defer c2()
			t0 := time.Now()
			var err error
			switch cfg.dnsType {
			case "AAAA":
				_, err = resolver.LookupIP(lc, "ip6", cfg.dnsName)
			case "MX":
				_, err = resolver.LookupMX(lc, cfg.dnsName)
			case "TXT":
				_, err = resolver.LookupTXT(lc, cfg.dnsName)
			case "NS":
				_, err = resolver.LookupNS(lc, cfg.dnsName)
			default:
				_, err = resolver.LookupIP(lc, "ip4", cfg.dnsName)
			}
			return time.Since(t0), err
		}
	case "udp":
		raddr, err := net.ResolveUDPAddr("udp", cfg.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stresslab: bad udp target %q: %v\n", cfg.url, err)
			os.Exit(2)
		}
		payload := []byte(cfg.udpPayload)
		pool := make(chan *net.UDPConn, cfg.workers)
		probe = func() (time.Duration, error) {
			var conn *net.UDPConn
			select {
			case conn = <-pool:
			default:
				c, e := net.DialUDP("udp", nil, raddr)
				if e != nil {
					return 0, e
				}
				conn = c
			}
			conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			t0 := time.Now()
			if _, e := conn.Write(payload); e != nil {
				conn.Close()
				return time.Since(t0), e
			}
			if cfg.udpEcho {
				buf := make([]byte, len(payload))
				if _, e := conn.Read(buf); e != nil {
					conn.Close()
					return time.Since(t0), e
				}
			}
			select {
			case pool <- conn:
			default:
				conn.Close()
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
				rtt, err := probe()
				atomic.AddInt64(&req, 1)
				if err != nil {
					atomic.AddInt64(&er, 1)
					continue
				}
				lat.add(float64(rtt.Microseconds()) / 1000.0)
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	wg.Wait()

	label := cfg.dnsType
	if mode == "udp" {
		label = "ECHO"
		if !cfg.udpEcho {
			label = "SEND"
		}
	}
	finish("go", mode, cfg.url, label, cfg.waf, start, lat, &ok, &er)
}

func main() {
	urlFlag := flag.String("url", "", "target URL, http(s)://host[:port]/path")
	duration := flag.Int("duration", 10, "test duration in seconds")
	workers := flag.Int("workers", 10, "concurrent workers")
	rps := flag.Int("rps", 50, "global request rate cap")
	method := flag.String("method", "GET", "HTTP method, or MIXED to rotate")
	timeoutMS := flag.Int("timeout-ms", 5000, "per-request timeout in milliseconds")
	body := flag.String("body", "", "request body for POST/PUT/PATCH")
	ramp := flag.Int("ramp", 0, "seconds to linearly ramp 0 -> rps")
	forceClose := flag.Bool("close", false, "send Connection: close")
	progressMS := flag.Int("progress-ms", 500, "progress interval, 0 = silent")
	mode := flag.String("mode", "http", "engine mode: http | dns | udp")
	dnsServer := flag.String("dns-server", "", "DNS server host[:port]")
	dnsName := flag.String("dns-name", "", "name to resolve (dns mode)")
	dnsType := flag.String("dns-type", "A", "record type: A | AAAA | MX | TXT | NS")
	udpPayload := flag.String("udp-payload", "hackit-ddos-probe", "UDP payload")
	udpEcho := flag.Bool("udp-echo", true, "wait for echo (udp mode)")
	useWAF := flag.Bool("waf", false, "randomise request identity per request")
	flag.Parse()

	if *mode == "dns" {
		if *dnsName == "" {
			fmt.Fprintln(os.Stderr, "stresslab: -dns-name is required in dns mode")
			os.Exit(2)
		}
		*urlFlag = "dns://" + *dnsName
	} else if *mode == "udp" {
		if *urlFlag == "" {
			fmt.Fprintln(os.Stderr, "stresslab: -url host:port is required in udp mode")
			os.Exit(2)
		}
	} else if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "stresslab: -url is required")
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
	if *method == "" {
		*method = "GET"
	}

	if *mode == "dns" || *mode == "udp" {
		runNet(*mode, netCfg{
			url: *urlFlag, dnsServer: *dnsServer, dnsName: *dnsName,
			dnsType: strings.ToUpper(*dnsType), udpPayload: *udpPayload,
			udpEcho: *udpEcho, duration: *duration, workers: *workers,
			rps: *rps, ramp: *ramp, progressMS: *progressMS, waf: *useWAF,
		})
		return
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        *workers * 2,
		MaxIdleConnsPerHost: *workers * 2,
		MaxConnsPerHost:     *workers,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
		ReadBufferSize:      32 * 1024,
		WriteBufferSize:     32 * 1024,
	}
	client := &http.Client{Timeout: time.Duration(*timeoutMS) * time.Millisecond, Transport: transport}
	defer client.CloseIdleConnections()

	var ok, er, req, h2 int64
	lat := newSampler(sampleCap)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*duration)*time.Second)
	defer cancel()
	start := time.Now()
	tokens := tokenSource(*rps, *ramp, start, ctx)
	startProgress(*progressMS, ctx, start, &ok, &er, &req)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		w := i
		go func() {
			defer wg.Done()
			var waf *wafProfile
			if *useWAF {
				waf = newWAF(time.Now().UnixNano() + int64(w+1)*7919)
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-tokens:
				}

				m := *method
				if m == "MIXED" {
					m = mixedMethods[rand.Intn(len(mixedMethods))]
				}

				target := *urlFlag
				if waf != nil {
					if u, err := url.Parse(*urlFlag); err == nil {
						u.Path = waf.buildPath(u.Path)
						target = u.String()
					}
				}

				var bodyReader io.Reader
				if *body != "" && (m == "POST" || m == "PUT" || m == "PATCH") {
					bodyReader = strings.NewReader(*body)
				}
				reqObj, err := http.NewRequestWithContext(ctx, m, target, bodyReader)
				if err != nil {
					atomic.AddInt64(&req, 1)
					atomic.AddInt64(&er, 1)
					continue
				}
				if waf != nil {
					h := map[string]string{}
					waf.apply(h, !*forceClose)
					for k, v := range h {
						reqObj.Header.Set(k, v)
					}
				} else {
					reqObj.Header.Set("User-Agent", "hackit-ddos/3.0 (+authorized resilience testing)")
					if *forceClose {
						reqObj.Header.Set("Connection", "close")
					}
				}
				if bodyReader != nil {
					if strings.HasPrefix(strings.TrimSpace(*body), "{") {
						reqObj.Header.Set("Content-Type", "application/json")
					} else {
						reqObj.Header.Set("Content-Type", "text/plain; charset=utf-8")
					}
				}

				t0 := time.Now()
				resp, err := client.Do(reqObj)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					atomic.AddInt64(&req, 1)
					atomic.AddInt64(&er, 1)
					continue
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()

				if resp.ProtoMajor == 2 {
					atomic.AddInt64(&h2, 1)
				}
				lat.add(float64(time.Since(t0).Microseconds()) / 1000.0)
				atomic.AddInt64(&req, 1)
				if resp.StatusCode < 500 {
					atomic.AddInt64(&ok, 1)
				} else {
					atomic.AddInt64(&er, 1)
				}
			}
		}()
	}
	wg.Wait()

	finish("go", "http", *urlFlag, *method, *useWAF, start, lat, &ok, &er)
	fmt.Fprintf(os.Stderr, "h2-responses: %d\n", atomic.LoadInt64(&h2))
}