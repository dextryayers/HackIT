package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ProxyInfo struct {
	Addr      string
	Protocol  string
	Latency   time.Duration
	FailCount int
	MaxFails  int
	Alive     bool
	LastCheck time.Time
	Country   string
}

type ProxyRotator struct {
	mu             sync.RWMutex
	proxies        []ProxyInfo
	current        int
	checkInterval  time.Duration
}

func NewProxyRotator(interval time.Duration) *ProxyRotator {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ProxyRotator{
		checkInterval: interval,
	}
}

func (r *ProxyRotator) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open proxy file: %w", err)
	}
	defer f.Close()

	var list []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		list = append(list, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read proxy file: %w", err)
	}

	r.LoadFromList(list)
	return nil
}

func (r *ProxyRotator) LoadFromList(list []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.proxies = make([]ProxyInfo, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		proto := "socks5"
		addr := entry

		if strings.Contains(entry, "://") {
			parts := strings.SplitN(entry, "://", 2)
			if len(parts) == 2 {
				proto = parts[0]
				addr = parts[1]
			}
		}

		r.proxies = append(r.proxies, ProxyInfo{
			Addr:     addr,
			Protocol: proto,
			MaxFails: 3,
			Alive:    true,
		})
	}
}

func (r *ProxyRotator) Get() *ProxyInfo {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return nil
	}

	n := len(r.proxies)
	for i := 0; i < n; i++ {
		idx := (r.current + i) % n
		if r.proxies[idx].Alive {
			r.current = (idx + 1) % n
			return &r.proxies[idx]
		}
	}
	return nil
}

func (r *ProxyRotator) GetRandom() *ProxyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.proxies) == 0 {
		return nil
	}

	var alive []int
	for i, p := range r.proxies {
		if p.Alive {
			alive = append(alive, i)
		}
	}
	if len(alive) == 0 {
		return nil
	}

	idx := alive[rand.Intn(len(alive))]
	return &r.proxies[idx]
}

func (r *ProxyRotator) MarkFailed(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.proxies {
		if r.proxies[i].Addr == addr {
			r.proxies[i].FailCount++
			r.proxies[i].LastCheck = time.Now()
			if r.proxies[i].FailCount >= r.proxies[i].MaxFails {
				r.proxies[i].Alive = false
			}
			return
		}
	}
}

func (r *ProxyRotator) MarkSuccess(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.proxies {
		if r.proxies[i].Addr == addr {
			r.proxies[i].FailCount = 0
			r.proxies[i].Alive = true
			r.proxies[i].LastCheck = time.Now()
			return
		}
	}
}

func (r *ProxyRotator) HealthCheck(ctx context.Context) {
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runHealthCheck()
		}
	}
}

func (r *ProxyRotator) runHealthCheck() {
	r.mu.RLock()
	proxies := make([]ProxyInfo, len(r.proxies))
	copy(proxies, r.proxies)
	r.mu.RUnlock()

	for i, p := range proxies {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", p.Addr, 3*time.Second)
		if err != nil {
			r.mu.Lock()
			for j := range r.proxies {
				if r.proxies[j].Addr == p.Addr {
					r.proxies[j].FailCount++
					r.proxies[j].Latency = 0
					r.proxies[j].LastCheck = time.Now()
					if r.proxies[j].FailCount >= r.proxies[j].MaxFails {
						r.proxies[j].Alive = false
					}
				}
			}
			r.mu.Unlock()
			continue
		}

		latency := time.Since(start)
		connected := false

		if p.Protocol == "http" || p.Protocol == "https" {
			fmt.Fprintf(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
			resp := make([]byte, 1024)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			n, _ := conn.Read(resp)
			if n > 0 && strings.Contains(string(resp[:n]), "200") {
				connected = true
			}
		} else {
			connected = true
		}
		conn.Close()

		r.mu.Lock()
		for j := range r.proxies {
			if r.proxies[j].Addr == p.Addr {
				r.proxies[j].Latency = latency
				r.proxies[j].LastCheck = time.Now()
				if connected {
					r.proxies[j].Alive = true
					r.proxies[j].FailCount = 0
				} else {
					r.proxies[j].FailCount++
					if r.proxies[j].FailCount >= r.proxies[j].MaxFails {
						r.proxies[j].Alive = false
					}
				}
			}
		}
		r.mu.Unlock()

		_ = i
	}
}

func (r *ProxyRotator) AliveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, p := range r.proxies {
		if p.Alive {
			count++
		}
	}
	return count
}

func (r *ProxyRotator) All() []ProxyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ProxyInfo, len(r.proxies))
	copy(result, r.proxies)
	return result
}
