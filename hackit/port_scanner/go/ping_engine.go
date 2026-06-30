package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type PingResult struct {
	IP     string        `json:"ip"`
	Alive  bool          `json:"alive"`
	RTT    time.Duration `json:"rtt"`
	Method string        `json:"method"`
}

func PingICMP(host string, timeout time.Duration) PingResult {
	start := time.Now()
	ip := ResolveHost(host)
	if len(ip) == 0 {
		return PingResult{IP: host, Alive: false, Method: "icmp"}
	}
	target := ip[0]

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), target)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-t", fmt.Sprintf("%d", int(timeout.Seconds())), target)
	default:
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), target)
	}

	done := make(chan struct{})
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return PingResult{IP: target, Alive: false, Method: "icmp"}
	}

	go func() {
		cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout + time.Second):
		cmd.Process.Kill()
		<-done
		return PingResult{IP: target, Alive: false, RTT: time.Since(start), Method: "icmp"}
	}

	elapsed := time.Since(start)
	output := out.String()

	alive := false
	if runtime.GOOS == "windows" {
		alive = strings.Contains(output, "Reply from") || strings.Contains(output, "bytes=")
	} else {
		alive = strings.Contains(output, "1 received") || strings.Contains(output, "1 packets received")
		if !alive {
			alive = strings.Contains(output, "0% packet loss") && !strings.Contains(output, "100% packet loss")
		}
	}

	return PingResult{IP: target, Alive: alive, RTT: elapsed, Method: "icmp"}
}

func PingTCP(host string, port int, timeout time.Duration) PingResult {
	start := time.Now()
	ip := ResolveHost(host)
	if len(ip) == 0 {
		return PingResult{IP: host, Alive: false, Method: "tcp"}
	}
	target := ip[0]

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		return PingResult{IP: target, Alive: false, RTT: elapsed, Method: "tcp"}
	}
	conn.Close()
	return PingResult{IP: target, Alive: true, RTT: elapsed, Method: "tcp"}
}

func PingUDP(host string, port int, timeout time.Duration) PingResult {
	start := time.Now()
	ip := ResolveHost(host)
	if len(ip) == 0 {
		return PingResult{IP: host, Alive: false, Method: "udp"}
	}
	target := ip[0]

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "udp", addr)
	elapsed := time.Since(start)

	if err != nil {
		return PingResult{IP: target, Alive: false, RTT: elapsed, Method: "udp"}
	}
	conn.Close()
	// UDP dial success means the host is at least reachable
	return PingResult{IP: target, Alive: true, RTT: elapsed, Method: "udp"}
}

func DiscoverHosts(cidr string, method string, timeout time.Duration) []PingResult {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var results []PingResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	ones, bits := ipnet.Mask.Size()
	hostCount := 1 << uint(bits-ones)
	if hostCount > 65536 {
		hostCount = 65536
	}

	sem := make(chan struct{}, 256)

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		host := ip.String()
		if ip.Equal(net.IPv4(0, 0, 0, 0)) || ip.Equal(net.IPv4(255, 255, 255, 255)) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() { <-sem }()
			defer wg.Done()

			var pr PingResult
			switch method {
			case "icmp":
				pr = PingICMP(h, timeout)
			case "tcp":
				pr = PingTCP(h, 80, timeout)
			case "udp":
				pr = PingUDP(h, 53, timeout)
			default:
				pr = PingICMP(h, timeout)
			}

			mu.Lock()
			results = append(results, pr)
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	return results
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IsHostAlive(host string, method string) bool {
	var pr PingResult
	switch method {
	case "icmp":
		pr = PingICMP(host, 3*time.Second)
	case "tcp":
		pr = PingTCP(host, 80, 3*time.Second)
	case "udp":
		pr = PingUDP(host, 53, 3*time.Second)
	default:
		pr = PingICMP(host, 3*time.Second)
	}
	return pr.Alive
}
