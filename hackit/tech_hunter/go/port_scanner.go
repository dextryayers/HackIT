package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

func ScanPorts(target string, ports []int, timeout time.Duration) []PortResult {
	var results []PortResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				mu.Lock()
				banner := ""
				// Try to grab banner
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				if n > 0 { banner = string(buf[:n]) }
				
				results = append(results, PortResult{
					Port:    p,
					Proto:   "tcp",
					Service: "Unknown",
					Banner:  banner,
				})
				mu.Unlock()
				conn.Close()
			}
		}(port)
	}
	wg.Wait()
	return results
}
