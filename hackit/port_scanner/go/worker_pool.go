package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ScanJob struct {
	Port  int
	Host  string
	Index int
}

type WorkerResult struct {
	Port      int    `json:"port"`
	State     int    `json:"state"`
	Err       string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

type WorkerPool struct {
	jobs    chan ScanJob
	results chan WorkerResult
	quit    chan struct{}
	wg      sync.WaitGroup
	counter int64
	timeout time.Duration
	verbose bool
}

func NewWorkerPool(numWorkers int, queueSize int, timeoutMs int, verbose bool) *WorkerPool {
	wp := &WorkerPool{
		jobs:    make(chan ScanJob, queueSize),
		results: make(chan WorkerResult, queueSize),
		quit:    make(chan struct{}),
		timeout: time.Duration(timeoutMs) * time.Millisecond,
		verbose: verbose,
	}
	for i := 0; i < numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
	return wp
}

func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	for {
		select {
		case job := <-wp.jobs:
			result := wp.scanPort(job.Host, job.Port)
			wp.results <- result
			atomic.AddInt64(&wp.counter, 1)
		case <-wp.quit:
			return
		}
	}
}

func (wp *WorkerPool) scanPort(host string, port int) WorkerResult {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, wp.timeout)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return WorkerResult{
			Port:      port,
			State:     0,
			LatencyMs: latency,
		}
	}
	conn.SetDeadline(time.Now().Add(wp.timeout / 2))
	conn.Close()
	return WorkerResult{
		Port:      port,
		State:     1,
		LatencyMs: latency,
	}
}

func (wp *WorkerPool) Submit(host string, port int) {
	wp.jobs <- ScanJob{
		Port: port,
		Host: host,
	}
}

func (wp *WorkerPool) Results() chan WorkerResult {
	return wp.results
}

func (wp *WorkerPool) Completed() int64 {
	return atomic.LoadInt64(&wp.counter)
}

func (wp *WorkerPool) Stop() {
	close(wp.quit)
	wp.wg.Wait()
	close(wp.results)
}

func (wp *WorkerPool) SubmitBatch(host string, ports []int) {
	for _, port := range ports {
		wp.Submit(host, port)
	}
}

func (wp *WorkerPool) RunBatch(host string, ports []int) []WorkerResult {
	go wp.SubmitBatch(host, ports)
	var results []WorkerResult
	for i := 0; i < len(ports); i++ {
		r := <-wp.results
		results = append(results, r)
	}
	return results
}

type AdaptivePool struct {
	WorkerPool
	minWorkers int
	maxWorkers int
	currentWorkers int32
	loadFactor float64
}

func NewAdaptivePool(minW, maxW, timeoutMs int) *AdaptivePool {
	ap := &AdaptivePool{
		minWorkers:      minW,
		maxWorkers:      maxW,
		currentWorkers:  int32(minW),
		loadFactor:      1.0,
	}
	wp := NewWorkerPool(minW, maxW*100, timeoutMs, false)
	ap.WorkerPool = *wp
	return ap
}

func ParsePorts(spec string) []int {
	var ports []int
	switch spec {
	case "all":
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports
	case "top100":
		top := []int{7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,
			135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
			554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,
			1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,
			4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,
			5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
			9999,10000,32768,49152,49154}
		return top
	}
	buf := []byte(spec)
	token := make([]byte, 0, len(buf))
	for i := 0; i <= len(buf); i++ {
		if i == len(buf) || buf[i] == ',' {
			if len(token) == 0 {
				continue
			}
			s := string(token)
			var start, end int
			if n, _ := fmt.Sscanf(s, "%d-%d", &start, &end); n == 2 {
				if start < 1 { start = 1 }
				if end > 65535 { end = 65535 }
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			} else if p, err := fmt.Sscanf(s, "%d", &start); p == 1 && err == nil {
				if start >= 1 && start <= 65535 {
					ports = append(ports, start)
				}
			}
			token = token[:0]
		} else {
			token = append(token, buf[i])
		}
	}
	return ports
}
