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
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
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
	mu             sync.Mutex
	jobs           chan ScanJob
	results        chan WorkerResult
	quit           chan struct{}
	workerQuit     chan struct{}
	wg             sync.WaitGroup
	managerWg      sync.WaitGroup
	counter        int64
	timeout        time.Duration
	minWorkers     int
	maxWorkers     int
	currentWorkers int32
	targetWorkers  int32
	backlogHigh    int
	backlogLow     int
	lastScaleTime  time.Time
	scaleCooldown  time.Duration
	verbose        bool
}

func NewAdaptivePool(minW, maxW, timeoutMs int) *AdaptivePool {
	ap := &AdaptivePool{
		jobs:          make(chan ScanJob, maxW*100),
		results:       make(chan WorkerResult, maxW*100),
		quit:          make(chan struct{}),
		workerQuit:    make(chan struct{}, maxW*2),
		minWorkers:    minW,
		maxWorkers:    maxW,
		currentWorkers: int32(minW),
		targetWorkers:  int32(minW),
		timeout:       time.Duration(timeoutMs) * time.Millisecond,
		backlogHigh:   maxW * 10,
		backlogLow:    maxW,
		scaleCooldown: 2 * time.Second,
		verbose:       false,
	}

	for i := 0; i < minW; i++ {
		ap.wg.Add(1)
		go ap.worker(i)
	}

	ap.managerWg.Add(1)
	go ap.manager()

	return ap
}

func (ap *AdaptivePool) worker(id int) {
	defer ap.wg.Done()
	for {
		select {
		case job := <-ap.jobs:
			result := ap.scanPort(job.Host, job.Port)
			ap.results <- result
			atomic.AddInt64(&ap.counter, 1)
		case <-ap.workerQuit:
			return
		case <-ap.quit:
			return
		}
	}
}

func (ap *AdaptivePool) manager() {
	defer ap.managerWg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ap.adjustWorkers()
		case <-ap.quit:
			return
		}
	}
}

func (ap *AdaptivePool) adjustWorkers() {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	backlog := len(ap.jobs)
	current := atomic.LoadInt32(&ap.currentWorkers)
	target := current

	if backlog > ap.backlogHigh && current < int32(ap.maxWorkers) {
		scaleBy := (backlog / ap.backlogHigh) + 1
		if scaleBy > 10 {
			scaleBy = 10
		}
		target = current + int32(scaleBy)
		if target > int32(ap.maxWorkers) {
			target = int32(ap.maxWorkers)
		}
	} else if backlog < ap.backlogLow && current > int32(ap.minWorkers) {
		if time.Since(ap.lastScaleTime) > ap.scaleCooldown {
			target = current - 1
			if target < int32(ap.minWorkers) {
				target = int32(ap.minWorkers)
			}
		}
	}

	if target > current {
		ap.lastScaleTime = time.Now()
		atomic.StoreInt32(&ap.targetWorkers, target)
		for i := current; i < target; i++ {
			ap.wg.Add(1)
			go ap.worker(int(i))
		}
		atomic.StoreInt32(&ap.currentWorkers, target)
		if ap.verbose && target > current {
			fmt.Fprintf(nil, "[adaptive] scaled up: %d → %d (backlog: %d)\n", current, target, backlog)
		}
	} else if target < current {
		ap.lastScaleTime = time.Now()
		shrink := current - target
		for i := int32(0); i < shrink; i++ {
			ap.workerQuit <- struct{}{}
		}
		atomic.StoreInt32(&ap.currentWorkers, target)
		atomic.StoreInt32(&ap.targetWorkers, target)
	}
}

func (ap *AdaptivePool) scanPort(host string, port int) WorkerResult {
	start := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, ap.timeout)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return WorkerResult{
			Port:      port,
			State:     0,
			LatencyMs: latency,
		}
	}
	conn.SetDeadline(time.Now().Add(ap.timeout / 2))
	conn.Close()
	return WorkerResult{
		Port:      port,
		State:     1,
		LatencyMs: latency,
	}
}

func (ap *AdaptivePool) Submit(host string, port int) {
	ap.jobs <- ScanJob{Port: port, Host: host}
}

func (ap *AdaptivePool) Results() chan WorkerResult {
	return ap.results
}

func (ap *AdaptivePool) Completed() int64 {
	return atomic.LoadInt64(&ap.counter)
}

func (ap *AdaptivePool) Stop() {
	close(ap.quit)
	ap.managerWg.Wait()
	close(ap.workerQuit)
	ap.wg.Wait()
	close(ap.results)
}

func (ap *AdaptivePool) SubmitBatch(host string, ports []int) {
	for _, port := range ports {
		ap.Submit(host, port)
	}
}

func (ap *AdaptivePool) RunBatch(host string, ports []int) []WorkerResult {
	go ap.SubmitBatch(host, ports)
	var results []WorkerResult
	for i := 0; i < len(ports); i++ {
		r := <-ap.results
		results = append(results, r)
	}
	return results
}

func (ap *AdaptivePool) Backlog() int {
	return len(ap.jobs)
}

func (ap *AdaptivePool) Workers() int {
	return int(atomic.LoadInt32(&ap.currentWorkers))
}

func (ap *AdaptivePool) SetVerbose(v bool) {
	ap.verbose = v
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
