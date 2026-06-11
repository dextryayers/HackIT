package main

import (
	"fmt"
	"sync"
	"time"
)

// Advanced worker pool implementation using channels
type WorkerPool struct {
	NumWorkers int
	Jobs       chan string
	Results    chan string
	WG         sync.WaitGroup
}

func NewWorkerPool(workers int) *WorkerPool {
	return &WorkerPool{
		NumWorkers: workers,
		Jobs:       make(chan string, 1000),
		Results:    make(chan string, 100),
	}
}

func (p *WorkerPool) Start() {
	fmt.Printf("[GO-POOL] Spawning %d advanced goroutine workers...\n", p.NumWorkers)
	for w := 1; w <= p.NumWorkers; w++ {
		p.WG.Add(1)
		go p.worker(w)
	}
	// Drain Results channel in background to prevent deadlock
	go func() {
		for range p.Results {
			// consumed, not currently used for further processing
		}
	}()
}

func (p *WorkerPool) worker(id int) {
	defer p.WG.Done()
	for job := range p.Jobs {
		// Simulate computation
		time.Sleep(10 * time.Millisecond)
		if CrackPBKDF2(job) {
			p.Results <- job
			return
		}
	}
}

func (p *WorkerPool) Wait() {
	p.WG.Wait()
	close(p.Results)
}
