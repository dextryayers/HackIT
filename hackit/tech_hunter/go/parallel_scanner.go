package main

import (
	"sync"
)

// ParallelScanner handles concurrent scanning of multiple discovered targets
func ParallelScanner(targets []string, opts *Options) []Result {
	results := make([]Result, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrency
	sem := make(chan struct{}, 10)

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := processTarget(t, opts)
			
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results
}
