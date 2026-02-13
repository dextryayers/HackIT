package main

import (
	"fmt"
	"sync"
)

// runDeep handles recursive subdomain enumeration
func runDeep(foundSubs []*Result, config Config) {
	if config.Verbose {
		fmt.Println("[*] Starting Deep Recursive Scanning...")
	}

	// We'll take the subdomains found so far and use them as base for further active scanning
	// To avoid infinite loops, we only go 1 level deep by default
	
	jobs := make(chan string, config.Concurrency)
	var wgDeep sync.WaitGroup

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wgDeep.Add(1)
		go resolveWorker(jobs, &wgDeep, config.Verbose)
	}

	// For each found subdomain, try to find more subdomains under it
	// Using a small but effective wordlist for recursion
	recursiveWords := []string{
		"dev", "stg", "test", "api", "corp", "internal", "vpn", "mail",
		"www", "app", "stage", "prod", "beta", "admin", "portal",
	}

	for _, res := range foundSubs {
		// Only recurse on subdomains that resolved to something (more likely to have children)
		if len(res.IPs) > 0 {
			for _, w := range recursiveWords {
				jobs <- fmt.Sprintf("%s.%s", w, res.Subdomain)
			}
		}
	}

	close(jobs)
	wgDeep.Wait()
}
