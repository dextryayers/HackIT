package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

var (
	wildcardIPs = make(map[string]bool)
	wildcardMu  sync.RWMutex
)

// DetectWildcard checks if the domain has a wildcard DNS record
func DetectWildcard(domain string) {
	testSub := fmt.Sprintf("hackit-wildcard-%d.%s", rand.Intn(1000000), domain)
	ips, err := net.LookupHost(testSub)
	if err == nil && len(ips) > 0 {
		wildcardMu.Lock()
		for _, ip := range ips {
			wildcardIPs[ip] = true
		}
		wildcardMu.Unlock()
		fmt.Printf("[!] Wildcard DNS detected for %s: %v. Enabling smart filtering.\n", domain, ips)
	}
}

// IsWildcard checks if the IPs match a known wildcard record
func IsWildcard(ips []string) bool {
	wildcardMu.RLock()
	defer wildcardMu.RUnlock()
	if len(wildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if wildcardIPs[ip] {
			return true
		}
	}
	return false
}

// filterWildcards removes results that match wildcard IPs
func filterWildcards(results []*Result) []*Result {
	wildcardMu.RLock()
	hasWildcard := len(wildcardIPs) > 0
	wildcardMu.RUnlock()

	if !hasWildcard {
		return results
	}

	filtered := []*Result{}
	removedCount := 0
	for _, r := range results {
		if !IsWildcard(r.IPs) {
			filtered = append(filtered, r)
		} else {
			removedCount++
		}
	}
	if removedCount > 0 {
		fmt.Printf("[*] Filtered %d false positives (wildcard DNS matches).\n", removedCount)
	}
	return filtered
}

var publicResolvers = []string{
	"8.8.8.8:53",        // Google
	"8.8.4.4:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"1.0.0.1:53",        // Cloudflare
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"208.67.220.220:53", // OpenDNS
	"64.6.64.6:53",      // Verisign
	"64.6.65.6:53",      // Verisign
	"76.76.2.0:53",      // Alternate DNS
	"76.76.10.0:53",     // Alternate DNS
	"94.140.14.14:53",   // AdGuard
	"94.140.15.15:53",   // AdGuard
}

// resolveIPs resolves the IPs for a list of subdomains
func resolveIPs(results []*Result, concurrency int) {
	// Dynamically adjust concurrency for large scans
	actualConcurrency := concurrency
	if len(results) > 1000 {
		actualConcurrency = concurrency * 2
		if actualConcurrency > 1000 {
			actualConcurrency = 1000
		}
	}

	sem := make(chan bool, actualConcurrency)
	var wg sync.WaitGroup

	for _, r := range results {
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			// Try multiple resolvers with retries and increasing timeouts
			for i := 0; i < 6; i++ {
				resolverAddr := publicResolvers[rand.Intn(len(publicResolvers))]
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: time.Duration(3+i) * time.Second}
						return d.DialContext(ctx, "udp", resolverAddr)
					},
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(3+i)*time.Second)
				ips, err := resolver.LookupHost(ctx, res.Subdomain)
				cancel()

				if err == nil && len(ips) > 0 {
					res.IPs = ips
					break
				}
				// If it's a context timeout, maybe the resolver is slow or blocking
				time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
			}
		}(r)
	}
	wg.Wait()
}
