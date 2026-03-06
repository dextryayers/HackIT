package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"
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
	if len(results) == 0 {
		return
	}

	// Use Rust Batch Resolver for high-speed resolution
	if rustResolveDNSBatch != nil && rustResolveDNSBatch.Find() == nil {
		// Split results into chunks to avoid passing too large strings to FFI
		chunkSize := 500
		for i := 0; i < len(results); i += chunkSize {
			end := i + chunkSize
			if end > len(results) {
				end = len(results)
			}
			chunk := results[i:end]

			var subs []string
			for _, r := range chunk {
				subs = append(subs, r.Subdomain)
			}

			input := strings.Join(subs, ",") + "\x00"
			ptr, _, _ := rustResolveDNSBatch.Call(uintptr(unsafe.Pointer(&([]byte(input))[0])))
			if ptr != 0 {
				rustRes := string(CStrToGo(ptr))
				if rustRes != "" {
					// Parse result format: domain:ip1;ip2|domain:NOT_FOUND
					parts := strings.Split(rustRes, "|")
					resMap := make(map[string][]string)
					for _, p := range parts {
						kv := strings.Split(p, ":")
						if len(kv) == 2 {
							domain := kv[0]
							val := kv[1]
							if val != "NOT_FOUND" && val != "ERROR" {
								resMap[domain] = strings.Split(val, ";")
							}
						}
					}

					// Update results
					for _, r := range chunk {
						if ips, ok := resMap[r.Subdomain]; ok {
							r.IPs = ips
						}
					}
				}
			}
		}
	}

	// Fallback/Validation for anything still without IPs
	sem := make(chan bool, concurrency*5) // Increased fallback concurrency
	var wg sync.WaitGroup
	for _, r := range results {
		if len(r.IPs) > 0 {
			continue
		}
		wg.Add(1)
		sem <- true
		go func(res *Result) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second) // Faster timeout
			defer cancel()
			ips, err := net.DefaultResolver.LookupHost(ctx, res.Subdomain)
			if err == nil && len(ips) > 0 {
				res.IPs = ips
			}
		}(r)
	}
	wg.Wait()
}
