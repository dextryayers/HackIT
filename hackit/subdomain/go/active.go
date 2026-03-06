package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"unsafe"
)

func runActive(config Config, jobs chan string) {
	if config.Verbose {
		fmt.Println("[*] Running Active Brute Force...")
	}

	// 1. Wildcard Detection
	randName := fmt.Sprintf("hackit-%d.%s", rand.Intn(999999), config.Domain)
	_, err := net.LookupHost(randName)
	if err == nil {
		if config.Verbose {
			fmt.Println("[!] Wildcard DNS detected! Active brute force might produce false positives.")
		}
	}

	// 2. Load Wordlist
	if config.Wordlist != "" {
		count := loadWordlist(config.Wordlist, config.Domain, jobs)
		if config.Verbose {
			fmt.Printf("[*] Loaded %d words from wordlist\n", count)
		}
	} else {
		if config.Verbose {
			fmt.Println("[*] No wordlist provided, skipping brute force. Relying on OSINT.")
		}
	}
}

func loadWordlist(path string, domain string, jobs chan<- string) int {
	file, err := os.Open(path)
	if err != nil {
		if true { // specific error, maybe always show?
			fmt.Printf("[!] Could not open wordlist: %v\n", err)
		}
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			sub := fmt.Sprintf("%s.%s", word, domain)
			jobs <- sub
			count++
		}
	}
	return count
}

func resolveWorker(jobs chan string, wg *sync.WaitGroup, verbose bool, domain string, recursive bool) {
	defer wg.Done()

	// Track seen subdomains for recursive scanning to avoid loops
	seen := make(map[string]struct{})
	var seenMu sync.Mutex

	for sub := range jobs {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}

		seenMu.Lock()
		if _, ok := seen[sub]; ok {
			seenMu.Unlock()
			continue
		}
		seen[sub] = struct{}{}
		seenMu.Unlock()

		// 1. Rust High-Speed Resolver (if available)
		var ips []string
		var err error

		if rustResolveDNS != nil && rustResolveDNS.Find() == nil {
			cDomain := []byte(sub + "\x00")
			ptr, _, _ := rustResolveDNS.Call(uintptr(unsafe.Pointer(&cDomain[0])))
			if ptr != 0 {
				rustRes := string(CStrToGo(ptr))
				if rustRes != "NOT_FOUND" && rustRes != "ERROR" {
					ips = strings.Split(rustRes, ",")
				}
			}
		}

		// 2. Fallback to Go standard library
		if len(ips) == 0 {
			ips, err = net.LookupHost(sub)
		}

		if (err == nil && len(ips) > 0) || len(ips) > 0 {
			addResult(sub, ips, "resolved")
			if verbose {
				fmt.Printf("[+] Found: %s (%s)\n", sub, strings.Join(ips, ", "))
			}

			// Recursive: If we found a subdomain and recursive is on, scan one level deeper
			if recursive && strings.Count(sub, ".") < 4 { // Max depth limit (sub.sub.sub.domain.com)
				// Use a small list for recursive to avoid explosion
				smallList := []string{"dev", "test", "stage", "prod", "api", "vpn", "mail", "admin", "internal", "corp"}
				go func(foundSub string) {
					for _, s := range smallList {
						// Be careful not to block here if channel is full
						select {
						case jobs <- fmt.Sprintf("%s.%s", s, foundSub):
						default:
							// Skip if channel is full to avoid deadlock
						}
					}
				}(sub)
			}
		}
	}
}
