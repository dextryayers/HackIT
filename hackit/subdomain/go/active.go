package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

func runActive(config Config, jobs chan string) {
	if config.Verbose {
		fmt.Println("[*] Running Active Brute Force...")
	}

	// 1. Wildcard Detection (bounded so a stalled resolver cannot hang the scan)
	randName := fmt.Sprintf("hackit-%d.%s", rand.Intn(999999), config.Domain)
	type lookupRes struct {
		err error
	}
	done := make(chan lookupRes, 1)
	go func() {
		_, err := net.LookupHost(randName)
		done <- lookupRes{err: err}
	}()
	select {
	case r := <-done:
		if r.err == nil && config.Verbose {
			fmt.Println("[!] Wildcard DNS detected! Active brute force might produce false positives.")
		}
	case <-time.After(15 * time.Second):
		if config.Verbose {
			fmt.Println("[!] Wildcard pre-check timed out, continuing.")
		}
	}

	// 2. Load Wordlist
	totalWords := 0
	if config.Wordlist != "" {
		count := loadWordlist(config.Wordlist, config.Domain, jobs)
		totalWords += count
		if config.Verbose {
			fmt.Printf("[*] Loaded %d words from wordlist\n", count)
		}
	}

	// 3. Built-in Common Wordlist
	if config.Common {
		count := loadBuiltinWordlist(config.Domain, jobs)
		totalWords += count
		if config.Verbose || count > 0 {
			fmt.Printf("[*] Loaded %d built-in common subdomains\n", count)
		}
	}

	if totalWords == 0 {
		if config.Verbose {
			fmt.Println("[*] No wordlist provided and --common not set. Use -w <wordlist> or --common for active scan.")
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

var (
	seenSubs   = make(map[string]struct{})
	seenSubsMu sync.Mutex
)

func resolveWorker(jobs chan string, wg *sync.WaitGroup, verbose bool, domain string, recursive bool) {
	defer wg.Done()

	for sub := range jobs {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}

		// Shared dedup across all workers so permutation
		// duplicates are resolved only once.
		seenSubsMu.Lock()
		if _, ok := seenSubs[sub]; ok {
			seenSubsMu.Unlock()
			continue
		}
		seenSubs[sub] = struct{}{}
		seenSubsMu.Unlock()

		var ips []string
		var err error

		// Try Linux Rust bridge first
		if runtime.GOOS == "linux" {
			ips = linuxRustResolveDNS(sub)
		}

		// Try Windows Rust FFI
		if len(ips) == 0 && rustResolveDNS != nil && rustResolveDNS.Find() == nil {
			cDomain := []byte(sub + "\x00")
			ptr, _, _ := rustResolveDNS.Call(uintptr(unsafe.Pointer(&cDomain[0])))
			if ptr != 0 {
				rustRes := string(CStrToGo(ptr))
				if rustRes != "NOT_FOUND" && rustRes != "ERROR" {
					ips = strings.Split(rustRes, ",")
				}
			}
		}

		// Fallback to Go standard library
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
					// CRITICAL: Recover from panic if jobs channel is already closed
					defer func() { recover() }()
					
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
