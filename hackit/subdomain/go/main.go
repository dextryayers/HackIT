package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

func main() {
	// Global Recovery for Industrial Stability
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n\033[1;31m[!] CRITICAL ENGINE FAILURE: %v\033[0m\n", r)
			os.Exit(1)
		}
	}()

	// Parse Flags
	domain := flag.String("d", "", "Target domain")
	wordlist := flag.String("w", "", "Wordlist path")
	concurrency := flag.Int("c", 100, "Concurrency/Threads")
	output := flag.String("o", "", "Output file")
	outputFormat := flag.String("of", "text", "Output format: text, json, csv")
	verbose := flag.Bool("v", false, "Verbose output")

	// Modes
	passiveOnly := flag.Bool("passive-only", false, "Passive only")
	activeOnly := flag.Bool("active-only", false, "Active only")
	permutations := flag.Bool("permutations", false, "Enable permutations")
	takeover := flag.Bool("takeover", false, "Check takeover")
	recursive := flag.Bool("recursive", false, "Enable recursive")
	stealth := flag.Bool("stealth", false, "Stealth mode")
	fast := flag.Bool("fast", false, "Fast mode")
	deep := flag.Bool("deep", false, "Deep scan mode")

	// Enhancement Flags
	common := flag.Bool("common", false, "Use built-in common subdomain wordlist")
	all := flag.Bool("all", false, "Max depth: common+passive+active+permutations+takeover+probe")
	noWildcard := flag.Bool("no-wildcard", false, "Disable wildcard DNS filtering")
	dnsOverHTTPS := flag.Bool("doh", false, "Use DNS-over-HTTPS resolvers")
	resolve := flag.Bool("resolve", true, "Resolve DNS for passive-only findings")

	// Probe
	sc := flag.Bool("sc", false, "Show status code")
	ip := flag.Bool("ip", false, "Show IP")
	title := flag.Bool("title", false, "Show Title")
	server := flag.Bool("server", false, "Show Server")
	tech := flag.Bool("tech", false, "Show Tech")
	asn := flag.Bool("asn", false, "Show ASN")
	probe := flag.Bool("probe", false, "Enable Probing")
	filterCodes := flag.String("fc", "", "Filter codes")

	flag.Parse()

	if *domain == "" {
		fmt.Println("[!] Target domain is required (-d domain.com)")
		os.Exit(1)
	}

	// --all flag enables everything
	if *all {
		*passiveOnly = false
		*activeOnly = false
		*permutations = true
		*takeover = true
		*recursive = true
		*probe = true
		*sc = true
		*ip = true
		*title = true
		*server = true
		*tech = true
		*asn = true
		*common = true
		*resolve = true
		*deep = true
	}

	config := Config{
		Domain:       *domain,
		Wordlist:     *wordlist,
		Concurrency:  *concurrency,
		Timeout:      10,
		PassiveOnly:  *passiveOnly,
		ActiveOnly:   *activeOnly,
		Permutations: *permutations,
		Takeover:     *takeover,
		Recursive:    *recursive,
		Stealth:      *stealth,
		Fast:         *fast,
		Deep:         *deep,
		ShowSC:       *sc,
		ShowIP:       *ip,
		ShowTitle:    *title,
		ShowServer:   *server,
		TechDetect:   *tech,
		ShowASN:      *asn,
		Probe:        *probe,
		FilterCodes:  *filterCodes,
		Output:       *output,
		OutputFormat: *outputFormat,
		Verbose:      *verbose,
		Common:       *common,
		All:          *all,
		NoWildcard:   *noWildcard,
		DNSOverHTTPS: *dnsOverHTTPS,
		Resolve:      *resolve,
	}

	// Industrial-Grade Adaptive Tuning
	if config.Deep {
		config.Recursive = true
		config.Permutations = true
		config.Takeover = true
		config.Probe = true
		config.Resolve = true
		if !config.Stealth {
			config.Concurrency = 400 // Boosted for deep intelligence
		}
	}
	if config.Fast {
		if config.Concurrency < 500 {
			config.Concurrency = 500 // Ultra-high for lightning speed
		}
		config.Timeout = 4
	}
	if config.Stealth {
		config.Concurrency = 5
		config.Timeout = 15
	}

	// Luxury Professional Banner
	startTime := time.Now()
	fmt.Printf("\033[1;36m╔══════════════════════════════════════════════════╗\033[0m\n")
	fmt.Printf("\033[1;36m║\033[0m  \033[1;33mHACKIT SUBDOMAIN RECON v3.5\033[0m              \033[1;36m║\033[0m\n")
	fmt.Printf("\033[1;36m╚══════════════════════════════════════════════════╝\033[0m\n")
	fmt.Printf("\033[1;32m  TARGET:\033[0m %s\n", config.Domain)

	engines := "OSINT"
	if !config.PassiveOnly {
		engines += " + Brute"
	}
	if config.Permutations {
		engines += " + Permutations"
	}
	if config.Takeover {
		engines += " + Takeover"
	}
	if config.Probe {
		engines += " + HTTP-Probe"
	}
	fmt.Printf("\033[1;36m  ENGINES:\033[0m %s\n", engines)
	fmt.Printf("\033[1;35m  WORKERS:\033[0m %d | \033[1;35mTIMEOUT:\033[0m %ds", config.Concurrency, config.Timeout)
	if config.Common {
		fmt.Printf(" | \033[1;32m+COMMON WL\033[0m")
	}
	fmt.Println()

	// 0. Wildcard Detection (Essential for professional results)
	if !config.NoWildcard {
		DetectWildcard(config.Domain)
	} else if config.Verbose {
		fmt.Println("\033[1;33m[*] Wildcard detection disabled\033[0m")
	}

	// 1. Passive OSINT Phase
	if !config.ActiveOnly {
		fmt.Printf("\033[1;34m[>] PHASE 1:\033[0m Multi-Source Passive Extraction...\n")
		passiveChan := make(chan []string)
		go runPassive(config.Domain, passiveChan, config.Verbose)

		for subs := range passiveChan {
			for _, s := range subs {
				cs := cleanSubdomain(s, config.Domain)
				if cs != "" {
					addResult(cs, nil, "passive")
				}
			}
		}
	}

	// 2. Active Discovery Phase
	if !config.PassiveOnly {
		fmt.Printf("\033[1;34m[>] PHASE 2:\033[0m Active Discovery...\n")
		jobs := make(chan string, config.Concurrency*2)
		var wgResolve sync.WaitGroup

		for i := 0; i < config.Concurrency; i++ {
			wgResolve.Add(1)
			go resolveWorker(jobs, &wgResolve, config.Verbose, config.Domain, config.Recursive)
		}

		runActive(config, jobs)

		// Permutations
		if config.Permutations {
			fmt.Printf("\033[1;34m[>] PHASE 3:\033[0m Smart Permutations...\n")
			currentResults := getResults()
			runPermutations(currentResults, config.Domain, jobs)
		}

		close(jobs)
		wgResolve.Wait()
	}

	// 3. Post-Discovery Intelligence
	finalResults := getResults()
	
	if len(finalResults) > 0 {
		fmt.Printf("\033[1;34m[>] PHASE 4:\033[0m Consolidating Assets...\n")

		// Resolve missing IPs for OSINT findings
		if config.Resolve {
			resolveIPs(finalResults, config.Concurrency)
		}

		if !config.NoWildcard {
			finalResults = filterWildcards(finalResults)
		}

		if config.ShowASN {
			resolveASNs(finalResults, config.Concurrency)
		}

		if config.Takeover {
			checkTakeovers(finalResults, config.Concurrency)
		}

		needsProbe := config.ShowSC || config.ShowTitle || config.ShowServer || config.TechDetect || config.Probe
		if needsProbe {
			fmt.Printf("\033[1;34m[>] PHASE 5:\033[0m HTTP Probing & Fingerprinting...\n")
			runProbe(finalResults, config)
		}
	}

	// 4. Print ALL final results with full enrichment detail
	if len(finalResults) > 0 {
		fmt.Printf("\n\033[1;34m[>]\033[0m \033[1;32mFINAL ENRICHED RESULTS:\033[0m\n")
		for _, r := range finalResults {
			if needsProbe := config.ShowSC || config.ShowTitle || config.ShowServer || config.TechDetect || config.Probe; needsProbe {
				printResultDetail(r, config)
			} else if config.ShowASN || config.ShowIP {
				printResultDetail(r, config)
			} else {
				// Silent mode: just subdomain
				fmt.Printf("\x1b[1;32m[+]\x1b[0m \x1b[1;36m[sub]\x1b[0m %s\n", r.Subdomain)
			}
		}
	}

	// 5. Tactical Summary
	duration := time.Since(startTime)
	fmt.Printf("\n\033[1;32m═══════════════════════════════════════\033[0m\n")
	fmt.Printf("\033[1;33m  TOTAL: %d subdomains | ELAPSED: %v\033[0m\n",
		len(finalResults), duration.Truncate(time.Second))
	fmt.Printf("\033[1;32m═══════════════════════════════════════\033[0m\n")
	fmt.Println()
}
