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
	output := flag.String("o", "", "Output file (JSON)")
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
		Verbose:      *verbose,
	}

	// Industrial-Grade Adaptive Tuning
	if config.Deep {
		config.Recursive = true
		if !config.Stealth {
			config.Concurrency = 400 // Boosted for deep intelligence
		}
	}
	if config.Fast {
		config.Concurrency = 500 // Ultra-high for lightning speed
		config.Timeout = 4
	}
	if config.Stealth {
		config.Concurrency = 5
		config.Timeout = 15
	}

	// Luxury Professional Banner
	startTime := time.Now()
	fmt.Printf("\033[1;36m[#] HACKIT INDUSTRIAL RECON v3.0\033[0m | \033[1;32mTARGET: %s\033[0m\n", config.Domain)
	fmt.Printf("\033[1;34m[*] Engaged Engines: OSINT, Brute, CNAME-Chain, HTTP-Probe\033[0m\n")
	fmt.Printf("\033[1;33m[*] Threading Grid: %d workers | Timeout: %ds\033[0m\n\n", config.Concurrency, config.Timeout)

	// 0. Wildcard Detection (Essential for professional results)
	DetectWildcard(config.Domain)

	// 1. Passive OSINT Phase
	if !config.ActiveOnly {
		fmt.Printf("\033[1;34m[>] PHASE 1:\033[0m Executing Multi-Source Passive Extraction...\n")
		passiveChan := make(chan []string)
		go runPassive(config.Domain, passiveChan, config.Verbose)

		for subs := range passiveChan {
			for _, s := range subs {
				addResult(s, nil, "passive")
			}
		}
	}

	// 2. Active Discovery Phase
	if !config.PassiveOnly {
		fmt.Printf("\033[1;34m[>] PHASE 2:\033[0m Activating High-Performance Active Discovery...\n")
		jobs := make(chan string, config.Concurrency*2)
		var wgResolve sync.WaitGroup

		for i := 0; i < config.Concurrency; i++ {
			wgResolve.Add(1)
			go resolveWorker(jobs, &wgResolve, config.Verbose, config.Domain, config.Recursive)
		}

		runActive(config, jobs)
		
		// Permutations
		if config.Permutations {
			fmt.Printf("\033[1;34m[>] PHASE 3:\033[0m Generating Smart Permutations (Altdns style)...\n")
			currentResults := getResults()
			runPermutations(currentResults, config.Domain, jobs)
		}

		close(jobs)
		wgResolve.Wait()
	}

	// 3. Post-Discovery Intelligence
	finalResults := getResults()
	
	if len(finalResults) > 0 {
		fmt.Printf("\033[1;34m[>] PHASE 4:\033[0m Consolidating Assets & Auditing Infrastructure...\n")
		
		// Resolve missing IPs for OSINT findings
		resolveIPs(finalResults, config.Concurrency)
		finalResults = filterWildcards(finalResults)

		if config.ShowASN {
			resolveASNs(finalResults, config.Concurrency)
		}

		if config.Takeover {
			checkTakeovers(finalResults, config.Concurrency)
		}

		needsProbe := config.ShowSC || config.ShowTitle || config.ShowServer || config.TechDetect || config.Probe
		if needsProbe {
			fmt.Printf("\033[1;34m[>] PHASE 5:\033[0m Probing Life-signs & Fingerprinting Tech Stacks...\n")
			runProbe(finalResults, config)
		}
	}

	// 4. Output Generation
	printResults(finalResults, config)

	// 5. Tactical Summary
	duration := time.Since(startTime)
	fmt.Printf("\n\033[1;36m[#] MISSION ACCOMPLISHED\033[0m | \033[1;32mELAPSED: %v\033[0m | \033[1;32mTOTAL ASSETS: %d\033[0m\n", 
		duration.Truncate(time.Second), len(finalResults))
	fmt.Printf("\033[1;34m--------------------------------------------------------------------------------\033[0m\n\n")
}
