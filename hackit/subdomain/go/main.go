package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
)

func main() {
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
		// Only print help/error if no arguments or domain missing
		// But for CLI tools, maybe just exit 1
		fmt.Println("[!] Domain is required")
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

	if config.Deep {
		config.Recursive = true
		config.Permutations = true
		if !config.Stealth {
			config.Concurrency = 300
		}
	}
	if config.Fast {
		config.Concurrency = 200
		config.Timeout = 5
	}
	if config.Stealth {
		config.Concurrency = 10
		config.Timeout = 20
	}

	// 0. Wildcard Detection
	DetectWildcard(config.Domain)

	// 1. Passive Enumeration
	if !config.ActiveOnly {
		if config.Verbose {
			fmt.Println("[*] Starting Passive Enumeration...")
		}
		subs := runPassive(config.Domain)
		if config.Verbose {
			fmt.Printf("[+] Passive Sources found %d subdomains\n", len(subs))
		}
		for _, s := range subs {
			addResult(s, nil, "passive")
		}
	}

	// 2. Active Enumeration
	if !config.PassiveOnly {
		jobs := make(chan string, config.Concurrency)
		var wgResolve sync.WaitGroup

		// Start Resolver Workers
		for i := 0; i < config.Concurrency; i++ {
			wgResolve.Add(1)
			go resolveWorker(jobs, &wgResolve, config.Verbose)
		}

		// Run Active
		runActive(config, jobs)
		close(jobs)
		wgResolve.Wait()
	}

	// 2.5 Permutations
	if config.Permutations {
		finalResultsSoFar := getResults()
		if len(finalResultsSoFar) > 0 {
			jobs := make(chan string, config.Concurrency)
			var wgPerm sync.WaitGroup

			for i := 0; i < config.Concurrency; i++ {
				wgPerm.Add(1)
				go resolveWorker(jobs, &wgPerm, config.Verbose)
			}

			runPermutations(finalResultsSoFar, config.Domain, jobs)
			close(jobs)
			wgPerm.Wait()
		}
	}

	// 2.6 Deep Recursive Scan
	if config.Recursive {
		finalResultsSoFar := getResults()
		if len(finalResultsSoFar) > 0 {
			runDeep(finalResultsSoFar, config)
		}
	}

	// 3. Collect Results
	finalResults := getResults()

	// 4. Resolve IPs if requested (and not already resolved by active)
	// Active scan resolves IPs, but Passive ones might not have IPs yet
	if config.ShowIP || config.Takeover || config.ShowASN {
		if config.Verbose {
			fmt.Println("[*] Resolving IPs...")
		}
		resolveIPs(finalResults, config.Concurrency)

		// 4.1 Filter Wildcard False Positives
		finalResults = filterWildcards(finalResults)
	}

	// 5. ASN Lookup
	if config.ShowASN {
		if config.Verbose {
			fmt.Println("[*] Resolving ASNs...")
		}
		resolveASNs(finalResults, config.Concurrency)
	}

	// 6. Takeover Check
	if config.Takeover {
		if config.Verbose {
			fmt.Println("[*] Checking for Takeovers...")
		}
		checkTakeovers(finalResults, config.Concurrency)
	}

	// 7. Probe HTTP if requested
	needsProbe := config.ShowSC || config.ShowTitle || config.ShowServer || config.TechDetect || config.Probe
	if needsProbe {
		if config.Verbose {
			fmt.Println("[*] Probing HTTP services...")
		}
		runProbe(finalResults, config)
	}

	// 6. Output
	if len(finalResults) == 0 {
		fmt.Println("[!] No subdomains found.")
		fmt.Println("    Hints:")
		fmt.Println("    - Check domain spelling (e.g., .go.id vs .gp.id)")
		fmt.Println("    - Check internet connectivity")
		fmt.Println("    - Try using a wordlist with -w")
	}
	printResults(finalResults, config)

	// 7. Summary
	fmt.Println(" ------------------------------------------------------------ ")
	fmt.Println(" [+] Scan Completed Successfully.")
	fmt.Printf(" [*] Total Subdomains Found: %d\n", len(finalResults))
	fmt.Println(" ------------------------------------------------------------ ")
}
