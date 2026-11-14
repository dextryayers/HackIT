package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Reset    = "\033[0m"
	Bold     = "\033[1m"
	Green    = "\033[92m"
	Cyan     = "\033[96m"
	Yellow   = "\033[93m"
	Red      = "\033[91m"
	Magenta  = "\033[95m"
	Blue     = "\033[94m"
	Dim      = "\033[2m"
	Italic   = "\033[3m"
)

func getColor(score float64) string {
	if score == 0.0 {
		return Green
	} else if score > 0.0 && score < 5.0 {
		return Cyan
	} else if score >= 5.0 && score < 8.0 {
		return Yellow
	} else if score >= 8.0 {
		return Red
	}
	return Reset
}

func severityBadge(severity string) string {
	switch severity {
	case "CRITICAL":
		return Red + Bold + "CRITICAL" + Reset
	case "HIGH":
		return Red + "HIGH" + Reset
	case "MEDIUM":
		return Yellow + "MEDIUM" + Reset
	case "LOW":
		return Cyan + "LOW" + Reset
	default:
		return Green + "INFO" + Reset
	}
}

func epssBar(score float64) string {
	if score < 0 {
		return Dim + "N/A" + Reset
	}
	barLen := 20
	filled := int(score * float64(barLen))
	if filled > barLen {
		filled = barLen
	}
	bar := ""
	for i := 0; i < barLen; i++ {
		if i < filled {
			if score >= 0.5 {
				bar += Red + "█" + Reset
			} else if score >= 0.1 {
				bar += Yellow + "█" + Reset
			} else {
				bar += Green + "█" + Reset
			}
		} else {
			bar += Dim + "░" + Reset
		}
	}
	pct := fmt.Sprintf("%.1f%%", score*100)
	return fmt.Sprintf("[%s] %s", bar, pct)
}

func PrintResults(software string, version string, results []ExportResult) {
	fmt.Printf("\n%s━━━ Results: %s %s ━━━%s\n", Bold, software, version, Reset)
	if len(results) == 0 {
		fmt.Printf("%s  ✓ Safe: No known CVEs found.%s\n", Green, Reset)
		return
	}

	for _, res := range results {
		color := getColor(res.Score)
		epssScore := res.EPSS
		cisa := CheckCISA(res.CVEID)
		gh := CheckGitHubAdvisory(res.CVEID)
		owasp := MapCWEtoOWASP(res.CWE)
		edb := CheckExploitDB(res.Severity, res.Score, res.CVEID)

		fmt.Printf("\n%s┌─────────────────────────────────────────────────────────────%s\n", color, Reset)
		fmt.Printf("%s│ %s%s%s\n", color, Bold, res.CVEID, Reset)
		fmt.Printf("%s│ CVSS v3 : %.1f %s%s\n", color, res.Score, severityBadge(res.Severity), Reset)
		if res.AttackType != "" {
			fmt.Printf("%s│ Vector  : %s%s\n", color, res.Vector, Reset)
			fmt.Printf("%s│ Attack  : %s%s\n", Dim, res.AttackType, Reset)
		} else {
			fmt.Printf("%s│ Vector  : %s%s\n", Dim, res.Vector, Reset)
		}
		if res.Description != "" {
			fmt.Printf("%s│ Desc    : %s%s\n", Dim, res.Description, Reset)
		}
		fmt.Printf("%s│ CWE     : %s%s\n", Dim, res.CWE, Reset)
		fmt.Printf("%s│ OWASP   : %s%s\n", Dim, owasp, Reset)

		// EPSS score bar
		if epssScore >= 0 {
			fmt.Printf("%s│ EPSS    : %s %s%s\n", Dim, epssBar(epssScore), epssLabel(epssScore), Reset)
		}

		// CISA KEV
		if cisa != "No" && cisa != "" {
			kevColor := Red
			if stringsContains(cisa, "YES") {
				kevColor = Red + Bold
			}
			fmt.Printf("%s│ CISA    : %s%s%s\n", kevColor, kevColor, cisa, Reset)
		}

		// Exploit probability
		fmt.Printf("%s│ Exploit : %s%s\n", Dim, edb, Reset)

		// GitHub Advisory / OSV
		if gh != "No Advisory Found" && gh != "OSV API unavailable" {
			fmt.Printf("%s│ OSV/GH  : %s%s\n", Dim, gh, Reset)
		}

		if res.Published != "" {
			pub := res.Published[:10]
			fmt.Printf("%s│ Pub     : %s%s\n", Dim, pub, Reset)
		}

		fmt.Printf("%s└─────────────────────────────────────────────────────────────%s\n", color, Reset)
	}

	if len(results) > 0 {
		fmt.Printf("%s  ⚠ %d vulnerability(es) found — review and patch accordingly%s\n",
			Yellow, len(results), Reset)
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

var outputPtr *string

func main() {
	targetPtr := flag.String("target", "", "Target URL/IP")
	modePtr := flag.String("mode", "main", "Mode (parameter/main)")
	outputPtr = flag.String("output", "", "Output JSON file")
	apiKeyPtr := flag.String("api-key", "", "NVD API key (for higher rate limits)")
	debugPtr := flag.Bool("debug", false, "Enable debug logging")
	maxResults := flag.Int("max-results", 20, "Max CVEs per tech/scan")
	concPtr := flag.Int("nvd-concurrency", 3, "Max concurrent NVD queries (1-10; public tier stays rate-limited)")
	subdomainsPtr := flag.Bool("subdomains", false, "Scan built-in common subdomains of the target domain")
	subFilePtr := flag.String("subdomains-file", "", "File with subdomain labels (one per line), read in addition to the built-in list")
	deepPtr := flag.Bool("deep", false, "Full scan: header/body tech detection + all common subdomains + wordlist override")
	flag.Parse()

	if *targetPtr == "" {
		fmt.Println("Usage: worker -target <url> -mode <parameter|main> [--api-key KEY] [--max-results N]")
		os.Exit(1)
	}

	cveDBg = *debugPtr

	// Setup NVD API key
	if *apiKeyPtr != "" {
		SetNVDAPIKey(*apiKeyPtr)
		debugCVE("NVD API key configured")
	}
	// Deep scans imply subdomain coverage, soft fail-safe.
	if *deepPtr {
		*subdomainsPtr = true
	}

	// Signal handler for clean exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[!] Interrupted, printing partial results...%s\n", Yellow, Reset)
	}()

	startTime := time.Now()
	fmt.Printf("%s[+] Initiating CVE Scanner on: %s%s%s\n", Magenta, Bold, *targetPtr, Reset)

	var allResults []ExportResult
	var reportTechs []DetectedTech

	if *deepPtr {
		fmt.Printf("%s[*] Deep mode: enhanced header/body detection + common subdomains + built-in wordlist%s\n", Blue, Reset)
	}

	if *modePtr == "parameter" {
		fmt.Printf("%s[*] Phase 1: Parameter/Logic Scanning%s\n", Blue, Reset)
		logicResults := AnalyzeParameterLogic(*targetPtr)
		if len(logicResults) == 0 {
			fmt.Printf("\n%s✓ CVSS Score: 0.0/10 (SAFE) — No vulnerable parameters detected%s\n", Green, Reset)
			os.Exit(0)
		}

		fmt.Printf("\n%s[*] Phase 2: Multi-Source Enrichment (NVD + CISA + EPSS)...%s\n", Blue, Reset)
		PrintResults("Parameter Scan", "Heuristic", logicResults)
		allResults = logicResults

	} else {
		fmt.Printf("%s[*] Phase 1: Tech Detection (headers + body + port scan)%s\n", Blue, Reset)
		techs := DetectTechnologies(*targetPtr)
		probed := ProbeTarget(*targetPtr)
		mergeSeen := map[string]bool{}
		unified := []DetectedTech{}
		for _, t := range techs {
			k := strings.ToLower(t.Software) + "@" + t.Version
			if !mergeSeen[k] {
				mergeSeen[k] = true
				unified = append(unified, t)
			}
		}
		for _, t := range probed {
			k := strings.ToLower(t.Software) + "@" + t.Version
			if !mergeSeen[k] {
				mergeSeen[k] = true
				unified = append(unified, t)
			}
		}
		techs = unified

		if len(techs) == 0 {
			fmt.Printf("%s[!] Enhanced probe yielded nothing. Escalating to port scan...%s\n", Yellow, Reset)
			techs = DeepScanPorts(*targetPtr)
		}

		if len(techs) == 0 {
			fmt.Printf("\n%s✓ CVSS Score: 0.0/10 (SAFE) — No tech detected / fully hidden%s\n", Green, Reset)
			os.Exit(0)
		}

		fmt.Printf("\n%s[*] Detected %d technologies, querying NVD in parallel...%s\n", Blue, len(techs), Reset)
		reportTechs = techs

		// Parallel NVD queries (bounded; public API is still rate-limited globally)
		conc := *concPtr
		if conc < 1 {
			conc = 1
		}
		if conc > 10 {
			conc = 10
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sema := make(chan struct{}, conc)

		for _, t := range techs {
			wg.Add(1)
			sema <- struct{}{}
			go func(tech DetectedTech) {
				defer wg.Done()
				defer func() { <-sema }()

				if tech.Version == "unknown" || tech.Version == "" {
					mu.Lock()
					fmt.Printf("\n%s• %s — version hidden, skipping NVD query%s\n", Dim, tech.Software, Reset)
					mu.Unlock()
					return
				}

				mu.Lock()
				fmt.Printf("%s  Querying NVD: %s %s...%s\n", Cyan, tech.Software, tech.Version, Reset)
				mu.Unlock()

				res := QueryNVD(tech.Software, tech.Version)

				mu.Lock()
				if len(res) > 0 {
					// Limit results
					if len(res) > *maxResults {
						res = res[:*maxResults]
					}
					allResults = append(allResults, res...)
				}
				mu.Unlock()
			}(t)
		}
		wg.Wait()
	}

	// Deduplicate
	deduped := deduplicateResults(allResults)
	elapsed := time.Since(startTime)

	fmt.Printf("\n%s[*] Phase 3: Deduplication & Enrichment%s\n", Blue, Reset)
	fmt.Printf("    Found %d unique CVEs across %d raw results in %v\n", len(deduped), len(allResults), elapsed.Round(time.Millisecond))

	// Batch EPSS enrichment
	fmt.Printf("%s[*] Querying EPSS scores for %d CVEs...%s\n", Dim, len(deduped), Reset)
	cveIDs := make([]string, len(deduped))
	for i, r := range deduped {
		cveIDs[i] = r.CVEID
	}
	epssMap := BatchQueryEPSS(cveIDs)

	// Apply EPSS scores to results
	for i := range deduped {
		if score, ok := epssMap[deduped[i].CVEID]; ok {
			deduped[i].EPSS = score
		} else {
			deduped[i].EPSS = -1
		}
	}

	// Print final results
	for _, r := range deduped {
		PrintResults(r.Software, "", []ExportResult{r})
	}

	// Summary
	fmt.Printf("\n%s━━━ Scan Summary ━━━%s\n", Bold, Reset)
	fmt.Printf("  Target    : %s\n", *targetPtr)
	fmt.Printf("  Mode      : %s\n", *modePtr)
	fmt.Printf("  Duration  : %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  CVEs      : %d\n", len(deduped))

	// Severity breakdown
	sevCount := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, r := range deduped {
		s := r.Severity
		if _, ok := sevCount[s]; ok {
			sevCount[s]++
		} else {
			sevCount["INFO"]++
		}
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if sevCount[sev] > 0 {
			c := getColor(mapSeverityScore(sev))
			fmt.Printf("  %s%-10s: %d%s\n", c, sev, sevCount[sev], Reset)
		}
	}

	// Top EPSS
	if len(deduped) > 0 {
		topEPSS := deduped[0]
		for _, r := range deduped {
			if r.EPSS > topEPSS.EPSS {
				topEPSS = r
			}
		}
		if topEPSS.EPSS >= 0 {
			fmt.Printf("\n  %sHighest EPSS: %s %.1f%% (%s)%s\n",
				Red, topEPSS.CVEID, topEPSS.EPSS*100, epssLabel(topEPSS.EPSS), Reset)
		}
	}

	// Subdomain intel pass — main target techs are the cite above; expand now.
	var subReports []SubdomainReport
	if *subdomainsPtr {
		extraHosts := []string{}
		if *subFilePtr != "" {
			extraHosts = LoadSubdomainFile(*subFilePtr)
			if len(extraHosts) == 0 {
				fmt.Printf("%s[!] Subdomains file %q empty or unreadable; assuming user-supplied list is empty. Probing passive providers only.%s\n", Yellow, *subFilePtr, Reset)
			}
		}
		fmt.Printf("\n%s[*] Phase 4: Subdomain intelligence — consulting crt.sh, hackertarget.com, wayback, rapiddns, commoncrawl, ...%s\n", Blue, Reset)
		subReports = ScanSubdomains(*targetPtr, true, nil, extraHosts)

		// Merge subdomain CVEs into overall results for ranked output/JSON.
		for _, sr := range subReports {
			for i := range sr.CVEs {
				allResults = append(allResults, sr.CVEs[i])
			}
		}
		if len(subReports) == 0 {
			fmt.Printf("%s[*] No public subdomains responded; target coverage limited to main host%s\n", Dim, Reset)
		} else {
			fmt.Printf("\n%s[*] Subdomain scan complete: %d subdomain(s) with public HTTP responses%s\n", Blue, len(subReports), Reset)
		}
	}

	// Recompute dedup for tech + subdomain enrichments combined.
	deduped = deduplicateResults(allResults)

	sevCountTotal := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, r := range deduped {
		if _, ok := sevCountTotal[r.Severity]; ok {
			sevCountTotal[r.Severity]++
		} else {
			sevCountTotal["INFO"]++
		}
	}
	fmt.Printf("\n%s━━━ Deep scan summary ━━━%s\n", Bold, Reset)
	fmt.Printf("  Target        : %s\n", *targetPtr)
	fmt.Printf("  Reachable host: %s\n", *targetPtr)
	fmt.Printf("  Subdomains    : %d reachable (passive-only providers + user extras)\n", len(subReports))
	fmt.Printf("  Techs detected: %d\n", len(reportTechs))
	fmt.Printf("  Total CVEs    : %d\n", len(deduped))
	fmt.Printf("  Critical=%d  High=%d  Medium=%d  Low=%d  Info=%d\n",
		sevCountTotal["CRITICAL"], sevCountTotal["HIGH"], sevCountTotal["MEDIUM"], sevCountTotal["LOW"], sevCountTotal["INFO"])

	// Export JSON report (referenced, structured, detailed).
	if *outputPtr != "" && len(deduped) >= 0 {
		ExportReport(*targetPtr, *modePtr, startTime, reportTechs, deduped, subReports)
	}

	elapsedTotal := time.Since(startTime)
	fmt.Printf("\n%sScan completed in %v%s\n", Dim, elapsedTotal.Round(time.Millisecond), Reset)
}

func mapSeverityScore(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 2.5
	default:
		return 0.0
	}
}
