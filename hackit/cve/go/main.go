package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Green  = "\033[92m"
	Cyan   = "\033[96m"
	Yellow = "\033[93m"
	Red    = "\033[91m"
	Magenta= "\033[95m"
	Blue   = "\033[94m"
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

func PrintResults(tech string, ver string, results []ExportResult) {
	fmt.Printf("\n%s[+] Results for %s version %s%s\n", Blue, tech, ver, Reset)
	if len(results) == 0 {
		fmt.Printf("%s[*] Safe: No known CVEs found.%s\n", Green, Reset)
		return
	}

	for _, res := range results {
		color := getColor(res.Score)
		cisa := CheckCISA(res.CVEID)
		gh := CheckGitHubAdvisory(res.CVEID)
		owasp := MapCWEtoOWASP(res.CWE)
		edb := CheckExploitDB(res.Severity, res.Score)

		fmt.Printf("%s==================================================%s\n", color, Reset)
		fmt.Printf("%sCVE ID      : %s%s\n", Bold, res.CVEID, Reset)
		fmt.Printf("CVSS Score  : %s%.1f (%s)%s\n", color, res.Score, res.Severity, Reset)
		fmt.Printf("Vector      : %s\n", res.Vector)
		fmt.Printf("Description : %s\n", res.Software) // we stored the description in Software field for heuristic
		fmt.Printf("CWE         : %s\n", res.CWE)
		fmt.Printf("OWASP Top 10: %s\n", owasp)
		fmt.Printf("CISA KEV    : %s\n", cisa)
		fmt.Printf("GitHub Adv  : %s\n", gh)
		fmt.Printf("Exploit-DB  : %s\n", edb)
	}
}

func main() {
	targetPtr := flag.String("target", "", "Target URL/IP")
	modePtr := flag.String("mode", "main", "Mode (parameter/main)")
	outputPtr := flag.String("output", "", "Output JSON file")
	flag.Parse()

	if *targetPtr == "" {
		fmt.Println("Usage: worker -target <url> -mode <parameter|main>")
		os.Exit(1)
	}

	fmt.Printf("%s[+] Initiating Defensive CVE Scanner on: %s%s\n", Magenta, *targetPtr, Reset)

	// Phase 1 & 2: Detection and Lookup
	var allResults []ExportResult

	if *modePtr == "parameter" {
		fmt.Println("[*] Phase 1: Parameter/Logic Scanning (Safe WAF Detection)...")
		fmt.Println("    [!] Parameter scanning is passive. Analyzing URL structures...")
		
		logicResults := AnalyzeParameterLogic(*targetPtr)
		if len(logicResults) == 0 {
			fmt.Printf("\n%s[+] CVSS Score : 0.0/10 (SAFE/GREEN) - No dynamic vulnerable parameters found.%s\n", Green, Reset)
			os.Exit(0)
		}

		fmt.Println("\n[*] Phase 2: Multi-Source CVE Mapping...")
		PrintResults("Dynamic URL Analysis", "Heuristic", logicResults)
		allResults = append(allResults, logicResults...)

	} else {
		fmt.Println("[*] Phase 1: Main URL (Deep Port & Tech Scanning)...")
		techs := DetectTechnologies(*targetPtr)
		if len(techs) == 0 {
			fmt.Printf("%s[!] HTTP Headers yielded nothing. Escalating to Safe Port Scanning...%s\n", Yellow, Reset)
			techs = DeepScanPorts(*targetPtr)
		}

		if len(techs) == 0 {
			fmt.Printf("\n%s[+] CVSS Score : 0.0/10 (SAFE/GREEN) - No known vulnerabilities mapped or stack fully hidden.%s\n", Green, Reset)
			os.Exit(0)
		}

		fmt.Println("\n[*] Phase 2: Multi-Source CVE Mapping...")
		for _, t := range techs {
			if t.Version == "unknown" {
				fmt.Printf("\n%s[+] Results for %s version [HIDDEN]%s\n", Blue, t.Software, Reset)
				fmt.Printf("%s[+] CVSS Score : 0.0/10 (SAFE/GREEN) - Version hidden, assuming safe defensive posture.%s\n", Green, Reset)
				continue
			}
			
			fmt.Printf("[*] Querying NVD for %s %s...\n", t.Software, t.Version)
			res := QueryNVD(t.Software, t.Version)
			
			if len(res) == 0 {
				fmt.Printf("\n%s[+] Results for %s version %s%s\n", Blue, t.Software, t.Version, Reset)
				fmt.Printf("%s[+] CVSS Score : 0.0/10 (SAFE/GREEN) - No known CVEs found in NVD database.%s\n", Green, Reset)
			} else {
				PrintResults(t.Software, t.Version, res)
				allResults = append(allResults, res...)
			}
			
			// Rate limit protection
			time.Sleep(2 * time.Second)
		}
	}

	// Phase 3: Export
	if *outputPtr != "" && len(allResults) > 0 {
		data, _ := json.MarshalIndent(allResults, "", "  ")
		os.WriteFile(*outputPtr, data, 0644)
		fmt.Printf("\n[*] Results exported to %s\n", *outputPtr)
	}
}
