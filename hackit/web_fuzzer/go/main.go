package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Initialize global high-concurrency client
	InitClient(10)

	// Support both CLI flags and positional JSON for cooperative mode
	urlFlag := flag.String("u", "", "Target URL")
	intelFlag := flag.String("intel", "", "JSON raw intelligence from Rust")
	harvestFlag := flag.String("harvest", "", "Domain to harvest parameters from")
	flag.Parse()

	if *harvestFlag != "" {
		handleHarvest(*harvestFlag)
		return
	}

	if *intelFlag != "" {
		handleCooperativeIntel(*intelFlag)
		return
	}

	if *urlFlag != "" {
		handleSingleTarget(*urlFlag)
		return
	}

	fmt.Println("[]")
}

func handleHarvest(domain string) {
	fmt.Fprintf(os.Stderr, "[*] HARVESTER: Launching multi-source intel cluster for %s...\n", domain)
	h := NewHarvester()
	urls := h.Harvest(domain)
	
	// Deep Scan JS for more params
	fmt.Fprintf(os.Stderr, "[*] HARVESTER: Discovered %d urls. Performing Deep JS Analysis...\n", len(urls))
	extra := h.DeepScanJS(urls)
	
	// Active Scan: Extract Forms
	fmt.Fprintf(os.Stderr, "[*] HARVESTER: Extracting live form parameters...\n")
	forms := h.ExtractForms(domain)
	extra = append(extra, forms...)
	
	// Add extra discovered params to urls as guesses or markers
	for _, p := range extra {
		if strings.Contains(p, "/") { // It's an endpoint
			urls = append(urls, fmt.Sprintf("http://%s%s", domain, p))
		} else { // It's a param
			urls = append(urls, fmt.Sprintf("http://%s/?%s=FUZZ", domain, p))
		}
	}
	
	for _, u := range urls {
		fmt.Println(u)
	}
}

func handleCooperativeIntel(raw string) {
	var rawURLs []string
	err := json.Unmarshal([]byte(raw), &rawURLs)
	if err != nil {
		fmt.Println("[]")
		return
	}

	var shaped []ShapedTarget
	// Unified tactical output
	fmt.Fprintf(os.Stderr, "[*] SHAPER: Processing %d intelligence artifacts...\n", len(rawURLs))
	
	for _, u := range rawURLs {
		waf := CheckWAF("", nil) 
		priority := 5
		if waf != "" {
			priority = 1
		}
		
		shaped = append(shaped, ShapedTarget{
			URL:      u,
			WAF:      waf,
			Priority: priority,
		})
	}

	out, _ := json.Marshal(shaped)
	fmt.Println(string(out))
}

func handleSingleTarget(url string) {
	waf := CheckWAF("", nil)
	res := []ShapedTarget{{URL: url, WAF: waf, Priority: 5}}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
}
