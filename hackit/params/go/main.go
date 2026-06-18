package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	targetURL        string
	targetDomain     string
	domainListFile   string
	placeholder      string
	enableFuzz       bool
	fuzzParams       string
	payloadFile      string
	method           string
	threads          int
	timeout          int
	outputFile       string
	proxyAddr        string
	ndjson           bool
	excludeExts      string
	sources          string
	verbose          bool
)

func init() {
	flag.StringVar(&targetURL, "u", "", "Target URL (e.g. https://example.com/page?foo=bar)")
	flag.StringVar(&targetDomain, "d", "", "Domain for archive discovery")
	flag.StringVar(&domainListFile, "l", "", "File containing list of domains")
	flag.StringVar(&placeholder, "p", "FUZZ", "Placeholder for param values")
	flag.BoolVar(&enableFuzz, "fuzz", false, "Enable fuzzing mode")
	flag.StringVar(&fuzzParams, "params", "", "Params to fuzz (comma separated)")
	flag.StringVar(&payloadFile, "payloads", "", "Custom payloads file")
	flag.StringVar(&method, "method", "GET", "HTTP method for fuzzing")
	flag.IntVar(&threads, "threads", 10, "Concurrency")
	flag.IntVar(&timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&outputFile, "output", "", "Save results to file")
	flag.StringVar(&proxyAddr, "proxy", "", "HTTP proxy address")
	flag.BoolVar(&ndjson, "ndjson", false, "Output NDJSON")
	flag.StringVar(&excludeExts, "e", "", "Extra extensions to exclude (comma separated)")
	flag.StringVar(&sources, "sources", "wayback,otx,urlscan,commoncrawl", "Archive sources: wayback,otx,urlscan,commoncrawl")
	flag.BoolVar(&verbose, "v", false, "Verbose debug output")
}

func main() {
	flag.Parse()

	if targetDomain == "" && targetURL == "" && domainListFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -d (domain), -u (URL), or -l (domain list file) required")
		os.Exit(1)
	}

	if enableFuzz && fuzzParams == "" && targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --fuzz requires --params or a URL with params")
		os.Exit(1)
	}

	startTime := time.Now()

	if domainListFile != "" {
		file, err := os.Open(domainListFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening domain list: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain == "" {
				continue
			}
			domain = cleanDomain(domain)
			processDomain(domain)
		}
	} else if targetDomain != "" {
		processDomain(cleanDomain(targetDomain))
	} else if targetURL != "" {
		processURL(targetURL)
	}

	elapsed := time.Since(startTime).Milliseconds()

	if ndjson {
		var domain string
		if targetDomain != "" {
			domain = targetDomain
		} else if targetURL != "" {
			if parsed, err := url.Parse(targetURL); err == nil {
				domain = parsed.Host
			}
		}
		emitTyped("done", map[string]interface{}{
			"duration_ms": elapsed,
			"domain":      domain,
		})
	} else if !ndjson {
		fmt.Printf("\nScan completed in %dms\n", elapsed)
	}
}

func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")
	return domain
}

func processDomain(domain string) {
	sourceList := []string{}
	if sources != "" {
		for _, s := range strings.Split(sources, ",") {
			sourceList = append(sourceList, strings.TrimSpace(s))
		}
	}

	debugLog("Processing domain: %s (sources: %v)", domain, sourceList)

	// Step 1: Discover URLs from archives
	results, uniqueParams := discoverFromArchive(domain, sourceList, placeholder)

	// Step 1b: Extract path-based REST parameters from all URLs
	for i, r := range results {
		pps := extractPathParams(r.URL)
		if len(pps) > 0 {
			results[i].PathParams = pps
			// Also add path params as query-like params for analysis
			for _, pp := range pps {
				if _, exists := results[i].Params[pp.Name]; !exists {
					results[i].Params[pp.Name] = pp.Value
					results[i].ParamNames = append(results[i].ParamNames, pp.Name)
					results[i].ParamCount++
					uniqueParams = append(uniqueParams, pp.Name)
				}
			}
		}
	}
	uniqueParams = sortedKeys(setFromSlice(uniqueParams))

	if ndjson {
		emitTyped("summary", map[string]interface{}{
			"domain":    domain,
			"urls":      len(results),
			"params":    len(uniqueParams),
			"sources":   sourceList,
		})
	} else {
		fmt.Printf("\n[*] Domain: %s\n", domain)
		fmt.Printf("[*] Discovered %d URLs with %d unique parameters\n", len(results), len(uniqueParams))
	}

	// Step 2: Analyze parameters (type detection + deep decode + value mining)
	paramDetails := analyzeParamsAcrossURLs(results)
	findings := findInterestingParams(paramDetails)

	// Step 2b: Path-based param findings
	pathFindings := findPathBasedFindings(domain, results)
	findings = append(findings, pathFindings...)

	// Step 2c: Deep decode findings (multi-layer encoded values)
	decodeFindings := findDeepDecodeFindings(results)
	findings = append(findings, decodeFindings...)

	// Step 2d: Value mining findings (enum/pattern detection)
	mineFindings, valueMines := findValueMineFindings(results)
	findings = append(findings, mineFindings...)

	// Step 3: Output results
	for _, r := range results {
		if ndjson {
			// Add path params to the discovery event
			if len(r.PathParams) > 0 {
				emitTyped("discovery_path", map[string]interface{}{
					"url":        r.URL,
					"path_params": r.PathParams,
					"domain":     r.Domain,
					"path":       r.Path,
				})
			}
			emitTyped("discovery", r)
		} else {
			ppInfo := ""
			if len(r.PathParams) > 0 {
				ppInfo = fmt.Sprintf(" +%d path", len(r.PathParams))
			}
			fmt.Printf("  %s (%d params%s)\n", r.URL, r.ParamCount, ppInfo)
		}
	}

	if !ndjson && len(paramDetails) > 0 {
		fmt.Printf("\n[*] Parameter Analysis:\n")
	}

	for _, d := range paramDetails {
		if ndjson {
			emitTyped("param_detail", d)
		} else {
			sens := ""
			if d.Sensitive {
				sens = " [SENSITIVE]"
			}
			fmt.Printf("  %-30s %-12s %3d URLs%s\n", d.Name, "("+string(d.Type)+")", d.URLCount, sens)
		}
	}

	// Emit value mine results if available
	if ndjson && len(valueMines) > 0 {
		for _, vm := range valueMines {
			emitTyped("value_mine", vm)
		}
	}

	// Emit path template info
	if ndjson {
		templates := detectPathTemplate(extractAllURLs(results))
		for tmpl, count := range templates {
			if count >= 2 {
				emitTyped("path_template", map[string]interface{}{
					"template": tmpl,
					"count":    count,
					"domain":   domain,
				})
			}
		}
	}

	if !ndjson && len(findings) > 0 {
		fmt.Printf("\n[*] Findings:\n")
	}

	for _, f := range findings {
		if ndjson {
			emitTyped("finding", f)
		} else {
			fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Category, f.Description)
		}
	}

	// Step 3: Fuzzing (if enabled)
	if enableFuzz {
		var payloads []string
		if payloadFile != "" {
			file, err := os.Open(payloadFile)
			if err == nil {
				defer file.Close()
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if line := strings.TrimSpace(scanner.Text()); line != "" {
						payloads = append(payloads, line)
					}
				}
			}
		} else {
			payloads = []string{
				"<script>alert(1)</script>",
				"' OR '1'='1",
				"\" OR \"1\"=\"1",
				"../../../etc/passwd",
				"{{7*7}}",
				"${7*7}",
				"<img src=x onerror=alert(1)>",
				"1' OR '1'='1' --",
				"1\" OR \"1\"=\"1\" --",
				"@@version",
			}
		}

		if !ndjson {
			fmt.Printf("\n[*] Fuzzing %d payloads across %d targets...\n", len(payloads), len(results))
		}

		fuzzer := NewFuzzer(timeout)
		fuzzResults := fuzzer.FuzzDiscovered(results, payloads, method, threads)

		for _, fr := range fuzzResults {
			if ndjson {
				emitTyped("fuzz_result", fr)
			} else {
				if fr.Reflected {
					fmt.Printf("\n[+] REFLECTED: param=%s payload=%q status=%d\n", fr.Param, fr.Payload, fr.Status)
				}
				if fr.Error != "" {
					fmt.Printf("[!] ERROR: param=%s %s\n", fr.Param, fr.Error)
				}
			}
		}

		if !ndjson {
			fmt.Printf("\n[*] Fuzzing complete: %d interesting results\n", len(fuzzResults))
		}
	}
}

func processURL(rawURL string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing URL: %v\n", err)
		return
	}

	domain := parsed.Host
	params := parsed.Query()

	if ndjson {
		emitTyped("summary", map[string]interface{}{
			"domain":    domain,
			"url":       rawURL,
			"params":    len(params),
		})
	}

	// Extract params from the URL
	if len(params) > 0 {
		var paramNames []string
		cleanParams := make(map[string]string)
		for k, vals := range params {
			v := ""
			if len(vals) > 0 {
				v = vals[0]
			}
			cleanParams[k] = v
			paramNames = append(paramNames, k)
		}

		discoResult := DiscoResult{
			URL:        rawURL,
			Domain:     domain,
			Source:     "direct",
			Params:     cleanParams,
			ParamNames: paramNames,
			ParamCount: len(cleanParams),
			Path:       parsed.Path,
		}

		if ndjson {
			emitTyped("discovery", discoResult)
		} else {
			fmt.Printf("  %s (%d params)\n", rawURL, len(params))
		}

		// Analyze
		details := analyzeParamsAcrossURLs([]DiscoResult{discoResult})
		findings := findInterestingParams(details)

		for _, d := range details {
			if ndjson {
				emitTyped("param_detail", d)
			} else {
				sens := ""
				if d.Sensitive {
					sens = " [SENSITIVE]"
				}
				fmt.Printf("  %-30s %-12s%s\n", d.Name, "("+string(d.Type)+")", sens)
			}
		}

		for _, f := range findings {
			if ndjson {
				emitTyped("finding", f)
			} else {
				fmt.Printf("  [%s] %s\n", f.Severity, f.Description)
			}
		}
	}

	// Fuzzing
	if enableFuzz {
		var payloads []string
		if payloadFile != "" {
			file, err := os.Open(payloadFile)
			if err == nil {
				defer file.Close()
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if line := strings.TrimSpace(scanner.Text()); line != "" {
						payloads = append(payloads, line)
					}
				}
			}
		} else {
			payloads = []string{"<script>alert(1)</script>", "' OR '1'='1"}
		}

		fuzzParamList := []string{}
		if fuzzParams != "" {
			fuzzParamList = strings.Split(fuzzParams, ",")
		} else {
			for k := range params {
				fuzzParamList = append(fuzzParamList, k)
			}
		}

		var results []DiscoResult
		results = append(results, DiscoResult{
			URL: rawURL, Domain: domain, ParamNames: fuzzParamList,
		})
		fuzzer := NewFuzzer(timeout)
		fuzzResults := fuzzer.FuzzDiscovered(results, payloads, method, threads)
		for _, fr := range fuzzResults {
			if ndjson {
				emitTyped("fuzz_result", fr)
			} else {
				if fr.Reflected {
					fmt.Printf("\n[+] REFLECTED: param=%s payload=%q status=%d\n", fr.Param, fr.Payload, fr.Status)
				}
				if fr.Error != "" {
					fmt.Printf("[!] ERROR: param=%s %s\n", fr.Param, fr.Error)
				}
			}
		}
	}
}

// json helper not in models
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func setFromSlice(s []string) map[string]bool {
	m := make(map[string]bool)
	for _, v := range s {
		m[v] = true
	}
	return m
}


